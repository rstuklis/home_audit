"""Rogue-DHCP responder collection (`check_rogue_dhcp`).

The function broadcasts one DHCP DISCOVER and gathers every OFFER that comes
back; more than one distinct responder means a second DHCP server is on the
wire, which can silently own every new lease. The parts worth pinning are pure:
the offered IP is decoded from the `yiaddr` field (bytes 16–20), responders are
de-duplicated by source IP, and a failure to bind port 68 degrades to a
`(list, error)` pair rather than an exception.

The socket is faked to replay a scripted set of datagrams; `describe_dhcp_offer`
runs for real over the bytes we hand it, so a malformed OFFER would surface here
too.
"""

import socket
import struct


def _offer_packet(yiaddr, options=b""):
    """A BOOTP reply with yiaddr set and an optional DHCP options trailer.

    Only the fixed header up to yiaddr matters to the responder loop; the magic
    cookie + options are appended so describe_dhcp_offer has something real to
    parse.
    """
    pkt = struct.pack(
        "!BBBBLHH4s4s4s4s16s64s128s",
        2, 1, 6, 0, 0x1234, 0, 0,
        b"\x00" * 4,                       # ciaddr
        socket.inet_aton(yiaddr),          # yiaddr — the offered address
        b"\x00" * 4, b"\x00" * 4,
        b"\x00" * 16, b"\x00" * 64, b"\x00" * 128,
    )
    if options:
        pkt += b"\x63\x82\x53\x63" + options + b"\xff"
    return pkt


class _FakeDhcpSocket:
    """Replays a scripted list of (data, addr) datagrams, then times out.

    `bind_error` makes bind() raise, to exercise the no-privilege path.
    """
    def __init__(self, datagrams, bind_error=None):
        self._datagrams = list(datagrams)
        self._bind_error = bind_error
    def setsockopt(self, *a): pass
    def settimeout(self, t): pass
    def bind(self, addr):
        if self._bind_error:
            raise self._bind_error
    def sendto(self, data, addr): pass
    def recvfrom(self, n):
        if self._datagrams:
            return self._datagrams.pop(0)
        raise socket.timeout()
    def close(self): pass


def _wire(monkeypatch, mod, datagrams=(), bind_error=None):
    # ifconfig is consulted only for a chaddr filler; a plain MAC line is enough.
    monkeypatch.setattr(mod, "run",
                        lambda cmd, *a, **k: "ether 3c:22:fb:00:11:22")
    monkeypatch.setattr(mod.socket, "socket",
                        lambda *a, **k: _FakeDhcpSocket(datagrams, bind_error))


class TestResponderCollection:
    def test_a_single_offer_yields_one_responder_with_its_offered_ip(self, mod, monkeypatch):
        pkt = _offer_packet("192.168.1.100")
        _wire(monkeypatch, mod, [(pkt, ("192.168.1.1", 67))])
        responders, err = mod.check_rogue_dhcp(timeout=5)
        assert err is None
        assert len(responders) == 1
        assert responders[0]["ip"] == "192.168.1.1"
        assert responders[0]["offered_ip"] == "192.168.1.100"

    def test_two_distinct_servers_are_both_recorded(self, mod, monkeypatch):
        # The whole point of the check: a second responder is the finding.
        _wire(monkeypatch, mod, [
            (_offer_packet("192.168.1.100"), ("192.168.1.1", 67)),
            (_offer_packet("10.0.0.50"), ("10.0.0.1", 67)),
        ])
        responders, err = mod.check_rogue_dhcp(timeout=5)
        assert sorted(r["ip"] for r in responders) == ["10.0.0.1", "192.168.1.1"]

    def test_repeat_datagrams_from_one_server_collapse_to_one_responder(self, mod, monkeypatch):
        # Real DHCP servers often send the OFFER two or three times; those are
        # one responder, not evidence of a rogue. Dedup is keyed on source IP.
        pkt = _offer_packet("192.168.1.100")
        _wire(monkeypatch, mod, [
            (pkt, ("192.168.1.1", 67)),
            (pkt, ("192.168.1.1", 67)),
            (pkt, ("192.168.1.1", 67)),
        ])
        responders, _ = mod.check_rogue_dhcp(timeout=5)
        assert len(responders) == 1

    def test_no_responses_is_a_clean_empty_result_not_an_error(self, mod, monkeypatch):
        # Unicast-only routers never answer this broadcast; that's normal, not
        # a failure — err must stay None so the caller doesn't cry SKIP.
        _wire(monkeypatch, mod, [])
        responders, err = mod.check_rogue_dhcp(timeout=5)
        assert responders == []
        assert err is None


class TestOfferParsing:
    def test_the_offered_gateway_option_is_surfaced(self, mod, monkeypatch):
        # Option 3 (router) is decoded by describe_dhcp_offer and merged into
        # the responder dict; a poisoned gateway is visible even with one server.
        opts = b"\x03\x04" + socket.inet_aton("192.168.1.254")
        pkt = _offer_packet("192.168.1.100", options=opts)
        _wire(monkeypatch, mod, [(pkt, ("192.168.1.1", 67))])
        responders, _ = mod.check_rogue_dhcp(timeout=5)
        assert responders[0]["router"] == ["192.168.1.254"]

    def test_a_runt_datagram_falls_back_to_unknown_offered_ip(self, mod, monkeypatch):
        # A packet too short to contain yiaddr must not index past its end; the
        # code guards with len(data) >= 20 and reports "unknown".
        _wire(monkeypatch, mod, [(b"\x02\x01\x06\x00", ("192.168.1.1", 67))])
        responders, _ = mod.check_rogue_dhcp(timeout=5)
        assert responders[0]["offered_ip"] == "unknown"


class TestBindFailure:
    def test_a_bind_denial_returns_an_error_string_not_an_exception(self, mod, monkeypatch):
        # Port 68 needs privilege; without it bind raises PermissionError. The
        # function must catch that and hand back a (empty, message) pair.
        _wire(monkeypatch, mod, [], bind_error=PermissionError("Operation not permitted"))
        responders, err = mod.check_rogue_dhcp(timeout=5)
        assert responders == []
        assert err is not None
        assert "68" in err


class TestDenialIsNotAPrivilegeProblem:
    """macOS Local Network privacy denies a background job its own subnet, and
    the DHCP broadcast is refused with EHOSTUNREACH — the same errno the port
    scan gets. The note used to say "try sudo", which is the one remedy that
    cannot work: the job is not short of privilege, it is short of a permission
    launchd jobs cannot be granted. A reader who follows that advice learns
    nothing and concludes the tool is broken."""

    def test_an_unreachable_bind_is_reported_as_a_denial_not_as_sudo(self, mod, monkeypatch):
        import errno as _errno
        _wire(monkeypatch, mod, [],
              bind_error=OSError(_errno.EHOSTUNREACH, "No route to host"))
        _, note = mod.check_rogue_dhcp(timeout=5)
        assert "sudo does not help" in note
        assert "Local Network privacy" in note

    def test_a_genuine_permission_error_still_recommends_sudo(self, mod, monkeypatch):
        # The distinction is the point: on a box where privilege really is the
        # blocker, sudo IS the answer and must still be offered.
        import errno as _errno
        _wire(monkeypatch, mod, [],
              bind_error=PermissionError(_errno.EACCES, "Permission denied"))
        _, note = mod.check_rogue_dhcp(timeout=5)
        assert "sudo" in note
        assert "Local Network privacy" not in note

    def test_an_unrecognised_bind_error_is_reported_plainly(self, mod, monkeypatch):
        _wire(monkeypatch, mod, [], bind_error=OSError(99, "Cannot assign requested address"))
        _, note = mod.check_rogue_dhcp(timeout=5)
        assert "port 68" in note
        assert "sudo" not in note and "Local Network" not in note
