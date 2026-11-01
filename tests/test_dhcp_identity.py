"""Rogue DHCP: options hidden by overload are read, and offers are counted by
the identity the server claims and by what it hands out.

Round 4, F31 and F32. parse_dhcp_options walked the options area only, so a
rogue OFFER carrying option 52 (overload) and a router, resolver or static
route inside the `file` or `sname` field — which macOS configd and dhclient
apply — described as router=[] and the baseline comparison had nothing to
compare. And check_rogue_dhcp de-duplicated responders by the UDP source
address, the one field a LAN host forges for free: a rogue stamping the
genuine server's address collapsed into it, "[OK] Only one DHCP server
responded", and whichever OFFER arrived first — the rogue's, by design — was
the one baselined as known-good.
"""

import socket
import struct

import pytest

GATEWAY, ROGUE = "192.168.1.1", "192.168.1.66"
POISON, RESOLVER = "66.66.66.66", "9.9.9.9"


def opt(code, payload):
    return bytes([code, len(payload)]) + payload


def ip(addr):
    return socket.inet_aton(addr)


def packet(yiaddr="192.168.1.100", options=b"", sname=b"", file=b""):
    """A BOOTP reply with the cookie at 236; `sname` and `file` are the raw
    field contents (padded), for options placed there by overload."""
    pkt = struct.pack(
        "!BBBBLHH4s4s4s4s16s64s128s",
        2, 1, 6, 0, 0x1234, 0, 0,
        b"\x00" * 4, ip(yiaddr), b"\x00" * 4, b"\x00" * 4,
        b"\x00" * 16, sname.ljust(64, b"\x00"), file.ljust(128, b"\x00"),
    )
    assert len(pkt) == 236
    return pkt + b"\x63\x82\x53\x63" + options + b"\xff"


class _FakeDhcpSocket:
    def __init__(self, datagrams):
        self._datagrams = list(datagrams)
    def setsockopt(self, *a): pass
    def settimeout(self, t): pass
    def bind(self, addr): pass
    def sendto(self, data, addr): pass
    def recvfrom(self, n):
        if self._datagrams:
            return self._datagrams.pop(0)
        raise socket.timeout()
    def close(self): pass


@pytest.fixture
def wire(mod, monkeypatch):
    def install(datagrams):
        monkeypatch.setattr(mod, "run", lambda cmd, *a, **k: "ether 3c:22:fb:00:11:22")
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: _FakeDhcpSocket(datagrams))
        responders, err = mod.check_rogue_dhcp(timeout=5)
        assert err is None
        return responders
    return install


class TestOptionOverload:
    def test_a_router_hidden_in_the_file_field_is_read(self, mod):
        pkt = packet(options=opt(53, b"\x02") + opt(52, b"\x01"), file=opt(3, ip(POISON)) + b"\xff")
        assert mod.describe_dhcp_offer(pkt)["router"] == [POISON]

    def test_a_resolver_hidden_in_the_sname_field_is_read(self, mod):
        pkt = packet(options=opt(53, b"\x02") + opt(52, b"\x02"), sname=opt(6, ip(RESOLVER)) + b"\xff")
        assert mod.describe_dhcp_offer(pkt)["dns"] == [RESOLVER]

    def test_both_fields_with_overload_three(self, mod):
        pkt = packet(options=opt(53, b"\x02") + opt(52, b"\x03"),
                     file=opt(3, ip(POISON)) + b"\xff", sname=opt(6, ip(RESOLVER)) + b"\xff")
        described = mod.describe_dhcp_offer(pkt)
        assert described["router"] == [POISON] and described["dns"] == [RESOLVER]

    def test_a_static_route_hidden_in_the_file_field_is_read(self, mod):
        classless = b"\x00" + ip(POISON)                      # 0.0.0.0/0 via the attacker
        pkt = packet(options=opt(53, b"\x02") + opt(52, b"\x01"), file=opt(121, classless) + b"\xff")
        assert mod.describe_dhcp_offer(pkt)["static_routes"] == [f"0.0.0.0/0 via {POISON}"]

    def test_without_option_52_the_fields_are_still_ignored(self, mod):
        # A decoy in `file` with no overload option is not an option stream;
        # reading it would hand the sender the parse back (round 1, H2).
        pkt = packet(options=opt(53, b"\x02") + opt(3, ip(GATEWAY)), file=opt(3, ip(POISON)) + b"\xff")
        assert mod.describe_dhcp_offer(pkt)["router"] == [GATEWAY]

    def test_a_router_in_both_areas_shows_both_addresses(self, mod):
        # RFC 3396: a repeated option is concatenated, so the poisoned second
        # router stands beside the benign first rather than replacing or
        # hiding under it — and differs from a baseline that holds one.
        pkt = packet(options=opt(53, b"\x02") + opt(3, ip(GATEWAY)) + opt(52, b"\x01"),
                     file=opt(3, ip(POISON)) + b"\xff")
        assert mod.describe_dhcp_offer(pkt)["router"] == [GATEWAY, POISON]

    def test_the_hidden_poison_now_differs_from_a_benign_baseline(self, mod):
        benign = mod.describe_dhcp_offer(packet(options=opt(53, b"\x02") + opt(3, ip(GATEWAY))))
        hidden = mod.describe_dhcp_offer(packet(options=opt(53, b"\x02") + opt(52, b"\x01"),
                                                file=opt(3, ip(POISON)) + b"\xff"))
        notes = mod.diff_dhcp_offer(benign, hidden)
        assert len(notes) == 1 and "different gateway" in notes[0] and POISON in notes[0]

    def test_a_truncated_overloaded_field_does_not_raise(self, mod):
        # A length that claims one byte more than the field holds.
        pkt = packet(options=opt(53, b"\x02") + opt(52, b"\x01"), file=b"\x03\x7f" + b"\x01" * 126)
        assert mod.describe_dhcp_offer(pkt)["router"] == []

    def test_an_overloaded_field_walk_cannot_escape_its_field(self, mod):
        # A length that runs past the end of `sname` must not read `file` or
        # the options area as its payload.
        pkt = packet(options=opt(53, b"\x02") + opt(52, b"\x02"), sname=b"\x03\x7f" + b"\x00" * 62)
        assert mod.parse_dhcp_options(pkt).get(3) is None

    def test_an_empty_overload_option_means_no_overload(self, mod):
        pkt = packet(options=opt(53, b"\x02") + opt(52, b""), file=opt(3, ip(POISON)) + b"\xff")
        assert mod.describe_dhcp_offer(pkt)["router"] == []


class TestOffersAreCountedByIdentity:
    def test_the_server_identifier_is_recorded(self, wire):
        pkt = packet(options=opt(53, b"\x02") + opt(54, ip(GATEWAY)) + opt(3, ip(GATEWAY)))
        responders = wire([(pkt, (GATEWAY, 67))])
        assert responders[0]["server_id"] == GATEWAY and responders[0]["ip"] == GATEWAY

    def test_a_rogue_forging_the_servers_source_is_two_offers_under_one_identity(self, wire, mod):
        """The F32 reproduction: both datagrams from ('192.168.1.1', 67), the
        poison first. This read as one responder, router [66.66.66.66], OK."""
        poison = packet(options=opt(53, b"\x02") + opt(54, ip(GATEWAY)) + opt(3, ip(POISON)))
        genuine = packet(options=opt(53, b"\x02") + opt(54, ip(GATEWAY)) + opt(3, ip(GATEWAY)))
        responders = wire([(poison, (GATEWAY, 67)), (genuine, (GATEWAY, 67))])
        assert len(responders) == 2
        assert [r["router"] for r in responders] == [[POISON], [GATEWAY]]
        summary = mod.summarise_dhcp_responders(responders)
        assert summary["servers"] == [GATEWAY]
        assert summary["conflicts"] == [{"server": GATEWAY, "field": "router", "values": [[POISON], [GATEWAY]]}]

    def test_a_repeated_identical_offer_is_still_one_responder(self, wire):
        pkt = packet(options=opt(53, b"\x02") + opt(54, ip(GATEWAY)) + opt(3, ip(GATEWAY)))
        responders = wire([(pkt, (GATEWAY, 67)), (pkt, (GATEWAY, 67)), (pkt, (GATEWAY, 67))])
        assert len(responders) == 1

    def test_a_rogue_claiming_the_real_servers_identifier_from_its_own_address(self, wire, mod):
        genuine = packet(options=opt(53, b"\x02") + opt(54, ip(GATEWAY)) + opt(3, ip(GATEWAY)))
        rogue = packet(options=opt(53, b"\x02") + opt(54, ip(GATEWAY)) + opt(3, ip(POISON)))
        responders = wire([(genuine, (GATEWAY, 67)), (rogue, (ROGUE, 67))])
        summary = mod.summarise_dhcp_responders(responders)
        assert summary["servers"] == [GATEWAY]
        assert summary["conflicts"] and summary["conflicts"][0]["field"] == "router"
        assert summary["spoofed"] == [{"ip": ROGUE, "server_id": GATEWAY}]

    def test_two_identities_are_two_servers(self, wire, mod):
        a = packet(options=opt(53, b"\x02") + opt(54, ip(GATEWAY)) + opt(3, ip(GATEWAY)))
        b = packet(options=opt(53, b"\x02") + opt(54, ip(ROGUE)) + opt(3, ip(POISON)))
        summary = mod.summarise_dhcp_responders(wire([(a, (GATEWAY, 67)), (b, (ROGUE, 67))]))
        assert summary["servers"] == [GATEWAY, ROGUE] and summary["conflicts"] == []

    def test_without_option_54_the_source_address_is_the_identity(self, wire, mod):
        a, b = packet(options=opt(53, b"\x02")), packet(yiaddr="10.0.0.50", options=opt(53, b"\x02"))
        responders = wire([(a, (GATEWAY, 67)), (b, ("10.0.0.1", 67))])
        assert mod.summarise_dhcp_responders(responders)["servers"] == ["10.0.0.1", GATEWAY]

    def test_the_summary_survives_hostile_input(self, mod):
        summary = mod.summarise_dhcp_responders([None, 3, {"ip": None}, {"server_id": 7, "router": "x"}])
        assert isinstance(summary["servers"], list) and summary["conflicts"] == []


class TestTheSectionSaysSo:
    def _dump(self, mod, monkeypatch, capsys, responders):
        monkeypatch.setattr(mod, "check_rogue_dhcp", lambda: (responders, None))
        result = mod.action_rogue_dhcp()
        return result, capsys.readouterr().out

    def test_offers_that_disagree_under_one_identity_are_high(self, mod, monkeypatch, capsys):
        responders = [{"ip": GATEWAY, "server_id": GATEWAY, "offered_ip": "192.168.1.100",
                       "router": [POISON], "dns": [], "static_routes": []},
                      {"ip": GATEWAY, "server_id": GATEWAY, "offered_ip": "192.168.1.100",
                       "router": [GATEWAY], "dns": [], "static_routes": []}]
        result, out = self._dump(mod, monkeypatch, capsys, responders)
        assert "[HIGH] One DHCP server identity (192.168.1.1) made offers that disagree" in out
        assert f"router ['{POISON}'] vs ['{GATEWAY}']" in out
        assert "[OK]" not in out
        assert result["summary"]["conflicts"]

    def test_one_server_whose_offers_agree_is_ok_and_named(self, mod, monkeypatch, capsys):
        responders = [{"ip": GATEWAY, "server_id": GATEWAY, "offered_ip": "192.168.1.100",
                       "router": [GATEWAY], "dns": [GATEWAY], "static_routes": []}]
        _, out = self._dump(mod, monkeypatch, capsys, responders)
        assert "[OK] Only one DHCP server responded (192.168.1.1), and its offers agree." in out
        assert "[HIGH]" not in out and "[REVIEW]" not in out

    def test_two_identities_are_multiple_servers(self, mod, monkeypatch, capsys):
        responders = [{"ip": GATEWAY, "server_id": GATEWAY, "offered_ip": "a", "router": [], "dns": [], "static_routes": []},
                      {"ip": ROGUE, "server_id": ROGUE, "offered_ip": "b", "router": [], "dns": [], "static_routes": []}]
        _, out = self._dump(mod, monkeypatch, capsys, responders)
        assert "[HIGH] Multiple DHCP servers detected" in out

    def test_a_forged_source_is_named_at_review(self, mod, monkeypatch, capsys):
        responders = [{"ip": ROGUE, "server_id": GATEWAY, "offered_ip": "a", "router": [GATEWAY], "dns": [], "static_routes": []}]
        _, out = self._dump(mod, monkeypatch, capsys, responders)
        assert f"[REVIEW] The offer from {ROGUE} names Server Identifier {GATEWAY}" in out
        assert f"{ROGUE} (Server Identifier {GATEWAY})" in out

    def test_the_html_report_still_renders_the_responders(self, mod, monkeypatch, capsys, tmp_path):
        from pathlib import Path
        responders = [{"ip": GATEWAY, "server_id": GATEWAY, "offered_ip": "192.168.1.100",
                       "router": [GATEWAY], "dns": [], "static_routes": []}]
        result, _ = self._dump(mod, monkeypatch, capsys, responders)
        text = Path(mod.generate_html_report({"dhcp": result}, output_path=str(tmp_path / "r.html"))).read_text()
        assert "One DHCP server: 192.168.1.1" in text and "Not Included In This Report" not in text
