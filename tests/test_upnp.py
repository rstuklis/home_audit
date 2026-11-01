"""UPnP port-mapping discovery and parsing (`get_upnp_port_mappings`).

Under all the SSDP/SOAP ceremony this is a parser: it pulls a LOCATION header
out of an SSDP reply, a `<controlURL>` out of a device-description XML, and a
handful of `<New...>` fields out of each SOAP mapping response. Every one of
those is a regex over vendor-formatted XML — the same fragile surface the rest
of the suite guards. These tests fake the two I/O stages (the SSDP UDP exchange
and the HTTP calls) and assert on what the parser extracts and when it stops.

Each returned mapping is a hole punched through the router's NAT, so a parse
error here either invents a hole that isn't there or hides one that is.

The HTTP stage is _http_get_plain / _http_post_plain — the bounded helpers the
other two UPnP fetchers use — and not urllib: the sandbox forbids urlopen, so a
test here reaching it would escape rather than pass.
"""

import socket

import pytest


DESC_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
      </service>
    </serviceList>
  </device>
</root>"""


def _mapping_soap(ext, proto, ip, iport, desc, enabled):
    return f"""<?xml version="1.0"?>
<s:Envelope><s:Body>
  <u:GetGenericPortMappingEntryResponse>
    <NewExternalPort>{ext}</NewExternalPort>
    <NewProtocol>{proto}</NewProtocol>
    <NewInternalClient>{ip}</NewInternalClient>
    <NewInternalPort>{iport}</NewInternalPort>
    <NewPortMappingDescription>{desc}</NewPortMappingDescription>
    <NewEnabled>{enabled}</NewEnabled>
  </u:GetGenericPortMappingEntryResponse>
</s:Body></s:Envelope>"""


# The fault SOAP a router returns once the index runs past the last mapping.
INVALID_INDEX_SOAP = """<?xml version="1.0"?>
<s:Envelope><s:Body><s:Fault><detail><UPnPError>
  <errorCode>713</errorCode>
  <errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
</UPnPError></detail></s:Fault></s:Body></s:Envelope>"""


class _FakeSsdpSocket:
    """Enough of a UDP socket for the SSDP M-SEARCH step.

    recvfrom yields the queued reply once, then raises socket.timeout so the
    discovery loop terminates exactly as it would against a real router that
    answered once.

    `replies` may instead be a list of (text, addr) pairs, which is how the
    several-responders case is driven — SSDP is a broadcast question and the
    gateway is not necessarily the one that answers first.
    """
    def __init__(self, reply):
        if reply is None:
            self._queue = []
        elif isinstance(reply, str):
            self._queue = [(reply, ("192.168.1.1", 1900))]
        else:
            self._queue = list(reply)
    def settimeout(self, t): pass
    def sendto(self, data, addr): pass
    def recvfrom(self, n):
        if not self._queue:
            raise socket.timeout()
        text, addr = self._queue.pop(0)
        return text.encode(), addr
    def close(self): pass


def _wire(monkeypatch, mod, ssdp_reply, http):
    """Wire up both I/O stages. Returns the list of HTTP exchanges made.

    `ssdp_reply` is the text of the SSDP datagram (or None for no responder).
    `http` is a callable (url, body) -> body-string, or -> (status, body-string)
    to drive the loop-termination branches. Each exchange is recorded as
    {"url", "body", <the keyword arguments the code passed>}.
    """
    monkeypatch.setattr(mod.socket, "socket",
                        lambda *a, **k: _FakeSsdpSocket(ssdp_reply))
    calls = []

    def answer(host, port, path, body, kwargs):
        url = f"http://{host}:{port}{path}"
        calls.append({"url": url, "body": body, **kwargs})
        reply = http(url, body)
        status, text = reply if isinstance(reply, tuple) else (200, reply)
        return status, "fake-server", text

    monkeypatch.setattr(mod, "_http_get_plain",
                        lambda host, port, path, **k: answer(host, port, path, None, k))
    monkeypatch.setattr(mod, "_http_post_plain",
                        lambda host, port, path, body, headers, **k: answer(host, port, path, body, k))
    return calls


SSDP_OK = ("HTTP/1.1 200 OK\r\n"
           "LOCATION: http://192.168.1.1:5000/desc.xml\r\n"
           "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n")


class TestDiscoveryFailure:
    def test_no_ssdp_responder_reports_disabled_upnp(self, mod, monkeypatch):
        _wire(monkeypatch, mod, None, lambda u, r: "")
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == []
        assert "No UPnP device" in err

    def test_missing_control_url_is_reported(self, mod, monkeypatch):
        # SSDP answered and the description fetched, but it carried no
        # WANIPConnection controlURL — nothing to query, and we say so.
        def http(url, req):
            return "<root><device></device></root>"
        _wire(monkeypatch, mod, SSDP_OK, http)
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == []
        assert "control URL" in err


SSDP_ATTACKER = ("HTTP/1.1 200 OK\r\n"
                 "LOCATION: http://192.168.1.50:5000/desc.xml\r\n"
                 "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n")


class TestOnlyTheGatewayIsBelieved:
    """SSDP is a broadcast question; anyone on the link may answer it.

    The loop used to discard the sender address and take the first LOCATION it
    saw. MX: 2 tells a conforming router to *wait* before replying, so an
    attacker who answers instantly wins the race by design — and then serves a
    description naming themselves. Their empty mapping list was reported as the
    gateway's, under an evidence label reading "the gateway's own list", while
    the real router forwarded a port to them.
    """

    def test_a_faster_stranger_does_not_replace_the_gateway(self, mod, monkeypatch):
        fetched = []

        def http(url, req):
            fetched.append(url)
            return DESC_XML

        _wire(monkeypatch, mod, [
            (SSDP_ATTACKER, ("192.168.1.50", 1900)),     # answers first
            (SSDP_OK, ("192.168.1.1", 1900)),            # the actual gateway
        ], http)
        mod.get_upnp_port_mappings("192.168.1.1")
        assert fetched, "the gateway's own reply must still be followed"
        assert not any("192.168.1.50" in u for u in fetched), \
            "a non-gateway responder must never be fetched"

    def test_a_lone_stranger_is_reported_as_no_upnp_device(self, mod, monkeypatch):
        _wire(monkeypatch, mod, [(SSDP_ATTACKER, ("192.168.1.50", 1900))],
              lambda u, r: pytest.fail(f"must not fetch {u}"))
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == []
        assert "No UPnP device" in err


class TestUrlsFromTheWireAreConstrained:
    """Both URLs here are read out of a document a LAN device wrote.

    Unchecked, LOCATION could name any scheme urllib's default opener
    understands — file: and ftp: among them — and an absolute <controlURL>
    could aim a hundred SOAP POSTs at any host on the internet. Neither is a
    UPnP feature; both were reachable by answering one broadcast.
    """

    @pytest.mark.parametrize("location", [
        "file:///etc/passwd",
        "ftp://192.168.1.1/desc.xml",
        "http://evil.example/desc.xml",
    ], ids=["file", "ftp", "off-host"])
    def test_a_location_that_is_not_http_on_the_gateway_is_not_followed(
            self, mod, monkeypatch, location):
        reply = ("HTTP/1.1 200 OK\r\n"
                 f"LOCATION: {location}\r\n\r\n")
        _wire(monkeypatch, mod, [(reply, ("192.168.1.1", 1900))],
              lambda u, r: pytest.fail(f"must not fetch {u}"))
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == []
        assert "not followed" in err.lower()

    def test_an_absolute_control_url_off_the_gateway_is_not_followed(self, mod, monkeypatch):
        desc = ("<root><service>"
                "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                "<controlURL>http://evil.example/ctl</controlURL>"
                "</service></root>")
        posted = []

        def http(url, req):
            if url.endswith("desc.xml"):
                return desc
            posted.append(url)
            return ""

        _wire(monkeypatch, mod, SSDP_OK, http)
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert posted == [], "no SOAP request may leave for a host we were told about"
        assert mappings == []
        assert "not followed" in err.lower()


class TestMappingParse:
    def _http_with(self, mappings_then_terminator):
        """Return an http() that serves the description, then the given SOAP
        bodies in order (the last one should terminate the loop)."""
        state = {"n": 0}

        def http(url, req):
            if url.endswith("/desc.xml"):
                return DESC_XML
            i = state["n"]
            state["n"] += 1
            if i < len(mappings_then_terminator):
                return mappings_then_terminator[i]
            return INVALID_INDEX_SOAP
        return http

    def test_a_single_mapping_is_parsed_into_its_fields(self, mod, monkeypatch):
        http = self._http_with([
            _mapping_soap("443", "TCP", "192.168.1.50", "8443", "webcam", "1"),
            INVALID_INDEX_SOAP,
        ])
        _wire(monkeypatch, mod, SSDP_OK, http)
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert err is None
        assert mappings == [{
            "ext_port": "443", "protocol": "TCP", "int_ip": "192.168.1.50",
            "int_port": "8443", "description": "webcam", "enabled": "1",
        }]

    def test_multiple_mappings_are_returned_in_order(self, mod, monkeypatch):
        http = self._http_with([
            _mapping_soap("80", "TCP", "192.168.1.10", "80", "http", "1"),
            _mapping_soap("53", "UDP", "192.168.1.11", "53", "dns", "0"),
            INVALID_INDEX_SOAP,
        ])
        _wire(monkeypatch, mod, SSDP_OK, http)
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert [m["ext_port"] for m in mappings] == ["80", "53"]
        assert mappings[1]["protocol"] == "UDP"

    def test_the_invalid_index_fault_stops_the_loop(self, mod, monkeypatch):
        # Without honouring SpecifiedArrayIndexInvalid the loop would run its
        # full 100 iterations and re-append blank entries; assert it stops at 1.
        http = self._http_with([
            _mapping_soap("22", "TCP", "192.168.1.5", "22", "ssh", "1"),
            INVALID_INDEX_SOAP,
        ])
        _wire(monkeypatch, mod, SSDP_OK, http)
        mappings, _ = mod.get_upnp_port_mappings("192.168.1.1")
        assert len(mappings) == 1

    def test_an_http_500_also_terminates_the_loop(self, mod, monkeypatch):
        # Many routers signal "no more entries" with a bare HTTP 500 rather
        # than a parseable fault body; that path must end the loop too.
        state = {"n": 0}

        def http(url, req):
            if url.endswith("/desc.xml"):
                return DESC_XML
            if state["n"] == 0:
                state["n"] += 1
                return _mapping_soap("21", "TCP", "192.168.1.9", "21", "ftp", "1")
            return (500, "<s:Fault/>")

        _wire(monkeypatch, mod, SSDP_OK, http)
        mappings, _ = mod.get_upnp_port_mappings("192.168.1.1")
        assert len(mappings) == 1
        assert mappings[0]["description"] == "ftp"

    def test_no_http_answer_at_all_ends_the_loop_with_what_was_read(self, mod, monkeypatch):
        _wire(monkeypatch, mod, SSDP_OK, lambda u, b: DESC_XML if u.endswith("/desc.xml")
              else _mapping_soap("21", "TCP", "192.168.1.9", "21", "ftp", "1"))
        monkeypatch.setattr(mod, "_http_post_plain", lambda *a, **k: None)
        mappings, note = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == [] and note is None


class TestTheFetchesAreBounded:
    """Round 4, F9. The description and up to a hundred SOAP replies were read
    with urllib: a per-operation timeout that a peer dripping one byte every
    few seconds never trips, an unbounded read, and redirects followed to any
    host — the slow-loris class rounds 2 and 3 rebuilt the other two UPnP
    fetchers without. This path runs before the baseline, the report and the
    email, so one such answer to the audit's own M-SEARCH suppressed the week.
    """

    def _serve(self, monkeypatch, mod, entries=2):
        state = {"n": 0}

        def http(url, body):
            if url.endswith("/desc.xml"):
                return DESC_XML
            i, state["n"] = state["n"], state["n"] + 1
            if i < entries:
                return _mapping_soap(str(8000 + i), "TCP", "192.168.1.50", "80", f"m{i}", "1")
            return INVALID_INDEX_SOAP
        return _wire(monkeypatch, mod, SSDP_OK, http)

    def test_every_exchange_goes_through_the_bounded_helpers_not_urllib(self, mod, monkeypatch):
        # The sandbox forbids urlopen outright, so reaching it would raise
        # EscapedSandbox here rather than quietly pass.
        calls = self._serve(monkeypatch, mod)
        mappings, note = mod.get_upnp_port_mappings("192.168.1.1")
        assert len(mappings) == 2 and note is None
        assert [c["url"] for c in calls] == ["http://192.168.1.1:5000/desc.xml"] + ["http://192.168.1.1:5000/ctl/IPConn"] * 3
        assert all(c["body"] is None for c in calls[:1]) and all("GetGenericPortMappingEntry" in c["body"] for c in calls[1:])

    def test_each_exchange_carries_a_wall_clock_budget_no_larger_than_the_helpers_default(self, mod, monkeypatch):
        calls = self._serve(monkeypatch, mod)
        mod.get_upnp_port_mappings("192.168.1.1")
        assert calls and all(0 < c["total"] <= mod.HTTP_GET_TOTAL_SECONDS for c in calls)

    def test_the_whole_loop_runs_under_one_deadline(self, mod, monkeypatch):
        # A gateway that answers every SOAP call just inside the per-call
        # budget used to hold the audit for a hundred of them. The clock here
        # advances 15 s per exchange against a 40 s budget.
        clock = {"now": 1000.0}

        def monotonic():
            clock["now"] += 15.0
            return clock["now"]
        monkeypatch.setattr(mod.time, "monotonic", monotonic)
        monkeypatch.setattr(mod, "UPNP_MAPPINGS_TOTAL_SECONDS", 40.0)
        calls = self._serve(monkeypatch, mod, entries=50)
        mappings, note = mod.get_upnp_port_mappings("192.168.1.1")
        assert len(calls) < 6, "the loop must stop at the deadline, not at the hundredth entry"
        assert mappings, "what was read before the deadline is kept"
        assert note and "may be incomplete" in note and str(len(mappings)) in note
        assert all(c["total"] <= mod.HTTP_GET_TOTAL_SECONDS for c in calls)

    def test_an_https_location_on_the_gateway_is_not_followed(self, mod, monkeypatch):
        # The bounded helper speaks plain http only, like its siblings; a
        # LOCATION that would need TLS is reported rather than fetched by
        # some other means.
        reply = ("HTTP/1.1 200 OK\r\nLOCATION: https://192.168.1.1/desc.xml\r\n\r\n")
        _wire(monkeypatch, mod, [(reply, ("192.168.1.1", 1900))],
              lambda u, b: pytest.fail(f"must not fetch {u}"))
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == [] and "not followed" in err.lower()

    def test_a_description_that_is_not_200_is_an_error_not_a_parse(self, mod, monkeypatch):
        _wire(monkeypatch, mod, SSDP_OK, lambda u, b: (404, "<html>nope</html>"))
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == [] and "HTTP 404" in err

    def test_a_description_that_never_answers_is_an_error(self, mod, monkeypatch):
        _wire(monkeypatch, mod, SSDP_OK, lambda u, b: "")
        monkeypatch.setattr(mod, "_http_get_plain", lambda *a, **k: None)
        mappings, err = mod.get_upnp_port_mappings("192.168.1.1")
        assert mappings == [] and "within the time allowed" in err

    def test_the_dump_keeps_a_cut_short_list_and_says_so(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "get_default_gateway", lambda: "192.168.1.1")
        monkeypatch.setattr(mod, "get_upnp_port_mappings", lambda gw: (
            [{"ext_port": "443", "protocol": "TCP", "int_ip": "192.168.1.50", "int_port": "443",
              "description": "cam", "enabled": "1"}],
            "Stopped after 1 mapping(s): the gateway took longer than 40s to answer, so the list may be incomplete."))
        result = mod.action_upnp_dump()
        out = capsys.readouterr().out
        assert len(result["mappings"]) == 1 and "may be incomplete" in result["note"]
        assert "443" in out and "[REVIEW] Stopped after 1 mapping(s)" in out


class TestSsdpRefusedIsNotAnAbsentRouter:
    """SSDP is multicast to the local subnet, so a background job's discovery is
    refused by the same Local Network privacy denial. Reporting that as "router
    may have UPnP disabled" is a claim about the router made from evidence that
    never left the machine — and it points the reader at their router's settings
    for a permission problem on their Mac."""

    def _blocked_socket(self, errno_code):
        class Refusing:
            def settimeout(self, t): pass
            def sendto(self, *a): raise OSError(errno_code, "No route to host")
            def recvfrom(self, n): raise socket.timeout()
            def close(self): pass
        return lambda *a, **k: Refusing()

    def test_a_refused_ssdp_send_is_reported_as_a_denial(self, mod, monkeypatch):
        import errno as _errno
        monkeypatch.setattr(mod.socket, "socket", self._blocked_socket(_errno.EHOSTUNREACH))
        mappings, note = mod.get_upnp_port_mappings("192.168.87.1")
        assert mappings == []
        assert "Local Network privacy" in note
        assert "UPnP disabled" not in note, "a denial was reported as a router setting"

    def test_a_genuinely_silent_network_still_reads_as_no_upnp_device(self, mod, monkeypatch):
        # SSDP left the machine and nothing answered: that IS a statement about
        # the network, and must keep being made.
        _wire(monkeypatch, mod, None, lambda u, r: "")
        mappings, note = mod.get_upnp_port_mappings("192.168.87.1")
        assert mappings == []
        assert "No UPnP device found" in note
