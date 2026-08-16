"""UPnP port-mapping discovery and parsing (`get_upnp_port_mappings`).

Under all the SSDP/SOAP ceremony this is a parser: it pulls a LOCATION header
out of an SSDP reply, a `<controlURL>` out of a device-description XML, and a
handful of `<New...>` fields out of each SOAP mapping response. Every one of
those is a regex over vendor-formatted XML — the same fragile surface the rest
of the suite guards. These tests fake the two I/O stages (the SSDP UDP exchange
and the HTTP calls) and assert on what the parser extracts and when it stops.

Each returned mapping is a hole punched through the router's NAT, so a parse
error here either invents a hole that isn't there or hides one that is.
"""

import socket
import urllib.error
import urllib.request

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


class _Resp:
    def __init__(self, body):
        self._body = body.encode()
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return self._body


def _wire(monkeypatch, mod, ssdp_reply, http):
    """Wire up both I/O stages.

    `ssdp_reply` is the text of the SSDP datagram (or None for no responder).
    `http` is a callable (url, req) -> body-string, or it may raise
    urllib.error.HTTPError to drive the loop-termination branch.
    """
    monkeypatch.setattr(mod.socket, "socket",
                        lambda *a, **k: _FakeSsdpSocket(ssdp_reply))

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        body = http(url, req)
        return _Resp(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


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
            raise urllib.error.HTTPError(url, 500, "Internal Error", {}, None)

        _wire(monkeypatch, mod, SSDP_OK, http)
        mappings, _ = mod.get_upnp_port_mappings("192.168.1.1")
        assert len(mappings) == 1
        assert mappings[0]["description"] == "ftp"


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
