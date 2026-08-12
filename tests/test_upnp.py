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
    """
    def __init__(self, reply):
        self._reply = reply
        self._sent = False
    def settimeout(self, t): pass
    def sendto(self, data, addr): pass
    def recvfrom(self, n):
        if self._reply is None or self._sent:
            raise socket.timeout()
        self._sent = True
        return self._reply.encode(), ("192.168.1.1", 1900)
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
