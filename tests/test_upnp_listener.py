"""classify_upnp_listener — what an open port 1900 is actually doing.

A port scan gives one answer, "open", for two very different devices: a router
that will forward a WAN port for anyone who asks, and one whose UPnP was switched
off while the SDK's web server stayed up. The second is what a TP-Link modem
looks like after its owner has done the right thing, and the bare "[REVIEW] 1900"
kept telling them to do it again.

The classifier asks the listener directly (unicast SSDP, then HTTP for a device
description) and these tests pin the four verdicts, plus the two rules that keep
the probe honest: only the asked host's replies count, and silence is reported as
silence rather than as "off".
"""

import errno
import socket

import pytest

HOST = "192.168.1.1"

IGD_REPLY = ("HTTP/1.1 200 OK\r\n"
             "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
             "SERVER: Linux/4.1 UPnP/1.0 miniupnpd/2.1\r\n"
             f"LOCATION: http://{HOST}:5431/rootDesc.xml\r\n\r\n")

MEDIA_REPLY = ("HTTP/1.1 200 OK\r\n"
               "ST: urn:schemas-upnp-org:device:MediaServer:1\r\n"
               "SERVER: Linux UPnP/1.0 MiniDLNA/1.2\r\n\r\n")

IGD_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
</device></root>"""

MEDIA_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
</device></root>"""

LIBUPNP = "Linux/4.1.52, UPnP/1.0, Portable SDK for UPnP devices/1.6.19"


@pytest.fixture
def probe(mod, monkeypatch):
    """classify_upnp_listener with both I/O stages faked.

    `http` maps (port, path) -> (status, server, body); anything absent is a
    404 from `server`, or no HTTP at all when `speaks_http` is False.
    """
    def run(replies=(), refused=False, http=None, server=LIBUPNP,
            speaks_http=True, onlink=None, multicast_replies=()):
        calls = []
        searches = []

        def fake_search(h, port=1900, wait=2.0, multicast=False):
            searches.append(multicast)
            if multicast:
                return list(multicast_replies), refused
            return list(replies), refused
        monkeypatch.setattr(mod, "_ssdp_search", fake_search)

        def fake_get(h, port, path, timeout=3.0, limit=65536):
            calls.append((h, port, path))
            if (port, path) in (http or {}):
                return (http or {})[(port, path)]
            return (404, server, "<h1>404 Not Found</h1>") if speaks_http else None

        monkeypatch.setattr(mod, "_http_get_plain", fake_get)
        verdict = mod.classify_upnp_listener(HOST, 1900, onlink=onlink)
        verdict["_calls"] = calls
        verdict["_searches"] = searches
        return verdict
    return run


class TestDormant:
    """The modem this was written for: port open, 404 to everything, silent."""

    def test_open_port_that_answers_nothing_as_upnp_is_dormant(self, mod, probe):
        v = probe()
        assert v["state"] == mod.UPNP_DORMANT
        assert v["risk"] == "INFO"

    def test_the_server_banner_is_kept_as_evidence(self, probe):
        assert "Portable SDK for UPnP" in probe()["server"]

    def test_every_well_known_description_path_was_tried(self, mod, probe):
        tried = {path for _, port, path in probe()["_calls"] if port == 1900}
        assert set(mod.UPNP_DESCRIPTION_PATHS) <= tried

    def test_dormant_never_claims_the_feature_is_off(self, probe):
        v = probe()
        text = (v["summary"] + " " + v["caveat"]).lower()
        assert "not proof" in text or "confirm" in text, (
            "a verdict resting on silence was stated as fact")

    def test_an_off_link_host_gets_the_multicast_caveat(self, probe):
        # Multicast cannot cross the router between this Mac and the modem, so
        # a stack that ignores unicast searches looks identical to a dormant one.
        assert "multicast" in probe(onlink=False)["caveat"].lower()

    def test_an_on_link_host_does_not(self, probe):
        assert "multicast" not in probe(onlink=True)["caveat"].lower()


class TestLiveGateway:
    def test_a_discovery_reply_naming_a_gateway_device_is_live(self, mod, probe):
        v = probe(replies=[IGD_REPLY])
        assert v["state"] == mod.UPNP_LIVE_GATEWAY
        assert v["risk"] == "REVIEW"

    def test_a_served_gateway_description_is_live_even_with_silent_discovery(self, mod, probe):
        # Some stacks answer multicast only. The description on the port is
        # enough on its own.
        v = probe(http={(1900, "/rootDesc.xml"): (200, "miniupnpd", IGD_XML)})
        assert v["state"] == mod.UPNP_LIVE_GATEWAY

    def test_the_advertised_location_is_fetched(self, mod, probe):
        media_then_igd = MEDIA_REPLY.replace(
            "\r\n\r\n", f"\r\nLOCATION: http://{HOST}:5431/desc.xml\r\n\r\n")
        v = probe(replies=[media_then_igd],
                  http={(5431, "/desc.xml"): (200, "x", IGD_XML)})
        assert (HOST, 5431, "/desc.xml") in v["_calls"]
        assert v["state"] == mod.UPNP_LIVE_GATEWAY

    def test_a_location_on_another_host_is_not_followed(self, probe):
        elsewhere = MEDIA_REPLY.replace(
            "\r\n\r\n", "\r\nLOCATION: http://203.0.113.9/desc.xml\r\n\r\n")
        v = probe(replies=[elsewhere])
        assert all(h == HOST for h, _, _ in v["_calls"])
        assert not any(path == "/desc.xml" for _, _, path in v["_calls"])

    def test_a_non_http_location_is_not_followed(self, probe):
        odd = MEDIA_REPLY.replace("\r\n\r\n", "\r\nLOCATION: file:///etc/passwd\r\n\r\n")
        v = probe(replies=[odd])
        assert not any("passwd" in path for _, _, path in v["_calls"])

    def test_the_summary_says_what_to_do(self, probe):
        assert "turn upnp off" in probe(replies=[IGD_REPLY])["summary"].lower()


class TestMulticastFallback:
    """MiniUPnPd on a Google Nest ignores unicast searches and answers the
    group address. Measured, not assumed — asking one way read it as silent."""

    def test_a_gateway_that_only_answers_multicast_is_still_live(self, mod, probe):
        v = probe(multicast_replies=[IGD_REPLY], onlink=True)
        assert v["state"] == mod.UPNP_LIVE_GATEWAY

    def test_multicast_is_tried_when_the_link_is_not_known(self, probe):
        assert probe(onlink=None)["_searches"] == [False, True]

    def test_multicast_is_not_sent_for_an_off_link_host(self, probe):
        # It could not reach the host, and the silence would be worthless.
        assert probe(onlink=False)["_searches"] == [False]

    def test_multicast_is_skipped_once_unicast_has_answered(self, probe):
        assert probe(replies=[IGD_REPLY], onlink=True)["_searches"] == [False]


class TestLiveOther:
    def test_a_media_server_is_live_but_cannot_open_ports(self, mod, probe):
        v = probe(replies=[MEDIA_REPLY])
        assert v["state"] == mod.UPNP_LIVE_OTHER
        assert v["risk"] == "INFO"
        assert "cannot open wan ports" in v["summary"].lower()

    def test_a_non_gateway_description_is_live_other(self, mod, probe):
        v = probe(http={(1900, "/description.xml"): (200, "MiniDLNA", MEDIA_XML)})
        assert v["state"] == mod.UPNP_LIVE_OTHER

    def test_a_200_page_that_is_not_a_upnp_description_does_not_count(self, mod, probe):
        v = probe(http={(1900, "/"): (200, "nginx", "<html>hello</html>")})
        assert v["state"] == mod.UPNP_DORMANT


class TestUnknown:
    def test_a_port_that_speaks_neither_protocol_is_unknown(self, mod, probe):
        v = probe(speaks_http=False)
        assert v["state"] == mod.UPNP_UNKNOWN
        assert v["risk"] == "REVIEW"

    def test_it_stops_asking_a_port_that_does_not_speak_http(self, probe):
        assert len(probe(speaks_http=False)["_calls"]) == 1

    def test_an_os_refusal_is_reported_as_a_refusal(self, probe):
        v = probe(refused=True, speaks_http=False)
        assert "refused by the OS" in v["summary"]

    def test_unknown_is_never_downgraded_below_review(self, probe):
        assert probe(refused=True, speaks_http=False)["risk"] == "REVIEW"


class _FakeUdp:
    def __init__(self, queue=(), send_error=None):
        self._queue = list(queue)
        self._send_error = send_error
        self.sent = []
    def settimeout(self, t): pass
    def sendto(self, data, addr):
        if self._send_error:
            raise self._send_error
        self.sent.append((data, addr))
    def recvfrom(self, n):
        if not self._queue:
            raise socket.timeout()
        text, addr = self._queue.pop(0)
        return text.encode(), addr
    def close(self): pass


class TestSearch:
    def test_the_search_goes_to_the_host_not_the_multicast_group(self, mod, monkeypatch):
        fake = _FakeUdp()
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: fake)
        mod._ssdp_search(HOST, wait=0.01)
        assert fake.sent[0][1] == (HOST, 1900)
        assert b"ssdp:discover" in fake.sent[0][0]

    def test_only_replies_from_the_asked_host_count(self, mod, monkeypatch):
        # Anyone on the link can answer a discovery. Another device's reply
        # says nothing about this listener, and must not make it look live.
        fake = _FakeUdp([(IGD_REPLY, ("192.168.1.66", 1900)),
                         (MEDIA_REPLY, (HOST, 1900))])
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: fake)
        replies, refused = mod._ssdp_search(HOST, wait=0.5)
        assert replies == [MEDIA_REPLY]
        assert refused is False

    def test_a_multicast_search_goes_to_the_group_address(self, mod, monkeypatch):
        fake = _FakeUdp()
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: fake)
        mod._ssdp_search(HOST, wait=0.01, multicast=True)
        assert fake.sent[0][1] == ("239.255.255.250", 1900)
        assert b"HOST: 239.255.255.250:1900" in fake.sent[0][0]

    def test_silence_is_an_empty_list_not_a_refusal(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: _FakeUdp())
        assert mod._ssdp_search(HOST, wait=0.01) == ([], False)

    def test_a_local_network_denial_is_reported_as_refused(self, mod, monkeypatch):
        fake = _FakeUdp(send_error=OSError(errno.EHOSTUNREACH, "No route to host"))
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: fake)
        assert mod._ssdp_search(HOST, wait=0.01) == ([], True)


class TestBanner:
    def test_control_characters_from_the_device_are_not_printed(self, mod):
        assert mod._banner_text("libupnp\x1b[31m\r\nX-Evil: 1") == "libupnp[31mX-Evil: 1"

    def test_a_long_banner_is_truncated(self, mod):
        assert len(mod._banner_text("a" * 500)) == 80


# ---------------------------------------------------------------------------
# audit_host and the reports
# ---------------------------------------------------------------------------

def _scan(open_ports):
    return {"open": sorted(open_ports), "probed": 25, "unreachable": 0, "blocked": False}


@pytest.fixture
def audited(mod, monkeypatch):
    def run(open_ports, verdict=None, **kwargs):
        seen = []
        monkeypatch.setattr(mod, "scan_ports_detailed",
                            lambda h, ports, workers=100: _scan(open_ports))
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: {"present": False})

        def fake_classify(host, port=1900, onlink=None):
            seen.append((host, port, onlink))
            return verdict
        monkeypatch.setattr(mod, "classify_upnp_listener", fake_classify)
        return mod.audit_host("upstream modem", HOST, **kwargs), seen
    return run


DORMANT = {"state": "dormant", "risk": "INFO", "server": LIBUPNP,
           "summary": "DORMANT — the port is open but nothing answered as UPnP.",
           "caveat": "Silence is weaker evidence than an answer."}


class TestAuditHostIntegration:
    def test_port_1900_is_printed_with_the_probes_risk(self, audited, capsys):
        audited([53, 1900], DORMANT)
        out = capsys.readouterr().out
        line = next(l for l in out.splitlines() if " 1900 " in l)
        assert "[INFO" in line
        assert "DORMANT" in out and "Server banner" in out

    def test_the_generic_upnp_warning_is_replaced_not_repeated(self, audited, capsys):
        audited([1900], DORMANT)
        assert "can auto-open WAN ports" not in capsys.readouterr().out

    def test_the_probe_is_not_run_when_1900_is_closed(self, audited):
        _, seen = audited([53, 80], DORMANT)
        assert seen == []

    def test_onlink_reaches_the_classifier(self, audited):
        _, seen = audited([1900], DORMANT, onlink=False)
        assert seen == [(HOST, 1900, False)]

    def test_the_return_value_is_still_the_list_of_ports(self, audited):
        ports, _ = audited([53, 1900], DORMANT)
        assert ports == [53, 1900]

    def test_the_verdict_is_handed_back_when_asked_for(self, audited):
        kept = {}
        audited([1900], DORMANT, verdicts=kept)
        assert kept == {HOST: DORMANT}


class TestReports:
    def test_the_probe_is_a_measured_finding(self, mod):
        assert mod.EVIDENCE["upnp_listeners"][0] == mod.MEASURED

    def test_the_html_report_knows_the_key(self, mod):
        assert "upnp_listeners" in mod.RENDERED_STATE_KEYS

    def test_the_html_report_shows_the_verdict(self, mod, tmp_path):
        out = tmp_path / "r.html"
        mod.generate_html_report(
            {"gateway": HOST, "router_open_ports": [1900],
             "upnp_listeners": {HOST: DORMANT}}, str(out))
        page = out.read_text()
        assert "UPnP Listener Probe" in page
        assert "DORMANT" in page
        assert "can auto-open WAN ports" not in page, (
            "the port table still carried the generic warning beside the verdict")

    def test_a_hostile_banner_is_escaped_in_html(self, mod, tmp_path):
        out = tmp_path / "r.html"
        evil = dict(DORMANT, server="<script>alert(1)</script>")
        mod.generate_html_report({"upnp_listeners": {HOST: evil}}, str(out))
        assert "<script>alert(1)</script>" not in out.read_text()
