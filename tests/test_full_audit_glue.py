"""action_full_audit seals what round 5 added, and the save carries it.

The sections are tested on their own throughout the suite; this drives the
full audit once, every section stubbed, to pin the glue that puts the new
readings on the state: the outcome of each port scan (F34), the modem's
identity (F12), and — through save_baseline — the departures the run reported
(F14) and the carry-forward of an unread identity.
"""

import pytest

GW, MODEM = "192.168.87.1", "192.168.1.1"
NET = "192.168.87.0/24"
CERT = "b761788ac45e493b" + "0" * 48
HUB = "a4:11:62:2a:b9:0a"


@pytest.fixture
def audit(mod, monkeypatch):
    """Run action_full_audit with every outbound section stubbed.

    `modem` is what audit_host returns for the modem: a port list, or None
    with the given outcome; `devices` the sweep's result.
    """
    def run(modem=([80, 443, 8443], "measured"), devices=()):
        ports, result = modem
        monkeypatch.setattr(mod, "print_network_info",
                            lambda: ([{"name": "en0", "ip": "192.168.87.20", "subnet": NET}], "192.168.87.20", GW))
        monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (NET, None))
        monkeypatch.setattr(mod, "describe_current_network", lambda *a, **k: "")
        monkeypatch.setattr(mod, "is_onlink", lambda addr, interfaces: addr == GW)

        def fake_audit_host(label, host, full_scan=False, onlink=None, verdicts=None, reference=None,
                            outcomes=None, identities=None):
            if host == GW:
                # The gateway's identity is not asked for: router_tls covers it.
                assert identities is None
                outcomes[host] = {"result": "measured", "probed": 25, "answered": 25, "filtered": 0, "unreachable": 0}
                return [80]
            outcomes[host] = {"result": result, "probed": 25, "answered": 25 if result == "measured" else 0,
                              "filtered": 0 if result == "measured" else 25, "unreachable": 0}
            if ports is not None:
                identities[host] = {"tls_443": CERT, "ssh_banner": "SSH-2.0-dropbear_2019.78"}
            return ports
        monkeypatch.setattr(mod, "audit_host", fake_audit_host)
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: {"present": False, "sha256": None})
        monkeypatch.setattr(mod, "get_dns_servers", lambda: [GW])
        monkeypatch.setattr(mod, "resolve_subnets", lambda *a, **k: [NET])
        monkeypatch.setattr(mod, "collect_devices", lambda *a, **k: [dict(d) for d in devices])
        monkeypatch.setattr(mod, "collect_device_names", lambda *a, **k: "")
        monkeypatch.setattr(mod, "onlink_coverage", lambda subnets, interfaces: [str(s) for s in subnets])
        monkeypatch.setattr(mod, "action_wifi_security", lambda: {"risk": "OK"})
        monkeypatch.setattr(mod, "action_arp_spoof_check", lambda: {"macs_seen": ["b0:2a:43:c8:22:5b"]})
        monkeypatch.setattr(mod, "action_interception_checks", lambda: {})
        monkeypatch.setattr(mod, "action_evil_twin", lambda known: {"bssids": [], "risk": "OK"})
        monkeypatch.setattr(mod, "action_ipv6_routers", lambda *a, **k: {"routers": [], "details": {}})
        monkeypatch.setattr(mod, "action_firewall_check", lambda: {})
        monkeypatch.setattr(mod, "action_sharing_services", lambda: [])
        monkeypatch.setattr(mod, "action_listening_services", lambda **k: [])
        monkeypatch.setattr(mod, "action_router_hostname", lambda: {})
        monkeypatch.setattr(mod, "action_upnp_dump", lambda: {"mappings": []})
        monkeypatch.setattr(mod, "action_rogue_dhcp", lambda: {"responders": []})
        return mod.action_full_audit(no_speedtest=True, no_names=True, upstream_ip=MODEM)
    return run


def dev(mac, ip):
    return {"ip": ip, "mac": mac, "subnet": NET, "vendor": ""}


class TestWhatTheStateCarries:
    def test_scan_outcomes_and_the_modem_identity_are_on_the_state(self, audit):
        state = audit()
        assert state["router_scan"]["result"] == "measured" and state["router_open_ports"] == [80]
        assert state["upstream_scan"]["result"] == "measured" and state["upstream_open_ports"] == [80, 443, 8443]
        assert state["upstream_identity"] == {"tls_443": CERT, "ssh_banner": "SSH-2.0-dropbear_2019.78"}

    def test_a_filtered_modem_scan_is_unmeasured_with_no_identity(self, audit):
        state = audit(modem=(None, "filtered"))
        assert state["upstream_open_ports"] is None
        assert state["upstream_scan"]["result"] == "filtered"
        assert state["upstream_identity"] == {}

    def test_the_save_carries_an_unread_identity_and_ports_forward(self, mod, audit, monkeypatch):
        monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
        mod.save_baseline(audit())
        mod.save_baseline(audit(modem=(None, "filtered")))
        saved = mod.load_baseline()
        assert saved["upstream_open_ports"] == [80, 443, 8443]
        assert saved["upstream_identity"] == {"tls_443": CERT, "ssh_banner": "SSH-2.0-dropbear_2019.78"}
        assert sorted(saved["carried_forward"]) == ["upstream_identity", "upstream_open_ports"]
        assert saved["upstream_scan"]["result"] == "filtered"

    def test_the_save_records_the_departures_the_run_reported(self, mod, audit, capsys):
        mod.save_baseline(audit(devices=[dev("b0:2a:43:c8:22:5b", GW), dev(HUB, "192.168.87.70")]))
        state = audit(devices=[dev("b0:2a:43:c8:22:5b", GW)])
        out = capsys.readouterr().out
        assert "CHANGES DETECTED:" in out and f"Device(s) gone since baseline: {HUB}" in out
        mod.save_baseline(state)
        assert mod.load_baseline()["departed"] == [HUB]

    def test_every_key_the_run_writes_is_a_rendered_key(self, mod, audit):
        state = audit(devices=[dev("b0:2a:43:c8:22:5b", GW)])
        mod.save_baseline(state)
        saved = mod.load_baseline()
        unrendered = sorted(k for k in saved if k not in mod.RENDERED_STATE_KEYS)
        assert unrendered == [], unrendered
