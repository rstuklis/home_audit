"""The upstream modem's identity is measured, sealed, carried and compared.

Round 4, F12. The modem's TLS certificate — the only one in the house — was
measured every week, printed as a 16-hex prefix and dropped. router_tls holds
the gateway's certificate, and every gateway here is a Nest with no 443, so
the certificate comparison never ran on this deployment; the modem's changed
on 2026-09-20 and nothing said so. 8443 was never fingerprinted and the UPnP
server banner was stored but not compared.

audit_host now records an identity for the host — certificate digests on 443
and 8443, the SSH banner, the UPnP server banner — which action_full_audit
seals as upstream_identity under the carry-forward discipline, diff_baseline
compares field by field, and the HTML report renders.
"""

import socket
from pathlib import Path

import pytest

MODEM = "192.168.1.1"
CERT_A, CERT_B = "b761788ac45e493b" + "0" * 48, "1695dc0b5e4e5364" + "0" * 48
IGD = {"state": "dormant", "risk": "INFO", "server": "Linux/4.1 UPnP/1.0 miniupnpd/2.1", "summary": "", "caveat": ""}


@pytest.fixture
def probe(mod, monkeypatch):
    """host_identity with every outbound call faked."""
    def run(open_ports, tls=None, alt=None, ssh="", verdict=None):
        calls = []

        def fake_tls(host, port=443):
            calls.append(("tls", port))
            got = tls if port == 443 else alt
            return {"present": True, "sha256": got} if got else {"present": False, "sha256": None}

        def fake_ssh(host, port=22, timeout=3):
            calls.append(("ssh", port))
            return ssh
        monkeypatch.setattr(mod, "check_tls", fake_tls)
        monkeypatch.setattr(mod, "read_ssh_banner", fake_ssh)
        return mod.host_identity(MODEM, open_ports, verdict), calls
    return run


class TestWhatIsMeasured:
    def test_the_certificate_on_443_is_recorded_as_a_digest(self, probe):
        identity, _ = probe([443], tls=CERT_A)
        assert identity == {"tls_443": CERT_A}

    def test_8443_is_fingerprinted_only_when_open(self, probe):
        identity, calls = probe([443, 8443], tls=CERT_A, alt=CERT_B)
        assert identity["tls_8443"] == CERT_B and ("tls", 8443) in calls
        _, calls = probe([443], tls=CERT_A, alt=CERT_B)
        assert ("tls", 8443) not in calls

    def test_the_ssh_banner_is_read_only_when_22_is_open(self, probe):
        identity, calls = probe([22], ssh="SSH-2.0-dropbear_2019.78")
        assert identity == {"ssh_banner": "SSH-2.0-dropbear_2019.78"} and ("ssh", 22) in calls
        _, calls = probe([80], ssh="SSH-2.0-dropbear_2019.78")
        assert ("ssh", 22) not in calls

    def test_the_upnp_server_banner_comes_from_the_verdict(self, probe):
        identity, _ = probe([1900], verdict=IGD)
        assert identity == {"upnp_server": "Linux/4.1 UPnP/1.0 miniupnpd/2.1"}

    def test_nothing_read_is_an_empty_identity_not_a_dict_of_nones(self, probe):
        identity, _ = probe([80])
        assert identity == {}

    def test_a_banner_is_cleaned_like_every_device_string(self, probe):
        identity, _ = probe([1900], verdict=dict(IGD, server="x\n  [OK    ] forged line"))
        assert "\n" not in identity["upnp_server"] and "[OK" not in identity["upnp_server"]


class TestTheSshBanner:
    def _socket(self, monkeypatch, mod, data=b"", error=None):
        class Sock:
            def __init__(self): self.timeout = None
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def settimeout(self, t): self.timeout = t
            def recv(self, n): return data

        def create(addr, timeout=None):
            if error:
                raise error
            return Sock()
        monkeypatch.setattr(mod.socket, "create_connection", create)

    def test_the_first_line_is_the_banner(self, mod, monkeypatch):
        self._socket(monkeypatch, mod, b"SSH-2.0-OpenSSH_9.9\r\n\x00\x00junk")
        assert mod.read_ssh_banner(MODEM) == "SSH-2.0-OpenSSH_9.9"

    def test_something_that_is_not_ssh_is_not_a_banner(self, mod, monkeypatch):
        self._socket(monkeypatch, mod, b"220 ftp ready\r\n")
        assert mod.read_ssh_banner(MODEM) == ""

    def test_a_refused_connection_is_an_empty_banner(self, mod, monkeypatch):
        self._socket(monkeypatch, mod, error=OSError(61, "refused"))
        assert mod.read_ssh_banner(MODEM) == ""

    def test_a_timeout_is_an_empty_banner(self, mod, monkeypatch):
        self._socket(monkeypatch, mod, error=socket.timeout("timed out"))
        assert mod.read_ssh_banner(MODEM) == ""


class TestAuditHostKeepsIt:
    def test_the_identity_is_stored_for_the_caller_and_printed(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "scan_ports_detailed", lambda h, ports, workers=100:
                            {"open": [22, 443, 8443], "probed": 25, "unreachable": 0, "blocked": False})
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: {"present": True, "sha256": CERT_A if port == 443 else CERT_B})
        monkeypatch.setattr(mod, "read_ssh_banner", lambda h, port=22, timeout=3: "SSH-2.0-dropbear_2019.78")
        identities = {}
        ports = mod.audit_host("upstream modem", MODEM, identities=identities)
        assert ports == [22, 443, 8443]
        assert identities[MODEM] == {"tls_443": CERT_A, "tls_8443": CERT_B, "ssh_banner": "SSH-2.0-dropbear_2019.78"}
        out = capsys.readouterr().out
        assert "HTTPS (TLS) certificate: present, sha256 b761788ac45e493b…" in out
        assert "Certificate on port 8443: 1695dc0b5e4e5364…" in out
        assert "SSH banner: SSH-2.0-dropbear_2019.78" in out

    def test_a_filtered_scan_records_no_identity(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "scan_ports_detailed", lambda h, ports, workers=100:
                            {"open": [], "probed": 25, "unreachable": 0, "filtered": 25, "answered": 0,
                             "blocked": False, "unanswered": True})
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: pytest.fail("no handshake on a filtered host"))
        identities = {}
        assert mod.audit_host("upstream modem", MODEM, identities=identities) is None
        assert identities == {}


class TestTheDiff:
    def test_a_changed_certificate_is_a_change_line_with_both_prefixes(self, mod):
        old = {"upstream_identity": {"tls_443": CERT_A}}
        new = {"upstream_identity": {"tls_443": CERT_B}}
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1
        assert notes[0].startswith("Upstream modem certificate CHANGED: b761788ac45e493b… -> 1695dc0b5e4e5364…")
        assert "answering in its place" in notes[0]

    def test_each_field_is_its_own_line(self, mod):
        old = {"upstream_identity": {"tls_443": CERT_A, "tls_8443": CERT_A, "ssh_banner": "SSH-2.0-dropbear_2019.78", "upnp_server": "miniupnpd/2.1"}}
        new = {"upstream_identity": {"tls_443": CERT_A, "tls_8443": CERT_B, "ssh_banner": "SSH-2.0-OpenSSH_9.9", "upnp_server": "miniupnpd/2.3"}}
        notes = mod.diff_baseline(old, new)
        assert [n.split(" CHANGED")[0] for n in notes] == [
            "Upstream modem certificate on port 8443", "Upstream modem SSH banner", "Upstream modem UPnP server banner"]
        assert "SSH-2.0-dropbear_2019.78 -> SSH-2.0-OpenSSH_9.9" in notes[1]

    def test_a_field_measured_on_one_side_only_is_not_a_change(self, mod):
        # 22 closed this week: the port diff says so; the banner is not "gone".
        old = {"upstream_identity": {"tls_443": CERT_A, "ssh_banner": "SSH-2.0-dropbear_2019.78"}}
        new = {"upstream_identity": {"tls_443": CERT_A}}
        assert mod.diff_baseline(old, new) == []

    def test_an_identical_identity_is_silent(self, mod):
        same = {"upstream_identity": {"tls_443": CERT_A, "upnp_server": "miniupnpd/2.1"}}
        assert mod.diff_baseline(same, dict(same)) == []

    def test_a_baseline_without_an_identity_is_not_compared(self, mod):
        assert mod.diff_baseline({}, {"upstream_identity": {"tls_443": CERT_A}}) == []
        assert mod.diff_baseline({"upstream_identity": {"tls_443": CERT_A}}, {}) == []

    def test_a_hostile_identity_does_not_raise(self, mod):
        assert mod.diff_baseline({"upstream_identity": {"tls_443": 7, "ssh_banner": None}},
                                 {"upstream_identity": [1, 2]}) == []
        assert mod.diff_baseline({"upstream_identity": {"tls_443": 7}},
                                 {"upstream_identity": {"tls_443": "x"}}) == []

    def test_the_real_change_of_20_september_would_have_been_reported(self, mod):
        # audit.log: b761788ac45e493b... on 2026-09-13, 1695dc0b5e4e5364... on
        # 2026-09-20, the same six ports, and "No changes since baseline."
        ports = [22, 53, 80, 443, 1900, 8443]
        old = {"upstream_open_ports": ports, "upstream_identity": {"tls_443": CERT_A}}
        new = {"upstream_open_ports": ports, "upstream_identity": {"tls_443": CERT_B}}
        assert any("certificate CHANGED" in n for n in mod.diff_baseline(old, new))


class TestCarryForward:
    def test_an_unread_identity_keeps_the_last_reading(self, mod):
        previous = {"timestamp": "2026-10-25T22:00:00+00:00", "upstream_identity": {"tls_443": CERT_A}}
        merged = mod.carry_forward_unmeasured({"timestamp": "2026-11-01T22:00:00+00:00", "upstream_identity": {}}, previous)
        assert merged["upstream_identity"] == {"tls_443": CERT_A}
        assert "upstream_identity" in merged["carried_forward"]
        assert merged["measured_at"]["upstream_identity"] == "2026-10-25T22:00:00+00:00"

    def test_a_reading_is_never_overwritten_by_an_older_one(self, mod):
        previous = {"upstream_identity": {"tls_443": CERT_A}}
        merged = mod.carry_forward_unmeasured({"timestamp": "2026-11-01T22:00:00+00:00",
                                               "upstream_identity": {"tls_443": CERT_B}}, previous)
        assert merged["upstream_identity"] == {"tls_443": CERT_B} and "carried_forward" not in merged

    def test_nothing_is_carried_when_there_was_never_a_reading(self, mod):
        merged = mod.carry_forward_unmeasured({"timestamp": "2026-11-01T22:00:00+00:00", "upstream_identity": {}},
                                              {"upstream_identity": {}})
        assert "carried_forward" not in merged

    def test_the_freshness_caveat_names_it(self, mod):
        state = {"carried_forward": ["upstream_identity"],
                 "measured_at": {"upstream_identity": "2026-10-01T00:00:00+00:00"}}
        assert "upstream modem identity" in mod.describe_baseline_freshness(state)

    def test_it_is_a_measured_finding_in_the_provenance_section(self, mod):
        assert mod.EVIDENCE["upstream_identity"][0] == mod.MEASURED
        assert "upstream_identity" in mod.findings_by_evidence({"upstream_identity": {"tls_443": CERT_A}})[mod.MEASURED]


class TestTheHtmlReport:
    def test_the_identity_is_rendered(self, mod, tmp_path):
        state = {"upstream_identity": {"tls_443": CERT_A, "ssh_banner": "SSH-2.0-dropbear_2019.78"}}
        text = Path(mod.generate_html_report(state, output_path=str(tmp_path / "r.html"))).read_text()
        assert "<h2>Upstream Modem Identity</h2>" in text
        assert "b761788ac45e493b…" in text and "SSH-2.0-dropbear_2019.78" in text
        assert "Not Included In This Report" not in text

    def test_an_empty_identity_says_nothing_was_read(self, mod, tmp_path):
        text = Path(mod.generate_html_report({"upstream_identity": {}}, output_path=str(tmp_path / "r.html"))).read_text()
        assert "Nothing identifying the upstream modem could be read" in text

    def test_a_hostile_banner_is_escaped(self, mod, tmp_path):
        state = {"upstream_identity": {"ssh_banner": "SSH-2.0-<script>alert(1)</script>"}}
        text = Path(mod.generate_html_report(state, output_path=str(tmp_path / "r.html"))).read_text()
        assert "<script>" not in text
