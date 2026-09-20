"""The modem section in brief, when a later network sees what an earlier one did.

Several networks sit behind one modem, and each audit scans it. From most of
them the answer is identical, so the report repeated the section. A later network
may now print it in brief — but only by agreeing, on its own measurement, with
what the earlier network recorded. The scan always runs, the ports printed are
always the ones measured here, and any disagreement prints the section in full
with a note — a note and not a rated finding, because a guest network is cut off
from the modem by design and would otherwise raise the same false flag weekly.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

MODEM = "192.168.1.1"
PORTS = [22, 53, 80, 443, 1900, 8443]
NOW = datetime(2026, 9, 20, 5, 40, tzinfo=timezone.utc)
DORMANT = {"state": "dormant", "risk": "INFO", "server": "libupnp", "summary": "DORMANT — nothing answered.", "caveat": ""}


def baseline(tmp_path, minutes_ago=3, **over):
    state = {"timestamp": (NOW - timedelta(minutes=minutes_ago)).isoformat(),
             "scanned_subnets": ["192.168.87.0/24"],
             "upstream_open_ports": list(PORTS),
             "upnp_listeners": {MODEM: {"state": "dormant", "risk": "INFO"}}}
    state.update(over)
    path = tmp_path / "baseline-192-168-87-0-24.json"
    path.write_text(json.dumps({"format": 2, "state": state}))
    return str(path)


class TestLoading:
    def test_a_fresh_baseline_from_another_network_is_a_reference(self, mod, tmp_path):
        ref = mod.load_upstream_reference(baseline(tmp_path), MODEM, "192.168.86.0/24", now=NOW)
        assert ref == {"ports": PORTS, "upnp_state": "dormant", "network": "loveshack", "age_min": 3}

    def test_this_networks_own_baseline_is_not(self, mod, tmp_path):
        assert mod.load_upstream_reference(baseline(tmp_path), MODEM, "192.168.87.0/24", now=NOW) is None

    def test_one_older_than_an_hour_is_not_the_same_report(self, mod, tmp_path):
        assert mod.load_upstream_reference(baseline(tmp_path, minutes_ago=61), MODEM, "192.168.86.0/24", now=NOW) is None

    def test_one_from_the_future_is_refused(self, mod, tmp_path):
        assert mod.load_upstream_reference(baseline(tmp_path, minutes_ago=-5), MODEM, "192.168.86.0/24", now=NOW) is None

    def test_a_carried_forward_modem_scan_was_not_measured_in_this_report(self, mod, tmp_path):
        path = baseline(tmp_path, carried_forward=["upstream_open_ports"])
        assert mod.load_upstream_reference(path, MODEM, "192.168.86.0/24", now=NOW) is None

    @pytest.mark.parametrize("over", [{"upstream_open_ports": None}, {"upstream_open_ports": "22,80"},
                                      {"upstream_open_ports": [22, "80"]}, {"timestamp": "whenever"}])
    def test_malformed_contents_yield_no_reference(self, mod, tmp_path, over):
        assert mod.load_upstream_reference(baseline(tmp_path, **over), MODEM, "192.168.86.0/24", now=NOW) is None

    @pytest.mark.parametrize("content", ["", "{not json", "[]", '{"state": 7}', "null"])
    def test_an_unreadable_file_yields_no_reference(self, mod, tmp_path, content):
        path = tmp_path / "b.json"
        path.write_text(content)
        assert mod.load_upstream_reference(str(path), MODEM, "192.168.86.0/24", now=NOW) is None

    def test_a_missing_file_yields_no_reference(self, mod, tmp_path):
        assert mod.load_upstream_reference(str(tmp_path / "nope.json"), MODEM, now=NOW) is None

    def test_a_network_name_from_the_file_cannot_carry_control_characters(self, mod, tmp_path, monkeypatch):
        monkeypatch.setattr(mod, "load_networks", lambda: {"192.168.87.0/24": "love\x1b[2Kshack\nFORGED LINE"})
        ref = mod.load_upstream_reference(baseline(tmp_path), MODEM, "192.168.86.0/24", now=NOW)
        assert "\x1b" not in ref["network"] and "\n" not in ref["network"]


@pytest.fixture
def scan(mod, monkeypatch, capsys):
    def run(open_ports, reference, verdict=DORMANT):
        monkeypatch.setattr(mod, "scan_ports_detailed", lambda h, ports, workers=100:
                            {"open": sorted(open_ports), "probed": 25, "unreachable": 0, "blocked": False})
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: {"present": True, "sha256": "16" * 32})
        monkeypatch.setattr(mod, "classify_upnp_listener", lambda host, port=1900, onlink=None: verdict)
        kept = {}
        ports = mod.audit_host("upstream modem", MODEM, onlink=False, verdicts=kept, reference=reference)
        return ports, kept, capsys.readouterr().out
    return run


REF = {"ports": PORTS, "upnp_state": "dormant", "network": "loveshack", "age_min": 3}


class TestBrief:
    def test_agreement_prints_the_section_in_brief(self, scan):
        _, _, out = scan(PORTS, REF)
        assert "as seen from loveshack 3 min ago" in out
        assert "DNS" not in out and "HTTPS admin" not in out and "DORMANT" not in out

    def test_the_ports_printed_are_the_ones_measured_here(self, scan):
        _, _, out = scan(PORTS, REF)
        assert "Open ports: [22, 53, 80, 443, 1900, 8443]" in out

    def test_every_line_rated_above_info_survives(self, scan):
        # The digest counts these per network; one that vanished from a network's
        # report would read as cleared there.
        _, _, out = scan(PORTS, REF)
        assert "[REVIEW]    22  SSH" in out and "[MEDIUM]    80  HTTP admin" in out

    def test_the_certificate_is_still_shown(self, scan):
        # Cheap, and the one line here that could differ between two vantage
        # points for a bad reason.
        assert "sha256 1616161616161616" in scan(PORTS, REF)[2]

    def test_everything_is_still_measured_and_returned(self, scan):
        ports, kept, _ = scan(PORTS, REF)
        assert ports == PORTS and kept == {MODEM: DORMANT}

    def test_no_reference_means_the_full_section_as_before(self, scan):
        _, _, out = scan(PORTS, None)
        assert "DNS" in out and "DORMANT" in out and "as seen from" not in out


class TestDisagreement:
    def test_a_port_open_here_but_not_there_prints_everything_and_says_why(self, scan):
        _, _, out = scan(PORTS + [23], REF)
        assert "Note: the open ports seen from here differ from what loveshack saw" in out
        assert "DNS" in out and "DORMANT" in out and "   23  " in out

    def test_a_port_missing_here_is_a_disagreement_too(self, scan):
        _, _, out = scan([53, 80, 443], REF)
        assert "differ from what loveshack saw" in out and "HTTPS admin" in out

    def test_the_same_ports_with_a_different_1900_verdict_is_a_disagreement(self, scan):
        live = {"state": "live-gateway", "risk": "REVIEW", "server": "", "summary": "LIVE — a UPnP gateway service answered.", "caveat": ""}
        _, _, out = scan(PORTS, REF, verdict=live)
        assert "the verdict on port 1900 seen from here differ" in out and "LIVE" in out

    def test_a_blocked_scan_is_never_brief(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "scan_ports_detailed", lambda h, ports, workers=100:
                            {"open": [], "probed": 25, "unreachable": 25, "blocked": True})
        assert mod.audit_host("upstream modem", MODEM, reference=REF) is None
        assert "UNKNOWN" in capsys.readouterr().out

    def test_a_guest_network_that_sees_nothing_gets_a_note_not_a_flag(self, scan):
        # loveshack-iot is cut off from the modem by design. "none found" is a
        # real, different answer — and an expected one, every single week. A rated
        # line here would be a permanent false flag in the email's TL;DR.
        _, _, out = scan([], REF, verdict=None)
        assert "none found" in out and "expected to differ" in out
        assert "[REVIEW" not in out and "[MEDIUM" not in out and "[HIGH" not in out

    def test_the_difference_note_is_never_a_rated_line(self, scan):
        import re
        _, _, out = scan(PORTS + [23], REF)
        note = next(l for l in out.splitlines() if "differ from what" in l)
        assert not re.match(r"^\s*\[(HIGH|MEDIUM|REVIEW|UNKNOWN)", note)
