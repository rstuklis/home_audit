"""audit_host — the function that decides what a port scan is allowed to claim.

It is one screen of printing wrapped around one decision, and that decision ends
up in the baseline: a list of open ports, or None for "I could not ask". Getting
it wrong is how a scheduled run came to report "no open ports on your router" as
fact for months, and how the empty list it saved then told the following run that
the ports had closed.

The distinction it rests on is made in scan_ports_detailed (covered in
test_net_helpers.py). What is pinned here is the contract on top of it:

  * blocked  -> return None, and say so in words the reader can act on
  * measured -> return the list, even when the list is empty

The scan itself is faked; check_tls is faked because it opens a socket of its
own and is tested in its own module.
"""

import pytest


def _scan(open_ports=(), blocked=False, probed=25):
    """A scan_ports_detailed result, shaped as the real one."""
    return {"open": sorted(open_ports), "probed": probed,
            "unreachable": probed if blocked else 0, "blocked": blocked}


@pytest.fixture
def host(mod, monkeypatch):
    """audit_host with its two outbound calls stubbed.

    Returns a setter: pick the scan result, get back (result, printed_text).
    """
    def run(scan_result, tls=None, label="default gateway", ip="192.168.87.1",
            capsys=None, full_scan=False):
        monkeypatch.setattr(mod, "scan_ports_detailed",
                            lambda h, ports, workers=100: scan_result)
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: tls or {"present": False})
        return mod.audit_host(label, ip, full_scan)
    return run


class TestBlockedScan:
    """Every probe refused. Not a quiet host — a host we were never able to ask."""

    def test_returns_none_rather_than_an_empty_list(self, host, capsys):
        assert host(_scan(blocked=True)) is None, (
            "a blocked scan returned a list, which the baseline would store as "
            "a measurement of zero open ports")

    def test_says_unknown_and_never_none_found(self, host, capsys):
        host(_scan(blocked=True))
        out = capsys.readouterr().out
        assert "UNKNOWN" in out
        assert "could not reach" in out
        assert "none found" not in out, "a refused scan was described as a finding"

    def test_names_the_host_it_could_not_reach(self, host, capsys):
        host(_scan(blocked=True), ip="10.9.9.1")
        assert "10.9.9.1" in capsys.readouterr().out

    def test_reports_how_many_probes_were_refused(self, host, capsys):
        # The count is the evidence: 25 of 25 refused instantly is a different
        # claim from one flaky probe, and the reader can weigh it.
        host(_scan(blocked=True, probed=25))
        assert "25 probes" in capsys.readouterr().out

    def test_does_not_print_a_port_table_for_a_scan_that_found_nothing(self, host, capsys):
        host(_scan(blocked=True))
        out = capsys.readouterr().out
        assert "[INFO" not in out and "[MEDIUM" not in out


class TestMeasuredScan:
    """The scan completed. Whatever it found is a real finding, including none."""

    def test_open_ports_are_returned_and_listed(self, host, capsys):
        result = host(_scan(open_ports=[53, 80]))
        assert result == [53, 80]
        out = capsys.readouterr().out
        assert "Open ports: [53, 80]" in out

    def test_an_empty_result_is_a_measurement_not_an_unknown(self, host, capsys):
        # The distinction the whole function exists for: a reachable host with
        # nothing listening returns [], which the baseline SHOULD store, while a
        # blocked scan returns None, which it should not.
        result = host(_scan(open_ports=[]))
        assert result == [], "a completed scan finding nothing must not read as unknown"
        assert "none found" in capsys.readouterr().out

    def test_each_open_port_is_annotated_with_its_risk(self, host, capsys):
        host(_scan(open_ports=[23]))
        out = capsys.readouterr().out
        assert "23" in out
        assert any(tag in out for tag in ("[HIGH", "[MEDIUM", "[REVIEW", "[INFO"))

    def test_an_unrecognised_port_is_flagged_for_review_not_ignored(self, host, capsys):
        host(_scan(open_ports=[47111]))
        out = capsys.readouterr().out
        assert "47111" in out
        assert "REVIEW" in out

    def test_a_certificate_fingerprint_is_shown_when_present(self, host, capsys):
        host(_scan(open_ports=[443]), tls={"present": True, "sha256": "ab" * 32})
        assert "sha256" in capsys.readouterr().out

    def test_port_80_without_443_earns_the_mesh_router_note(self, host, capsys):
        # Google Nest and eero serve 80/5000 locally and have no web admin at
        # all, so the bare fact is misleading without it.
        host(_scan(open_ports=[80, 5000]))
        assert "mesh" in capsys.readouterr().out.lower()

    def test_the_mesh_note_is_absent_when_443_is_also_open(self, host, capsys):
        host(_scan(open_ports=[80, 443]))
        assert "mesh" not in capsys.readouterr().out.lower()


class TestScanScope:
    def test_a_full_scan_announces_the_wider_range(self, host, capsys):
        host(_scan(open_ports=[]), full_scan=True)
        assert "65535" in capsys.readouterr().out

    def test_the_default_scan_announces_the_common_port_count(self, mod, host, capsys):
        host(_scan(open_ports=[]))
        assert str(len(mod.COMMON_PORTS)) in capsys.readouterr().out


def _filtered(probed=25, filtered=25, unreachable=0):
    return {"open": [], "probed": probed, "unreachable": unreachable, "filtered": filtered,
            "answered": 0, "blocked": False, "unanswered": True}


class TestFilteredScan:
    """No probe answered. Round 4, F34: this printed 'none found' and returned
    [], a measurement the baseline kept."""

    def test_returns_none_rather_than_an_empty_list(self, host, capsys):
        assert host(_filtered()) is None

    def test_says_filtered_and_never_none_found(self, host, capsys):
        host(_filtered())
        out = capsys.readouterr().out
        assert "FILTERED: no probe was answered" in out
        assert "none found" not in out and "Open ports:" not in out

    def test_it_is_a_review_line_naming_the_counts(self, host, capsys):
        host(_filtered(filtered=20, unreachable=5))
        out = capsys.readouterr().out
        assert "[REVIEW]" in out and "25 probes" in out and "20 timed out" in out and "5 unreachable" in out
        assert "carried forward" in out

    def test_the_outcome_is_recorded_for_the_caller(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "scan_ports_detailed", lambda h, ports, workers=100: _filtered())
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: {"present": False})
        outcomes = {}
        assert mod.audit_host("upstream modem", "192.168.1.1", outcomes=outcomes) is None
        assert outcomes["192.168.1.1"]["result"] == "filtered"
        assert outcomes["192.168.1.1"]["probed"] == 25

    @pytest.mark.parametrize("scan,result", [
        (_scan(open_ports=[80]), "measured"),
        (_scan(open_ports=[]), "measured"),
        (_scan(blocked=True), "blocked"),
    ], ids=["ports", "empty", "blocked"])
    def test_the_other_outcomes_are_recorded_too(self, mod, monkeypatch, scan, result):
        monkeypatch.setattr(mod, "scan_ports_detailed", lambda h, ports, workers=100: scan)
        monkeypatch.setattr(mod, "check_tls", lambda h, port=443: {"present": False})
        outcomes = {}
        mod.audit_host("default gateway", "192.168.87.1", outcomes=outcomes)
        assert outcomes["192.168.87.1"]["result"] == result

    def test_a_scan_result_without_the_new_keys_is_still_a_measurement(self, host):
        # scan_ports_detailed results from before `unanswered` existed.
        assert host(_scan(open_ports=[22])) == [22]
