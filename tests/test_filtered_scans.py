"""A scan nobody answered is unmeasured, and the week it answers again is not
"NEW open ports". Round 4, F34, from the diff and the baseline side.

audit_host now returns None for a filtered scan (see test_audit_host.py) and
records the outcome; the baseline carries the previous reading forward and
seals the outcome beside it; and the comparison reads that outcome rather than
the carried list.
"""

from pathlib import Path

import pytest

PORTS = [22, 53, 80, 443, 1900, 8443]
FILTERED = {"result": "filtered", "probed": 25, "answered": 0, "filtered": 25, "unreachable": 0}
MEASURED = {"result": "measured", "probed": 25, "answered": 25, "filtered": 0, "unreachable": 0}


class TestTheDiff:
    def test_a_modem_answering_again_is_became_reachable_not_new_ports(self, mod):
        old = {"upstream_open_ports": [], "upstream_scan": FILTERED}        # the IoT baseline, as deployed
        new = {"upstream_open_ports": PORTS, "upstream_scan": MEASURED}
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1 and "became reachable" in notes[0] and str(PORTS) in notes[0]
        assert "NEW open port" not in notes[0] and "faces the internet" not in notes[0]

    def test_a_carried_list_is_not_diffed_against_the_first_reading_since(self, mod):
        # Last week's scan was filtered; the list it holds came from the week
        # before. Six ports then, six now: no port changed, and a reading that
        # differs would be said by "became reachable", not as a change in ports.
        old = {"upstream_open_ports": PORTS, "upstream_scan": FILTERED, "carried_forward": ["upstream_open_ports"]}
        new = {"upstream_open_ports": PORTS[:-1], "upstream_scan": MEASURED}
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1 and "became reachable" in notes[0]
        assert not any("now closed" in n for n in notes)

    def test_a_filtered_run_against_a_measured_baseline_is_silent(self, mod):
        # None on the new side: nothing to compare, exactly as a blocked scan.
        old = {"upstream_open_ports": PORTS, "upstream_scan": MEASURED}
        new = {"upstream_open_ports": None, "upstream_scan": FILTERED}
        assert mod.diff_baseline(old, new) == []

    def test_filtered_both_weeks_is_silent(self, mod):
        old = {"upstream_open_ports": [], "upstream_scan": FILTERED}
        new = {"upstream_open_ports": None, "upstream_scan": FILTERED}
        assert mod.diff_baseline(old, new) == []

    def test_the_router_gets_the_same_treatment(self, mod):
        old = {"router_open_ports": [80], "router_scan": FILTERED}
        new = {"router_open_ports": [80, 443], "router_scan": MEASURED}
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1 and notes[0].startswith("The router became reachable")

    def test_a_baseline_without_an_outcome_diffs_as_before(self, mod):
        notes = mod.diff_baseline({"upstream_open_ports": [80]}, {"upstream_open_ports": [80, 23]})
        assert len(notes) == 1 and "NEW open port(s) on upstream modem: [23]" in notes[0]

    def test_a_hostile_outcome_does_not_raise(self, mod):
        assert mod.diff_baseline({"upstream_open_ports": [80], "upstream_scan": "filtered"},
                                 {"upstream_open_ports": [80], "upstream_scan": None}) == []


class TestTheBaseline:
    def test_a_filtered_scan_carries_the_previous_reading_and_keeps_the_outcome(self, mod):
        mod.save_baseline({"timestamp": "2026-10-25T22:00:00+00:00", "gateway": "10.0.0.1",
                           "upstream_open_ports": PORTS, "upstream_scan": MEASURED})
        mod.save_baseline({"timestamp": "2026-11-01T22:00:00+00:00", "gateway": "10.0.0.1",
                           "upstream_open_ports": None, "upstream_scan": FILTERED})
        saved = mod.load_baseline()
        assert saved["upstream_open_ports"] == PORTS, "the last real reading, not an empty list"
        assert "upstream_open_ports" in saved["carried_forward"]
        assert saved["upstream_scan"]["result"] == "filtered", "and the baseline says why it was carried"
        assert saved["measured_at"]["upstream_open_ports"] == "2026-10-25T22:00:00+00:00"

    def test_the_html_report_says_filtered_rather_than_could_not_be_scanned(self, mod, tmp_path):
        state = {"upstream_open_ports": None, "upstream_scan": FILTERED}
        text = Path(mod.generate_html_report(state, output_path=str(tmp_path / "r.html"))).read_text()
        assert "FILTERED" in text and "closed port answers with a reset" in text
        assert "Not Included In This Report" not in text

    def test_the_outcome_keys_are_rendered_keys(self, mod):
        assert {"router_scan", "upstream_scan"} <= set(mod.RENDERED_STATE_KEYS)
