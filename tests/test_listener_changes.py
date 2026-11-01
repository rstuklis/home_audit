"""A new fixed-port listener on this Mac is a change the email carries.

Round 4, F11. action_listening_services printed a newcomer as
"  + not in the baseline: nc on TCP port 4444" — a form nothing downstream
reads. The digest counts risk-tagged lines and the "  ! " lines of the change
section; diff_baseline never compared listeners at all. So a week whose only
event was a backdoor opening TCP 4444 was mailed as "no changes", with the one
line that said otherwise under a table the owner never scrolled to.

Pinned here: the section's lines are risk-tagged (REVIEW for a fixed port,
INFO for a named process on a dynamic port or for a listener that left);
diff_baseline reports fixed-port arrivals and departures as change notes; a
failed enumeration is not compared; and the brief host-section renderer still
prints the whole section for a tagged newcomer.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from conftest import make_run

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def svc(port, proc, proto="TCP"):
    return {"proto": proto, "port": port, "pid": "1", "process": proc}


BASE = [svc(22, "sshd"), svc(5353, "mDNSResponder", "UDP"), svc(50000, "rapportd")]


@pytest.fixture
def section(mod, monkeypatch, capsys):
    """action_listening_services over a fixed service list and baseline."""
    def run(services, known, compact=False):
        monkeypatch.setattr(mod, "check_listening_services", lambda: services)
        result = mod.action_listening_services(compact=compact, known=known)
        return result, capsys.readouterr().out
    return run


class TestTheSectionTagsWhatChanged:
    def test_a_new_fixed_port_listener_is_a_review_line(self, section):
        _, out = section(BASE + [svc(4444, "nc")], BASE)
        assert "  [REVIEW] Listening: not in the baseline: nc on TCP port 4444" in out
        assert "+ not in the baseline" not in out

    def test_a_new_named_dynamic_port_listener_is_info(self, section):
        _, out = section(BASE + [svc(60123, "Zoom")], BASE)
        assert "  [INFO  ] Listening: not in the baseline: Zoom on TCP a dynamic port" in out

    def test_a_listener_that_left_is_info(self, section):
        _, out = section(BASE[:2], BASE)
        assert "  [INFO  ] Listening: in the baseline, gone now: rapportd on TCP a dynamic port" in out

    def test_the_compact_summary_tags_departures_too(self, section):
        _, out = section(BASE[:2], BASE, compact=True)
        assert "none of them new since the baseline" in out
        assert "  [INFO  ] Listening: in the baseline, gone now: rapportd on TCP a dynamic port" in out

    def test_nothing_is_tagged_when_nothing_changed(self, section):
        _, out = section(list(BASE), BASE)
        assert "Listening: not in the baseline" not in out and "gone now" not in out

    def test_the_digest_reads_the_line_as_a_flagged_item(self, section):
        spec = importlib.util.spec_from_file_location("report_digest", TOOLS / "report_digest.py")
        dg = importlib.util.module_from_spec(spec)
        sys.modules["report_digest"] = dg
        spec.loader.exec_module(dg)
        _, out = section(BASE + [svc(4444, "nc")], BASE)
        report = "\n".join(["", "=" * 64, "LISTENING SERVICES AUDIT", "=" * 64]) + "\n" + out \
            + "\n" + "=" * 64 + "\nCHANGE DETECTION (vs saved baseline)\n" + "=" * 64 + "\nNo changes since baseline.\n"
        parsed = dg.parse_report(report)
        assert any(f["risk"] == "REVIEW" and "nc on TCP port 4444" in f["text"]
                   and f["section"] == "LISTENING SERVICES AUDIT" for f in parsed["flagged"])

    def test_the_brief_renderer_prints_the_whole_section_for_a_tagged_newcomer(self, mod):
        quiet = "\n" + "=" * 64 + "\nFIREWALL STATUS\n" + "=" * 64 + "\n  [OK    ] Application Firewall : ON\n"
        loud = ("\n" + "=" * 64 + "\nLISTENING SERVICES AUDIT\n" + "=" * 64
                + "\n  Port    Proto  Process\n* 4444    TCP    nc\n"
                "  [REVIEW] Listening: not in the baseline: nc on TCP port 4444\n")
        out = mod.render_host_sections_brief([("firewall", quiet), ("listening services", loud)])
        assert "LISTENING SERVICES AUDIT" in out and "* 4444    TCP    nc" in out
        assert "Re-checked here and recorded in this network's baseline: firewall." in out


class TestTheDiffCarriesIt:
    def test_a_new_fixed_port_listener_is_a_change_note(self, mod):
        notes = mod.diff_baseline({"listening": BASE}, {"listening": BASE + [svc(4444, "nc")]})
        assert len(notes) == 1
        assert notes[0].startswith("NEW listener(s) on this Mac since baseline: nc on TCP port 4444")

    def test_a_fixed_port_listener_leaving_is_a_change_note(self, mod):
        notes = mod.diff_baseline({"listening": BASE}, {"listening": BASE[1:]})
        assert notes == ["Listener(s) on this Mac gone since baseline: sshd on TCP port 22"]

    def test_the_same_daemon_on_a_new_dynamic_port_is_not_a_change(self, mod):
        moved = BASE[:2] + [svc(51234, "rapportd")]
        assert mod.diff_baseline({"listening": BASE}, {"listening": moved}) == []

    def test_a_new_named_process_on_a_dynamic_port_is_the_sections_business_not_a_change(self, mod):
        assert mod.diff_baseline({"listening": BASE}, {"listening": BASE + [svc(60123, "Zoom")]}) == []

    def test_an_unattributed_fixed_port_is_still_a_change(self, mod):
        notes = mod.diff_baseline({"listening": BASE}, {"listening": BASE + [svc(8021, "?")]})
        assert len(notes) == 1 and "unattributed on TCP port 8021" in notes[0]

    @pytest.mark.parametrize("old,new", [
        ([], BASE), (BASE, []), (None, BASE), (BASE, None),
    ], ids=["old-empty", "new-empty", "old-missing", "new-missing"])
    def test_a_failed_enumeration_is_not_compared(self, mod, old, new):
        # lsof and netstat returning nothing is a failure to look, which the
        # HTML report already says; it must not read as every listener leaving.
        assert mod.diff_baseline({"listening": old}, {"listening": new}) == []

    def test_a_hostile_listener_list_does_not_raise(self, mod):
        assert mod.diff_baseline({"listening": [None, 3, {"port": "x"}]},
                                 {"listening": [{"port": 22, "proto": "TCP", "process": "sshd"}, "junk"]}) == [
            "NEW listener(s) on this Mac since baseline: sshd on TCP port 22. A fixed port is a choice "
            "somebody made; a new one accepting connections on this Mac is what a backdoor looks like."]

    def test_the_change_flips_the_verdict_in_the_full_audit_block(self, mod, capsys, monkeypatch):
        # The change note is what turns "No changes since baseline." into
        # "CHANGES DETECTED", which is what the subject line and TL;DR read.
        mod.save_baseline({"timestamp": "2026-10-25T22:00:00+00:00", "gateway": "10.0.0.1", "listening": BASE})
        monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (None, None))
        monkeypatch.setattr(mod, "describe_current_network", lambda *a, **k: "")
        mod.action_compare_baseline({"timestamp": "2026-11-01T22:00:00+00:00", "gateway": "10.0.0.1",
                                     "listening": BASE + [svc(4444, "nc")]})
        out = capsys.readouterr().out
        assert "CHANGES DETECTED:" in out and "  ! NEW listener(s) on this Mac since baseline: nc on TCP port 4444" in out
