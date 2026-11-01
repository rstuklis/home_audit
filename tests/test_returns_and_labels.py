"""A return the previous run called "gone" is a change; labels are listed for
pruning, never pruned; a MAC at two addresses is said.

Round 4, F14. Every stable MAC whose last sighting was within 30 days was
subtracted from "appeared", and the return got an INFO line the email digest
drops. labels.json was only ever added to. So the nine Tuya, Arlo and Apple TV
addresses retired this week — on the air for months, cleartext in every
802.11 header — could be reused by anyone with the guest key and print as the
owner's own labelled device under "No changes since baseline".

Now: save_baseline records which departures its run reported ("departed"), and
a remembered device coming back that the previous run's own gone line named is
a change line, which flips the verdict and reaches the TL;DR; an ordinary
return stays INFO. Labels no network has seen for DEVICE_MEMORY_DAYS are
listed at REVIEW with the --unlabel command; nothing is removed by itself.
"""

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

NET = "192.168.85.0/24"
GW = "b0:2a:43:c8:22:5b"
PLUG = "70:89:76:78:6d:c6"
HUB = "a4:11:62:2a:b9:0a"
LABELS = {PLUG: "Tuya device A (6d:c6)", GW: "Nest Wifi", HUB: "Arlo hub"}
T0 = datetime(2026, 10, 18, 22, 0, tzinfo=timezone.utc)
TOOLS = Path(__file__).resolve().parent.parent / "tools"


def at(days):
    return (T0 + timedelta(days=days)).isoformat()


def dev(mac, ip, subnet=NET):
    return {"ip": ip, "mac": mac, "subnet": subnet}


def state(devices, when, **over):
    s = {"timestamp": when, "gateway": "192.168.85.1", "scanned_subnets": [NET], "devices": list(devices)}
    s.update(over)
    return s


class TestDeparturesAreRecorded:
    def test_the_saved_baseline_lists_what_its_run_reported_gone(self, mod):
        mod.save_baseline(state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(0)))
        mod.save_baseline(state([dev(GW, "192.168.85.1")], at(7)))
        assert mod.load_baseline()["departed"] == [PLUG]

    def test_a_run_with_no_departures_records_an_empty_list(self, mod):
        mod.save_baseline(state([dev(GW, "192.168.85.1")], at(0)))
        mod.save_baseline(state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(7)))
        assert mod.load_baseline()["departed"] == []

    def test_a_run_that_did_not_sweep_records_none(self, mod):
        mod.save_baseline(state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(0)))
        mod.save_baseline({"timestamp": at(7), "gateway": "192.168.85.1"})
        assert "departed" not in mod.load_baseline()

    def test_departures_respect_the_sweep_coverage(self, mod):
        other = "192.168.87.0/24"
        old = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.87.60", other)], at(0), scanned_subnets=[NET, other])
        new = state([dev(GW, "192.168.85.1")], at(7))
        assert mod.device_departures(old, new) == set(), "not looked for is not gone"

    def test_departures_match_the_gone_line(self, mod):
        old = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60"), dev(HUB, "192.168.85.70")], at(0))
        new = state([dev(GW, "192.168.85.1")], at(7))
        gone = mod.device_departures(old, new, LABELS)
        note = next(n for n in mod.diff_baseline(old, new, LABELS) if "gone since baseline" in n)
        assert gone == {PLUG, HUB} and all(m in note for m in gone)

    def test_it_is_a_rendered_key(self, mod):
        assert "departed" in mod.RENDERED_STATE_KEYS


class TestAReturnTheGoneLineNamedIsAChange:
    def _chain(self, mod):
        r1 = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(0))
        mod.save_baseline(r1)
        mod.save_baseline(state([dev(GW, "192.168.85.1")], at(7)))        # the week the plug left
        return mod.load_baseline()                                          # departed == [PLUG], memory holds it

    def test_the_f14_scenario(self, mod):
        """The retired plug's address joins again a week later, labelled."""
        old = self._chain(mod)
        new = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(14))
        notes = mod.diff_baseline(old, new, LABELS)
        assert len(notes) == 1
        assert notes[0].startswith("Device(s) back after an absence the previous run reported as gone: "
                                   f"{PLUG} [Tuya device A (6d:c6)] (last seen 2026-10-18 22:00 UTC)")
        assert "clone" in notes[0]
        assert not any("NEW device" in n for n in notes)

    def test_it_is_not_also_the_info_line(self, mod):
        old = self._chain(mod)
        new = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(14))
        assert mod.describe_returning_devices(old, new, LABELS) is None

    def test_a_return_from_further_back_is_still_only_info(self, mod):
        # Gone two runs ago: the previous run's gone line did not name it.
        old = self._chain(mod)
        mod.save_baseline(state([dev(GW, "192.168.85.1")], at(14)))        # a quiet week
        old = mod.load_baseline()
        assert old["departed"] == []
        new = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(21))
        assert mod.diff_baseline(old, new, LABELS) == []
        assert PLUG in mod.describe_returning_devices(old, new, LABELS)

    def test_the_digest_carries_it_and_the_verdict_flips(self, mod, capsys, monkeypatch):
        spec = importlib.util.spec_from_file_location("report_digest", TOOLS / "report_digest.py")
        dg = importlib.util.module_from_spec(spec)
        sys.modules["report_digest"] = dg
        spec.loader.exec_module(dg)
        self._chain(mod)
        mod.save_labels(dict(LABELS))
        monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (None, None))
        monkeypatch.setattr(mod, "describe_current_network", lambda *a, **k: "")
        mod.action_compare_baseline(state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(14)))
        out = capsys.readouterr().out
        parsed = dg.parse_report(out, "loveshack-iot")
        assert parsed["verdict"] == "CHANGES DETECTED"
        assert any("back after an absence" in c and PLUG in c for c in parsed["changes"])

    def test_a_baseline_without_the_key_behaves_as_before(self, mod):
        old = state([dev(GW, "192.168.85.1")], at(7),
                    device_memory={PLUG: {"first_seen": at(0), "last_seen": at(0)}})
        new = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(14))
        assert mod.diff_baseline(old, new, LABELS) == []
        assert PLUG in mod.describe_returning_devices(old, new, LABELS)

    def test_a_hostile_departed_list_does_not_raise(self, mod):
        old = state([dev(GW, "192.168.85.1")], at(7), departed=[None, 3, PLUG.upper()],
                    device_memory={PLUG: {"first_seen": at(0), "last_seen": at(0)}})
        new = state([dev(GW, "192.168.85.1"), dev(PLUG, "192.168.85.60")], at(14))
        assert any("back after an absence" in n for n in mod.diff_baseline(old, new))


def _write_baseline(mod, name, state):
    path = Path(mod.BASELINE_DIR) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"format": mod.BASELINE_FORMAT, "state": state}))


class TestStaleLabelsAreListedNotPruned:
    def test_every_network_baseline_is_read(self, mod, tmp_path):
        _write_baseline(mod, "baseline-192-168-85-0-24.json", state([dev(PLUG, "192.168.85.60")], at(0)))
        _write_baseline(mod, "baseline-192-168-87-0-24.json", state([dev(HUB, "192.168.87.70")], at(0)))
        (Path(mod.BASELINE_DIR) / "baseline-bad.json").write_text("{not json")
        (Path(mod.BASELINE_DIR) / "labels.json").write_text("{}")
        states = mod.all_network_baselines()
        assert sorted(d["mac"] for s in states for d in s["devices"]) == sorted([HUB, PLUG])

    def test_a_label_unseen_everywhere_for_the_window_is_listed(self, mod):
        _write_baseline(mod, "baseline-192-168-85-0-24.json",
                        state([dev(GW, "192.168.85.1")], at(40), device_memory={PLUG: {"first_seen": at(0), "last_seen": at(2)}}))
        stale = mod.stale_labels(LABELS, mod.all_network_baselines(), now=T0 + timedelta(days=40))
        assert stale == [(PLUG, "Tuya device A (6d:c6)", at(2))]

    def test_a_label_seen_on_another_network_recently_is_not(self, mod):
        _write_baseline(mod, "baseline-192-168-85-0-24.json",
                        state([dev(GW, "192.168.85.1")], at(40), device_memory={PLUG: {"first_seen": at(0), "last_seen": at(2)}}))
        _write_baseline(mod, "baseline-192-168-87-0-24.json", state([dev(PLUG, "192.168.87.60", "192.168.87.0/24")], at(38)))
        assert mod.stale_labels(LABELS, mod.all_network_baselines(), now=T0 + timedelta(days=40)) == []

    def test_a_label_never_seen_anywhere_is_not_listed(self, mod):
        _write_baseline(mod, "baseline-192-168-85-0-24.json", state([dev(GW, "192.168.85.1")], at(40)))
        assert mod.stale_labels({"de:ad:be:ef:00:01": "typo"}, mod.all_network_baselines(), now=T0 + timedelta(days=40)) == []

    def test_a_labelled_private_address_counts_as_seen(self, mod):
        laa = "02:4b:00:00:00:01"
        _write_baseline(mod, "baseline-192-168-85-0-24.json", state([dev(laa, "192.168.85.34")], at(38)))
        assert mod.stale_labels({laa: "LinkTap"}, mod.all_network_baselines(), now=T0 + timedelta(days=40)) == []

    def test_the_line_is_review_names_the_label_and_the_command(self, mod):
        _write_baseline(mod, "baseline-192-168-85-0-24.json",
                        state([dev(GW, "192.168.85.1")], at(40), device_memory={PLUG: {"first_seen": at(0), "last_seen": at(2)}}))
        line = mod.describe_stale_labels(LABELS, mod.all_network_baselines(), now=T0 + timedelta(days=40))
        assert line.startswith("  [REVIEW] Label(s) on addresses no network has seen for 30 days: ")
        assert f"{PLUG} [Tuya device A (6d:c6)] (last seen 2026-10-20)" in line
        assert "--unlabel" in line and "Nothing is removed by itself" in line

    def test_nothing_stale_is_silent(self, mod):
        _write_baseline(mod, "baseline-192-168-85-0-24.json", state([dev(PLUG, "192.168.85.60")], at(39)))
        assert mod.describe_stale_labels(LABELS, mod.all_network_baselines(), now=T0 + timedelta(days=40)) is None

    def test_nothing_is_ever_removed(self, mod, monkeypatch):
        _write_baseline(mod, "baseline-192-168-85-0-24.json",
                        state([dev(GW, "192.168.85.1")], at(40), device_memory={PLUG: {"first_seen": at(0), "last_seen": at(2)}}))
        mod.save_labels(dict(LABELS))
        monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (None, None))
        monkeypatch.setattr(mod, "describe_current_network", lambda *a, **k: "")
        mod.action_compare_baseline(state([dev(GW, "192.168.85.1")], at(40)))
        assert mod.load_labels() == LABELS

    def test_the_compare_block_prints_it(self, mod, monkeypatch, capsys):
        _write_baseline(mod, "baseline-192-168-85-0-24.json",
                        state([dev(GW, "192.168.85.1")], at(40), device_memory={PLUG: {"first_seen": at(0), "last_seen": at(2)}}))
        mod.save_labels(dict(LABELS))
        monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (None, None))
        monkeypatch.setattr(mod, "describe_current_network", lambda *a, **k: "")
        mod.action_compare_baseline(state([dev(GW, "192.168.85.1")], at(40)))
        assert "[REVIEW] Label(s) on addresses no network has seen" in capsys.readouterr().out


class TestUnlabel:
    def _main(self, mod, monkeypatch, argv):
        monkeypatch.setattr(mod, "action_full_audit", lambda **k: pytest.fail("an audit ran"))
        monkeypatch.setattr(sys, "argv", ["home_net_audit.py"] + argv)
        mod._main()

    def test_it_removes_the_label_and_exits_without_an_audit(self, mod, monkeypatch, capsys):
        mod.save_labels(dict(LABELS))
        self._main(mod, monkeypatch, ["--unlabel", PLUG.upper()])
        assert PLUG not in mod.load_labels() and GW in mod.load_labels()
        assert f"Label removed: {PLUG} [Tuya device A (6d:c6)]" in capsys.readouterr().out

    def test_an_unknown_address_is_said_and_nothing_changes(self, mod, monkeypatch, capsys):
        mod.save_labels(dict(LABELS))
        self._main(mod, monkeypatch, ["--unlabel", "de:ad:be:ef:00:01"])
        assert mod.load_labels() == LABELS
        assert "No label for de:ad:be:ef:00:01" in capsys.readouterr().out
