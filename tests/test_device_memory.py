"""Remembering devices for longer than one run.

The baseline is the last run, so "new" meant "not there last time". A camera hub
that missed one sweep read as a NEW device an hour later, most runs, on a house
full of sleepy gadgets — and a NEW line that is usually the owner's own hardware
is one nobody reads by the week a stranger's appears in it. Each network's
baseline now remembers what it has seen for 30 days.

Pinned here: a return is not a change but is always said; a stranger is still
NEW; departures are untouched; private addresses are never remembered; and the
memory is read as hostile JSON, because it is a file on disk.
"""

from datetime import datetime, timedelta, timezone

import pytest

NET = "192.168.86.0/24"
HUB = "a4:11:62:2a:b9:0a"
TV = "8c:79:f5:8c:48:a7"
STRANGER = "00:1b:63:84:45:e6"          # globally administered, so compared by name
PRIVATE = "02:4b:43:1d:eb:b5"      # locally administered: a rotating address

T0 = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)


def at(days=0, hours=0):
    return (T0 + timedelta(days=days, hours=hours)).isoformat()


def run(when, macs, memory=None):
    state = {"timestamp": when, "scanned_subnets": [NET],
             "devices": [{"ip": f"192.168.86.{i + 10}", "mac": m, "subnet": NET} for i, m in enumerate(macs)]}
    if memory is not None:
        state["device_memory"] = memory
    return state


def saved(mod, previous, state):
    """What save_baseline would store: the state plus its updated memory."""
    out = dict(state)
    out["device_memory"] = mod.update_device_memory(previous, state)
    return out


class TestTheFlap:
    """The case this exists for: present, missing one run, present again."""

    def chain(self, mod, gap_days=0, gap_hours=1):
        r1 = saved(mod, {}, run(at(0), [HUB, TV]))
        r2 = saved(mod, r1, run(at(0, 1), [TV]))                       # hub misses the sweep
        r3 = run(at(gap_days, 1 + gap_hours), [HUB, TV])               # hub answers again
        return r1, r2, r3

    def test_the_run_it_goes_missing_still_says_gone(self, mod):
        r1, r2, _ = self.chain(mod)
        assert any("gone since baseline" in n and HUB in n for n in mod.diff_baseline(r1, r2))

    def test_the_run_it_comes_back_is_not_a_new_device(self, mod):
        _, r2, r3 = self.chain(mod)
        assert mod.diff_baseline(r2, r3) == []

    def test_but_the_return_is_always_said_by_name(self, mod):
        _, r2, r3 = self.chain(mod)
        text = mod.describe_returning_devices(r2, r3, {HUB: "Arlo SmartHub (VMB5000)"})
        assert HUB in text and "Arlo SmartHub (VMB5000)" in text and "not counted as new" in text
        assert "2026-09-01 09:00" in text

    def test_a_stranger_arriving_beside_it_is_still_new(self, mod):
        _, r2, r3 = self.chain(mod)
        r3["devices"].append({"ip": "192.168.86.99", "mac": STRANGER, "subnet": NET})
        notes = mod.diff_baseline(r2, r3)
        assert len(notes) == 1 and STRANGER in notes[0] and HUB not in notes[0]

    def test_after_the_window_it_is_new_again(self, mod):
        r1 = saved(mod, {}, run(at(0), [HUB, TV]))
        r2 = saved(mod, r1, run(at(1), [TV]))
        r3 = run(at(mod.DEVICE_MEMORY_DAYS + 2), [HUB, TV])
        assert any("NEW device" in n and HUB in n for n in mod.diff_baseline(r2, r3))
        assert mod.describe_returning_devices(r2, r3) is None

    def test_it_is_remembered_across_many_runs_not_just_two(self, mod):
        state = saved(mod, {}, run(at(0), [HUB, TV]))
        for day in range(1, 20):
            state = saved(mod, state, run(at(day), [TV]))
        assert mod.diff_baseline(state, run(at(20), [HUB, TV])) == []


class TestUpdate:
    def test_first_and_last_seen_are_tracked(self, mod):
        m1 = mod.update_device_memory({}, run(at(0), [HUB]))
        m2 = mod.update_device_memory(run(at(0), [HUB], m1), run(at(3), [HUB]))
        assert m2[HUB] == {"first_seen": at(0), "last_seen": at(3)}

    def test_an_absent_device_keeps_its_last_sighting(self, mod):
        m1 = mod.update_device_memory({}, run(at(0), [HUB, TV]))
        m2 = mod.update_device_memory(run(at(0), [HUB, TV], m1), run(at(3), [TV]))
        assert m2[HUB]["last_seen"] == at(0) and m2[TV]["last_seen"] == at(3)

    def test_entries_expire_after_the_window(self, mod):
        m1 = mod.update_device_memory({}, run(at(0), [HUB, TV]))
        m2 = mod.update_device_memory(run(at(0), [TV], m1), run(at(mod.DEVICE_MEMORY_DAYS + 1), [TV]))
        assert HUB not in m2 and TV in m2

    def test_rotating_private_addresses_are_never_remembered(self, mod):
        assert PRIVATE not in mod.update_device_memory({}, run(at(0), [HUB, PRIVATE]))

    def test_a_run_that_did_not_sweep_changes_nothing_not_even_expiry(self, mod):
        m1 = mod.update_device_memory({}, run(at(0), [HUB]))
        unswept = {"timestamp": at(mod.DEVICE_MEMORY_DAYS + 5)}
        assert mod.update_device_memory(run(at(0), [HUB], m1), unswept) == m1

    def test_a_baseline_from_before_the_memory_existed_seeds_it(self, mod):
        legacy = run(at(0), [HUB, TV])          # no device_memory key at all
        assert set(mod.remembered_devices(legacy)) == {HUB, TV}

    def test_it_is_capped(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "DEVICE_MEMORY_LIMIT", 3)
        macs = [f"00:11:22:33:44:{i:02x}" for i in range(6)]
        assert len(mod.update_device_memory({}, run(at(0), macs))) == 3


class TestHostileMemory:
    """A baseline is a JSON file on disk. The seal says whether it was edited;
    this code still has to survive reading one that was."""

    @pytest.mark.parametrize("junk", [None, [], "x", 7, {"a4:11:62:2a:b9:0a": "yesterday"},
                                      {7: {"last_seen": at(0)}}, {"not-a-mac": {"last_seen": at(0)}},
                                      {HUB: {"last_seen": "whenever"}}, {HUB: {}}, {HUB: None}])
    def test_malformed_memory_is_ignored_not_fatal(self, mod, junk):
        state = {"timestamp": at(0), "device_memory": junk}
        assert mod.remembered_devices(state) == {}

    def test_uppercase_macs_are_normalised(self, mod):
        state = {"device_memory": {HUB.upper(): {"first_seen": at(0), "last_seen": at(0)}}}
        assert HUB in mod.remembered_devices(state)

    def test_a_private_address_smuggled_into_the_memory_is_dropped(self, mod):
        state = {"device_memory": {PRIVATE: {"first_seen": at(0), "last_seen": at(0)}}}
        assert mod.remembered_devices(state) == {}

    def test_a_memory_entry_cannot_vouch_for_a_device_beyond_the_window(self, mod):
        old = run(at(40), [TV], {STRANGER: {"first_seen": at(0), "last_seen": at(0)}})
        notes = mod.diff_baseline(old, run(at(41), [TV, STRANGER]))
        assert any("NEW device" in n and STRANGER in n for n in notes)


class TestUnmeasuredSides:
    def test_no_return_is_claimed_when_either_side_did_not_sweep(self, mod):
        r1 = saved(mod, {}, run(at(0), [HUB]))
        assert mod.returning_devices(r1, {"timestamp": at(1)}) == {}
        assert mod.returning_devices({"timestamp": at(0)}, run(at(1), [HUB])) == {}

    def test_without_timestamps_the_old_behaviour_is_unchanged(self, mod):
        old = {"devices": [{"mac": TV, "subnet": NET}], "scanned_subnets": [NET]}
        new = {"devices": [{"mac": TV, "subnet": NET}, {"mac": HUB, "subnet": NET}], "scanned_subnets": [NET]}
        assert any("NEW device" in n and HUB in n for n in mod.diff_baseline(old, new))


class TestSaving:
    def test_save_baseline_stores_the_memory_inside_the_sealed_state(self, mod):
        mod.save_baseline(run(at(0), [HUB, TV]))
        assert set(mod.load_baseline()["device_memory"]) == {HUB, TV}
        mod.save_baseline(run(at(1), [TV]))
        memory = mod.load_baseline()["device_memory"]
        assert memory[HUB]["last_seen"] == at(0) and memory[TV]["last_seen"] == at(1)

    def test_a_no_discovery_save_does_not_stamp_carried_devices_as_seen_now(self, mod):
        # carry_forward_unmeasured copies the previous device list into a run
        # that skipped the sweep. Computed after that, every carried device
        # would read as seen today, for ever, by runs that never looked.
        mod.save_baseline(run(at(0), [HUB, TV]))
        mod.save_baseline({"timestamp": at(9), "dns": ["1.1.1.1"]})
        memory = mod.load_baseline()["device_memory"]
        assert memory[HUB]["last_seen"] == at(0) and memory[TV]["last_seen"] == at(0)

    def test_a_state_with_nothing_about_devices_gains_no_memory_key(self, mod):
        mod.save_baseline({"timestamp": at(0), "dns": ["1.1.1.1"]})
        assert "device_memory" not in mod.load_baseline()

    def test_the_html_report_does_not_flag_the_key_as_unrendered(self, mod):
        assert "device_memory" in mod.RENDERED_STATE_KEYS
