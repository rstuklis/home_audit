"""Monitor mode — continuous observation, roadmap P0's last piece.

Two of this tool's detections can only see an attack that is still happening
when you look. A rogue Router Advertisement sent and withdrawn between scans
leaves no trace, and so does a brief ARP poisoning window. Against an adversary
who keeps that window short, point-in-time scanning structurally cannot help —
which is why continuous observation is a security requirement here rather than
a convenience.

What runs in the loop is deliberately the cheap half: local command output only,
no port scans, no probes, no speed test. Two things these tests hold it to:

  * an alert must leave the machine. Printing to a terminal on the host under
    suspicion delivers it to the adversary and nowhere else.
  * the first poll must be silent. A monitor that alarms on startup, when it has
    nothing to compare against, trains the reader to dismiss it.
"""

import pytest

from conftest import make_run

GW = "192.168.1.1"
ROUTER_MAC = "3c:22:fb:11:22:33"
ATTACKER_MAC = "0e:8b:02:1a:2b:3c"


def snap(**over):
    base = {
        "gateway": GW,
        "gateway_mac": ROUTER_MAC,
        "ipv6_routers": ["fe80::1%en0"],
        "dns": ["192.168.1.1"],
        "neighbours": [GW, "192.168.1.42"],
    }
    base.update(over)
    return base


class TestChangesThatMeanSomeoneIsInThePath:
    def test_a_changed_gateway_mac_is_high(self, mod):
        """The signature of ARP poisoning: same IP, different hardware."""
        events = mod.diff_snapshots(snap(), snap(gateway_mac=ATTACKER_MAC))
        assert [e["kind"] for e in events] == ["gateway_mac_changed"]
        assert events[0]["severity"] == "HIGH"
        assert "ARP poisoning" in events[0]["detail"]

    def test_a_new_ipv6_router_is_high(self, mod):
        events = mod.diff_snapshots(
            snap(), snap(ipv6_routers=["fe80::1%en0", "fe80::bad%en0"]))
        assert events[0]["kind"] == "ipv6_router_appeared"
        assert events[0]["severity"] == "HIGH"
        assert "fe80::bad%en0" in events[0]["detail"]

    def test_changed_dns_is_high(self, mod):
        events = mod.diff_snapshots(snap(), snap(dns=["9.9.9.9"]))
        assert events[0]["kind"] == "dns_changed"
        assert events[0]["severity"] == "HIGH"

    def test_a_changed_gateway_address_is_high(self, mod):
        events = mod.diff_snapshots(snap(), snap(gateway="192.168.1.99"))
        assert events[0]["kind"] == "gateway_changed"

    def test_a_new_neighbour_is_review_not_high(self, mod):
        # Devices join a home network constantly. Treating that as HIGH would
        # bury the two events above under everyday noise.
        events = mod.diff_snapshots(
            snap(), snap(neighbours=[GW, "192.168.1.42", "192.168.1.77"]))
        assert events[0]["kind"] == "neighbour_appeared"
        assert events[0]["severity"] == "REVIEW"

    def test_simultaneous_changes_each_raise_their_own_event(self, mod):
        events = mod.diff_snapshots(
            snap(), snap(gateway_mac=ATTACKER_MAC, dns=["9.9.9.9"]))
        assert {e["kind"] for e in events} == {"gateway_mac_changed", "dns_changed"}


class TestQuietOnAHealthyNetwork:
    def test_an_unchanged_network_raises_nothing(self, mod):
        assert mod.diff_snapshots(snap(), snap()) == []

    def test_the_first_poll_is_silent(self, mod):
        # Nothing to compare against yet. Alarming here would make the monitor
        # cry wolf every time it restarts.
        assert mod.diff_snapshots(None, snap()) == []

    def test_reordered_lists_are_not_changes(self, mod):
        assert mod.diff_snapshots(
            snap(), snap(dns=["192.168.1.1"], neighbours=["192.168.1.42", GW])) == []

    def test_a_device_leaving_is_not_an_alert(self, mod):
        # Phones sleep. Only arrivals are interesting for this loop.
        assert mod.diff_snapshots(snap(), snap(neighbours=[GW])) == []

    def test_an_unresolvable_gateway_mac_does_not_alarm(self, mod):
        # A poll that simply failed to read the ARP entry must not look like a
        # MAC change, or every transient read failure becomes a false HIGH.
        assert mod.diff_snapshots(snap(), snap(gateway_mac=None)) == []
        assert mod.diff_snapshots(snap(gateway_mac=None), snap()) == []

    def test_a_router_that_stops_advertising_is_not_an_alert(self, mod):
        assert mod.diff_snapshots(snap(), snap(ipv6_routers=[])) == []


class TestSnapshotIsCheap:
    def test_the_snapshot_runs_only_local_readers(self, mod, monkeypatch):
        """No port scans, no probes — this loop runs every minute on a Pi."""
        fake = make_run({
            "route -n get default": "   gateway: 192.168.1.1\n",
            "arp -a": f"? ({GW}) at {ROUTER_MAC} on en0 ifscope [ethernet]\n",
            "ndp -r": "fe80::1%en0 if=en0, flags=O\n",
            "scutil --dns": "  nameserver[0] : 192.168.1.1\n",
        })
        monkeypatch.setattr(mod, "run", fake)
        result = mod.monitor_snapshot()

        assert result["gateway"] == GW
        assert result["gateway_mac"] == ROUTER_MAC
        assert result["ipv6_routers"] == ["fe80::1%en0"]
        # Nothing expensive was invoked.
        for cmd in fake.calls:
            assert "ping" not in cmd and "lsof" not in cmd

    def test_a_missing_gateway_does_not_raise(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({}))
        assert mod.monitor_snapshot()["gateway_mac"] is None


class TestAlertsLeaveTheMachine:
    def test_an_alert_is_written_to_the_configured_destination(self, mod, tmp_path):
        target = tmp_path / "alerts.jsonl"
        result = mod.send_alert({"severity": "HIGH", "kind": "dns_changed",
                                 "detail": "x"}, destination=str(target))
        assert result["published"] is True
        assert "dns_changed" in target.read_text(encoding="utf-8")

    def test_an_alert_carries_a_timestamp(self, mod, tmp_path):
        target = tmp_path / "a.jsonl"
        mod.send_alert({"kind": "k", "detail": "d"}, destination=str(target))
        assert '"at"' in target.read_text(encoding="utf-8")

    def test_no_destination_is_reported_rather_than_silently_dropped(self, mod, monkeypatch):
        monkeypatch.delenv(mod.ALERT_ENV, raising=False)
        result = mod.send_alert({"kind": "k", "detail": "d"})
        assert result["published"] is False
        assert "stayed on this machine" in result["detail"]

    def test_a_failing_destination_is_reported_not_raised(self, mod, tmp_path):
        blocked = tmp_path / "afile"
        blocked.write_text("x", encoding="utf-8")
        result = mod.send_alert({"kind": "k", "detail": "d"},
                                destination=str(blocked / "nested" / "a.jsonl"))
        assert result["published"] is False

    def test_the_environment_supplies_the_destination(self, mod, monkeypatch, tmp_path):
        target = tmp_path / "env.jsonl"
        monkeypatch.setenv(mod.ALERT_ENV, str(target))
        assert mod.send_alert({"kind": "k", "detail": "d"})["published"] is True

    def test_the_alert_sink_is_separate_from_the_receipt_sink(self, mod, monkeypatch, tmp_path):
        # Routine bookkeeping and things a person must see usually belong on
        # different channels.
        monkeypatch.setenv(mod.SINK_ENV, str(tmp_path / "receipts"))
        monkeypatch.setenv(mod.ALERT_ENV, str(tmp_path / "alerts.jsonl"))
        assert mod.resolve_alert_sink() != mod.resolve_sink()


class TestObservationSurvivesARestart:
    """The monitor's reference point must outlive the process holding it.

    Keeping it in memory only meant stopping and starting the monitor
    re-baselined it into whatever world it woke up in. An attacker who could
    stop the process — or a reboot, a crash, an OOM kill, a RestartSec window —
    got the change adopted as normal and never alerted on, then or ever. That is
    a cheaper attack than defeating any check in the loop, because every check
    in the loop is worth nothing when the process is not running.
    """

    def _clock(self, *times):
        """A clock() returning each time in turn, then holding the last."""
        seq, state = list(times), {"i": 0}

        def now():
            value = seq[min(state["i"], len(seq) - 1)]
            state["i"] += 1
            return value
        return now

    def _at(self, hours):
        from datetime import datetime, timezone
        return datetime(2026, 8, 16, hours, 0, tzinfo=timezone.utc)

    def _watch(self, mod, monkeypatch, snapshot, **kw):
        monkeypatch.setattr(mod, "monitor_snapshot", lambda: snapshot)
        return mod.run_monitor(interval=0, iterations=1, sleeper=lambda _: None,
                               printer=lambda *a: None, **kw)

    def test_a_change_across_a_restart_is_still_caught(self, mod, monkeypatch):
        """The core regression: the poisoning must not be absorbed silently."""
        self._watch(mod, monkeypatch, snap())
        events = self._watch(mod, monkeypatch, snap(gateway_mac=ATTACKER_MAC,
                                                    dns=["66.66.66.66"]))
        assert {e["kind"] for e in events} == {"gateway_mac_changed", "dns_changed"}

    def test_the_very_first_start_reports_no_gap(self, mod, monkeypatch):
        # Nothing has ever watched here. That is a genuine start, not a lapse,
        # and calling it one would make the monitor cry wolf on day one.
        events = self._watch(mod, monkeypatch, snap())
        assert events == []

    def test_a_prompt_restart_is_not_reported_as_a_gap(self, mod, monkeypatch):
        # A service restart inside the polling allowance is not a blind window.
        self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(1)))
        events = self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(1)))
        assert [e for e in events if e["kind"] == "observation_gap"] == []

    def test_resuming_after_a_real_gap_says_so(self, mod, monkeypatch):
        self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(1)))
        events = self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(5)))
        gap = [e for e in events if e["kind"] == "observation_gap"]
        assert len(gap) == 1
        assert "4h" in gap[0]["detail"]

    def test_a_gap_is_raised_even_when_nothing_changed(self, mod, monkeypatch):
        """The whole point: silence is only reassuring if someone was watching.

        An unobserved window is worth reporting precisely when it looks clean,
        because a change made and undone inside it is indistinguishable from
        nothing having happened.
        """
        self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(1)))
        events = self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(9)))
        assert [e["kind"] for e in events] == ["observation_gap"]

    def test_a_change_seen_across_a_gap_is_marked_as_unwitnessed(self, mod, monkeypatch):
        self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(1)))
        events = self._watch(mod, monkeypatch, snap(gateway_mac=ATTACKER_MAC),
                             clock=self._clock(self._at(6)))
        change = [e for e in events if e["kind"] == "gateway_mac_changed"][0]
        assert change["across_gap"] is True
        assert "when it happened is unknown" in change["detail"]

    def test_the_gap_alert_leaves_the_machine(self, mod, monkeypatch, tmp_path):
        target = tmp_path / "alerts.jsonl"
        self._watch(mod, monkeypatch, snap(), clock=self._clock(self._at(1)))
        self._watch(mod, monkeypatch, snap(), alert_to=str(target),
                    clock=self._clock(self._at(7)))
        assert "observation_gap" in target.read_text(encoding="utf-8")


class TestHeartbeatsRecordThatSomeoneWasWatching:
    """Off-host proof of liveness — the receipt chain's idea, one layer up.

    A missing baseline could not be told from a genuine first run, so receipts
    recorded what had happened. A missing observation cannot be told from a quiet
    network, so heartbeats record when observation was happening. Neither
    prevents anything; both make the absence legible afterwards.
    """

    def test_the_loop_publishes_liveness_to_the_sink(self, mod, monkeypatch, tmp_path):
        sink = tmp_path / "receipts"
        sink.mkdir()
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        monkeypatch.setattr(mod, "monitor_snapshot", lambda: snap())
        mod.run_monitor(interval=0, iterations=1, sleeper=lambda _: None,
                        printer=lambda *a: None)
        assert mod.read_heartbeats(str(sink))

    def test_a_heartbeat_carries_no_snapshot_of_the_network(self, mod, tmp_path):
        target = tmp_path / "hb.jsonl"
        mod.monitor_heartbeat(destination=str(target))
        blob = target.read_text(encoding="utf-8")
        for secret in (GW, ROUTER_MAC, "192.168.1.42"):
            assert secret not in blob, f"{secret} was published off-host"

    def test_a_missing_sink_is_reported_not_silently_skipped(self, mod, monkeypatch):
        monkeypatch.delenv(mod.SINK_ENV, raising=False)
        result = mod.monitor_heartbeat()
        assert result["published"] is False
        assert "look the same" in result["detail"]

    def test_a_hole_in_the_heartbeats_is_found(self, mod):
        beats = [{"kind": "heartbeat", "at": "2026-08-16T01:00:00+00:00"},
                 {"kind": "heartbeat", "at": "2026-08-16T05:00:00+00:00"}]
        gaps = mod.observation_gaps(beats, interval=900,
                                    now=mod._parse_stamp("2026-08-16T05:05:00+00:00"))
        assert len(gaps) == 1 and gaps[0]["seconds"] == 4 * 3600

    def test_continuous_heartbeats_report_nothing(self, mod):
        beats = [{"kind": "heartbeat", "at": f"2026-08-16T01:{m:02d}:00+00:00"}
                 for m in (0, 15, 30)]
        gaps = mod.observation_gaps(beats, interval=900,
                                    now=mod._parse_stamp("2026-08-16T01:35:00+00:00"))
        assert gaps == []
        assert mod.describe_observation_gaps(gaps) is None

    def test_a_monitor_that_stopped_and_never_came_back_is_high(self, mod):
        """The gap an attacker is inside right now, not one they have left."""
        beats = [{"kind": "heartbeat", "at": "2026-08-16T01:00:00+00:00"}]
        gaps = mod.observation_gaps(beats, interval=900,
                                    now=mod._parse_stamp("2026-08-16T09:00:00+00:00"))
        assert len(gaps) == 1 and gaps[0]["end"] is None
        line = mod.describe_observation_gaps(gaps)
        assert "HIGH" in line and "not running now" in line

    def test_a_closed_gap_is_review_rather_than_high(self, mod):
        gaps = [{"start": "a", "end": "b", "seconds": 7200}]
        assert "REVIEW" in mod.describe_observation_gaps(gaps)

    def test_a_malformed_heartbeat_line_does_not_crash_the_reader(self, mod):
        beats = [{"kind": "heartbeat", "at": "not-a-timestamp"},
                 {"kind": "heartbeat", "at": "2026-08-16T01:00:00+00:00"}]
        assert mod.observation_gaps(
            beats, now=mod._parse_stamp("2026-08-16T01:05:00+00:00")) == []

    def test_heartbeats_are_not_counted_as_baseline_receipts(self, mod, tmp_path):
        """A log of pure liveness says nothing about whether a baseline ran."""
        sink = tmp_path / "r.jsonl"
        mod.monitor_heartbeat(destination=str(sink))
        report = mod.compare_with_receipts({"seq": 1, "seal": "x"},
                                           mod.read_receipts(str(sink)))
        assert report["status"] == "no_receipts"


class TestMonitorLoop:
    def _readers(self, mod, monkeypatch, macs):
        """Return a run() whose ARP answer changes on each successive poll."""
        seq = list(macs)
        state = {"i": 0}

        def fake_run(cmd, timeout=10):
            joined = " ".join(cmd)
            if "arp -a" in joined:
                mac = seq[min(state["i"], len(seq) - 1)]
                return f"? ({GW}) at {mac} on en0 ifscope [ethernet]\n"
            if "route -n get default" in joined:
                return f"   gateway: {GW}\n"
            return ""

        monkeypatch.setattr(mod, "run", fake_run)
        return state

    def test_the_loop_alerts_when_the_gateway_mac_changes(self, mod, monkeypatch, tmp_path):
        state = self._readers(mod, monkeypatch, [ROUTER_MAC, ATTACKER_MAC])
        target = tmp_path / "alerts.jsonl"

        def tick(_):
            state["i"] += 1

        events = mod.run_monitor(interval=0, iterations=2, alert_to=str(target),
                                 sleeper=tick, printer=lambda *a: None)
        assert [e["kind"] for e in events] == ["gateway_mac_changed"]
        assert "ARP poisoning" in target.read_text(encoding="utf-8")

    def test_a_stable_network_produces_no_events(self, mod, monkeypatch):
        self._readers(mod, monkeypatch, [ROUTER_MAC])
        assert mod.run_monitor(interval=0, iterations=3, sleeper=lambda _: None,
                               printer=lambda *a: None) == []

    def test_iterations_bound_the_loop(self, mod, monkeypatch):
        state = self._readers(mod, monkeypatch, [ROUTER_MAC])
        polls = {"n": 0}
        original = mod.monitor_snapshot

        def counting():
            polls["n"] += 1
            return original()

        monkeypatch.setattr(mod, "monitor_snapshot", counting)
        mod.run_monitor(interval=0, iterations=4, sleeper=lambda _: None,
                        printer=lambda *a: None)
        assert polls["n"] == 4

    def test_it_does_not_sleep_after_the_final_poll(self, mod, monkeypatch):
        self._readers(mod, monkeypatch, [ROUTER_MAC])
        sleeps = []
        mod.run_monitor(interval=30, iterations=3, sleeper=sleeps.append,
                        printer=lambda *a: None)
        assert sleeps == [30, 30]

    def test_a_missing_alert_sink_is_called_out_at_startup(self, mod, monkeypatch):
        monkeypatch.delenv(mod.ALERT_ENV, raising=False)
        self._readers(mod, monkeypatch, [ROUTER_MAC])
        lines = []
        mod.run_monitor(interval=0, iterations=1, sleeper=lambda _: None,
                        printer=lambda *a: lines.append(" ".join(str(x) for x in a)))
        assert any("leave this machine" in l for l in lines)

    def test_an_undelivered_alert_says_so(self, mod, monkeypatch):
        state = self._readers(mod, monkeypatch, [ROUTER_MAC, ATTACKER_MAC])
        monkeypatch.delenv(mod.ALERT_ENV, raising=False)
        lines = []

        def tick(_):
            state["i"] += 1

        mod.run_monitor(interval=0, iterations=2, sleeper=tick,
                        printer=lambda *a: lines.append(" ".join(str(x) for x in a)))
        assert any("not delivered" in l for l in lines)

    def test_ctrl_c_stops_cleanly_and_returns_what_it_saw(self, mod, monkeypatch):
        state = self._readers(mod, monkeypatch, [ROUTER_MAC, ATTACKER_MAC])

        def interrupt_after_change(_):
            state["i"] += 1
            if state["i"] > 1:
                raise KeyboardInterrupt

        events = mod.run_monitor(interval=0, iterations=None,
                                 sleeper=interrupt_after_change,
                                 printer=lambda *a: None)
        assert [e["kind"] for e in events] == ["gateway_mac_changed"]
