"""Round 4 — the alarms that fired on nothing, and the one that never fired.

The weekly email of 1 November 2026 carried two HIGHs, both false, and the
monitor had sent 449 "new device" alerts in a week about the household's own
devices. Each was a design choice this file now pins the other way:

  * An IPv6 router was keyed by its link-local address. The Play Room Apple TV
    is a HomeKit/Thread border router and takes a new link-local address on
    every reboot, so it was a HIGH "rogue router" three times in three months.
    Routers are now known by MAC: the same MAC at a new address is the same
    router, said at INFO. A new MAC is HIGH when this machine has taken it as
    a default route or nobody has named it, and REVIEW with the name when it
    is a labelled device advertising without being a default route.
  * The heartbeat log cannot know which network the one monitor runs on. The
    Mac sat on loveshack-iot for four days, heartbeating under that chain; when
    it went home the chain fell silent and every audit of that network printed
    "the monitor is not running now" at HIGH, for ever. --unmonitored says the
    network has no monitor of its own, and the line becomes information.
  * The monitor compared bare address lists and forgot a device the moment it
    left the ARP cache. It now remembers devices for 30 days by MAC, names a
    newcomer, and raises HIGH when an address changes hardware between two
    polls — ARP spoofing of a host, which nothing watched before.
  * A camera hub leaving got the same one-line "gone" as a speaker. A device
    marked --critical is its own change line, HIGH on every run while it is
    remembered, and a monitor alert after ten silent polls.
"""

import json
import sys
from datetime import datetime, timedelta, timezone

import pytest

from conftest import load_fixture, make_run

GW = "192.168.87.1"
GW_MAC = "38:8b:59:e0:f1:70"
GW_V6 = "fe80::1%en0"
HUB_MAC = "c4:f7:c1:10:53:b8"                 # the Apple TV, a Thread border router
HUB_OLD = "fe80::8d4:9925:81a:2e79%en0"
HUB_NEW = "fe80::87e:f5b1:f821:c252%en0"
ROGUE = "fe80::c8b:2ff:fe1a:2b3c%en0"
ROGUE_MAC = "0e:8b:02:1a:2b:3c"
PRINTER = "192.168.87.35"
PRINTER_MAC = "34:64:a9:cc:57:2e"
HUB_IP = "192.168.86.40"
ARLO_MAC = "a4:11:62:2a:b9:0a"
LABELS = {HUB_MAC: "Apple TV - Play Room", PRINTER_MAC: "HP Printer",
          ARLO_MAC: "Arlo SmartHub (VMB5000)"}

NDP_R_HUB = f"{HUB_NEW} if=en0, flags=, pref=medium, expire=1h59m50s\n"
NDP_R_HUB_INSTALLED = f"{HUB_NEW} if=en0, flags=I, pref=medium, expire=1h59m50s\n"
NDP_R_GW_AND_HUB = f"{GW_V6} if=en0, flags=O, pref=medium, expire=29m30s\n" + NDP_R_HUB
NDP_R_GW_AND_ROGUE = (f"{GW_V6} if=en0, flags=O, pref=medium, expire=29m30s\n"
                      f"{ROGUE} if=en0, flags=, pref=high, expire=1m48s\n")
NDP_A = ("Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n"
         f"{GW_V6:<40}{GW_MAC}  en0   23h59m58s R  R\n"
         f"{HUB_NEW:<40}{HUB_MAC}  en0   21h36m38s S  R\n"
         f"{ROGUE:<40}{ROGUE_MAC}  en0   expired   R  R\n")
NDP_P = (f"fdca:7af7:13bd:4743::/64 if=en0\n"
         "flags=ALO vltime=1800, pltime=1800, expire=29m50s, ref=1\n"
         "  advertised by\n"
         f"    {HUB_NEW} (reachable)\n"
         "fe80::%en0/64 if=en0\n"
         "flags=AILSO vltime=infinity, pltime=infinity, expire=Never, ref=0\n"
         "  No advertising router\n")


def at(hours=0, days=0):
    return datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc) + timedelta(hours=hours, days=days)


def readers(routers_out, neighbours_out=NDP_A, prefixes_out=""):
    return make_run({"ndp -rn": routers_out, "ndp -an": neighbours_out, "ndp -pn": prefixes_out})


@pytest.fixture(autouse=True)
def _quiet_startup(mod, monkeypatch):
    """The two things the loop and the snapshot do that these tests are not about
    (covered by test_monitor); both are forbidden by the sandbox, correctly."""
    monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (None, None))
    monkeypatch.setattr(mod, "ping", lambda ip: None)


def snap(**over):
    base = {
        "gateway": GW, "gateway_mac": GW_MAC,
        "ipv6_routers": [GW_V6], "ipv6_router_macs": {GW_V6: GW_MAC},
        "dns": [GW],
        "neighbours": [GW, PRINTER], "neighbour_macs": {GW: GW_MAC, PRINTER: PRINTER_MAC},
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# 1. Routers are known by MAC
# ---------------------------------------------------------------------------

class TestRoutersAreKnownByMac:
    def test_the_installed_flag_is_read_from_ndp(self, mod):
        assert mod.parse_ndp_router_entries(NDP_R_HUB) == [{"address": HUB_NEW, "installed": False}]
        assert mod.parse_ndp_router_entries(NDP_R_HUB_INSTALLED)[0]["installed"] is True
        # The fixture's flags=O is the advertisement's other-config flag, not I.
        assert mod.parse_ndp_router_entries(load_fixture("ndp_r.out"))[0]["installed"] is False
        assert mod.parse_ndp_routers(NDP_R_GW_AND_HUB) == [GW_V6, HUB_NEW]

    def test_a_known_router_at_a_new_address_is_the_same_router(self, mod, monkeypatch):
        """The Apple TV rebooted. That is all that happened."""
        monkeypatch.setattr(mod, "run", readers(NDP_R_HUB))
        result = mod.check_ipv6_routers(
            known=[HUB_OLD], known_details={HUB_OLD: {"mac": HUB_MAC, "installed": False}},
            labels=LABELS)
        assert result["risk"] == "INFO"
        assert result["unexpected"] == []
        assert result["renumbered"] == [{"address": HUB_NEW, "mac": HUB_MAC, "was": HUB_OLD}]
        assert "Apple TV - Play Room" in result["note"] and "Not a new router" in result["note"]
        assert "rogue" not in result["note"].lower()

    def test_a_labelled_device_advertising_without_a_default_route_is_review(self, mod, monkeypatch):
        """A hub behaving like a hub: named, not alarmed, not waved through."""
        monkeypatch.setattr(mod, "run", readers(NDP_R_GW_AND_HUB))
        result = mod.check_ipv6_routers(
            known=[GW_V6], known_details={GW_V6: {"mac": GW_MAC, "installed": True}},
            labels=LABELS)
        assert result["risk"] == "REVIEW"
        assert result["unexpected"] == [HUB_NEW]
        assert "Apple TV - Play Room" in result["note"]
        assert "not taken it as a default route" in result["note"]

    def test_a_labelled_device_that_is_the_default_route_is_high(self, mod, monkeypatch):
        """The label buys nothing once the traffic is going through it."""
        monkeypatch.setattr(mod, "run", readers(
            f"{GW_V6} if=en0, flags=O, pref=medium, expire=29m30s\n" + NDP_R_HUB_INSTALLED))
        result = mod.check_ipv6_routers(
            known=[GW_V6], known_details={GW_V6: {"mac": GW_MAC}}, labels=LABELS)
        assert result["risk"] == "HIGH"
        assert "HAS installed" in result["note"] and HUB_NEW in result["note"]

    def test_a_new_mac_nobody_named_is_high(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", readers(NDP_R_GW_AND_ROGUE))
        result = mod.check_ipv6_routers(
            known=[GW_V6], known_details={GW_V6: {"mac": GW_MAC}}, labels=LABELS)
        assert result["risk"] == "HIGH"
        assert result["unexpected"] == [ROGUE]
        assert "rogue" in result["note"].lower()

    def test_without_a_mac_the_address_decides_as_it_always_did(self, mod, monkeypatch):
        # No neighbour table at all: a new address cannot be matched to anything.
        monkeypatch.setattr(mod, "run", readers(NDP_R_HUB, neighbours_out=""))
        result = mod.check_ipv6_routers(
            known=[HUB_OLD], known_details={HUB_OLD: {"mac": HUB_MAC}}, labels=LABELS)
        assert result["risk"] == "HIGH" and result["unexpected"] == [HUB_NEW]

    def test_the_check_records_what_each_router_hands_out(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", readers(NDP_R_HUB, prefixes_out=NDP_P))
        details = mod.check_ipv6_routers(known=[HUB_NEW])["details"]
        assert details[HUB_NEW] == {"mac": HUB_MAC, "installed": False,
                                    "prefixes": ["fdca:7af7:13bd:4743::/64"]}

    def test_prefixes_are_read_per_router_and_link_local_is_nobodys(self, mod):
        assert mod.parse_ndp_prefixes(NDP_P) == {HUB_NEW: ["fdca:7af7:13bd:4743::/64"]}
        assert mod.parse_ndp_prefixes("") == {}

    def test_the_section_names_the_device_behind_the_address(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "run", readers(NDP_R_HUB))
        result = mod.action_ipv6_routers(
            known=[HUB_OLD], known_details={HUB_OLD: {"mac": HUB_MAC}}, labels=LABELS, compact=True)
        out = capsys.readouterr().out
        assert "[Apple TV - Play Room]" in out
        assert "[INFO  ]" in out and "HIGH" not in out
        assert result["details"][HUB_NEW]["mac"] == HUB_MAC


class TestTheBaselineDiffAgrees:
    def _old(self, **details):
        det = details or {HUB_OLD: {"mac": HUB_MAC, "installed": False,
                                    "prefixes": ["fdca:7af7:13bd:4743::/64"]}}
        return {"ipv6_routers": list(det), "ipv6_router_details": det}

    def _new(self, **details):
        det = details or {HUB_NEW: {"mac": HUB_MAC, "installed": False,
                                    "prefixes": ["fdca:7af7:13bd:4743::/64"]}}
        return {"ipv6_routers": list(det), "ipv6_router_details": det}

    def test_a_renumbered_router_is_not_a_change(self, mod):
        assert mod.diff_baseline(self._old(), self._new(), LABELS) == []

    def test_but_it_is_said_by_name_at_info(self, mod):
        line = mod.describe_ipv6_renumbering(self._old(), self._new(), LABELS)
        assert line.startswith("  [INFO  ] IPv6 router renumbered")
        assert "Apple TV - Play Room" in line and HUB_NEW in line and HUB_OLD in line
        assert mod.describe_ipv6_renumbering(self._old(), self._old(), LABELS) is None

    def test_a_new_mac_is_still_a_change(self, mod):
        new = self._new(**{HUB_OLD: {"mac": HUB_MAC}, ROGUE: {"mac": ROGUE_MAC}})
        notes = mod.diff_baseline(self._old(), new, LABELS)
        assert len(notes) == 1 and "NEW IPv6 router" in notes[0] and ROGUE in notes[0]

    def test_a_known_router_becoming_the_default_route_is_a_change(self, mod):
        new = self._new(**{HUB_NEW: {"mac": HUB_MAC, "installed": True,
                                     "prefixes": ["fdca:7af7:13bd:4743::/64"]}})
        notes = mod.diff_baseline(self._old(), new, LABELS)
        assert len(notes) == 1
        assert "default route" in notes[0] and "Apple TV - Play Room" in notes[0]
        assert "NEW IPv6 router" not in notes[0]

    def test_a_known_router_with_a_new_prefix_is_a_change(self, mod):
        new = self._new(**{HUB_NEW: {"mac": HUB_MAC, "installed": False,
                                     "prefixes": ["fdca:7af7:13bd:4743::/64", "fd00:dead::/64"]}})
        notes = mod.diff_baseline(self._old(), new, LABELS)
        assert len(notes) == 1 and "fd00:dead::/64" in notes[0] and "prefix" in notes[0]

    def test_a_baseline_without_details_compares_by_address(self, mod):
        # Saved before MACs were kept: nothing to match the new address against.
        notes = mod.diff_baseline({"ipv6_routers": [HUB_OLD]}, self._new(), LABELS)
        assert any("NEW IPv6 router" in n for n in notes)
        assert any("no longer advertising" in n for n in notes)


class TestTheMonitorAgrees:
    def test_a_renumbered_router_is_info_not_high(self, mod):
        old = snap(ipv6_routers=[GW_V6, HUB_OLD], ipv6_router_macs={GW_V6: GW_MAC, HUB_OLD: HUB_MAC})
        new = snap(ipv6_routers=[GW_V6, HUB_NEW], ipv6_router_macs={GW_V6: GW_MAC, HUB_NEW: HUB_MAC})
        events = mod.diff_snapshots(old, new, labels=LABELS)
        assert [e["kind"] for e in events] == ["ipv6_router_renumbered"]
        assert events[0]["severity"] == "INFO"
        assert "Apple TV - Play Room" in events[0]["detail"] and HUB_OLD in events[0]["detail"]

    def test_a_new_mac_is_still_high(self, mod):
        new = snap(ipv6_routers=[GW_V6, ROGUE], ipv6_router_macs={GW_V6: GW_MAC, ROGUE: ROGUE_MAC})
        events = mod.diff_snapshots(snap(), new)
        assert [e["kind"] for e in events] == ["ipv6_router_appeared"]
        assert events[0]["severity"] == "HIGH"

    def test_a_reference_without_router_macs_is_compared_by_address(self, mod):
        old = snap(ipv6_routers=[HUB_OLD], ipv6_router_macs={})
        new = snap(ipv6_routers=[HUB_NEW], ipv6_router_macs={HUB_NEW: HUB_MAC})
        assert [e["kind"] for e in mod.diff_snapshots(old, new)] == ["ipv6_router_appeared"]

    def test_the_snapshot_keeps_the_mac_behind_each_router_and_neighbour(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({
            "route -n get default": f"   gateway: {GW}\n",
            "arp -an": (f"? ({GW}) at {GW_MAC} on en0 ifscope [ethernet]\n"
                        f"? ({PRINTER}) at {PRINTER_MAC} on en0 ifscope [ethernet]\n"),
            "ndp -rn": NDP_R_HUB, "ndp -an": NDP_A,
            "scutil --dns": f"  nameserver[0] : {GW}\n",
        }))
        result = mod.monitor_snapshot()
        assert result["ipv6_router_macs"] == {HUB_NEW: HUB_MAC}
        assert result["neighbour_macs"] == {GW: GW_MAC, PRINTER: PRINTER_MAC}
        assert result["neighbours"] == [GW, PRINTER]

    def test_a_blank_poll_carries_the_mac_tables_too(self, mod):
        blank = snap(neighbours=[], neighbour_macs={}, ipv6_routers=[], ipv6_router_macs={})
        carried, _ = mod.carry_forward_blank_fields(blank, snap())
        assert carried["neighbour_macs"] == snap()["neighbour_macs"]
        assert carried["ipv6_router_macs"] == snap()["ipv6_router_macs"]


# ---------------------------------------------------------------------------
# 2. A network with no monitor of its own
# ---------------------------------------------------------------------------

class TestAnUnmonitoredNetwork:
    BEAT = "2026-10-24T22:28:41+00:00"

    def _open_gap(self, mod):
        beats = [{"kind": "heartbeat", "at": self.BEAT, "interval": 900}]
        gaps = mod.observation_gaps(beats, now=mod._parse_stamp("2026-11-01T00:00:00+00:00"))
        assert len(gaps) == 1 and gaps[0]["end"] is None
        return gaps

    def test_an_open_gap_is_information_not_a_stopped_monitor(self, mod):
        line = mod.describe_observation_gaps(self._open_gap(mod), monitored=False)
        assert line.startswith("  [INFO  ]")
        assert "HIGH" not in line and "not running now" not in line
        assert "--unmonitored" in line and self.BEAT in line

    def test_a_monitored_network_is_still_high_and_says_how_to_silence_it(self, mod):
        line = mod.describe_observation_gaps(self._open_gap(mod))
        assert "HIGH" in line and "not running now" in line
        assert f"since {self.BEAT}" in line and "--unmonitored" in line

    def test_current_heartbeats_under_the_flag_are_named_as_such(self, mod):
        gaps = [{"start": "2026-10-30T00:00:00+00:00", "end": "2026-10-30T04:00:00+00:00",
                 "seconds": 4 * 3600}]
        line = mod.describe_observation_gaps(gaps, monitored=False)
        assert line.startswith("  [INFO  ]") and "after all" in line

    def test_continuous_observation_stays_silent_either_way(self, mod):
        assert mod.describe_observation_gaps([], monitored=False) is None
        assert mod.describe_observation_gaps([]) is None

    def test_the_flag_reaches_the_comparison(self, mod, monkeypatch, tmp_path, capsys):
        sink = tmp_path / "receipts.jsonl"
        sink.write_text(json.dumps({"kind": "heartbeat", "chain": mod.chain_id(),
                                    "at": self.BEAT, "interval": 900}) + "\n", encoding="utf-8")
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        mod.action_compare_baseline({}, unmonitored=True)
        out = capsys.readouterr().out
        coverage = [l for l in out.splitlines() if "Observation coverage" in l]
        assert len(coverage) == 1 and "[INFO  ]" in coverage[0] and "HIGH" not in coverage[0]

    def test_the_command_line_passes_it_on(self, mod, monkeypatch):
        seen = {}

        def fake_audit(**kwargs):
            seen.update(kwargs)
            return {"gateway": None}
        monkeypatch.setattr(mod, "action_full_audit", fake_audit)
        monkeypatch.setattr(sys, "argv", ["home_net_audit.py", "--no-discovery", "--unmonitored"])
        mod._main()
        assert seen["unmonitored"] is True


# ---------------------------------------------------------------------------
# 3. The monitor remembers devices and watches their hardware addresses
# ---------------------------------------------------------------------------

class TestTheMonitorRemembersDevices:
    MEMORY = {PRINTER_MAC: {"ip": PRINTER, "first_seen": "2026-10-01T00:00:00+00:00",
                            "last_seen": "2026-10-31T00:00:00+00:00"}}

    def test_a_remembered_device_coming_back_is_not_new(self, mod):
        old = snap(neighbours=[GW], neighbour_macs={GW: GW_MAC})
        assert mod.diff_snapshots(old, snap(), memory=self.MEMORY) == []

    def test_a_never_seen_mac_is_review_and_named(self, mod):
        new = snap(neighbours=[GW, PRINTER, "192.168.87.77"],
                   neighbour_macs={GW: GW_MAC, PRINTER: PRINTER_MAC, "192.168.87.77": ARLO_MAC})
        events = mod.diff_snapshots(snap(), new, memory=self.MEMORY, labels=LABELS)
        assert [e["kind"] for e in events] == ["neighbour_appeared"]
        assert events[0]["severity"] == "REVIEW"
        assert "192.168.87.77 (a4:11:62:2a:b9:0a [Arlo SmartHub (VMB5000)])" in events[0]["detail"]

    def test_a_private_address_is_marked_as_one(self, mod):
        new = snap(neighbours=[GW, PRINTER, "192.168.87.21"],
                   neighbour_macs={GW: GW_MAC, PRINTER: PRINTER_MAC, "192.168.87.21": "1a:cd:58:93:00:04"})
        events = mod.diff_snapshots(snap(), new, memory=self.MEMORY)
        assert "(randomized/private MAC)" in events[0]["detail"]

    def test_an_address_that_changed_hardware_is_high(self, mod):
        """ARP spoofing of a host: the one host-level signal nothing watched."""
        new = snap(neighbour_macs={GW: GW_MAC, PRINTER: ROGUE_MAC})
        events = mod.diff_snapshots(snap(), new, memory=self.MEMORY, labels=LABELS)
        assert [e["kind"] for e in events] == ["neighbour_mac_changed"]
        assert events[0]["severity"] == "HIGH"
        assert "HP Printer" in events[0]["detail"] and ROGUE_MAC in events[0]["detail"]

    def test_the_gateway_is_left_to_its_own_check(self, mod):
        new = snap(gateway_mac=ROGUE_MAC, neighbour_macs={GW: ROGUE_MAC, PRINTER: PRINTER_MAC})
        assert [e["kind"] for e in mod.diff_snapshots(snap(), new)] == ["gateway_mac_changed"]

    def test_a_reference_without_macs_compares_by_address_as_before(self, mod):
        old = {"gateway": GW, "gateway_mac": GW_MAC, "ipv6_routers": [], "dns": [GW],
               "neighbours": [GW]}
        new = dict(old, neighbours=[GW, PRINTER])
        events = mod.diff_snapshots(old, new, memory=self.MEMORY)
        assert [e["kind"] for e in events] == ["neighbour_appeared"]
        assert events[0]["detail"] == f"New device(s) on the LAN: {PRINTER}."

    def test_memory_is_learned_after_the_comparison_and_kept(self, mod, monkeypatch):
        """Three starts: learn, lose the printer, see it return — silently."""
        def watch(snapshot, when):
            monkeypatch.setattr(mod, "monitor_snapshot", lambda critical_ips=(): snapshot)
            return mod.run_monitor(interval=0, iterations=1, sleeper=lambda _: None,
                                   printer=lambda *a: None, clock=lambda: when)
        def kinds(events):
            # A day between starts is a real observation gap and is reported as
            # one (test_monitor covers it); the point here is what else is said.
            return [e["kind"] for e in events if e["kind"] != "observation_gap"]
        assert kinds(watch(snap(), at(0))) == []
        assert mod.load_monitor_memory()[PRINTER_MAC]["ip"] == PRINTER
        assert kinds(watch(snap(neighbours=[GW], neighbour_macs={GW: GW_MAC}), at(0, 1))) == []
        assert kinds(watch(snap(), at(0, 2))) == []

    def test_a_newcomer_is_still_reported_across_a_restart(self, mod, monkeypatch):
        def watch(snapshot, when):
            monkeypatch.setattr(mod, "monitor_snapshot", lambda critical_ips=(): snapshot)
            return mod.run_monitor(interval=0, iterations=1, sleeper=lambda _: None,
                                   printer=lambda *a: None, clock=lambda: when)
        watch(snap(), at(0))
        new = snap(neighbours=[GW, PRINTER, "192.168.87.77"],
                   neighbour_macs={GW: GW_MAC, PRINTER: PRINTER_MAC, "192.168.87.77": ROGUE_MAC})
        events = watch(new, at(1))
        assert [e["kind"] for e in events if e["kind"] != "observation_gap"] == ["neighbour_appeared"]
        assert "192.168.87.77" in events[-1]["detail"] and PRINTER not in events[-1]["detail"]

    def test_memory_expires_after_thirty_days(self, mod):
        stale = {ROGUE_MAC: {"ip": "192.168.87.77", "first_seen": at(0, -40).isoformat(),
                             "last_seen": at(0, -31).isoformat()},
                 PRINTER_MAC: {"ip": PRINTER, "first_seen": at(0, -40).isoformat(),
                               "last_seen": at(0, -29).isoformat()}}
        kept = mod.update_monitor_memory(stale, snap(neighbours=[GW], neighbour_macs={GW: GW_MAC}), at(0))
        assert ROGUE_MAC not in kept and PRINTER_MAC in kept and GW_MAC in kept

    def test_a_poll_with_no_mac_table_teaches_and_expires_nothing(self, mod):
        stale = {ROGUE_MAC: {"ip": "x", "first_seen": at(0, -40).isoformat(),
                             "last_seen": at(0, -31).isoformat()}}
        assert mod.update_monitor_memory(stale, {"neighbours": [GW]}, at(0)) == stale

    def test_the_state_file_survives_a_hand_edit(self, mod, tmp_path):
        mod.save_monitor_state(snap(), at(0), memory={PRINTER_MAC: {"ip": PRINTER, "last_seen": at(0).isoformat()},
                                                      "junk": {"last_seen": "never"},
                                                      "zz:zz:zz:zz:zz:zz": "not a dict"})
        memory = mod.load_monitor_memory()
        assert list(memory) == [PRINTER_MAC]
        assert memory[PRINTER_MAC]["first_seen"] == at(0).isoformat()


# ---------------------------------------------------------------------------
# 4. Devices whose silence matters
# ---------------------------------------------------------------------------

class TestCriticalDevices:
    def _old(self):
        return {"timestamp": at(0, -7).isoformat(), "scanned_subnets": ["192.168.86.0/24"],
                "devices": [{"mac": ARLO_MAC, "ip": HUB_IP, "subnet": "192.168.86.0/24"},
                            {"mac": PRINTER_MAC, "ip": PRINTER, "subnet": "192.168.86.0/24"}]}

    def _new(self, *macs):
        return {"timestamp": at(0).isoformat(), "scanned_subnets": ["192.168.86.0/24"],
                "devices": [{"mac": m, "ip": "192.168.86.9", "subnet": "192.168.86.0/24"} for m in macs]}

    def test_marks_are_saved_lowercased_and_read_defensively(self, mod):
        mod.save_critical({"A4:11:62:2A:B9:0A"})
        assert mod.load_critical() == {ARLO_MAC}
        with open(mod.CRITICAL_FILE, "w") as f:
            json.dump([ARLO_MAC, "not a mac", 7], f)
        assert mod.load_critical() == {ARLO_MAC}
        with open(mod.CRITICAL_FILE, "w") as f:
            f.write("{")
        assert mod.load_critical() == set()

    def test_a_critical_device_gone_is_its_own_change_line(self, mod):
        notes = mod.diff_baseline(self._old(), self._new(PRINTER_MAC), LABELS, critical={ARLO_MAC})
        assert len(notes) == 1
        assert notes[0].startswith("CRITICAL device(s) gone since baseline")
        assert "Arlo SmartHub (VMB5000)" in notes[0]

    def test_an_ordinary_device_gone_reads_as_before(self, mod):
        notes = mod.diff_baseline(self._old(), self._new(ARLO_MAC), LABELS, critical={ARLO_MAC})
        assert len(notes) == 1 and notes[0].startswith("Device(s) gone since baseline")

    def test_absence_is_high_on_every_run_while_remembered(self, mod):
        line = mod.describe_critical_absences(self._old(), self._new(PRINTER_MAC), {ARLO_MAC}, LABELS)
        assert line.startswith("  [HIGH  ] Critical device(s) not answering")
        assert "Arlo SmartHub (VMB5000)" in line and "last seen 2026-10-25" in line
        # Still absent a week later: the baseline no longer lists it, the memory does.
        later = dict(self._new(PRINTER_MAC),
                     device_memory={ARLO_MAC: {"first_seen": at(0, -30).isoformat(),
                                               "last_seen": at(0, -7).isoformat()}})
        assert mod.describe_critical_absences(later, self._new(PRINTER_MAC), {ARLO_MAC}, LABELS)

    def test_present_or_never_seen_here_is_silent(self, mod):
        assert mod.describe_critical_absences(self._old(), self._new(ARLO_MAC, PRINTER_MAC), {ARLO_MAC}) is None
        # Marked critical, but a device of another network: nothing to miss here.
        assert mod.describe_critical_absences(self._new(PRINTER_MAC), self._new(PRINTER_MAC), {ARLO_MAC}) is None
        assert mod.describe_critical_absences(self._old(), {"timestamp": at(0).isoformat()}, {ARLO_MAC}) is None

    def test_the_monitor_alerts_after_ten_silent_polls_and_once(self, mod):
        memory = {ARLO_MAC: {"ip": HUB_IP, "first_seen": at(-1).isoformat(), "last_seen": at(0).isoformat()}}
        gone = snap(neighbour_macs={GW: GW_MAC})
        raised = []
        for _ in range(12):
            raised += mod.critical_device_events({ARLO_MAC}, gone, memory, LABELS)
        assert [e["kind"] for e in raised] == ["critical_device_absent"]
        assert raised[0]["severity"] == "HIGH"
        assert "Arlo SmartHub (VMB5000)" in raised[0]["detail"] and HUB_IP in raised[0]["detail"]
        back = snap(neighbour_macs={GW: GW_MAC, HUB_IP: ARLO_MAC})
        returned = mod.critical_device_events({ARLO_MAC}, back, memory, LABELS)
        assert [e["kind"] for e in returned] == ["critical_device_back"]
        assert memory[ARLO_MAC]["absent_polls"] == 0

    def test_a_poll_that_could_not_read_the_table_does_not_count(self, mod):
        memory = {ARLO_MAC: {"ip": HUB_IP, "last_seen": at(0).isoformat()}}
        unreadable = {"gateway": GW, "neighbours": []}
        assert mod.critical_device_events({ARLO_MAC}, unreadable, memory, polls=1) == []

    def test_a_device_never_seen_on_this_network_is_not_missed(self, mod):
        assert mod.critical_device_events({ARLO_MAC}, snap(), {}, polls=1) == []

    def test_the_loop_pings_critical_devices_where_they_last_answered(self, mod, monkeypatch):
        mod.save_critical({ARLO_MAC})
        mod.save_monitor_state(snap(), at(0), memory={
            ARLO_MAC: {"ip": HUB_IP, "first_seen": at(-1).isoformat(), "last_seen": at(0).isoformat()}})
        asked = []

        def fake_snapshot(critical_ips=()):
            asked.append(list(critical_ips))
            return snap()
        monkeypatch.setattr(mod, "monitor_snapshot", fake_snapshot)
        mod.run_monitor(interval=0, iterations=1, sleeper=lambda _: None,
                        printer=lambda *a: None, clock=lambda: at(1))
        assert asked == [[HUB_IP]]

    def test_the_snapshot_pings_them_once_each_and_never_the_gateway_twice(self, mod, monkeypatch):
        pinged = []
        monkeypatch.setattr(mod, "ping", lambda ip: pinged.append(ip))
        monkeypatch.setattr(mod, "run", make_run({"route -n get default": f"   gateway: {GW}\n"}))
        mod.monitor_snapshot([HUB_IP, GW])
        assert pinged == [GW, HUB_IP]

    def test_the_command_line_marks_and_exits(self, mod, monkeypatch, capsys):
        def never(**kwargs):
            raise AssertionError("marking a device must not start an audit")
        monkeypatch.setattr(mod, "action_full_audit", never)
        monkeypatch.setattr(sys, "argv", ["home_net_audit.py", "--critical", "A4:11:62:2A:B9:0A", "nonsense"])
        mod._main()
        assert mod.load_critical() == {ARLO_MAC}
        out = capsys.readouterr().out
        assert "Critical devices saved (1 total)" in out and "not marked critical: nonsense" in out
        monkeypatch.setattr(sys, "argv", ["home_net_audit.py", "--not-critical", ARLO_MAC])
        mod._main()
        assert mod.load_critical() == set()

    def test_with_an_audit_flag_the_audit_still_runs(self, mod, monkeypatch):
        seen = {}

        def fake_audit(**kwargs):
            seen.update(kwargs)
            return {"gateway": None}
        monkeypatch.setattr(mod, "action_full_audit", fake_audit)
        monkeypatch.setattr(sys, "argv", ["home_net_audit.py", "--critical", ARLO_MAC, "--no-discovery"])
        mod._main()
        assert seen.get("no_discovery") is True and mod.load_critical() == {ARLO_MAC}
