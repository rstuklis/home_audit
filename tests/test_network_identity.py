"""Round 5 — the monitor knows its network, and a baseline knows which one it is.

The round-4 attack audit (1 November 2026) confirmed seven ways the tool lost
track of WHICH network it was describing, or of WHO was advertising on it:

  * F2.  The monitor bound its chain, state file and heartbeat identity once at
         start-up. A Wi-Fi roam inside the process diffed the new network
         against the old reference (a false "ARP poisoning" triple HIGH),
         heartbeated the abandoned chain as continuous coverage, and wrote the
         new network's snapshot into the old network's state file.
  * F35. A gap inside a surviving process — the Mac asleep for an hour — was
         never detected: no observation_gap, and whatever it saw on waking was
         reported as witnessed just now.
  * F13. Deleting the state file re-baselined the monitor silently onto
         whatever the network looked like, heartbeats flowing throughout.
  * F5.  A baselined router address answering from a different MAC was a
         false all-clear everywhere: the address was the identity.
  * F6.  Only the default-router list was read; a Router Advertisement with
         lifetime 0 carrying a prefix or a more-specific route rerouted a
         traffic subset and never appeared in it.
  * F22. Network identity was the subnet string alone, so a /23 lease adopted
         a sibling's chain and a stranger's 192.168.86.0/24 audited into pearl's.
  * F23. A host with no IPv4 address was never a device.

Every fix is pinned here against the mechanism, not the wording. The monitor
tests drive run_monitor with a sequence of snapshots and a clock; the network a
snapshot "is on" is read from its gateway by a stand-in for the per-poll
identification, which on the real Mac reads the interfaces and this machine's
own address (both forbidden by the sandbox, correctly).
"""

import ipaddress
import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import make_run

HOME, IOT, PEARL = "192.168.87.0/24", "192.168.85.0/24", "192.168.86.0/24"
HOME_GW, IOT_GW, PEARL_GW = "192.168.87.1", "192.168.85.1", "192.168.86.1"
HOME_GW_MAC = "38:8b:59:aa:00:01"
IOT_GW_MAC = "38:8b:59:aa:00:02"
PEARL_GW_MAC = "38:8b:59:aa:00:03"
BEACH_GW_MAC = "f0:9f:c2:bb:00:04"          # a Google Wifi somewhere else, same addresses
ATTACKER_MAC = "0e:8b:02:1a:2b:3c"
PRINTER, PRINTER_MAC = "192.168.87.35", "34:64:a9:cc:57:2e"
HUB_IP, HUB_MAC = "192.168.86.40", "c4:f7:c1:aa:bb:cc"     # a HomeKit hub on pearl
CAMERA_MAC = "ac:de:48:00:11:22"
GW_V6 = "fe80::1%en0"
HUB_V6 = "fe80::87e:f5b1:f821:c252%en0"
HUB_ULA = "fdca:7af7:13bd:4743:1c3c:c1ff:fe2a:3b4c%en0"
CAMERA_V6 = "fe80::aede:48ff:fe00:1122%en0"
ULA_PREFIX = "fdca:7af7:13bd:4743::/64"
MESH_ROUTE = "fda6:3e0a:d2be::/64"

NDP_HEADER = "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n"
NDP_A_GW = NDP_HEADER + f"{GW_V6:<40}{HOME_GW_MAC}  en0   23h59m58s R  R\n"
NDP_A_IMPOSTOR = NDP_HEADER + f"{GW_V6:<40}{ATTACKER_MAC}  en0   23h59m58s R  R\n"
NDP_A_GW_AND_HUB = NDP_A_GW + f"{HUB_V6:<40}{HUB_MAC}  en0   21h36m38s S  R\n"
NDP_A_DEVICES = (NDP_A_GW_AND_HUB
                 + f"{HUB_ULA:<40}{HUB_MAC}  en0   23h58m12s S\n"
                 + f"{CAMERA_V6:<40}{CAMERA_MAC}  en0   23h58m12s S\n"
                 + f"{'fe80::dead:beef%en0':<40}(incomplete)       en0   expired   I\n")
NDP_R_GW = f"{GW_V6} if=en0, flags=I, pref=medium, expire=29m30s\n"
NDP_P_HUB = (f"{ULA_PREFIX} if=en0\n"
             "flags=ALO vltime=1800, pltime=1800, expire=29m50s, ref=1\n"
             "  advertised by\n"
             f"    {HUB_V6} (reachable)\n"
             "fe80::%en0/64 if=en0\n"
             "flags=AILSO vltime=infinity, pltime=infinity, expire=Never, ref=0\n"
             "  No advertising router\n")
NETSTAT_INET6 = f"""Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            {HOME_GW}       UGScg                 en0

Internet6:
Destination                             Gateway                         Flags               Netif Expire
default                                 {GW_V6}                     UGcg                  en0
default                                 fe80::%utun4                    UGcIg               utun4
::1                                     ::1                             UHL                   lo0
{MESH_ROUTE}                     {HUB_V6}    UGc                   en0
{ULA_PREFIX}                link#12                         UC                    en0
fe80::%en0/64                           link#12                         UCI                   en0
{GW_V6}                             38:8b:59:aa:0:1                 UHLWIir               en0
ff00::/8                                ::1                             UmCI                  lo0
"""
IP6_ROUTE = (f"{MESH_ROUTE} via fe80::87e:f5b1:f821:c252 dev eth0 proto ra metric 1024 expires 1750sec pref medium\n"
             f"{ULA_PREFIX} dev eth0 proto kernel metric 256 expires 1750sec pref medium\n"
             "fe80::/64 dev eth0 proto kernel metric 256 pref medium\n"
             "default via fe80::1 dev eth0 proto ra metric 1024 expires 1794sec pref medium\n")


def at(minutes=0, hours=0, days=0):
    return (datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
            + timedelta(minutes=minutes, hours=hours, days=days))


def ticking(*times):
    """A clock returning each time in turn, then holding the last."""
    seq, state = list(times), {"i": 0}

    def now():
        value = seq[min(state["i"], len(seq) - 1)]
        state["i"] += 1
        return value
    return now


def snap(**over):
    base = {
        "gateway": HOME_GW, "gateway_mac": HOME_GW_MAC,
        "ipv6_routers": [GW_V6], "ipv6_router_macs": {GW_V6: HOME_GW_MAC},
        "ipv6_router_installed": {GW_V6: True},
        "dns": [HOME_GW],
        "neighbours": [HOME_GW, PRINTER], "neighbour_macs": {HOME_GW: HOME_GW_MAC, PRINTER: PRINTER_MAC},
    }
    base.update(over)
    return base


def iot_snap(**over):
    base = snap(gateway=IOT_GW, gateway_mac=IOT_GW_MAC, ipv6_routers=[], ipv6_router_macs={},
                ipv6_router_installed={}, dns=[IOT_GW], neighbours=[IOT_GW, "192.168.85.20"],
                neighbour_macs={IOT_GW: IOT_GW_MAC, "192.168.85.20": "d4:a6:51:00:00:20"})
    base.update(over)
    return base


@pytest.fixture(autouse=True)
def _quiet(mod, monkeypatch):
    """What the loop reads from the machine that these tests are not about:
    the gateway ping, and the interfaces and local address behind the start-up
    selection and the per-poll identification. Tests that are about them
    install their own stand-ins through on_network()."""
    monkeypatch.setattr(mod, "ping", lambda ip: None)
    monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (None, None))
    monkeypatch.setattr(mod, "identify_monitor_network", lambda snapshot: (None, None))


def on_network(mod, monkeypatch, subnet):
    """Start the monitor on `subnet`, and identify every poll by its gateway."""
    monkeypatch.setattr(mod, "use_current_network_baseline",
                        lambda *a, **k: (subnet, mod.select_network_baseline(subnet)))

    def identify(snapshot):
        gateway = (snapshot or {}).get("gateway")
        if not gateway:
            return None, None
        net = str(ipaddress.ip_network(f"{gateway}/24", strict=False))
        return net, mod.baseline_key(net)
    monkeypatch.setattr(mod, "identify_monitor_network", identify)


def watch(mod, monkeypatch, snapshots, clock=None, **kw):
    """Run the loop once over `snapshots`, one poll each, and return its events."""
    seq, state = list(snapshots), {"i": 0}

    def snapshot(critical_ips=()):
        value = seq[min(state["i"], len(seq) - 1)]
        state["i"] += 1
        return value
    monkeypatch.setattr(mod, "monitor_snapshot", snapshot)
    return mod.run_monitor(interval=0, iterations=len(seq), sleeper=lambda _: None,
                           printer=lambda *a: None, clock=clock, **kw)


def chain_of(mod, subnet):
    mod.select_network_baseline(subnet)
    return mod.chain_id()


def beats_for(mod, sink, subnet, *stamps):
    """Heartbeats under `subnet`'s chain, as a monitor there would have left them."""
    mod.select_network_baseline(subnet)
    for stamp in stamps:
        assert mod.monitor_heartbeat(destination=str(sink), at=stamp)["published"]


def home_baseline(mod, **over):
    """A weekly baseline for the home network, as action_full_audit saves one."""
    mod.select_network_baseline(HOME)
    state = {
        "timestamp": at(days=-1).isoformat(), "gateway": HOME_GW, "gateway_mac": HOME_GW_MAC,
        "arp_spoof": {"gateway": HOME_GW, "macs_seen": [HOME_GW_MAC], "spoofing_suspected": False},
        "dns": [HOME_GW], "ipv6_routers": [GW_V6],
        "ipv6_router_details": {GW_V6: {"mac": HOME_GW_MAC, "installed": True, "prefixes": [], "routes": []}},
        "devices": [{"ip": HOME_GW, "mac": HOME_GW_MAC, "subnet": HOME},
                    {"ip": PRINTER, "mac": PRINTER_MAC, "subnet": HOME}],
        "scanned_subnets": [HOME], "router_open_ports": [80],
        "wifi": {"ssid": "loveshack", "auth": "WPA3", "cipher": "AES", "risk": "OK", "note": ""},
    }
    state.update(over)
    mod.save_baseline(state)
    return state


# ---------------------------------------------------------------------------
# F2. The monitor follows the Mac
# ---------------------------------------------------------------------------

class TestTheMonitorFollowsTheMac:
    def test_a_roam_switches_the_reference_instead_of_comparing_two_networks(self, mod, monkeypatch):
        """The production alert of 24 October: gateway_changed, gateway_mac_changed
        "while its IP stayed the same ... ARP poisoning", ipv6_router_appeared and
        ten new devices — all of it the monitor comparing loveshack against the
        IoT network's reference. Now: one REVIEW saying what happened."""
        on_network(mod, monkeypatch, IOT)
        events = watch(mod, monkeypatch, [iot_snap(), snap()])
        assert [e["kind"] for e in events] == ["network_changed"]
        assert events[0]["severity"] == "REVIEW"
        assert (f"network changed from {IOT} to {HOME}; reference switched"
                in events[0]["detail"].lower())

    def test_nothing_is_saved_under_a_chain_that_is_not_the_snapshots(self, mod, monkeypatch):
        on_network(mod, monkeypatch, IOT)
        watch(mod, monkeypatch, [iot_snap(), snap()])
        mod.select_network_baseline(IOT)
        assert mod.load_monitor_state()[0]["gateway"] == IOT_GW, \
            "the IoT network's file was overwritten with the home network's snapshot"
        mod.select_network_baseline(HOME)
        assert mod.load_monitor_state() == (None, None), \
            "the switch poll adopted the new network's snapshot without comparing it"

    def test_the_poll_after_a_switch_compares_against_that_networks_own_reference(self, mod, monkeypatch):
        """Arriving home is a resume on the home chain: the reference it left
        there is what the next poll is compared against, across the gap."""
        mod.select_network_baseline(HOME)
        mod.save_monitor_state(snap(), at=at(days=-3))
        on_network(mod, monkeypatch, IOT)
        poisoned = snap(gateway_mac=ATTACKER_MAC)
        events = watch(mod, monkeypatch, [iot_snap(), poisoned, poisoned], clock=lambda: at())
        assert [e["kind"] for e in events] == ["network_changed", "observation_gap", "gateway_mac_changed"]
        assert "3d" in events[1]["detail"]
        assert events[2]["across_gap"] is True
        assert "stayed the same" in events[2]["detail"], "the address did stay the same here"

    def test_heartbeats_carry_the_chain_of_the_network_each_poll_was_on(self, mod, monkeypatch, tmp_path):
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        on_network(mod, monkeypatch, IOT)
        watch(mod, monkeypatch, [iot_snap(), snap(), snap()], heartbeat_interval=0)
        beats = [r["chain"] for r in mod.read_receipts(str(sink)) if r.get("kind") == "heartbeat"]
        assert beats == [chain_of(mod, IOT), chain_of(mod, HOME), chain_of(mod, HOME)]

    def test_the_heartbeat_clock_is_reset_so_the_new_chain_is_covered_at_once(self, mod, monkeypatch, tmp_path):
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        on_network(mod, monkeypatch, IOT)
        # A 900 s heartbeat interval and two polls a minute apart: without the
        # reset the second poll would publish nothing, and the new network's
        # chain would show no coverage until the old one's interval ran out.
        watch(mod, monkeypatch, [iot_snap(), snap()], clock=ticking(at(), at(minutes=1)),
              heartbeat_interval=900)
        beats = [r["chain"] for r in mod.read_receipts(str(sink)) if r.get("kind") == "heartbeat"]
        assert beats == [chain_of(mod, IOT), chain_of(mod, HOME)]

    def test_a_poll_whose_network_cannot_be_identified_does_not_switch(self, mod, monkeypatch):
        on_network(mod, monkeypatch, IOT)
        events = watch(mod, monkeypatch, [iot_snap(), iot_snap(gateway=None, gateway_mac=None)])
        assert "network_changed" not in [e["kind"] for e in events]
        mod.select_network_baseline(IOT)
        assert mod.load_monitor_state()[0]["gateway"] == IOT_GW

    def test_a_reference_written_by_a_roamed_monitor_is_discarded_not_compared(self, mod, monkeypatch):
        """The residue of the old behaviour on the city Mac: the IoT network's
        state file holds the home network's snapshot. Compared, it would repeat
        the triple HIGH on the first visit; it describes another network."""
        mod.select_network_baseline(IOT)
        mod.save_monitor_state(snap(), at=at(days=-3))        # home's gateway, under the IoT chain
        on_network(mod, monkeypatch, IOT)
        events = watch(mod, monkeypatch, [iot_snap(), iot_snap()], clock=lambda: at())
        assert [e["kind"] for e in events] == ["monitor_state_foreign"]
        assert events[0]["severity"] == "REVIEW" and HOME_GW in events[0]["detail"]
        assert mod.load_monitor_state()[0]["gateway"] == IOT_GW

    def test_the_weekly_baseline_stands_in_for_a_discarded_reference(self, mod, monkeypatch):
        mod.select_network_baseline(IOT)
        mod.save_baseline({"timestamp": at(days=-1).isoformat(), "gateway": IOT_GW,
                           "gateway_mac": IOT_GW_MAC, "dns": [IOT_GW], "ipv6_routers": [],
                           "devices": [{"ip": IOT_GW, "mac": IOT_GW_MAC, "subnet": IOT},
                                       {"ip": "192.168.85.20", "mac": "d4:a6:51:00:00:20", "subnet": IOT}],
                           "scanned_subnets": [IOT], "router_open_ports": [80]})
        mod.save_monitor_state(snap(), at=at(days=-3))
        on_network(mod, monkeypatch, IOT)
        events = watch(mod, monkeypatch, [iot_snap(gateway_mac=ATTACKER_MAC)], clock=lambda: at())
        assert [e["kind"] for e in events] == ["monitor_state_foreign", "observation_gap",
                                               "gateway_mac_changed"]
        assert events[2]["across_gap"] is True
        assert PRINTER_MAC not in mod.load_monitor_memory(), \
            "the other network's memory went with its reference"

    def test_the_queue_and_memory_follow_the_network(self, mod, monkeypatch):
        mod.select_network_baseline(HOME)
        mod.save_monitor_state(snap(), at=at(minutes=-1),
                               undelivered=[{"severity": "HIGH", "kind": "dns_changed", "detail": "x"}],
                               memory={PRINTER_MAC: {"ip": PRINTER, "first_seen": at(days=-2).isoformat(),
                                                     "last_seen": at(minutes=-1).isoformat()}})
        sent = []
        monkeypatch.setattr(mod, "send_alert",
                            lambda e, *a, **k: sent.append(e) or {"published": True, "detail": "ok"})
        on_network(mod, monkeypatch, IOT)
        watch(mod, monkeypatch, [iot_snap(), snap(), snap()], clock=lambda: at())
        assert any(e["kind"] == "dns_changed" for e in sent), \
            "the alert the home network could not deliver is retried once the monitor is back there"
        assert PRINTER_MAC in mod.load_monitor_memory()

    def test_the_start_up_line_names_the_network_and_its_chain(self, mod, monkeypatch):
        on_network(mod, monkeypatch, HOME)
        lines = []
        monkeypatch.setattr(mod, "monitor_snapshot", lambda critical_ips=(): snap())
        mod.run_monitor(interval=0, iterations=1, sleeper=lambda _: None,
                        printer=lambda *a: lines.append(" ".join(str(x) for x in a)))
        assert any(HOME in l and mod.chain_id() in l for l in lines)

    def test_a_changed_gateway_mac_with_a_changed_address_does_not_claim_the_address_stayed(self, mod):
        events = mod.diff_snapshots(iot_snap(), snap())
        mac = [e for e in events if e["kind"] == "gateway_mac_changed"][0]
        assert "stayed the same" not in mac["detail"] and "ARP poisoning" not in mac["detail"]
        assert IOT_GW in mac["detail"] and HOME_GW in mac["detail"]

    def test_the_same_address_with_new_hardware_still_reads_as_poisoning(self, mod):
        events = mod.diff_snapshots(snap(), snap(gateway_mac=ATTACKER_MAC))
        assert [e["kind"] for e in events] == ["gateway_mac_changed"]
        assert "stayed the same" in events[0]["detail"] and "ARP poisoning" in events[0]["detail"]

    def test_the_identification_reads_the_live_interfaces_and_the_snapshots_gateway(self, mod, monkeypatch):
        monkeypatch.undo()
        monkeypatch.setattr(mod, "get_all_interfaces",
                            lambda: [("en0", "192.168.87.25", ipaddress.ip_network(HOME))])
        monkeypatch.setattr(mod, "get_local_ip", lambda: "192.168.87.25")
        assert mod.identify_monitor_network(snap()) == (HOME, "192-168-87-0-24")
        # The gateway decides, as it does for the audit: a snapshot taken on the
        # IoT network while the interface list still shows home is the IoT network.
        monkeypatch.setattr(mod, "get_all_interfaces",
                            lambda: [("en0", "192.168.85.25", ipaddress.ip_network(IOT))])
        monkeypatch.setattr(mod, "get_local_ip", lambda: "192.168.85.25")
        assert mod.identify_monitor_network(iot_snap()) == (IOT, "192-168-85-0-24")
        assert mod.identify_monitor_network({"gateway": None}) == (IOT, "192-168-85-0-24"), \
            "with no gateway this machine's own address names the network"


# ---------------------------------------------------------------------------
# F35. A gap inside the process
# ---------------------------------------------------------------------------

class TestAGapInsideTheProcess:
    def test_a_machine_that_slept_reports_the_gap_and_marks_what_it_sees_as_unwitnessed(self, mod, monkeypatch):
        """31 October: heartbeats stopped 04:02 and resumed 05:15 with no restart,
        and the five devices seen on waking were alerted as witnessed at 05:16."""
        woke = snap(neighbours=[HOME_GW, PRINTER, "192.168.87.77"],
                    neighbour_macs={HOME_GW: HOME_GW_MAC, PRINTER: PRINTER_MAC,
                                    "192.168.87.77": "d4:a6:51:00:00:77"})
        events = watch(mod, monkeypatch, [snap(), woke], clock=ticking(at(), at(hours=24)))
        assert [e["kind"] for e in events] == ["observation_gap", "neighbour_appeared"]
        assert "1d" in events[0]["detail"] and "did not poll" in events[0]["detail"]
        assert events[1]["across_gap"] is True
        assert "when it happened is unknown" in events[1]["detail"]

    def test_a_poll_on_time_is_not_a_gap(self, mod, monkeypatch):
        # interval 0 gives the same allowance a restart gets: interval*2 + 60.
        assert watch(mod, monkeypatch, [snap(), snap()], clock=ticking(at(), at(minutes=1))) == []

    def test_only_the_poll_after_the_gap_is_decorated(self, mod, monkeypatch):
        events = watch(mod, monkeypatch, [snap(), snap(), snap(dns=["9.9.9.9"])],
                       clock=ticking(at(), at(hours=2), at(hours=2, minutes=1)))
        assert [e["kind"] for e in events] == ["observation_gap", "dns_changed"]
        assert "across_gap" not in events[1]

    def test_the_gap_alert_leaves_the_machine(self, mod, monkeypatch, tmp_path):
        target = tmp_path / "alerts.jsonl"
        watch(mod, monkeypatch, [snap(), snap()], clock=ticking(at(), at(hours=2)),
              alert_to=str(target))
        assert "observation_gap" in target.read_text(encoding="utf-8")

    def test_a_restart_gap_still_says_the_monitor_was_not_running(self, mod, monkeypatch):
        watch(mod, monkeypatch, [snap()], clock=lambda: at())
        events = watch(mod, monkeypatch, [snap()], clock=lambda: at(hours=4))
        assert [e["kind"] for e in events] == ["observation_gap"]
        assert "resumed after 4h" in events[0]["detail"] and "did not poll" not in events[0]["detail"]


# ---------------------------------------------------------------------------
# F13. A wiped state file is not a fresh start
# ---------------------------------------------------------------------------

class TestAWipedStateFileIsNotAFreshStart:
    def test_missing_state_with_heartbeats_on_record_is_high_and_compared_against_the_baseline(
            self, mod, monkeypatch, tmp_path):
        """Poison the gateway, rm the state file, wait for the KeepAlive restart:
        the restart used to adopt the attacker's MAC with zero alerts."""
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        home_baseline(mod)
        beats_for(mod, sink, HOME, at(hours=-2), at(hours=-1))
        on_network(mod, monkeypatch, HOME)
        events = watch(mod, monkeypatch, [snap(gateway_mac=ATTACKER_MAC)], clock=lambda: at())
        assert [e["kind"] for e in events] == ["monitor_state_missing", "gateway_mac_changed"]
        assert events[0]["severity"] == "HIGH"
        assert "2 heartbeat" in events[0]["detail"] and "weekly baseline" in events[0]["detail"]
        assert events[1]["across_gap"] is True and "1h" in events[1]["detail"]
        # The reference is rebuilt from this poll, so the next one has a file again.
        assert mod.load_monitor_state()[0]["gateway_mac"] == ATTACKER_MAC

    def test_without_a_baseline_the_high_still_fires_and_the_poll_becomes_the_reference(
            self, mod, monkeypatch, tmp_path):
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        beats_for(mod, sink, HOME, at(hours=-1))
        on_network(mod, monkeypatch, HOME)
        events = watch(mod, monkeypatch, [snap()], clock=lambda: at())
        assert [e["kind"] for e in events] == ["monitor_state_missing"]
        assert "no weekly baseline" in events[0]["detail"].lower()
        assert mod.load_monitor_state()[0]["gateway"] == HOME_GW

    def test_a_genuine_first_start_is_silent(self, mod, monkeypatch, tmp_path):
        monkeypatch.setenv(mod.SINK_ENV, str(tmp_path / "receipts.jsonl"))
        home_baseline(mod)
        on_network(mod, monkeypatch, HOME)
        assert watch(mod, monkeypatch, [snap()], clock=lambda: at()) == []

    def test_heartbeats_of_another_chain_do_not_count(self, mod, monkeypatch, tmp_path):
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        beats_for(mod, sink, IOT, at(hours=-1))
        on_network(mod, monkeypatch, HOME)
        assert watch(mod, monkeypatch, [snap()], clock=lambda: at()) == []

    def test_the_household_devices_in_the_baseline_are_remembered_not_new(self, mod, monkeypatch, tmp_path):
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        home_baseline(mod)
        beats_for(mod, sink, HOME, at(hours=-1))
        on_network(mod, monkeypatch, HOME)
        moved = snap(neighbours=[HOME_GW, "192.168.87.36"],
                     neighbour_macs={HOME_GW: HOME_GW_MAC, "192.168.87.36": PRINTER_MAC})
        events = watch(mod, monkeypatch, [moved], clock=lambda: at())
        assert [e["kind"] for e in events] == ["monitor_state_missing"], \
            "the printer at a new address is a household device the baseline remembers"

    def test_the_baseline_becomes_a_reference_the_monitor_can_compare(self, mod):
        state = home_baseline(mod)
        ref = mod.baseline_reference_snapshot(state)
        assert ref["gateway"] == HOME_GW and ref["gateway_mac"] == HOME_GW_MAC
        assert ref["dns"] == [HOME_GW]
        assert ref["ipv6_routers"] == [GW_V6]
        assert ref["ipv6_router_macs"] == {GW_V6: HOME_GW_MAC}
        assert ref["ipv6_router_installed"] == {GW_V6: True}
        assert ref["ipv6_router_prefixes"] == {GW_V6: []} and ref["ipv6_router_routes"] == {GW_V6: []}
        assert ref["neighbours"] == [HOME_GW, PRINTER]
        assert ref["neighbour_macs"] == {HOME_GW: HOME_GW_MAC, PRINTER: PRINTER_MAC}
        assert mod.diff_snapshots(ref, snap()) == []

    def test_a_baseline_whose_arp_check_saw_two_macs_binds_the_gateway_to_neither(self, mod):
        state = {"gateway": HOME_GW,
                 "arp_spoof": {"macs_seen": [HOME_GW_MAC, ATTACKER_MAC], "spoofing_suspected": True}}
        assert mod.baseline_reference_snapshot(state)["gateway_mac"] is None
        assert mod.baseline_reference_snapshot(None) is None
        assert mod.baseline_reference_snapshot({}) is None


# ---------------------------------------------------------------------------
# F5. A baselined router address answering from different hardware
# ---------------------------------------------------------------------------

class TestARouterAddressAnsweringFromNewHardware:
    def test_the_section_is_high(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({"ndp -rn": NDP_R_GW, "ndp -an": NDP_A_IMPOSTOR}))
        result = mod.check_ipv6_routers(
            known=[GW_V6], known_details={GW_V6: {"mac": HOME_GW_MAC, "installed": True}})
        assert result["risk"] == "HIGH"
        assert result["impersonated"] == [GW_V6]
        assert ATTACKER_MAC in result["note"] and HOME_GW_MAC in result["note"]
        assert "unexpected" in result and result["unexpected"] == []

    def test_a_mac_that_cannot_be_read_is_not_a_change(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({"ndp -rn": NDP_R_GW}))
        result = mod.check_ipv6_routers(
            known=[GW_V6], known_details={GW_V6: {"mac": HOME_GW_MAC, "installed": True}})
        assert result["risk"] == "OK" and result["impersonated"] == []

    def test_a_baseline_without_a_mac_cannot_be_impersonated(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({"ndp -rn": NDP_R_GW, "ndp -an": NDP_A_IMPOSTOR}))
        assert mod.check_ipv6_routers(known=[GW_V6])["risk"] == "OK"

    def test_the_baseline_diff_notes_it(self, mod):
        old = {"ipv6_routers": [GW_V6], "ipv6_router_details": {GW_V6: {"mac": HOME_GW_MAC}}}
        new = {"ipv6_routers": [GW_V6], "ipv6_router_details": {GW_V6: {"mac": ATTACKER_MAC}}}
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1
        assert "hardware" in notes[0].lower() and ATTACKER_MAC in notes[0] and HOME_GW_MAC in notes[0]
        unread = {"ipv6_routers": [GW_V6], "ipv6_router_details": {GW_V6: {"mac": None}}}
        assert mod.diff_baseline(old, unread) == []
        assert mod.diff_baseline(unread, new) == []

    def test_the_monitor_is_high(self, mod):
        events = mod.diff_snapshots(snap(), snap(ipv6_router_macs={GW_V6: ATTACKER_MAC}))
        assert [e["kind"] for e in events] == ["ipv6_router_mac_changed"]
        assert events[0]["severity"] == "HIGH"
        assert GW_V6 in events[0]["detail"] and ATTACKER_MAC in events[0]["detail"]
        assert mod.diff_snapshots(snap(), snap(ipv6_router_macs={})) == []
        assert mod.diff_snapshots(snap(ipv6_router_macs={}), snap()) == []


# ---------------------------------------------------------------------------
# F6. Routers that only hand out prefixes or routes
# ---------------------------------------------------------------------------

class TestRoutersThatOnlyHandOutPrefixesOrRoutes:
    def test_the_inet6_route_table_names_non_default_next_hops(self, mod):
        """The default route, the tunnel placeholder, interface routes (link#N),
        the loopback and the neighbour's own host route are not routes via a
        router; the mesh route via the hub is."""
        assert mod.parse_inet6_routes_netstat(NETSTAT_INET6) == {HUB_V6: [MESH_ROUTE]}
        assert mod.parse_inet6_routes_iproute(IP6_ROUTE) == {"fe80::87e:f5b1:f821:c252": [MESH_ROUTE]}
        assert mod.parse_inet6_routes_netstat("") == {}
        assert mod.parse_inet6_routes_iproute("") == {}

    def test_the_readers_fall_through_as_the_other_ipv6_readers_do(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({"netstat -rn -f inet6": NETSTAT_INET6}))
        assert mod.get_ipv6_route_hops() == {HUB_V6: [MESH_ROUTE]}
        monkeypatch.setattr(mod, "run", make_run({"ip -6 route": IP6_ROUTE}))
        assert mod.get_ipv6_route_hops() == {"fe80::87e:f5b1:f821:c252": [MESH_ROUTE]}
        monkeypatch.setattr(mod, "run", make_run({}))
        assert mod.get_ipv6_route_hops() == {}

    def test_a_prefix_only_advertiser_is_a_router(self, mod, monkeypatch):
        """Lifetime 0 with a Prefix Information Option: absent from ndp -rn,
        present in ndp -pn, and macOS has installed the prefix."""
        monkeypatch.setattr(mod, "run", make_run(
            {"ndp -rn": NDP_R_GW, "ndp -an": NDP_A_GW_AND_HUB, "ndp -pn": NDP_P_HUB}))
        result = mod.check_ipv6_routers(
            known=[GW_V6], known_details={GW_V6: {"mac": HOME_GW_MAC, "installed": True}})
        assert result["routers"] == [GW_V6, HUB_V6]
        assert result["details"][HUB_V6] == {"mac": HUB_MAC, "installed": False,
                                             "prefixes": [ULA_PREFIX], "routes": []}
        assert result["risk"] == "HIGH" and result["unexpected"] == [HUB_V6]

    def test_a_route_only_next_hop_is_a_router(self, mod, monkeypatch):
        """RFC 4191 Route Information Option, lifetime 0: only the route table knows."""
        monkeypatch.setattr(mod, "run", make_run(
            {"ndp -rn": NDP_R_GW, "ndp -an": NDP_A_GW_AND_HUB, "netstat -rn -f inet6": NETSTAT_INET6}))
        result = mod.check_ipv6_routers(
            known=[GW_V6], known_details={GW_V6: {"mac": HOME_GW_MAC, "installed": True}})
        assert HUB_V6 in result["routers"]
        assert result["details"][HUB_V6]["routes"] == [MESH_ROUTE]
        assert result["details"][HUB_V6]["installed"] is False
        assert result["risk"] == "HIGH"

    def test_a_known_prefix_only_router_is_quiet_and_recorded(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run(
            {"ndp -rn": NDP_R_GW, "ndp -an": NDP_A_GW_AND_HUB, "ndp -pn": NDP_P_HUB}))
        result = mod.check_ipv6_routers(
            known=[GW_V6, HUB_V6],
            known_details={GW_V6: {"mac": HOME_GW_MAC, "installed": True, "prefixes": [], "routes": []},
                           HUB_V6: {"mac": HUB_MAC, "installed": False, "prefixes": [ULA_PREFIX], "routes": []}})
        assert result["risk"] == "OK" and result["expanded"] == []

    def test_a_known_router_adding_a_route_or_prefix_is_high(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run(
            {"ndp -rn": NDP_R_GW, "ndp -an": NDP_A_GW_AND_HUB, "ndp -pn": NDP_P_HUB,
             "netstat -rn -f inet6": NETSTAT_INET6}))
        result = mod.check_ipv6_routers(
            known=[GW_V6, HUB_V6],
            known_details={GW_V6: {"mac": HOME_GW_MAC, "installed": True, "prefixes": [], "routes": []},
                           HUB_V6: {"mac": HUB_MAC, "installed": False, "prefixes": [ULA_PREFIX], "routes": []}})
        assert result["risk"] == "HIGH"
        assert result["expanded"] == [HUB_V6]
        assert MESH_ROUTE in result["note"]

    def test_a_baseline_that_never_recorded_routes_is_not_a_change(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run(
            {"ndp -rn": NDP_R_GW, "ndp -an": NDP_A_GW_AND_HUB, "ndp -pn": NDP_P_HUB,
             "netstat -rn -f inet6": NETSTAT_INET6}))
        result = mod.check_ipv6_routers(
            known=[GW_V6, HUB_V6],
            known_details={GW_V6: {"mac": HOME_GW_MAC, "installed": True},
                           HUB_V6: {"mac": HUB_MAC, "installed": False, "prefixes": [ULA_PREFIX]}})
        assert result["risk"] == "OK" and result["expanded"] == []

    def test_the_baseline_diff_agrees(self, mod):
        old = {"ipv6_routers": [HUB_V6],
               "ipv6_router_details": {HUB_V6: {"mac": HUB_MAC, "installed": False,
                                                "prefixes": [ULA_PREFIX], "routes": []}}}
        new = {"ipv6_routers": [HUB_V6],
               "ipv6_router_details": {HUB_V6: {"mac": HUB_MAC, "installed": False,
                                                "prefixes": [ULA_PREFIX], "routes": [MESH_ROUTE]}}}
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1 and MESH_ROUTE in notes[0] and "route" in notes[0].lower()
        never = {"ipv6_routers": [HUB_V6],
                 "ipv6_router_details": {HUB_V6: {"mac": HUB_MAC, "installed": False,
                                                  "prefixes": [ULA_PREFIX]}}}
        assert mod.diff_baseline(never, new) == []

    def test_the_monitor_snapshot_keeps_prefix_and_route_advertisers(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({
            "route -n get default": f"   gateway: {HOME_GW}\n",
            "arp -an": f"? ({HOME_GW}) at {HOME_GW_MAC} on en0 ifscope [ethernet]\n",
            "ndp -rn": NDP_R_GW, "ndp -an": NDP_A_GW_AND_HUB, "ndp -pn": NDP_P_HUB,
            "netstat -rn -f inet6": NETSTAT_INET6,
            "scutil --dns": f"  nameserver[0] : {HOME_GW}\n",
        }))
        result = mod.monitor_snapshot()
        assert result["ipv6_routers"] == [GW_V6, HUB_V6]
        assert result["ipv6_router_macs"] == {GW_V6: HOME_GW_MAC, HUB_V6: HUB_MAC}
        assert result["ipv6_router_installed"] == {GW_V6: True, HUB_V6: False}
        assert result["ipv6_router_prefixes"] == {GW_V6: [], HUB_V6: [ULA_PREFIX]}
        assert result["ipv6_router_routes"] == {GW_V6: [], HUB_V6: [MESH_ROUTE]}

    def test_the_monitor_raises_high_when_a_known_router_expands(self, mod):
        old = snap(ipv6_router_prefixes={GW_V6: []}, ipv6_router_routes={GW_V6: []})
        new = snap(ipv6_router_prefixes={GW_V6: [ULA_PREFIX]}, ipv6_router_routes={GW_V6: []})
        events = mod.diff_snapshots(old, new)
        assert [e["kind"] for e in events] == ["ipv6_router_expanded"]
        assert events[0]["severity"] == "HIGH" and ULA_PREFIX in events[0]["detail"]
        routed = snap(ipv6_router_prefixes={GW_V6: []}, ipv6_router_routes={GW_V6: [MESH_ROUTE]})
        assert [e["kind"] for e in mod.diff_snapshots(old, routed)] == ["ipv6_router_expanded"]
        # A reference that never recorded the maps says nothing.
        assert mod.diff_snapshots(snap(), new) == []
        # A prefix withdrawn is not an event, as a router leaving is not.
        assert mod.diff_snapshots(new, old) == []

    def test_a_new_prefix_only_router_is_high_in_the_monitor(self, mod):
        new = snap(ipv6_routers=[GW_V6, HUB_V6], ipv6_router_macs={GW_V6: HOME_GW_MAC, HUB_V6: HUB_MAC},
                   ipv6_router_installed={GW_V6: True, HUB_V6: False})
        events = mod.diff_snapshots(snap(), new)
        assert [e["kind"] for e in events] == ["ipv6_router_appeared"]
        assert events[0]["severity"] == "HIGH"

    def test_a_blank_poll_carries_the_new_maps(self, mod):
        full = snap(ipv6_router_prefixes={GW_V6: [ULA_PREFIX]}, ipv6_router_routes={GW_V6: []})
        blank = snap(ipv6_routers=[], ipv6_router_macs={}, ipv6_router_installed={},
                     ipv6_router_prefixes={}, ipv6_router_routes={})
        carried, _ = mod.carry_forward_blank_fields(blank, full)
        assert carried["ipv6_router_prefixes"] == {GW_V6: [ULA_PREFIX]}
        assert carried["ipv6_router_routes"] == {GW_V6: []}

    def test_the_section_marks_a_prefix_advertiser_as_a_router(self, mod, monkeypatch, capsys):
        no_r_flag = NDP_A_GW + f"{HUB_V6:<40}{HUB_MAC}  en0   21h36m38s S\n"
        monkeypatch.setattr(mod, "run", make_run(
            {"ndp -rn": NDP_R_GW, "ndp -an": no_r_flag, "ndp -pn": NDP_P_HUB}))
        mod.action_ipv6_routers(known=[GW_V6], compact=True)
        out = capsys.readouterr().out
        assert HUB_V6 in out and "advertising as a router" in out


# ---------------------------------------------------------------------------
# F22. A baseline is bound to the network it was taken on
# ---------------------------------------------------------------------------

def pearl_baseline(mod, gateway_mac=PEARL_GW_MAC, ssid="pearl", devices=None):
    mod.select_network_baseline(PEARL)
    state = {"timestamp": at(days=-7).isoformat(), "gateway": PEARL_GW, "gateway_mac": gateway_mac,
             "arp_spoof": {"gateway": PEARL_GW, "macs_seen": [gateway_mac] if gateway_mac else [],
                           "spoofing_suspected": False},
             "dns": [PEARL_GW], "router_open_ports": [80],
             "devices": devices if devices is not None else [
                 {"ip": PEARL_GW, "mac": gateway_mac or "unknown", "subnet": PEARL},
                 {"ip": HUB_IP, "mac": HUB_MAC, "subnet": PEARL}],
             "scanned_subnets": [PEARL],
             "wifi": {"ssid": ssid, "auth": "WPA2", "cipher": "AES", "risk": "OK", "note": ""}}
    mod.save_baseline(state)
    return state


class TestABaselineIsBoundToItsNetwork:
    def test_the_audit_records_the_gateway_mac_it_saw(self, mod):
        assert mod.observed_gateway_mac(HOME_GW_MAC, {"macs_seen": [HOME_GW_MAC]}) == HOME_GW_MAC
        assert mod.observed_gateway_mac(None, {"macs_seen": [HOME_GW_MAC]}) == HOME_GW_MAC
        assert mod.observed_gateway_mac(HOME_GW_MAC, {"macs_seen": []}) == HOME_GW_MAC
        # Two MACs in six seconds is poisoning in progress; the baseline binds to neither.
        assert mod.observed_gateway_mac(HOME_GW_MAC, {"macs_seen": [HOME_GW_MAC, ATTACKER_MAC]}) is None
        assert mod.observed_gateway_mac(None, None) is None

    def test_a_baseline_from_before_the_key_is_read_from_its_arp_check(self, mod):
        assert mod.baseline_gateway_mac({"gateway_mac": HOME_GW_MAC}) == HOME_GW_MAC
        assert mod.baseline_gateway_mac({"arp_spoof": {"macs_seen": [HOME_GW_MAC]}}) == HOME_GW_MAC
        assert mod.baseline_gateway_mac({"arp_spoof": {"macs_seen": [HOME_GW_MAC, ATTACKER_MAC]}}) is None
        assert mod.baseline_gateway_mac({"gateway_mac": "not a mac"}) is None
        assert mod.baseline_gateway_mac(None) is None
        assert mod.baseline_ssid({"wifi": {"ssid": "pearl"}}) == "pearl"
        assert mod.baseline_ssid({"wifi": {"ssid": None}}) is None

    def test_a_strangers_network_with_the_same_addresses_is_refused(self, mod, capsys):
        """The city Mac at the beach house: 192.168.86.0/24 there too, a different
        Google Wifi, a different SSID. pearl's chain must not audit it."""
        pearl_baseline(mod)
        key = mod.select_network_baseline(PEARL, gateway_mac=BEACH_GW_MAC, ssid="BeachHouse")
        assert key == "192-168-86-0-24"
        out = capsys.readouterr().out
        assert "[REVIEW] The baseline for 192.168.86.0/24 was taken on a different network" in out
        assert mod.baseline_refused()
        assert mod.load_baseline() is None, "a refused baseline must not be compared against"
        assert mod.load_baseline_record() is not None, "the file itself is untouched"

    def test_the_same_ssid_with_a_new_gateway_mac_is_compared_not_refused(self, mod):
        """The other reading of a changed gateway MAC is ARP poisoning on the
        home network, and refusing the chain there would silence the one HIGH
        the comparison exists to raise."""
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL, gateway_mac=ATTACKER_MAC, ssid="pearl")
        assert mod.baseline_refused() is None
        notes = mod.diff_baseline(mod.load_baseline(),
                                  {"gateway": PEARL_GW, "arp_spoof": {"macs_seen": [ATTACKER_MAC]}})
        assert any("Gateway MAC CHANGED" in n for n in notes)

    def test_a_known_device_on_the_link_ties_the_network_to_its_baseline(self, mod):
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL, gateway_mac=ATTACKER_MAC, seen_macs={HUB_MAC})
        assert mod.baseline_refused() is None

    def test_with_nothing_tying_them_the_refusal_names_both_readings(self, mod, capsys):
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL, gateway_mac=ATTACKER_MAC, seen_macs={"d4:a6:51:00:00:99"})
        reason = mod.baseline_refused()
        assert reason and "different network" in reason
        assert "ARP poisoning" in reason or "different hardware" in reason
        assert PEARL_GW_MAC in reason and ATTACKER_MAC in reason

    def test_a_different_ssid_refuses_even_when_the_mac_matches_nothing_else(self, mod):
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL, gateway_mac=BEACH_GW_MAC, ssid="BeachHouse", seen_macs={HUB_MAC})
        # The SSID is the stronger witness: a known device's MAC is a claim any
        # sender can make, a beacon with another name is a different network.
        assert mod.baseline_refused() and "BeachHouse" in mod.baseline_refused()

    def test_the_same_mac_is_accepted_whatever_else_differs(self, mod):
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL, gateway_mac=PEARL_GW_MAC, ssid="pearl-5G")
        assert mod.baseline_refused() is None and mod.load_baseline() is not None

    def test_a_baseline_without_a_recorded_mac_is_adopted_as_before(self, mod):
        pearl_baseline(mod, gateway_mac=None)
        mod.select_network_baseline(PEARL, gateway_mac=BEACH_GW_MAC, ssid="BeachHouse")
        assert mod.baseline_refused() is None and mod.load_baseline() is not None

    def test_selecting_without_a_live_mac_clears_an_earlier_refusal(self, mod):
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL, gateway_mac=BEACH_GW_MAC, ssid="BeachHouse")
        assert mod.baseline_refused()
        mod.select_network_baseline(HOME)
        assert mod.baseline_refused() is None

    def test_a_refused_chain_is_not_saved_to(self, mod, monkeypatch, capsys):
        pearl_baseline(mod)
        monkeypatch.setattr(mod, "use_current_network_baseline",
                            lambda *a, **k: (PEARL, mod.select_network_baseline(
                                PEARL, gateway_mac=k.get("gateway_mac"), ssid=k.get("ssid"),
                                seen_macs=k.get("seen_macs") or ())))
        monkeypatch.setattr(mod, "resolve_passphrase", lambda prompt=False: None)
        seq_before = mod.load_baseline_record()["seq"]
        mod.action_save_baseline({"timestamp": at().isoformat(), "gateway": PEARL_GW,
                                  "gateway_mac": BEACH_GW_MAC, "router_open_ports": [22],
                                  "devices": [{"ip": PEARL_GW, "mac": BEACH_GW_MAC, "subnet": PEARL}],
                                  "scanned_subnets": [PEARL],
                                  "wifi": {"ssid": "BeachHouse", "risk": "OK", "note": ""}})
        out = capsys.readouterr().out
        assert "different network" in out and "not saved" in out.lower()
        assert mod.load_baseline_record()["seq"] == seq_before
        assert mod.load_baseline_record()["state"]["router_open_ports"] == [80]

    def test_the_menu_comparison_says_why_it_compared_nothing(self, mod, monkeypatch, capsys):
        pearl_baseline(mod)
        monkeypatch.setattr(mod, "use_current_network_baseline",
                            lambda *a, **k: (PEARL, mod.select_network_baseline(
                                PEARL, gateway_mac=k.get("gateway_mac"), ssid=k.get("ssid"),
                                seen_macs=k.get("seen_macs") or ())))
        monkeypatch.setattr(mod, "resolve_passphrase", lambda prompt=False: None)
        monkeypatch.delenv(mod.SINK_ENV, raising=False)
        mod.action_compare_baseline({"timestamp": at().isoformat(), "gateway": PEARL_GW,
                                     "gateway_mac": BEACH_GW_MAC, "router_open_ports": [22],
                                     "wifi": {"ssid": "BeachHouse", "risk": "OK", "note": ""}})
        out = capsys.readouterr().out
        assert "different network" in out
        assert "CHANGES DETECTED" not in out and "No baseline saved yet" not in out

    def test_the_monitor_refuses_a_chain_whose_baseline_is_another_networks(self, mod, monkeypatch, tmp_path):
        pearl_baseline(mod)
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        on_network(mod, monkeypatch, PEARL)
        beach = snap(gateway=PEARL_GW, gateway_mac=BEACH_GW_MAC, ipv6_routers=[], ipv6_router_macs={},
                     ipv6_router_installed={}, dns=[PEARL_GW],
                     neighbours=[PEARL_GW, "192.168.86.50"],
                     neighbour_macs={PEARL_GW: BEACH_GW_MAC, "192.168.86.50": "f0:9f:c2:bb:00:05"})
        lines = []
        monkeypatch.setattr(mod, "monitor_snapshot", lambda critical_ips=(): beach)
        events = mod.run_monitor(interval=0, iterations=3, sleeper=lambda _: None,
                                 printer=lambda *a: lines.append(" ".join(str(x) for x in a)),
                                 clock=lambda: at(), heartbeat_interval=0)
        assert [e["kind"] for e in events] == ["baseline_foreign"], "said once, not once per poll"
        assert events[0]["severity"] == "REVIEW"
        assert any("taken on a different network" in l for l in lines)
        mod.select_network_baseline(PEARL)
        assert mod.load_monitor_state() == (None, None), "nothing saved under pearl's chain"
        assert mod.read_heartbeats(str(sink)) == [], "nothing heartbeated under pearl's chain"

    def test_the_monitor_compares_once_a_known_device_ties_the_network_to_the_chain(
            self, mod, monkeypatch, tmp_path):
        """A poisoned gateway on pearl itself: the hub is still there, so this is
        pearl, and the changed MAC is the HIGH it always was."""
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL)
        reference = snap(gateway=PEARL_GW, gateway_mac=PEARL_GW_MAC, ipv6_routers=[], ipv6_router_macs={},
                         ipv6_router_installed={}, dns=[PEARL_GW], neighbours=[PEARL_GW, HUB_IP],
                         neighbour_macs={PEARL_GW: PEARL_GW_MAC, HUB_IP: HUB_MAC})
        mod.save_monitor_state(reference, at=at(minutes=-1))
        on_network(mod, monkeypatch, PEARL)
        poisoned = dict(reference, gateway_mac=ATTACKER_MAC,
                        neighbour_macs={PEARL_GW: ATTACKER_MAC, HUB_IP: HUB_MAC})
        events = watch(mod, monkeypatch, [poisoned], clock=lambda: at())
        assert [e["kind"] for e in events] == ["gateway_mac_changed"]
        assert events[0]["severity"] == "HIGH"
        assert mod.load_monitor_state()[0]["gateway_mac"] == ATTACKER_MAC

    def test_the_monitor_decides_again_each_poll_while_it_refuses(self, mod, monkeypatch):
        """Right after joining, the ARP cache holds only the gateway. A poisoned
        gateway then looks like a foreign network — until a household device
        answers, and the chain is accepted and the comparison made."""
        pearl_baseline(mod)
        mod.select_network_baseline(PEARL)
        reference = snap(gateway=PEARL_GW, gateway_mac=PEARL_GW_MAC, ipv6_routers=[], ipv6_router_macs={},
                         ipv6_router_installed={}, dns=[PEARL_GW], neighbours=[PEARL_GW, HUB_IP],
                         neighbour_macs={PEARL_GW: PEARL_GW_MAC, HUB_IP: HUB_MAC})
        mod.save_monitor_state(reference, at=at(minutes=-1))
        on_network(mod, monkeypatch, PEARL)
        alone = dict(reference, gateway_mac=ATTACKER_MAC, neighbours=[PEARL_GW],
                     neighbour_macs={PEARL_GW: ATTACKER_MAC})
        hub_back = dict(reference, gateway_mac=ATTACKER_MAC,
                        neighbour_macs={PEARL_GW: ATTACKER_MAC, HUB_IP: HUB_MAC})
        events = watch(mod, monkeypatch, [alone, alone, hub_back], clock=lambda: at())
        assert [e["kind"] for e in events] == ["baseline_foreign", "gateway_mac_changed"]


class TestAWiderMaskAdoptsOnlyAContainingBaseline:
    def _save(self, mod, subnet):
        mod.select_network_baseline(subnet)
        prefix = subnet.rsplit(".", 1)[0]
        mod.save_baseline({"timestamp": at().isoformat(), "gateway": f"{prefix}.1",
                           "router_open_ports": [80], "scanned_subnets": [subnet]})

    def test_a_23_lease_does_not_adopt_the_24_inside_it(self, mod, capsys):
        """A rogue DHCP server handing loveshack a /23 made the run pearl's:
        192.168.86.0/23 matched pearl's network address, so pearl's chain was
        adopted, diffed against loveshack and saved over."""
        self._save(mod, PEARL)
        key = mod.select_network_baseline("192.168.86.0/23")
        assert key == "192-168-86-0-23"
        assert mod.load_baseline() is None, "pearl's chain was adopted by a wider network"
        out = capsys.readouterr().out
        assert "192.168.86.0/24" in out and "fresh baseline" in out

    def test_a_narrower_lease_adopts_the_baseline_that_contains_it_and_says_so(self, mod, capsys):
        self._save(mod, HOME)
        assert mod.select_network_baseline("192.168.87.0/25") == "192-168-87-0-24"
        assert mod.load_baseline()["router_open_ports"] == [80]
        assert "contains" in capsys.readouterr().out

    def test_a_containing_baseline_with_another_inside_it_is_ambiguous(self, mod, tmp_path):
        self._save(mod, HOME)
        directory = str(tmp_path / "home_net_audit_data")
        (tmp_path / "home_net_audit_data" / "baseline-192-168-87-128-25.json").write_text("{}")
        assert mod.existing_key_for_same_network(directory, "192.168.87.0/25") is None

    def test_the_narrowest_containing_baseline_wins(self, mod, tmp_path):
        self._save(mod, HOME)
        directory = str(tmp_path / "home_net_audit_data")
        (tmp_path / "home_net_audit_data" / "baseline-192-168-86-0-23.json").write_text("{}")
        # The /23 contains the /24 which contains the request: the /23 is
        # disqualified by the /24 inside it, the /24 is adopted.
        assert mod.existing_key_for_same_network(directory, "192.168.87.0/26") == "192-168-87-0-24"

    def test_the_exact_key_still_wins_and_prints_nothing(self, mod, capsys):
        self._save(mod, HOME)
        capsys.readouterr()
        assert mod.select_network_baseline(HOME) == "192-168-87-0-24"
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# F23. IPv6-only hosts are devices
# ---------------------------------------------------------------------------

class TestIPv6OnlyHostsAreDevices:
    IFACES = [("en0", "192.168.87.25", ipaddress.ip_network(HOME))]

    def test_neighbour_table_hosts_join_the_device_list_by_mac(self, mod, monkeypatch):
        fake = make_run({"ndp -an": NDP_A_DEVICES})
        monkeypatch.setattr(mod, "run", fake)
        swept = [{"ip": HOME_GW, "mac": HOME_GW_MAC, "subnet": HOME}]
        extra, macs = mod.ipv6_only_devices(swept, self.IFACES)
        assert extra == [{"ip": None, "ip6": CAMERA_V6, "mac": CAMERA_MAC, "subnet": HOME},
                         {"ip": None, "ip6": HUB_V6, "mac": HUB_MAC, "subnet": HOME}]
        assert macs == sorted([HOME_GW_MAC, HUB_MAC, CAMERA_MAC])

    def test_the_all_nodes_probe_goes_out_before_the_table_is_read(self, mod, monkeypatch):
        fake = make_run({"ndp -an": NDP_A_DEVICES})
        monkeypatch.setattr(mod, "run", fake)
        mod.ipv6_only_devices([], self.IFACES)
        probes = [c for c in fake.calls if c.startswith("ping6 -c 1 ff02::1%en0")]
        assert len(probes) == 1
        assert fake.calls.index(probes[0]) < fake.calls.index("ndp -an")

    def test_the_stable_address_is_the_one_recorded(self, mod):
        # Identity is the MAC; the address kept is the one least likely to
        # rotate — link-local, then a ULA, then anything global.
        assert mod.preferred_ipv6([HUB_ULA, HUB_V6]) == HUB_V6
        assert mod.preferred_ipv6([HUB_ULA, "2001:db8::1%en0"]) == HUB_ULA
        assert mod.preferred_ipv6(["2001:db8::1%en0"]) == "2001:db8::1%en0"
        assert mod.preferred_ipv6([]) is None

    def test_a_host_the_sweep_found_is_not_duplicated(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({"ndp -an": NDP_A_GW}))
        assert mod.ipv6_only_devices([{"ip": HOME_GW, "mac": HOME_GW_MAC.upper()}], self.IFACES)[0] == []
        # Nothing swept at all: every neighbour with a MAC is a device, with no
        # subnet to file it under when no interface is known.
        assert mod.ipv6_only_devices([], []) == (
            [{"ip": None, "ip6": GW_V6, "mac": HOME_GW_MAC}], [HOME_GW_MAC])

    def test_a_mac_still_in_the_neighbour_table_is_not_gone(self, mod):
        """The 1 November report: the Apple TV 'gone since baseline' and
        'advertising as a router' in the same report."""
        old = {"timestamp": at(days=-7).isoformat(), "scanned_subnets": [HOME],
               "devices": [{"ip": HOME_GW, "mac": HOME_GW_MAC, "subnet": HOME},
                           {"ip": "192.168.87.40", "mac": HUB_MAC, "subnet": HOME}]}
        new = {"timestamp": at().isoformat(), "scanned_subnets": [HOME],
               "devices": [{"ip": HOME_GW, "mac": HOME_GW_MAC, "subnet": HOME}],
               "ipv6_neighbour_macs": [HOME_GW_MAC, HUB_MAC]}
        assert mod.diff_baseline(old, new) == []
        without = dict(new, ipv6_neighbour_macs=[HOME_GW_MAC])
        assert any("gone" in n for n in mod.diff_baseline(old, without))

    def test_an_ipv6_only_newcomer_is_new_and_a_returning_one_is_remembered(self, mod):
        old = {"timestamp": at(days=-7).isoformat(), "scanned_subnets": [HOME],
               "devices": [{"ip": HOME_GW, "mac": HOME_GW_MAC, "subnet": HOME}]}
        new = {"timestamp": at().isoformat(), "scanned_subnets": [HOME],
               "devices": [{"ip": HOME_GW, "mac": HOME_GW_MAC, "subnet": HOME},
                           {"ip": None, "ip6": CAMERA_V6, "mac": CAMERA_MAC, "subnet": HOME}],
               "ipv6_neighbour_macs": [HOME_GW_MAC, CAMERA_MAC]}
        notes = mod.diff_baseline(old, new, labels={CAMERA_MAC: "Hall camera"})
        assert len(notes) == 1 and "NEW device" in notes[0] and "Hall camera" in notes[0]
        memory = mod.update_device_memory(old, new)
        assert CAMERA_MAC in memory

    def test_the_device_table_prints_an_address_for_a_host_without_ipv4(self, mod, capsys):
        mod._print_devices_grouped([{"ip": None, "ip6": CAMERA_V6, "mac": CAMERA_MAC, "subnet": HOME}],
                                   {CAMERA_MAC: "Hall camera"}, {HOME: "loveshack"})
        out = capsys.readouterr().out
        assert CAMERA_V6 in out and "Hall camera" in out and "None" not in out

    def test_names_are_only_asked_of_hosts_with_an_ipv4_address(self, mod):
        assert mod.collect_device_names([{"ip": None, "ip6": CAMERA_V6, "mac": CAMERA_MAC}]) == ""
