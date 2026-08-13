"""Tests for diff_baseline() — the tool's change-detection brain.

Quality matters in both directions here: a missed change is a missed intrusion,
a spurious change is alarm fatigue that trains the user to ignore the report.
So every "produces a note" test is paired with a "produces NO note" test for
the nearest-neighbour non-event (reordering, same-set, unknown MACs).

diff_baseline is pure — dict in, list-of-strings out — so nothing here needs
the command fakes; the autouse sandbox still guarantees no baseline on disk is
touched.
"""

import pytest


def dev(mac, ip="192.168.1.10", subnet="192.168.1.0/24", **extra):
    """A device dict shaped like collect_devices() produces (line 2005)."""
    d = {"ip": ip, "mac": mac, "subnet": subnet}
    d.update(extra)
    return d


LAPTOP = "3c:22:fb:11:22:33"
PRINTER = "34:64:a9:aa:bb:cc"
INTRUDER = "b8:27:eb:de:ad:01"


class TestDeviceAppearedOrVanished:
    def test_mac_only_in_new_produces_one_note_naming_it(self, mod):
        old = {"devices": [dev(LAPTOP)]}
        new = {"devices": [dev(LAPTOP), dev(INTRUDER, ip="192.168.1.66")]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert INTRUDER in notes[0]
        assert LAPTOP not in notes[0], "unchanged device must not be named"

    def test_mac_only_in_old_produces_one_note_naming_it(self, mod):
        old = {"devices": [dev(LAPTOP), dev(PRINTER, ip="192.168.1.40")]}
        new = {"devices": [dev(LAPTOP)]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert PRINTER in notes[0]

    def test_appeared_and_vanished_are_two_separate_notes(self, mod):
        old = {"devices": [dev(PRINTER)]}
        new = {"devices": [dev(INTRUDER)]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 2
        appeared = [n for n in notes if INTRUDER in n]
        vanished = [n for n in notes if PRINTER in n]
        assert len(appeared) == 1 and len(vanished) == 1
        assert appeared[0] != vanished[0], "the two events must not share a note"

    def test_several_new_devices_are_collapsed_into_one_note(self, mod):
        old = {"devices": []}
        new = {"devices": [dev(INTRUDER), dev(PRINTER, ip="192.168.1.40")]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert INTRUDER in notes[0] and PRINTER in notes[0]

    def test_device_order_is_not_a_change(self, mod):
        old = {"devices": [dev(LAPTOP), dev(PRINTER, ip="192.168.1.40")]}
        new = {"devices": [dev(PRINTER, ip="192.168.1.40"), dev(LAPTOP)]}

        assert mod.diff_baseline(old, new) == []

    def test_same_mac_on_a_new_ip_is_not_reported(self, mod):
        # DOCUMENTS ACTUAL BEHAVIOUR, not necessarily desired behaviour: only
        # the MAC set is compared, so a DHCP lease change is silent. That is
        # arguably right (lease churn is constant noise) and arguably wrong (an
        # ARP-spoofing device takes over a new IP silently). Left un-xfailed
        # because the intent is genuinely ambiguous.
        old = {"devices": [dev(LAPTOP, ip="192.168.1.50")]}
        new = {"devices": [dev(LAPTOP, ip="192.168.1.77")]}

        assert mod.diff_baseline(old, new) == []

    def test_a_mac_differing_only_in_case_is_the_same_device(self, mod):
        # Fixed regression: the MAC sets were built from the raw d['mac']
        # strings, so the comparison was case-sensitive and '3C:22:FB:...' and
        # '3c:22:fb:...' were two different devices — one unmoved device raised
        # BOTH a 'NEW device(s)' and a 'Device(s) gone' note. read_arp_table
        # normalises to lowercase, so the two sides agreed only by accident; a
        # hand-edited or vendor-pasted baseline (uppercase is the usual vendor
        # rendering) broke the coincidence and double-alarmed for ever.
        # _split now lowercases both sides.
        old = {"devices": [dev(LAPTOP.upper())]}
        new = {"devices": [dev(LAPTOP)]}

        assert mod.diff_baseline(old, new) == []


class TestUnknownMacsAreSuppressed:
    """mac == "unknown" means the ARP cache had no entry, which flaps between
    scans. Both sides filter it out (lines 420-421) so it can never raise an
    alarm — deliberate noise suppression that is easy to break."""

    def test_unknown_mac_appearing_produces_no_note(self, mod):
        old = {"devices": [dev(LAPTOP)]}
        new = {"devices": [dev(LAPTOP), dev("unknown", ip="192.168.1.99")]}

        assert mod.diff_baseline(old, new) == []

    def test_unknown_mac_vanishing_produces_no_note(self, mod):
        old = {"devices": [dev(LAPTOP), dev("unknown", ip="192.168.1.99")]}
        new = {"devices": [dev(LAPTOP)]}

        assert mod.diff_baseline(old, new) == []

    def test_two_different_unknown_mac_devices_do_not_cancel_into_an_alarm(self, mod):
        # Both sides hold a single unknown-MAC device on different IPs: a naive
        # implementation that kept "unknown" in the set would still be quiet,
        # but one that keyed on (ip, mac) would fire twice.
        old = {"devices": [dev("unknown", ip="192.168.1.31")]}
        new = {"devices": [dev("unknown", ip="192.168.1.32")]}

        assert mod.diff_baseline(old, new) == []

    def test_a_real_new_mac_is_still_reported_alongside_unknowns(self, mod):
        old = {"devices": [dev("unknown", ip="192.168.1.31")]}
        new = {"devices": [dev("unknown", ip="192.168.1.32"), dev(INTRUDER)]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert INTRUDER in notes[0]
        assert "unknown" not in notes[0]


class TestRouterPorts:
    def test_newly_opened_port_produces_one_note_listing_it(self, mod):
        old = {"router_open_ports": [80, 443]}
        new = {"router_open_ports": [80, 443, 23]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "23" in notes[0]
        assert "443" not in notes[0], "unchanged port must not be listed"

    def test_newly_closed_port_produces_one_note_listing_it(self, mod):
        old = {"router_open_ports": [80, 443]}
        new = {"router_open_ports": [443]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "80" in notes[0]

    def test_opened_and_closed_are_two_separate_notes(self, mod):
        old = {"router_open_ports": [80, 443]}
        new = {"router_open_ports": [443, 23]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 2
        opened = [n for n in notes if "23" in n]
        closed = [n for n in notes if "80" in n]
        assert len(opened) == 1 and len(closed) == 1
        assert opened[0] != closed[0]

    def test_port_order_is_not_a_change(self, mod):
        old = {"router_open_ports": [443, 80, 53]}
        new = {"router_open_ports": [53, 443, 80]}

        assert mod.diff_baseline(old, new) == []

    def test_repeated_port_in_a_hand_edited_baseline_is_not_a_change(self, mod):
        old = {"router_open_ports": [80, 80, 443]}
        new = {"router_open_ports": [443, 80]}

        assert mod.diff_baseline(old, new) == []

    def test_both_sides_missing_the_key_is_not_a_change(self, mod):
        assert mod.diff_baseline({"dns": ["1.1.1.1"]}, {"dns": ["1.1.1.1"]}) == []

    def test_an_unmeasured_port_section_is_not_read_as_every_port_closing(self, mod):
        # This test previously pinned the OPPOSITE, as a documented wart: an
        # absent "router_open_ports" was treated as "no ports open" rather than
        # "not measured", so a scan that could not reach the gateway raised a
        # false "every port closed" alarm.
        #
        # The wart had a real cause, found later: macOS Local Network privacy
        # denies a launchd-scheduled run any connection to its own subnet, and
        # the refusal arrives as an instant EHOSTUNREACH. check_port collapsed
        # that to False, so a blocked scan looked exactly like a router with
        # nothing listening — and every scheduled run wrote that false empty
        # list into the baseline. probe_port keeps the states apart and
        # audit_host now returns None for a blocked scan, so the diff has an
        # "unknown" to recognise. Unknown on either side means no comparison.
        old = {"router_open_ports": [80, 443]}

        assert mod.diff_baseline(old, {}) == []
        assert mod.diff_baseline(old, {"router_open_ports": None}) == []

    def test_a_recovered_scan_after_a_blocked_one_is_not_read_as_new_ports(self, mod):
        # The mirror image, and the reason "unknown" must not default to []:
        # otherwise the run after a blocked one reports every port as newly
        # opened. Both directions have to stay silent.
        assert mod.diff_baseline({"router_open_ports": None},
                                 {"router_open_ports": [80, 443]}) == []

    def test_a_real_port_change_is_still_reported(self, mod):
        # The safety valve above must not silence genuine findings.
        notes = mod.diff_baseline({"router_open_ports": [80]},
                                  {"router_open_ports": [80, 23]})
        assert len(notes) == 1
        assert "23" in notes[0]


class TestUnmeasuredDoesNotDestroyTheBaseline:
    """A run that could not measure must not overwrite the last real reading.

    Found by adversarial review of the unreachable-scan change, which hardened
    the read side (diff_baseline skips unknowns) without hardening the write
    side. The combination was worse than the bug it replaced: a blocked run
    saved None over the known-good port list, and because the diff then refuses
    to compare against an unknown, the NEXT successful run reported nothing and
    re-baselined its own reading as known-good. A port opened in between was
    never reported, on that run or any later one — where the pre-change
    behaviour at least raised a noisy false alarm that named the port.

    main()'s existing guard cannot catch this: it skips the save only when the
    gateway is unknown, and the gateway comes from the routing table, which
    macOS Local Network privacy does not gate. A blocked scheduled run has a
    perfectly good gateway and an unmeasurable scan.
    """

    def test_an_unmeasured_scan_keeps_the_previous_reading(self, mod):
        previous = {"router_open_ports": [80, 443]}
        merged = mod.carry_forward_unmeasured(
            {"gateway": "192.168.87.1", "router_open_ports": None}, previous)
        assert merged["router_open_ports"] == [80, 443]

    def test_the_substitution_is_recorded_rather_than_silent(self, mod):
        # The baseline must not imply a measurement that was never taken.
        merged = mod.carry_forward_unmeasured(
            {"router_open_ports": None}, {"router_open_ports": [80]})
        assert merged["carried_forward"] == ["router_open_ports"]

    def test_a_real_reading_is_never_overwritten_by_an_older_one(self, mod):
        merged = mod.carry_forward_unmeasured(
            {"router_open_ports": [22]}, {"router_open_ports": [80, 443]})
        assert merged["router_open_ports"] == [22]
        assert "carried_forward" not in merged

    def test_an_empty_list_is_a_real_measurement_and_is_kept(self, mod):
        # [] means "scanned, nothing listening" — a genuine finding, and the
        # whole point of the tri-state. Only None is "not measured".
        merged = mod.carry_forward_unmeasured(
            {"router_open_ports": []}, {"router_open_ports": [80]})
        assert merged["router_open_ports"] == []

    def test_no_previous_baseline_leaves_the_unknown_as_unknown(self, mod):
        merged = mod.carry_forward_unmeasured({"router_open_ports": None}, {})
        assert merged["router_open_ports"] is None

    def test_a_run_that_skipped_discovery_keeps_the_known_devices(self, mod):
        # A real incident, not a hypothetical. `--no-discovery` produces a state
        # with no "devices" key at all; saving it wiped a baseline of ten known
        # devices, and the next audit would have reported every device in the
        # house as newly arrived. Skipping the sweep says "do not spend the time
        # looking", never "there is nothing there".
        known = [{"ip": "192.168.87.1", "mac": "38:8b:59:e0:f1:70",
                  "subnet": "192.168.87.0/24"}]
        previous = {"devices": known, "scanned_subnets": ["192.168.87.0/24"]}
        merged = mod.carry_forward_unmeasured({"gateway": "192.168.87.1"}, previous)

        assert merged["devices"] == known
        assert merged["scanned_subnets"] == ["192.168.87.0/24"]
        assert "devices" in merged["carried_forward"]

    def test_a_sweep_that_genuinely_found_nothing_is_kept(self, mod):
        # [] is a measurement — the sweep ran and the network was empty — and
        # must not be replaced by an older, richer list. Only an absent key or
        # None means "not measured".
        merged = mod.carry_forward_unmeasured(
            {"devices": []}, {"devices": [{"mac": "aa:bb:cc:dd:ee:ff"}]})
        assert merged["devices"] == []

    def test_the_upstream_modem_reading_is_carried_forward_too(self, mod):
        merged = mod.carry_forward_unmeasured(
            {"upstream_open_ports": None}, {"upstream_open_ports": [443]})
        assert merged["upstream_open_ports"] == [443]

    def test_a_port_opened_during_a_blocked_run_is_still_reported_afterwards(
            self, mod, tmp_path, monkeypatch):
        # The reviewer's end-to-end scenario, through the real save path.
        monkeypatch.setattr(mod, "BASELINE_FILE", str(tmp_path / "baseline.json"))
        monkeypatch.setattr(mod, "HISTORY_FILE", str(tmp_path / "history.jsonl"))

        # 1. A good interactive run establishes the known-good ports.
        mod.save_baseline({"gateway": "192.168.87.1",
                           "router_open_ports": [80, 443]})

        # 2. A blocked scheduled run: gateway resolves, scan does not.
        mod.save_baseline({"gateway": "192.168.87.1",
                           "router_open_ports": None})
        assert mod.load_baseline()["router_open_ports"] == [80, 443], \
            "the blocked run destroyed the known-good reading"

        # 3. Telnet appears. The next successful run must say so.
        notes = mod.diff_baseline(mod.load_baseline(),
                                  {"gateway": "192.168.87.1",
                                   "router_open_ports": [80, 443, 23]})
        assert any("23" in n for n in notes), \
            f"a newly opened port went unreported after a blocked run: {notes}"


class TestDNS:
    def test_changed_dns_server_produces_one_note(self, mod):
        old = {"dns": ["192.168.1.1"]}
        new = {"dns": ["45.33.12.9"]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "45.33.12.9" in notes[0]

    def test_reordered_dns_with_the_same_set_is_not_a_change(self, mod):
        # Resolver order flips between scans on multi-homed macs; the code
        # compares sets (line 434) precisely so that is not an alarm.
        old = {"dns": ["1.1.1.1", "8.8.8.8", "192.168.1.1"]}
        new = {"dns": ["192.168.1.1", "1.1.1.1", "8.8.8.8"]}

        assert mod.diff_baseline(old, new) == []

    def test_duplicated_dns_entry_is_not_a_change(self, mod):
        old = {"dns": ["1.1.1.1", "1.1.1.1"]}
        new = {"dns": ["1.1.1.1"]}

        assert mod.diff_baseline(old, new) == []

    def test_an_added_dns_server_is_a_change(self, mod):
        old = {"dns": ["192.168.1.1"]}
        new = {"dns": ["192.168.1.1", "45.33.12.9"]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "45.33.12.9" in notes[0]

    def test_a_removed_dns_server_is_a_change(self, mod):
        old = {"dns": ["192.168.1.1", "1.1.1.1"]}
        new = {"dns": ["192.168.1.1"]}

        assert len(mod.diff_baseline(old, new)) == 1

    def test_dns_note_names_the_section_it_is_about(self, mod):
        notes = mod.diff_baseline({"dns": ["1.1.1.1"]}, {"dns": ["9.9.9.9"]})

        assert "DNS" in notes[0].upper()


class TestNoChangeIsSilent:
    def test_identical_states_produce_no_notes(self, mod):
        state = {
            "timestamp": "2026-08-11 09:00:00",
            "devices": [dev(LAPTOP), dev(PRINTER, ip="192.168.1.40")],
            "router_open_ports": [53, 80, 443],
            "upstream_open_ports": [],
            "dns": ["192.168.1.1", "1.1.1.1"],
        }

        assert mod.diff_baseline(state, dict(state)) == []

    def test_a_changed_timestamp_alone_is_not_a_change(self, mod):
        old = {"timestamp": "2026-08-01 09:00:00", "dns": ["1.1.1.1"]}
        new = {"timestamp": "2026-08-11 21:30:00", "dns": ["1.1.1.1"]}

        assert mod.diff_baseline(old, new) == []

    def test_two_empty_states_produce_no_notes_and_no_exception(self, mod):
        assert mod.diff_baseline({}, {}) == []

    def test_empty_device_and_port_lists_produce_no_notes(self, mod):
        empty = {"devices": [], "router_open_ports": [], "dns": []}

        assert mod.diff_baseline(empty, dict(empty)) == []


class TestCombinedChanges:
    def test_each_simultaneous_change_gets_its_own_note(self, mod):
        old = {
            "devices": [dev(LAPTOP), dev(PRINTER, ip="192.168.1.40")],
            "router_open_ports": [80, 443],
            "dns": ["192.168.1.1"],
        }
        new = {
            "devices": [dev(LAPTOP), dev(INTRUDER, ip="192.168.1.66")],
            "router_open_ports": [80, 443, 23],
            "dns": ["45.33.12.9"],
        }

        notes = mod.diff_baseline(old, new)

        # new device, gone device, opened port, changed DNS
        assert len(notes) == 4
        assert len(set(notes)) == 4, "each change must get its own distinct note"
        assert any(INTRUDER in n for n in notes)
        assert any(PRINTER in n for n in notes)
        assert any("23" in n for n in notes)
        assert any("45.33.12.9" in n for n in notes)

    def test_notes_are_non_empty_strings(self, mod):
        old = {"devices": [dev(PRINTER)], "router_open_ports": [80], "dns": ["1.1.1.1"]}
        new = {"devices": [dev(INTRUDER)], "router_open_ports": [23], "dns": ["9.9.9.9"]}

        notes = mod.diff_baseline(old, new)

        assert isinstance(notes, list)
        assert notes, "a fully changed state must produce notes"
        for n in notes:
            assert isinstance(n, str)
            assert n.strip(), "a blank note would print as an empty alarm line"

    def test_inputs_are_not_mutated(self, mod):
        old = {"devices": [dev(PRINTER)], "router_open_ports": [80], "dns": ["1.1.1.1"]}
        new = {"devices": [dev(INTRUDER)], "router_open_ports": [23], "dns": ["9.9.9.9"]}
        old_copy, new_copy = repr(old), repr(new)

        mod.diff_baseline(old, new)

        assert repr(old) == old_copy and repr(new) == new_copy


class TestKnownBugs:
    @pytest.mark.parametrize("corrupt_side", ["old", "new"], ids=["corrupt_old", "corrupt_new"])
    def test_device_entry_without_a_mac_key_degrades_instead_of_raising(self, mod, corrupt_side):
        # Fixed regression: d['mac'] was indexed directly, so one device dict
        # missing the 'mac' key raised KeyError and change detection died
        # outright. Baselines are hand-editable JSON on disk and a truncated
        # write corrupts them. _split now skips entries without a usable MAC.
        healthy = {"devices": [dev(LAPTOP)]}
        corrupt = {"devices": [{"ip": "192.168.1.99"}]}  # truncated write: no "mac"
        old, new = (corrupt, healthy) if corrupt_side == "old" else (healthy, corrupt)

        notes = mod.diff_baseline(old, new)

        assert isinstance(notes, list)
        assert all(isinstance(n, str) for n in notes)
        # Asserting only "it did not raise" was too weak to be worth much: a
        # version that indexed the corrupt record as an empty MAC also passes
        # that, while emitting "NEW device(s) since baseline: " — an unnamed
        # intruder alarm nobody can act on or dismiss. Found by adversarial
        # review, which demonstrated the mutation surviving the suite. Pin the
        # exact note instead: the corrupt entry contributes nothing, and the one
        # healthy device is named correctly on whichever side it sits.
        expected = (f"NEW device(s) since baseline: {LAPTOP}" if corrupt_side == "old"
                    else f"Device(s) gone since baseline: {LAPTOP}")
        assert notes == [expected], f"corrupt entry leaked into the notes: {notes}"

    def test_a_corrupt_device_entry_does_not_hide_a_real_new_device(self, mod):
        # Fixed regression, and the one that made the KeyError above dangerous
        # rather than merely annoying: it was raised before any comparison ran,
        # so the healthy devices beside the corrupt record were never compared
        # and a real intruder went unreported.
        old = {"devices": [dev(LAPTOP)]}
        new = {"devices": [{"ip": "192.168.1.99"}, dev(INTRUDER, ip="192.168.1.66")]}

        notes = mod.diff_baseline(old, new)

        assert any(INTRUDER in n for n in notes), "new device masked by a corrupt neighbour"

    def test_new_port_on_the_upstream_modem_is_reported(self, mod):
        # Fixed regression: only 'router_open_ports' was diffed.
        # 'upstream_open_ports' had been collected and saved into the baseline
        # all along but never compared, so Telnet appearing on the modem was
        # silent — on the one device in the house facing the internet directly.
        old = {"router_open_ports": [80], "upstream_open_ports": [80]}
        new = {"router_open_ports": [80], "upstream_open_ports": [23, 80]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "23" in notes[0]
        assert "upstream" in notes[0].lower(), "note must say which host opened the port"

    def test_an_unmeasured_upstream_scan_is_not_diffed(self, mod):
        # The upstream host gets the same tri-state treatment as the router:
        # None means the scan could not reach it, so comparing it against a
        # known list would invent a change in whichever direction the blocked
        # run happened to fall. Both directions must stay silent.
        assert mod.diff_baseline({"upstream_open_ports": [80, 443]},
                                 {"upstream_open_ports": None}) == []
        assert mod.diff_baseline({"upstream_open_ports": None},
                                 {"upstream_open_ports": [80, 443]}) == []

    def test_both_hosts_are_reported_separately_in_one_run(self, mod):
        # The note has to say WHICH host opened the port. Reporting a change on
        # the modem as though it were on the router would send the reader to the
        # wrong admin page, and the two hosts carry different weight.
        old = {"router_open_ports": [80], "upstream_open_ports": [80]}
        new = {"router_open_ports": [80, 8080], "upstream_open_ports": [80, 23]}

        notes = mod.diff_baseline(old, new)

        router_note = [n for n in notes if "router" in n and "8080" in n]
        modem_note = [n for n in notes if "upstream" in n and "23" in n]
        assert router_note and modem_note, f"hosts not reported separately: {notes}"
        assert "8080" not in modem_note[0] and "23" not in router_note[0], \
            "a port was attributed to the wrong host"

    def test_closed_port_on_the_upstream_modem_is_reported(self, mod):
        # The other direction of the same gap. A port closing matters too: it
        # can mean a service you rely on has died, or that something reconfigured
        # the modem without telling you.
        old = {"upstream_open_ports": [80, 443]}
        new = {"upstream_open_ports": [443]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "80" in notes[0]
        assert "upstream" in notes[0].lower()

    def test_disjoint_scan_coverage_is_not_reported_as_a_move(self, mod):
        # Found by adversarial review. The two runs cover different ground, so a
        # device answering on both subnets under one MAC — a gateway, or a VLAN
        # subinterface sharing the parent MAC — is seen on A by one run and on B
        # by the other. The subnet sets ARE disjoint, so a disjointness test
        # alone calls that a move; it is a scope change. This is not exotic on
        # this tool: the menu's device scan sweeps one subnet chosen from
        # DEFAULT_NETWORKS, a full audit sweeps what the interfaces suggest, and
        # a baseline from one is routinely compared against the other.
        MAC = "3c:22:fb:11:22:33"
        old = {"devices": [dev(MAC, ip="192.168.85.5", subnet="192.168.85.0/24")],
               "scanned_subnets": ["192.168.85.0/24"]}
        new = {"devices": [dev(MAC, ip="192.168.87.5", subnet="192.168.87.0/24")],
               "scanned_subnets": ["192.168.87.0/24"]}

        assert mod.diff_baseline(old, new) == [], \
            "a scope change was reported as a device moving"

    def test_no_move_is_claimed_without_recorded_coverage(self, mod):
        # A baseline saved before scanned_subnets was recorded carries no
        # evidence of where anyone looked, so "it is not there any more" is not
        # a claim the data supports. Same refusal the router-port diff makes
        # when either side is unknown.
        MAC = "3c:22:fb:11:22:33"
        old = {"devices": [dev(MAC, ip="192.168.1.50", subnet="192.168.1.0/24")]}
        new = {"devices": [dev(MAC, ip="192.168.87.50", subnet="192.168.87.0/24")]}

        assert mod.diff_baseline(old, new) == []

    def test_coverage_records_only_subnets_a_sighting_was_possible_on(self, mod):
        # Found by adversarial review, and the subtlest defect in this cluster.
        # scanned_subnets used to record the nominal sweep LIST. Discovery
        # resolves neighbours through the ARP cache, which is on-link only, so
        # sweeping a subnet this Mac has no interface in finds nothing whatever
        # is there — and recording it as coverage turns "could not reach" into
        # "measured absence", the one inference the rest of the module refuses
        # to make.
        #
        # The consequence: menu option 3's "All networks" sweeps all of
        # DEFAULT_NETWORKS regardless of which SSID the laptop is on, so a
        # router answering on whichever subnet is currently on-link looked like
        # it crossed a network boundary every time the OBSERVER moved.
        import ipaddress
        sweep = [ipaddress.ip_network(s) for s in
                 ("192.168.85.0/24", "192.168.86.0/24", "192.168.87.0/24")]
        interfaces = [("en0", "192.168.87.249",
                       ipaddress.ip_network("192.168.87.0/24"))]

        assert mod.onlink_coverage(sweep, interfaces) == ["192.168.87.0/24"], \
            "an unreachable subnet was recorded as if it had been searched"
        assert mod.onlink_coverage(sweep, []) == [], \
            "with no interfaces nothing could have been seen anywhere"

    def test_the_observer_changing_network_is_not_reported_as_a_device_move(self, mod):
        # The end-to-end shape of the bug above. The AP answers under one MAC on
        # whichever subnet is on-link; the laptop was joined to 86 when the
        # baseline was taken and to 87 the next day. Coverage now records only
        # the subnet each run could actually see, so "not on 86 any more" is
        # never claimed — because this run could not have seen it there.
        AP = "3c:28:6d:aa:bb:cc"
        old = {"devices": [dev(AP, ip="192.168.86.1", subnet="192.168.86.0/24")],
               "scanned_subnets": ["192.168.86.0/24"]}
        new = {"devices": [dev(AP, ip="192.168.87.1", subnet="192.168.87.0/24")],
               "scanned_subnets": ["192.168.87.0/24"]}

        assert not any("moved to a different subnet" in n
                       for n in mod.diff_baseline(old, new)), \
            "the scanning Mac changing network was reported as the AP moving"

    def test_a_move_into_ground_the_baseline_never_covered_is_still_reported(self, mod):
        # Found by adversarial review, and the most dangerous defect in this
        # cluster because it was silent. Requiring the BASELINE to have covered
        # the destination reads as caution and behaves as blindness: a baseline
        # saved from the menu covers the one subnet it swept, so that test
        # vetoed a move onto ANY other network — including a device crossing
        # from the IoT subnet to the trusted one, which is the boundary crossing
        # the check exists to catch. The new run swept 192.168.85.0/24 and did
        # not find the device there; that is a measurement, and it must reach
        # the reader whether or not the destination was ever baselined.
        MAC = "3c:22:fb:11:22:33"
        old = {"devices": [dev(MAC, ip="192.168.85.5", subnet="192.168.85.0/24")],
               "scanned_subnets": ["192.168.85.0/24"]}
        new = {"devices": [dev(MAC, ip="192.168.87.5", subnet="192.168.87.0/24")],
               "scanned_subnets": ["192.168.85.0/24", "192.168.87.0/24"]}

        notes = mod.diff_baseline(old, new)

        assert any(MAC in n for n in notes), "a device leaving its baselined subnet was silent"
        assert any("192.168.87.0/24" in n for n in notes)
        assert any("never covered" in n for n in notes), \
            "the note should say the destination was outside the baseline's coverage"

    def test_the_move_note_survives_alongside_other_findings(self, mod):
        # The move note was briefly gated on there being no arrivals, which
        # deleted a boundary crossing exactly when the run was most eventful.
        MOVER, INTRUDER_MAC = "3c:22:fb:11:22:33", "b8:27:eb:de:ad:01"
        cov = ["192.168.1.0/24", "192.168.87.0/24"]
        old = {"devices": [dev(MOVER, ip="192.168.1.50", subnet="192.168.1.0/24")],
               "scanned_subnets": cov, "router_open_ports": [80]}
        new = {"devices": [dev(MOVER, ip="192.168.87.50", subnet="192.168.87.0/24"),
                           dev(INTRUDER_MAC, ip="192.168.1.66", subnet="192.168.1.0/24")],
               "scanned_subnets": cov, "router_open_ports": [80, 23]}

        notes = mod.diff_baseline(old, new)

        assert any("moved to a different subnet" in n for n in notes), "the move was dropped"
        assert any(INTRUDER_MAC in n for n in notes), "the arrival was dropped"
        assert any("23" in n for n in notes), "the new open port was dropped"

    def test_no_note_claims_the_rest_of_the_report_is_clean(self, mod):
        # The move note used to end "nothing else about the network looks
        # different" — a claim about the WHOLE report made from inside one
        # check, before the router-port, evil-twin, DHCP and certificate
        # comparisons below have even run. It printed above a new-open-port and
        # an evil-twin finding and told the reader to stand down about them.
        MOVER = "3c:22:fb:11:22:33"
        cov = ["192.168.1.0/24", "192.168.87.0/24"]
        old = {"devices": [dev(MOVER, ip="192.168.1.50", subnet="192.168.1.0/24")],
               "scanned_subnets": cov, "router_open_ports": [80],
               "wifi_bssids": ["aa:aa:aa:aa:aa:aa"]}
        new = {"devices": [dev(MOVER, ip="192.168.87.50", subnet="192.168.87.0/24")],
               "scanned_subnets": cov, "router_open_ports": [80, 23],
               "wifi_bssids": ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"]}

        notes = mod.diff_baseline(old, new)

        assert any("23" in n for n in notes) and any("evil twin" in n.lower() for n in notes)
        assert not any("nothing else about the network" in n for n in notes), \
            "a note told the reader to stand down about findings printed beside it"

    def test_the_move_note_does_not_contradict_an_arrival_note(self, mod):
        # Found by adversarial review, and the worst of the three: the note used
        # to end with "The MAC set is unchanged, so nothing else about the
        # network looks different" unconditionally — printed directly beneath a
        # NEW-device note, telling the reader to stand down about a genuine
        # intrusion signal three lines above it.
        MOVER, INTRUDER_MAC = "3c:22:fb:11:22:33", "b8:27:eb:de:ad:01"
        cov = ["192.168.1.0/24", "192.168.87.0/24"]
        old = {"devices": [dev(MOVER, ip="192.168.1.50", subnet="192.168.1.0/24")],
               "scanned_subnets": cov}
        new = {"devices": [dev(MOVER, ip="192.168.87.50", subnet="192.168.87.0/24"),
                           dev(INTRUDER_MAC, ip="192.168.1.66", subnet="192.168.1.0/24")],
               "scanned_subnets": cov}

        notes = mod.diff_baseline(old, new)

        assert any(INTRUDER_MAC in n for n in notes), "the arrival must still be reported"
        assert not any("nothing else about the network" in n for n in notes), \
            "a stand-down sentence was printed alongside a real arrival"

    def test_a_changed_scan_coverage_is_not_reported_as_a_move(self, mod):
        # A device seen on {A, B} and then only on {B} has not moved — the
        # second run simply scanned less of the network (--extra-subnet used
        # once and not the next time). An earlier version of the move check
        # tested `was != now` and emitted "A, B -> B", which is not a move and
        # not a sentence. The check requires the sets to be DISJOINT: no longer
        # on ANY subnet it used to be on. The surrounding code goes to some
        # trouble to avoid alarms that fire when nothing happened; this is one
        # of them.
        MAC = "3c:22:fb:11:22:33"          # globally administered, so it is a
                                           # stable identity the check applies to
        both = {"devices": [dev(MAC, ip="192.168.1.5", subnet="192.168.1.0/24"),
                            dev(MAC, ip="192.168.87.5", subnet="192.168.87.0/24")],
                "scanned_subnets": ["192.168.1.0/24", "192.168.87.0/24"]}
        one = {"devices": [dev(MAC, ip="192.168.87.5", subnet="192.168.87.0/24")],
               "scanned_subnets": ["192.168.87.0/24"]}

        assert mod.diff_baseline(both, one) == [], "narrower scan read as a move"
        assert mod.diff_baseline(one, both) == [], "wider scan read as a move"

    def test_a_device_moving_between_subnets_is_reported(self, mod):
        # Fixed regression: only MAC sets were compared, so a device moving to
        # another subnet left the set unchanged and produced no note at all —
        # structurally invisible — even though collect_devices records a
        # 'subnet' per device. diff_baseline now compares subnets per stable MAC.
        # Both runs swept both subnets, so "not on 192.168.1.0/24 any more" is a
        # measurement rather than an absence of looking. Without that coverage
        # the tool correctly declines to claim a move — see
        # test_no_move_is_claimed_without_recorded_coverage.
        cov = ["192.168.1.0/24", "192.168.87.0/24"]
        old = {"devices": [dev(LAPTOP, ip="192.168.1.50", subnet="192.168.1.0/24")],
               "scanned_subnets": cov}
        new = {"devices": [dev(LAPTOP, ip="192.168.87.50", subnet="192.168.87.0/24")],
               "scanned_subnets": cov}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert LAPTOP in notes[0]
        assert "192.168.87.0/24" in notes[0], "note must say which subnet it moved to"


# iOS and macOS rotate their private Wi-Fi address, so these are the same
# phone on three different days — and nothing about that is an event.
PHONE_MON = "52:29:4f:ce:4a:d7"
PHONE_TUE = "7e:f2:c6:51:17:99"
PHONE_WED = "d2:9c:f8:3e:4e:41"


class TestRotatingPrivateAddresses:
    """A household of phones re-randomises constantly, and compared as a set
    every rotation is one device arriving and another leaving.

    This came out of a real run: five of the seven MACs in a NEW device(s)
    alarm were rotating private addresses, so that line was going to fire on
    every future run for ever, with nothing wrong and while burying the two
    findings beside it that meant something.
    """

    def test_a_phone_that_re_randomised_is_not_a_new_device(self, mod):
        old = {"devices": [dev(LAPTOP), dev(PHONE_MON)]}
        new = {"devices": [dev(LAPTOP), dev(PHONE_TUE)]}
        assert not [n for n in mod.diff_baseline(old, new) if "NEW device" in n]

    def test_nor_a_departed_one(self, mod):
        old = {"devices": [dev(LAPTOP), dev(PHONE_MON)]}
        new = {"devices": [dev(LAPTOP), dev(PHONE_TUE)]}
        assert not [n for n in mod.diff_baseline(old, new) if "gone since" in n]

    def test_a_real_device_still_alarms_beside_them(self, mod):
        """The property that makes the suppression safe rather than merely
        quiet: rotation is filtered, a new stable MAC is not."""
        old = {"devices": [dev(PHONE_MON)]}
        new = {"devices": [dev(PHONE_TUE), dev(INTRUDER)]}
        notes = [n for n in mod.diff_baseline(old, new) if "NEW device" in n]
        assert len(notes) == 1
        assert INTRUDER in notes[0]
        assert PHONE_TUE not in notes[0]

    def test_a_growing_population_is_still_reported(self, mod):
        """Not tracked is not ignored. Most new devices on a home network are
        phones and every one of them arrives with a private address, so the
        count is the one claim a rotating identifier still supports."""
        old = {"devices": [dev(PHONE_MON)]}
        new = {"devices": [dev(PHONE_MON), dev(PHONE_TUE), dev(PHONE_WED)]}
        notes = [n for n in mod.diff_baseline(old, new) if "rotating private" in n]
        assert len(notes) == 1
        assert "3" in notes[0] and "1" in notes[0]

    def test_a_shrinking_population_is_not_an_alarm(self, mod):
        """Phones sleep and drop off the table constantly. A count that fell
        is the most ordinary thing on a home network."""
        old = {"devices": [dev(PHONE_MON), dev(PHONE_TUE), dev(PHONE_WED)]}
        new = {"devices": [dev(PHONE_MON)]}
        assert not [n for n in mod.diff_baseline(old, new) if "rotating private" in n]

    def test_a_steady_household_is_silent(self, mod):
        """The nearest-neighbour non-event: three phones, all re-randomised,
        same count. Nothing happened and nothing should be said."""
        old = {"devices": [dev(LAPTOP), dev(PHONE_MON), dev(PHONE_TUE)]}
        new = {"devices": [dev(LAPTOP), dev(PHONE_WED), dev("6a:11:22:33:44:55")]}
        assert mod.diff_baseline(old, new) == []
