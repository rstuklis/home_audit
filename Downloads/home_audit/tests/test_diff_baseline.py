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

    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "lines 420-421 build the MAC sets from the raw d['mac'] strings, so the "
        "comparison is case-sensitive: '3C:22:FB:...' and '3c:22:fb:...' are two "
        "different devices and one unmoved device raises BOTH a 'NEW device(s)' "
        "and a 'Device(s) gone' note. read_arp_table normalises to lowercase "
        "(line 218), so the two sides only agree by accident — a hand-edited or "
        "vendor-pasted baseline (uppercase is the usual vendor rendering) breaks "
        "the coincidence and double-alarms forever."))
    def test_a_mac_differing_only_in_case_is_the_same_device(self, mod):
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

    def test_dropping_the_port_section_reads_as_every_port_closing(self, mod):
        # DOCUMENTS ACTUAL BEHAVIOUR: a scan that could not reach the gateway
        # has no "router_open_ports" key at all, and an absent key is treated
        # as "no ports open" rather than "not measured". main() guards the
        # save path against this (lines 2498-2502) but a comparison against an
        # incomplete in-session state still raises the false alarm.
        old = {"router_open_ports": [80, 443]}
        new = {}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "80" in notes[0] and "443" in notes[0]


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
    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "lines 420-421 index d['mac'] directly, so one device dict missing the "
        "'mac' key raises KeyError and change detection dies. Baselines are "
        "hand-editable JSON on disk and a truncated write corrupts them."))
    @pytest.mark.parametrize("corrupt_side", ["old", "new"], ids=["corrupt_old", "corrupt_new"])
    def test_device_entry_without_a_mac_key_degrades_instead_of_raising(self, mod, corrupt_side):
        healthy = {"devices": [dev(LAPTOP)]}
        corrupt = {"devices": [{"ip": "192.168.1.99"}]}  # truncated write: no "mac"
        old, new = (corrupt, healthy) if corrupt_side == "old" else (healthy, corrupt)

        notes = mod.diff_baseline(old, new)

        assert isinstance(notes, list)
        assert all(isinstance(n, str) for n in notes)

    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "lines 420-421 raise KeyError on a mac-less device, so the healthy "
        "devices beside it are never compared and a real change is lost."))
    def test_a_corrupt_device_entry_does_not_hide_a_real_new_device(self, mod):
        old = {"devices": [dev(LAPTOP)]}
        new = {"devices": [{"ip": "192.168.1.99"}, dev(INTRUDER, ip="192.168.1.66")]}

        notes = mod.diff_baseline(old, new)

        assert any(INTRUDER in n for n in notes), "new device masked by a corrupt neighbour"

    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "lines 428-433 diff only 'router_open_ports'. 'upstream_open_ports' is "
        "collected (line 2123) and saved into the baseline but never compared, "
        "so Telnet appearing on the upstream modem is silent."))
    def test_new_port_on_the_upstream_modem_is_reported(self, mod):
        old = {"router_open_ports": [80], "upstream_open_ports": [80]}
        new = {"router_open_ports": [80], "upstream_open_ports": [23, 80]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "23" in notes[0]
        assert "upstream" in notes[0].lower(), "note must say which host opened the port"

    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "lines 428-433 diff only 'router_open_ports'; a port closing on the "
        "upstream modem (line 2123's 'upstream_open_ports') is never reported."))
    def test_closed_port_on_the_upstream_modem_is_reported(self, mod):
        old = {"upstream_open_ports": [80, 443]}
        new = {"upstream_open_ports": [443]}

        notes = mod.diff_baseline(old, new)

        assert len(notes) == 1
        assert "80" in notes[0]
        assert "upstream" in notes[0].lower()

    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "lines 420-423 compare MAC sets only, so a device that moves to another "
        "subnet leaves the set unchanged and produces no note, even though "
        "collect_devices records a 'subnet' key per device (line 2005)."))
    def test_a_device_moving_between_subnets_is_reported(self, mod):
        old = {"devices": [dev(LAPTOP, ip="192.168.1.50", subnet="192.168.1.0/24")]}
        new = {"devices": [dev(LAPTOP, ip="192.168.87.50", subnet="192.168.87.0/24")]}

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
