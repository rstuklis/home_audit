"""What identifies a device: the owner's label, and nothing a device chooses.

Round 4, F26 and F27.

F26: the locally-administered bit alone decided whether an address was a
rotating phone, and the household's fixed devices that carry it — the LinkTap
irrigation gateways, the IoT network's own gateway, "This Mac" on each network
— were handled as phones: never reported gone or replaced, never remembered,
only counted, and padding the rotating count so a stranger arriving while one
of them was off read as no change. A label typed by the owner is the one proof
of a fixed identity, and it was ignored on exactly this axis.

F27: a vendor name counted as identification. It is a registry lookup of a
prefix the device itself chose, fetched from a third party over the network
being audited; any registered OUI escaped "<-- unlabelled" and the TL;DR's
"N unidentified", so seven unlabelled Tuya plugs read "0 unidentified" while
a private-address phone was flagged every week.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

NET = "192.168.86.0/24"
GW = "b0:2a:43:c8:22:5b"
LINKTAP = "02:4b:00:00:00:01"           # locally-administered bit set, labelled by the owner
LINKTAP_2 = "02:4b:00:00:00:02"         # a stranger with a similar address, unlabelled
PHONE_A, PHONE_B = "52:29:4f:ce:4a:d7", "7e:f2:c6:51:17:99"
LABELS = {LINKTAP: "LinkTap gateway (front)", GW: "Nest Wifi"}
TOOLS = Path(__file__).resolve().parent.parent / "tools"


def dev(mac, ip="192.168.86.10", vendor=""):
    return {"ip": ip, "mac": mac, "subnet": NET, "vendor": vendor}


def state(devices, when="2026-10-25T22:00:00+00:00", memory=None):
    s = {"timestamp": when, "scanned_subnets": [NET], "devices": list(devices)}
    if memory is not None:
        s["device_memory"] = memory
    return s


class TestALabelledPrivateAddressIsADevice:
    def test_the_bit_alone_still_means_rotating(self, mod):
        assert mod.is_rotating_mac(LINKTAP) is True
        assert mod.is_rotating_mac(LINKTAP, LABELS) is False
        assert mod.is_rotating_mac(GW, LABELS) is False
        assert mod.labelled_macs({"AA:BB:CC:DD:EE:FF": "x", "bad": "", 3: "y"}) == {"aa:bb:cc:dd:ee:ff"}

    def test_a_labelled_linktap_going_quiet_is_reported_gone(self, mod):
        old = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")])
        new = state([dev(GW, "192.168.86.1")])
        notes = mod.diff_baseline(old, new, LABELS)
        assert len(notes) == 1 and notes[0].startswith("Device(s) gone since baseline")
        assert f"{LINKTAP} [LinkTap gateway (front)]" in notes[0]

    def test_without_the_label_it_is_still_a_rotating_address(self, mod):
        old = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")])
        new = state([dev(GW, "192.168.86.1")])
        assert mod.diff_baseline(old, new, {GW: "Nest Wifi"}) == []

    def test_a_replacement_is_a_departure_and_a_rise_in_strangers(self, mod):
        # The LinkTap gone, something with a similar unlabelled address in its
        # place: the owner's device is reported gone BY NAME, and the newcomer
        # raises the rotating count from 0 — not 1 -> 1 and silence.
        old = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")])
        new = state([dev(GW, "192.168.86.1"), dev(LINKTAP_2, "192.168.86.200")])
        notes = mod.diff_baseline(old, new, LABELS)
        assert any("gone since baseline" in n and LINKTAP in n for n in notes)
        assert any("1 device(s) using rotating private addresses, up from 0" in n for n in notes)

    def test_a_labelled_device_present_both_runs_is_silent(self, mod):
        old = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")])
        assert mod.diff_baseline(old, dict(old), LABELS) == []

    def test_the_labelled_mac_is_excluded_from_the_rotating_count(self, mod):
        # loveshack this morning: "3 device(s) using rotating private
        # addresses, up from 1", where the "1" was the labelled Mac itself.
        this_mac = "1a:4b:9f:2b:a2:ab"
        labels = {this_mac: "This Mac"}
        old = state([dev(GW, "192.168.86.1"), dev(this_mac, "192.168.86.20")])
        new = state([dev(GW, "192.168.86.1"), dev(this_mac, "192.168.86.20"),
                     dev(PHONE_A, "192.168.86.40"), dev(PHONE_B, "192.168.86.41")])
        notes = [n for n in mod.diff_baseline(old, new, labels) if "rotating private" in n]
        assert len(notes) == 1 and "2 device(s) using rotating private addresses, up from 0" in notes[0]

    def test_a_stranger_arriving_while_the_labelled_device_is_off_is_still_a_rise(self, mod):
        old = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")])
        new = state([dev(GW, "192.168.86.1"), dev(PHONE_A, "192.168.86.40")])
        notes = mod.diff_baseline(old, new, LABELS)
        assert any("gone since baseline" in n and LINKTAP in n for n in notes)
        assert any("1 device(s) using rotating private addresses, up from 0" in n for n in notes)

    def test_a_labelled_device_moving_subnet_is_reported(self, mod):
        other = "192.168.87.0/24"
        old = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")])
        new = {"timestamp": "2026-11-01T22:00:00+00:00", "scanned_subnets": [NET, other],
               "devices": [dev(GW, "192.168.86.1"), dict(dev(LINKTAP, "192.168.87.34"), subnet=other)]}
        notes = mod.diff_baseline(old, new, LABELS)
        assert any("moved to a different subnet" in n and LINKTAP in n for n in notes)


class TestItIsRemembered:
    def test_a_labelled_private_address_enters_the_memory(self, mod):
        memory = mod.update_device_memory({}, state([dev(LINKTAP)]), LABELS)
        assert LINKTAP in memory

    def test_an_unlabelled_one_still_does_not(self, mod):
        assert LINKTAP not in mod.update_device_memory({}, state([dev(LINKTAP)]), {})
        assert PHONE_A not in mod.update_device_memory({}, state([dev(PHONE_A)]), LABELS)

    def test_a_remembered_labelled_device_is_read_back_with_the_labels(self, mod):
        memory = {LINKTAP: {"first_seen": "2026-10-01T00:00:00+00:00", "last_seen": "2026-10-18T00:00:00+00:00"}}
        assert LINKTAP in mod.remembered_devices(state([], memory=memory), LABELS)
        assert LINKTAP not in mod.remembered_devices(state([], memory=memory)), \
            "a label is the only thing that keeps it; a smuggled private address is still dropped"

    def test_its_return_within_the_window_is_not_a_new_device(self, mod):
        r1 = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")], "2026-10-18T22:00:00+00:00")
        r2 = state([dev(GW, "192.168.86.1")], "2026-10-25T22:00:00+00:00",
                   memory=mod.update_device_memory(r1, r1, LABELS))
        r3 = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")], "2026-11-01T22:00:00+00:00")
        assert mod.returning_devices(r2, r3, LABELS) == {LINKTAP: "2026-10-18T22:00:00+00:00"}
        assert not any("NEW device" in n for n in mod.diff_baseline(r2, r3, LABELS))
        assert LINKTAP in (mod.describe_returning_devices(r2, r3, LABELS) or "")

    def test_save_baseline_remembers_it_with_the_labels_on_disk(self, mod):
        mod.save_labels(dict(LABELS))
        mod.save_baseline(state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")]))
        assert LINKTAP in mod.load_baseline()["device_memory"]

    def test_a_labelled_critical_device_is_reported_absent(self, mod):
        old = state([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")])
        old["device_memory"] = mod.update_device_memory({}, old, LABELS)
        new = state([dev(GW, "192.168.86.1")], "2026-11-01T22:00:00+00:00")
        line = mod.describe_critical_absences(old, new, {LINKTAP}, LABELS)
        assert line and "[HIGH  ]" in line and "LinkTap gateway (front)" in line


@pytest.fixture
def grouped(mod, monkeypatch, capsys):
    def run(devices, labels):
        mod._print_devices_grouped(devices, labels, {}, scanned_subnets=None)
        return capsys.readouterr().out
    return run


class TestAVendorIsNotIdentification:
    def test_a_vendor_only_device_is_flagged_and_counted_on_its_own_line(self, grouped):
        out = grouped([dev("3c:28:6d:aa:bb:cc", "192.168.86.30", vendor="Google")], {})
        row = next(l for l in out.splitlines() if "3c:28:6d:aa:bb:cc" in l)
        assert "<-- unlabelled" in row and "vendor says Google" in row
        assert "1 device(s) known only by vendor name" in out
        assert "unidentified device(s)" not in out
        assert "Tag them with" in out

    def test_a_private_address_is_unidentified_as_before(self, grouped, mod):
        out = grouped([dev(PHONE_A, "192.168.86.40", vendor=mod.PRIVATE_MAC_VENDOR)], {})
        row = next(l for l in out.splitlines() if PHONE_A in l)
        assert "<-- unlabelled" in row and "vendor says" not in row
        assert "1 unidentified device(s)." in out and "known only by vendor" not in out

    def test_a_labelled_device_is_identified_whatever_its_vendor(self, grouped):
        out = grouped([dev("3c:28:6d:aa:bb:cc", "192.168.86.30", vendor="Google")], {"3c:28:6d:aa:bb:cc": "Nest Hub"})
        row = next(l for l in out.splitlines() if "3c:28:6d:aa:bb:cc" in l)
        assert "Nest Hub" in row and "unlabelled" not in row and "vendor says" not in row
        assert "known only by vendor" not in out and "unidentified" not in out and "Tag them" not in out

    def test_the_seven_tuya_plugs(self, grouped):
        plugs = [dev(f"2c:b4:71:eb:00:{i:02x}", f"192.168.85.{20 + i}", vendor="Tuya Smart Inc.") for i in range(7)]
        out = grouped(plugs + [dev(GW, "192.168.85.1"), dev(PHONE_A, "192.168.85.50")], {GW: "Nest"})
        assert "7 device(s) known only by vendor name" in out
        assert "1 unidentified device(s)." in out
        assert out.count("<-- unlabelled") == 8

    def test_the_digest_carries_both_counts(self, grouped):
        spec = importlib.util.spec_from_file_location("report_digest", TOOLS / "report_digest.py")
        dg = importlib.util.module_from_spec(spec)
        sys.modules["report_digest"] = dg
        spec.loader.exec_module(dg)
        plugs = [dev(f"2c:b4:71:eb:00:{i:02x}", f"192.168.85.{20 + i}", vendor="Tuya Smart Inc.") for i in range(7)]
        out = grouped(plugs + [dev(GW, "192.168.85.1"), dev(PHONE_A, "192.168.85.50")], {GW: "Nest"})
        report = "\n" + "=" * 64 + "\nCONNECTED DEVICES\n" + "=" * 64 + "\n" + out \
            + "\n" + "=" * 64 + "\nCHANGE DETECTION (vs saved baseline)\n" + "=" * 64 + "\nNo changes since baseline.\n"
        parsed = dg.parse_report(report, "loveshack-iot")
        assert (parsed["devices"], parsed["unidentified"], parsed["vendor_only"]) == (9, 1, 7)
        facts, _ = dg.build_facts([parsed])
        assert "9 devices, 1 unidentified, 7 known only by vendor" in facts

    def test_an_older_report_without_the_line_parses_as_before(self):
        spec = importlib.util.spec_from_file_location("report_digest", TOOLS / "report_digest.py")
        dg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dg)
        parsed = dg.parse_report("  Total: 3 device(s) across 1 subnet(s) scanned.\n  1 unidentified device(s). Tag them with:\n")
        assert parsed["vendor_only"] == 0
        facts, _ = dg.build_facts([parsed])
        assert "known only by vendor" not in facts


class TestAMacAtTwoAddresses:
    def test_is_review_within_one_subnet(self, mod, grouped):
        printer = "34:64:a9:cc:57:2e"
        out = grouped([dev(printer, "192.168.86.35"), dev(printer, "192.168.86.250")], {printer: "HP Printer"})
        assert "[REVIEW] Hardware address answering at more than one IP: 34:64:a9:cc:57:2e [HP Printer] at 192.168.86.35, 192.168.86.250" in out

    def test_one_address_is_silent(self, mod):
        assert mod.describe_duplicate_addresses([dev(GW, "192.168.86.1"), dev(LINKTAP, "192.168.86.34")], LABELS) is None

    def test_a_rotating_address_is_not_followed(self, mod):
        assert mod.describe_duplicate_addresses([dev(PHONE_A, "192.168.86.40"), dev(PHONE_A, "192.168.86.41")]) is None

    def test_a_labelled_private_address_is(self, mod):
        line = mod.describe_duplicate_addresses([dev(LINKTAP, "192.168.86.34"), dev(LINKTAP, "192.168.86.35")], LABELS)
        assert line and "LinkTap gateway (front)" in line

    def test_the_same_mac_on_two_subnets_is_not_a_duplicate(self, mod):
        other = dict(dev(GW, "192.168.87.1"), subnet="192.168.87.0/24")
        assert mod.describe_duplicate_addresses([dev(GW, "192.168.86.1"), other]) is None

    def test_unknown_and_malformed_entries_are_skipped(self, mod):
        assert mod.describe_duplicate_addresses([{"ip": "a", "mac": "unknown"}, {"ip": "b", "mac": "unknown"}, None, 3]) is None
