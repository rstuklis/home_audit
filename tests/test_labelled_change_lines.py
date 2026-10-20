"""The change lines name devices, not just addresses.

"Device(s) gone: 34:64:a9:cc:57:2e" sends the reader to look an address up;
"34:64:a9:cc:57:2e [HP Printer]" does not. These lines top the email, so what may
be added to them is kept narrow: a label the owner typed, or a vendor from the OUI
registry. Never what the device announces about itself.
"""

import pytest

NET = "192.168.87.0/24"
PRINTER = "34:64:a9:cc:57:2e"
TV = "8c:79:f5:8c:48:a7"
NEWCOMER = "00:1b:63:84:45:e6"


def state(devices, subnets=(NET,)):
    return {"scanned_subnets": list(subnets),
            "devices": [dict({"ip": f"10.0.0.{i}", "subnet": NET}, **d) for i, d in enumerate(devices)]}


class TestDescribeMac:
    def test_a_label_wins(self, mod):
        assert mod.describe_mac(PRINTER, {PRINTER: "HP Printer"}, state([{"mac": PRINTER, "vendor": "Hewlett Packard"}])) \
            == f"{PRINTER} [HP Printer]"

    def test_without_a_label_the_vendor_is_given_and_it_says_unlabelled(self, mod):
        assert mod.describe_mac(TV, {}, state([{"mac": TV, "vendor": "Samsung Electronics Co.,Ltd"}])) \
            == f"{TV} [unlabelled; Samsung Electronics Co.,Ltd]"

    def test_a_label_with_brackets_of_its_own_stays_readable(self, mod):
        assert mod.describe_mac(TV, {TV: "Tuya device A (6d:c6)"}) == f"{TV} [Tuya device A (6d:c6)]"

    def test_a_vendor_keeps_its_trailing_full_stop(self, mod):
        # The DNS-name cleaner trims it; "Apple, Inc" is not the company's name.
        assert mod.describe_mac(TV, {}, state([{"mac": TV, "vendor": "Apple, Inc."}])).endswith("Apple, Inc.]")

    def test_with_neither_it_is_the_bare_address_as_before(self, mod):
        assert mod.describe_mac(TV, {}, state([{"mac": TV}])) == TV
        assert mod.describe_mac(TV) == TV

    def test_the_private_mac_placeholder_is_not_a_vendor(self, mod):
        assert mod.describe_mac(TV, {}, state([{"mac": TV, "vendor": mod.PRIVATE_MAC_VENDOR}])) == TV

    def test_what_a_device_announces_is_never_used(self, mod):
        # These lines are read first. A name is free to claim; a label is not.
        s = state([{"mac": NEWCOMER, "names": {"upnp": "Google Nest - Hallway"}}])
        assert mod.describe_mac(NEWCOMER, {}, s) == NEWCOMER

    def test_a_label_cannot_smuggle_a_forged_line_into_the_report(self, mod):
        out = mod.describe_mac(PRINTER, {PRINTER: "Printer\n  [OK    ] all clear\x1b[2K"})
        assert "\n" not in out and "\x1b" not in out

    @pytest.mark.parametrize("labels", [None, {}, {PRINTER: ""}, {PRINTER: None}, {PRINTER: 7}, {PRINTER: "   "}])
    def test_an_unusable_label_falls_through(self, mod, labels):
        assert mod.describe_mac(PRINTER, labels, state([{"mac": PRINTER, "vendor": "Hewlett Packard"}])) \
            == f"{PRINTER} [unlabelled; Hewlett Packard]"

    def test_malformed_device_lists_are_survived(self, mod):
        assert mod.describe_mac(TV, {}, {"devices": [None, 3, {"vendor": "x"}, {"mac": 9}]}, None, {}) == TV


class TestChangeLines:
    def test_a_departure_is_described_from_the_baseline(self, mod):
        old = state([{"mac": PRINTER, "vendor": "Hewlett Packard"}, {"mac": TV}])
        notes = mod.diff_baseline(old, state([{"mac": TV}]), {PRINTER: "HP Printer"})
        assert notes == [f"Device(s) gone since baseline: {PRINTER} [HP Printer]"]

    def test_an_arrival_is_described_from_this_run(self, mod):
        new = state([{"mac": TV}, {"mac": NEWCOMER, "vendor": "Apple, Inc."}])
        notes = mod.diff_baseline(state([{"mac": TV}]), new, {})
        assert notes == [f"NEW device(s) since baseline: {NEWCOMER} [unlabelled; Apple, Inc.]"]

    def test_several_devices_are_each_described(self, mod):
        old = state([{"mac": PRINTER}, {"mac": TV, "vendor": "Samsung"}])
        note = mod.diff_baseline(old, state([]), {PRINTER: "HP Printer"})[0]
        assert f"{PRINTER} [HP Printer]" in note and f"{TV} [unlabelled; Samsung]" in note

    def test_a_subnet_move_names_the_device_too(self, mod):
        other = "192.168.85.0/24"
        old = {"scanned_subnets": [NET, other], "devices": [{"mac": TV, "subnet": other}]}
        new = {"scanned_subnets": [NET, other], "devices": [{"mac": TV, "subnet": NET}]}
        notes = mod.diff_baseline(old, new, {TV: "Lounge TV"})
        assert any(f"{TV} [Lounge TV]" in n and "->" in n for n in notes)

    def test_without_labels_the_lines_are_exactly_as_they_were(self, mod):
        # Every caller that does not pass labels, and every stored expectation,
        # keeps working unchanged.
        notes = mod.diff_baseline(state([{"mac": TV}]), state([{"mac": TV}, {"mac": NEWCOMER}]))
        assert notes == [f"NEW device(s) since baseline: {NEWCOMER}"]


class TestTheDigestStillReadsThem:
    def test_a_labelled_change_line_passes_through_the_tl_dr(self):
        import importlib.util, sys
        from pathlib import Path
        spec = importlib.util.spec_from_file_location("report_digest", Path(__file__).resolve().parent.parent / "tools" / "report_digest.py")
        dg = importlib.util.module_from_spec(spec); sys.modules["report_digest"] = dg; spec.loader.exec_module(dg)
        text = "\n".join(["# NETWORK: loveshack — 09:00:01   ip x", "", "── CHANGE DETECTION (vs saved baseline) ─────",
                          "CHANGES DETECTED:", f"  ! Device(s) gone since baseline: {PRINTER} [HP Printer]"])
        facts, _ = dg.build_facts([dg.parse_report(text)])
        assert f"loveshack: Device(s) gone since baseline: {PRINTER} [HP Printer]" in facts
