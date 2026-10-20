"""A sweep whose ARP read failed must not be read as every device leaving.

The beach-house run of 2026-10-10 found eleven hosts by ping and read a MAC for
none of them: `arp -an` returned nothing, every device was recorded as
"unknown", and because diff_baseline compares identities, all twelve devices in
the baseline were reported gone. The next week's run then reported all twelve as
NEW, and a device memory would have been emptied in between. These tests pin
the guard: such a list is a count, not identities, and is treated like a run
that did not sweep wherever identities matter — while the count is still
printed and the omission is named.
"""

import ipaddress

# Globally administered addresses on purpose: a second hex digit of 2, 6, a or e
# marks a locally administered (rotating private) MAC, which the diff counts
# rather than compares — the wrong fixture for a test about identities.
A = "3c:22:fb:00:00:01"
B = "3c:22:fb:00:00:02"
C = "3c:22:fb:00:00:03"


def dev(mac, ip, subnet="192.168.86.0/24"):
    return {"ip": ip, "mac": mac, "subnet": subnet}


def good(stamp="2026-10-02T23:55:48+00:00"):
    return {"timestamp": stamp, "scanned_subnets": ["192.168.86.0/24"],
            "devices": [dev(A, "192.168.86.1"), dev(B, "192.168.86.108"),
                        dev(C, "192.168.86.112")]}


def unknowns(stamp="2026-10-09T22:55:48+00:00"):
    return {"timestamp": stamp, "scanned_subnets": ["192.168.86.0/24"],
            "devices": [dev("unknown", "192.168.86.1"), dev("unknown", "192.168.86.108")]}


class TestMacsUnreadable:
    def test_every_device_unknown_is_unreadable(self, mod):
        assert mod.macs_unreadable(unknowns()) is True

    def test_one_readable_mac_is_enough(self, mod):
        state = unknowns()
        state["devices"].append(dev(A, "192.168.86.5"))
        assert mod.macs_unreadable(state) is False

    def test_an_empty_or_absent_list_is_not_this_case(self, mod):
        # swept_anywhere owns "found nothing"; this guard must not take it over.
        assert mod.macs_unreadable({"devices": []}) is False
        assert mod.macs_unreadable({}) is False
        assert mod.macs_unreadable({"devices": None}) is False

    def test_malformed_entries_do_not_count_as_readable(self, mod):
        assert mod.macs_unreadable({"devices": ["junk", {"mac": None}, {"mac": ""}]}) is True

    def test_a_single_host_without_an_address_is_a_straggler_not_a_failure(self, mod):
        # One host with no ARP entry is ordinary and already contributes nothing
        # to the comparison; the verdict needs two or more, all without one.
        assert mod.macs_unreadable({"devices": [dev("unknown", "192.168.86.99")]}) is False
        assert mod.macs_unreadable({"devices": [{"ip": "192.168.86.99"}]}) is False

    def test_devices_identified_needs_both(self, mod):
        assert mod.devices_identified(good()) is True
        assert mod.devices_identified(unknowns()) is False
        assert mod.devices_identified({}) is False


class TestDiffBaseline:
    def test_a_run_of_unknowns_does_not_report_the_baseline_gone(self, mod):
        notes = mod.diff_baseline(good(), unknowns())
        assert not any("gone" in n for n in notes), notes

    def test_a_baseline_of_unknowns_does_not_report_everything_new(self, mod):
        notes = mod.diff_baseline(unknowns(), good())
        assert not any("NEW device" in n for n in notes), notes

    def test_a_real_departure_is_still_reported(self, mod):
        new = good("2026-10-09T22:55:48+00:00")
        new["devices"] = new["devices"][:2]
        notes = mod.diff_baseline(good(), new)
        assert any("gone" in n and C in n for n in notes), notes

    def test_one_unknown_straggler_does_not_disable_the_comparison(self, mod):
        new = good("2026-10-09T22:55:48+00:00")
        new["devices"][2] = dev("unknown", "192.168.86.112")
        notes = mod.diff_baseline(good(), new)
        assert any("gone" in n and C in n for n in notes), notes


class TestCoverageCaveat:
    def test_the_omission_is_named_for_this_run(self, mod):
        line = mod.describe_comparison_coverage(good(), unknowns())
        assert line and "REVIEW" in line and "this run" in line
        assert "2 host(s)" in line and "hardware address" in line

    def test_the_omission_is_named_for_the_baseline(self, mod):
        line = mod.describe_comparison_coverage(unknowns(), good())
        assert line and "the baseline" in line

    def test_silent_when_both_sides_identified(self, mod):
        assert mod.describe_comparison_coverage(good(), good()) is None


class TestCarryForward:
    def test_the_previous_list_survives_an_identity_less_run(self, mod):
        merged = mod.carry_forward_unmeasured(unknowns(), previous=good())
        assert merged["devices"] == good()["devices"]
        assert "devices" in merged["carried_forward"]
        assert merged["measured_at"]["devices"] == good()["timestamp"]

    def test_a_real_sweep_is_not_carried(self, mod):
        later = good("2026-10-09T22:55:48+00:00")
        merged = mod.carry_forward_unmeasured(later, previous=good())
        assert merged.get("carried_forward") in (None, [])


class TestDeviceMemory:
    def test_memory_is_unchanged_by_a_run_of_unknowns(self, mod):
        before = mod.remembered_devices(good())
        assert before
        assert mod.update_device_memory(good(), unknowns()) == before

    def test_returning_devices_are_not_computed_against_unknowns(self, mod):
        assert mod.returning_devices(unknowns(), good()) == {}


class TestDiscoverDevicesRetry:
    def _sweep(self, mod, monkeypatch, tables):
        subnet = ipaddress.ip_network("192.168.86.0/24")
        alive = {"192.168.86.1", "192.168.86.108"}
        monkeypatch.setattr(mod, "ping", lambda ip: str(ip) if str(ip) in alive else None)
        calls = []
        def fake_table():
            calls.append(1)
            return dict(tables.pop(0)) if tables else {}
        monkeypatch.setattr(mod, "read_arp_table", fake_table)
        monkeypatch.setattr(mod.time, "sleep", lambda s: None)
        return mod.discover_devices(subnet, workers=4), len(calls)

    def test_an_empty_table_is_read_again_once(self, mod, monkeypatch):
        devices, reads = self._sweep(mod, monkeypatch,
                                     [{}, {"192.168.86.1": A, "192.168.86.108": B}])
        assert reads == 2
        assert {d["mac"] for d in devices} == {A, B}

    def test_a_table_naming_the_hosts_is_not_re_read(self, mod, monkeypatch):
        devices, reads = self._sweep(mod, monkeypatch,
                                     [{"192.168.86.1": A, "192.168.86.108": B}])
        assert reads == 1

    def test_two_failures_still_record_the_count(self, mod, monkeypatch):
        devices, reads = self._sweep(mod, monkeypatch, [{}, {}])
        assert reads == 2
        assert len(devices) == 2 and all(d["mac"] == "unknown" for d in devices)


class TestEndToEnd:
    def test_the_october_scenario_through_the_real_save_path(self, mod, tmp_path, monkeypatch):
        monkeypatch.setattr(mod, "BASELINE_FILE", str(tmp_path / "baseline.json"))
        monkeypatch.setattr(mod, "HISTORY_FILE", str(tmp_path / "history.jsonl"))
        mod.save_baseline(good())
        # The failed-ARP run saves. The identities must not be lost.
        mod.save_baseline(unknowns())
        saved = mod.load_baseline()
        assert {d["mac"] for d in saved["devices"]} == {A, B, C}
        assert set(saved["device_memory"]) == {A, B, C}
        # The following good run compares against the real list: no NEW line.
        notes = mod.diff_baseline(saved, good("2026-10-16T22:55:49+00:00"))
        assert not any("NEW device" in n or "gone" in n for n in notes), notes
