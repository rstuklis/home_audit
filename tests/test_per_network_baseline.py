"""One baseline per network.

A single baseline.json served every network, and this machine has three known
Wi-Fi networks. Comparing one against another's baseline is not a comparison:
every device on the new network reads as an arrival, every device on the old one
as a departure, and two different routers' port lists are diffed against each
other. The run then saves over the baseline, so switching back produces the
mirror image — neither network ever accumulates a usable history, and the report
cries wolf every time the laptop moves.

The identity is the subnet, not the friendly name: renaming "pearl" in
networks.json is a labelling change and must not orphan that network's baseline
or its seal chain.
"""

import json
import os

import pytest


LOVESHACK = "192.168.87.0/24"
PEARL = "192.168.86.0/24"
IOT = "192.168.85.0/24"


def state_for(subnet, macs, ports, timestamp="2026-08-13T05:00:00+00:00"):
    prefix = subnet.rsplit(".", 2)[0]
    return {
        "timestamp": timestamp,
        "gateway": f"{prefix}.1",
        "devices": [{"ip": f"{prefix}.{i}", "mac": m, "subnet": subnet}
                    for i, m in enumerate(macs, start=10)],
        "scanned_subnets": [subnet],
        "router_open_ports": ports,
    }


@pytest.fixture
def net(mod, monkeypatch, tmp_path):
    """Point BASELINE_DIR at tmp and give tests a select/save/load helper."""
    monkeypatch.setattr(mod, "BASELINE_DIR", str(tmp_path))
    monkeypatch.setattr(mod, "BASELINE_FILE", str(tmp_path / "baseline.json"))
    monkeypatch.setattr(mod, "HISTORY_FILE", str(tmp_path / "history.jsonl"))
    return tmp_path


class TestNetworksDoNotShareABaseline:
    def test_saving_one_network_does_not_disturb_another(self, mod, net):
        mod.select_network_baseline(LOVESHACK)
        mod.save_baseline(state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80, 5000]))
        mod.select_network_baseline(PEARL)
        mod.save_baseline(state_for(PEARL, ["b8:27:eb:00:00:01"], [80]))

        mod.select_network_baseline(LOVESHACK)
        assert mod.load_baseline()["router_open_ports"] == [80, 5000]
        mod.select_network_baseline(PEARL)
        assert mod.load_baseline()["router_open_ports"] == [80]

    def test_switching_networks_reports_no_change(self, mod, net):
        # The whole point. Each network diffed against ITS OWN baseline is
        # quiet; the old shared file made every switch a full false alarm.
        love = state_for(LOVESHACK, ["3c:22:fb:00:00:01", "3c:22:fb:00:00:02"], [80, 5000])
        pearl = state_for(PEARL, ["b8:27:eb:00:00:01"], [80])

        mod.select_network_baseline(LOVESHACK)
        mod.save_baseline(love)
        mod.select_network_baseline(PEARL)
        mod.save_baseline(pearl)

        mod.select_network_baseline(LOVESHACK)
        assert mod.diff_baseline(mod.load_baseline(), love) == []
        mod.select_network_baseline(PEARL)
        assert mod.diff_baseline(mod.load_baseline(), pearl) == []

    def test_the_old_shared_file_would_have_alarmed(self, mod, net):
        # Pins what the change is worth, by showing the failure it removes: the
        # two states really are wholly different, so a shared baseline alarms
        # about a switch on which nothing whatever has happened.
        love = state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80, 5000])
        pearl = state_for(PEARL, ["b8:27:eb:00:00:01"], [80])
        notes = mod.diff_baseline(love, pearl)
        assert any("NEW device" in n for n in notes)
        assert any("closed" in n for n in notes)
        # The departure half is NOT asserted, and its absence is the point of a
        # separate fix rather than a weakening of this one. The Pearl run swept
        # only Pearl's subnet, so it never looked where the Loveshack device
        # answers; "gone" would be a claim about ground nobody covered. Per-network
        # baselines are still what keeps the switch quiet — the arrival above
        # fires on the shared file and no coverage test can withhold it, because
        # the device really was seen.
        assert not any("gone" in n for n in notes)

    def test_each_network_keeps_its_own_seal_chain(self, mod, net):
        # A chain means nothing except relative to what it chains, so a shared
        # history would interleave three networks' sequence numbers.
        mod.select_network_baseline(LOVESHACK)
        mod.save_baseline(state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))
        mod.save_baseline(state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))
        mod.select_network_baseline(PEARL)
        mod.save_baseline(state_for(PEARL, ["b8:27:eb:00:00:01"], [80]))

        assert mod.load_baseline_record()["seq"] == 1, "pearl inherited another chain"
        mod.select_network_baseline(LOVESHACK)
        assert mod.load_baseline_record()["seq"] == 2

    def test_a_third_network_starts_clean_rather_than_inheriting(self, mod, net):
        mod.select_network_baseline(LOVESHACK)
        mod.save_baseline(state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))
        mod.select_network_baseline(IOT)
        assert mod.load_baseline() is None, "an unseen network inherited a baseline"


class TestKeying:
    def test_the_key_is_filename_safe(self, mod):
        key = mod.baseline_key(LOVESHACK)
        assert "/" not in key and "." not in key
        assert key == "192-168-87-0-24"

    def test_distinct_subnets_get_distinct_keys(self, mod):
        assert len({mod.baseline_key(s) for s in (LOVESHACK, PEARL, IOT)}) == 3

    def test_an_unidentifiable_network_leaves_the_defaults_alone(self, mod, net):
        before = mod.BASELINE_FILE
        assert mod.select_network_baseline(None) is None
        assert mod.BASELINE_FILE == before, \
            "an unknown network silently repointed the baseline"

    def test_renaming_a_network_does_not_orphan_its_baseline(self, mod, net):
        # The key comes from the subnet, so the friendly name is presentation.
        mod.select_network_baseline(LOVESHACK)
        mod.save_baseline(state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))
        path_before = mod.BASELINE_FILE
        mod.select_network_baseline(LOVESHACK)   # as if renamed in networks.json
        assert mod.BASELINE_FILE == path_before
        assert mod.load_baseline() is not None


class TestIdentifyNetwork:
    IFACES = [("en0", "192.168.87.249", __import__("ipaddress").ip_network(LOVESHACK))]

    def test_the_gateway_subnet_wins(self, mod):
        assert mod.identify_network(self.IFACES, "192.168.87.249", "192.168.87.1") == LOVESHACK

    def test_falls_back_to_this_machine_s_own_subnet(self, mod):
        assert mod.identify_network(self.IFACES, "192.168.87.249", None) == LOVESHACK

    def test_a_gateway_outside_every_interface_does_not_match_one(self, mod):
        # An upstream modem on another subnet must not be mistaken for the
        # network this machine is attached to.
        assert mod.identify_network(self.IFACES, "192.168.87.249", "192.168.1.1") == LOVESHACK

    def test_no_interfaces_and_no_ip_identifies_nothing(self, mod):
        assert mod.identify_network([], None, None) is None


class TestLegacyMigration:
    """A baseline saved before per-network storage says which network it
    describes; migrating on that evidence keeps a verified seal chain attached
    to the right network instead of stranding it."""

    def _write_legacy(self, mod, net, state):
        mod.BASELINE_FILE = str(net / "baseline.json")
        mod.HISTORY_FILE = str(net / "history.jsonl")
        mod.save_baseline(state)

    def test_a_legacy_baseline_moves_to_the_network_it_recorded(self, mod, net):
        self._write_legacy(mod, net, state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80, 5000]))
        assert mod.migrate_legacy_baseline() == "192-168-87-0-24"
        assert not (net / "baseline.json").exists()
        mod.select_network_baseline(LOVESHACK)
        assert mod.load_baseline()["router_open_ports"] == [80, 5000]

    def test_the_seal_chain_moves_with_it(self, mod, net):
        self._write_legacy(mod, net, state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))
        mod.migrate_legacy_baseline()
        assert (net / "history-192-168-87-0-24.jsonl").exists()
        assert not (net / "history.jsonl").exists()

    def test_a_baseline_with_nothing_identifying_is_left_alone(self, mod, net):
        # Filing it under a guess would attach a real chain to the wrong
        # network, which is worse than leaving it where it is. Note a recorded
        # gateway IS enough — see
        # TestUnidentifiableLegacyBaselineIsNotAbandoned — so this state has
        # none: no coverage, no devices, no gateway.
        self._write_legacy(mod, net, {"timestamp": "t", "router_open_ports": [80]})
        assert mod.migrate_legacy_baseline() is None
        assert (net / "baseline.json").exists()

    def test_migration_never_overwrites_an_existing_per_network_baseline(self, mod, net):
        mod.select_network_baseline(LOVESHACK)
        mod.save_baseline(state_for(LOVESHACK, ["3c:22:fb:00:00:99"], [443]))
        self._write_legacy(mod, net, state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))

        assert mod.migrate_legacy_baseline() is None
        mod.select_network_baseline(LOVESHACK)
        assert mod.load_baseline()["router_open_ports"] == [443], "migration clobbered a newer baseline"

    def test_migrating_twice_is_harmless(self, mod, net):
        self._write_legacy(mod, net, state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))
        assert mod.migrate_legacy_baseline() == "192-168-87-0-24"
        assert mod.migrate_legacy_baseline() is None

    def test_the_device_subnet_identifies_it_when_coverage_was_not_recorded(self, mod, net):
        # Baselines saved before scanned_subnets existed still carry a subnet
        # on every device.
        state = state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80])
        del state["scanned_subnets"]
        self._write_legacy(mod, net, state)
        assert mod.migrate_legacy_baseline() == "192-168-87-0-24"

    def test_a_corrupt_legacy_file_is_not_moved(self, mod, net):
        (net / "baseline.json").write_text("{not json")
        mod.BASELINE_FILE = str(net / "baseline.json")
        assert mod.migrate_legacy_baseline() is None
        assert (net / "baseline.json").exists()


class TestSelectionCannotEscapeRedirection:
    """Selection must follow wherever the baseline has been pointed.

    BASELINE_DIR and BASELINE_FILE are separate module names that can disagree.
    Deriving the per-network paths from BASELINE_DIR meant anything repointing
    only BASELINE_FILE — the test sandbox in conftest.py patches every attribute
    ending in _FILE — had selection jump back to BASELINE_DIR and write outside
    the redirection. In a test suite that means writing into the user's real
    ~/.home_net_audit, which is the one thing the sandbox exists to prevent.
    Deriving from the selected file leaves a single source of truth.
    """

    def test_selection_lands_beside_the_file_it_was_pointed_at(self, mod, tmp_path,
                                                               monkeypatch):
        elsewhere = tmp_path / "somewhere_else"
        elsewhere.mkdir()
        monkeypatch.setattr(mod, "BASELINE_FILE", str(elsewhere / "baseline.json"))
        # BASELINE_DIR deliberately NOT repointed: the disagreement is the test.
        mod.select_network_baseline(LOVESHACK)
        assert str(elsewhere) in mod.BASELINE_FILE, mod.BASELINE_FILE
        assert str(elsewhere) in mod.HISTORY_FILE, mod.HISTORY_FILE

    def test_selection_never_reaches_the_real_home_directory(self, mod, tmp_path,
                                                             monkeypatch):
        real = os.path.expanduser("~/.home_net_audit")
        monkeypatch.setattr(mod, "BASELINE_FILE", str(tmp_path / "baseline.json"))
        for subnet in (IOT, PEARL, LOVESHACK):
            mod.select_network_baseline(subnet)
            assert not mod.BASELINE_FILE.startswith(real), mod.BASELINE_FILE
            assert not mod.HISTORY_FILE.startswith(real), mod.HISTORY_FILE

    def test_selecting_twice_does_not_nest_directories(self, mod, net):
        mod.select_network_baseline(LOVESHACK)
        first = mod.BASELINE_FILE
        mod.select_network_baseline(LOVESHACK)
        assert mod.BASELINE_FILE == first
        mod.select_network_baseline(PEARL)
        assert os.path.dirname(mod.BASELINE_FILE) == os.path.dirname(first)


class TestReceiptChains:
    """Sequence numbers restart at 1 per network, so a shared off-host sink
    holds several chains whose seq values collide. Untangling them must not cost
    the check those receipts exist for: catching a wiped ~/.home_net_audit,
    where the local baseline and its history go together and only the off-host
    record survives to contradict a run claiming to be the first.

    Adversarial review found the whole filter untested — deleting it left the
    entire suite green while restoring the cross-network false alarm.
    """

    def _chain_for(self, mod, subnet):
        mod.select_network_baseline(subnet)
        return mod.chain_id()

    def test_another_network_s_receipts_do_not_read_as_deleted_evidence(self, mod, net):
        love = self._chain_for(mod, LOVESHACK)
        pearl = self._chain_for(mod, PEARL)
        sink = ([{"seq": n, "seal": f"s{n}", "chain": love} for n in range(1, 14)]
                + [{"seq": 1, "seal": "p1", "chain": pearl}])

        mod.select_network_baseline(PEARL)
        assert mod.compare_with_receipts({"seq": 1, "seal": "p1"}, sink)["status"] == "ok"

    def test_this_network_s_own_receipts_still_catch_a_wipe(self, mod, net):
        love = self._chain_for(mod, LOVESHACK)
        sink = [{"seq": n, "seal": f"s{n}", "chain": love} for n in range(1, 8)]
        mod.select_network_baseline(LOVESHACK)
        # A wiped machine starts again at seq 1 while the sink remembers seven.
        assert mod.compare_with_receipts({"seq": 1, "seal": "s1"}, sink)["status"] == \
            "history_truncated"

    def test_receipts_predating_chains_still_catch_a_wipe_after_migration(self, mod, net):
        # The regression that mattered most. Pre-upgrade receipts carry no chain
        # id; pinning them to an id derived from the old filename meant
        # migration renamed the baseline, the id moved, and every one of them
        # stopped matching — silently disabling wipe detection for exactly the
        # users who had been publishing receipts the longest.
        legacy = [{"seq": n, "seal": f"s{n}"} for n in range(1, 6)]   # no "chain"
        mod.select_network_baseline(LOVESHACK)                        # i.e. migrated
        assert mod.compare_with_receipts({"seq": 1, "seal": "x"}, legacy)["status"] == \
            "history_truncated"

    def test_a_chainless_receipt_is_accepted_on_any_network(self, mod, net):
        # It cannot be attributed to one network now, and the alternative to
        # accepting it everywhere was discarding it everywhere.
        legacy = [{"seq": 4, "seal": "d"}]
        for subnet in (LOVESHACK, PEARL, IOT):
            mod.select_network_baseline(subnet)
            assert mod.compare_with_receipts({"seq": 1, "seal": "a"}, legacy)["status"] == \
                "history_truncated"

    def test_distinct_networks_get_distinct_chain_ids(self, mod, net):
        ids = {self._chain_for(mod, s) for s in (LOVESHACK, PEARL, IOT)}
        assert len(ids) == 3

    def test_a_chain_id_says_nothing_about_the_network(self, mod, net):
        # baseline_receipt exists to prove a run happened without shipping the
        # network's shape off-host, so the id must not carry the subnet.
        cid = self._chain_for(mod, LOVESHACK)
        assert "192" not in cid and "87" not in cid
        assert "loveshack" not in cid.lower()


class TestUnidentifiableLegacyBaselineIsNotAbandoned:
    def test_a_no_discovery_baseline_is_identified_by_its_gateway(self, mod, net):
        # Scheduled runs use --no-discovery, so they save neither coverage nor
        # devices — but they do record the gateway, and the network is its own.
        mod.BASELINE_FILE = str(net / "baseline.json")
        mod.HISTORY_FILE = str(net / "history.jsonl")
        mod.save_baseline({"timestamp": "t", "gateway": "192.168.87.1",
                           "router_open_ports": [80]})
        assert mod.migrate_legacy_baseline() == "192-168-87-0-24"

    def test_a_baseline_with_nothing_identifying_stays_selected(self, mod, net):
        # Selecting a per-network file here would leave a sealed, verified chain
        # on disk and unread for ever, and restart at seq 1 — losing change
        # detection AND the chain, which is worse than sharing one baseline was.
        mod.BASELINE_FILE = str(net / "baseline.json")
        mod.HISTORY_FILE = str(net / "history.jsonl")
        mod.save_baseline({"timestamp": "t", "router_open_ports": [80]})

        subnet, key = mod.use_current_network_baseline(
            interfaces=[], local_ip=None, gateway=None, announce=None)

        assert (subnet, key) == (None, None)
        assert mod.load_baseline() is not None, "a sealed baseline was abandoned"


class TestTheNetworkLineIsActuallyPrinted:
    """Found by adversarial review: an unreachable `return None` had been left in
    describe_current_network, so the one line telling the reader WHICH baseline a
    comparison used never printed. "No changes since baseline" means nothing
    without it, and it is the guard that would surface a mis-selected network."""

    def test_a_known_network_is_named(self, mod):
        line = mod.describe_current_network(LOVESHACK, {LOVESHACK: "loveshack"})
        assert line is not None, "the network line is dead code again"
        assert "loveshack" in line and LOVESHACK in line

    def test_an_unnamed_subnet_still_reports_the_subnet(self, mod):
        line = mod.describe_current_network("10.9.9.0/24", {})
        assert line is not None and "10.9.9.0/24" in line

    def test_no_line_when_the_network_is_unknown(self, mod):
        assert mod.describe_current_network(None) is None


class TestAChangedNetmaskDoesNotStartOver:
    """The key carries the prefix, so 192.168.87.0/24 and /23 are different
    files. A router handing out a changed netmask would otherwise look like a
    network nobody had ever audited: "no baseline saved yet", a fresh chain from
    seq 1, and the real baseline left on disk unread. Nothing is renamed — the
    exact key is tried first and an existing chain for the same network is
    adopted only as a fallback."""

    def _save_under(self, mod, subnet, ports):
        mod.select_network_baseline(subnet)
        mod.save_baseline(state_for(subnet, ["3c:22:fb:00:00:01"], ports))

    def test_a_wider_mask_finds_the_existing_chain(self, mod, net):
        self._save_under(mod, LOVESHACK, [80, 5000])          # /24 baseline exists
        mod.select_network_baseline("192.168.87.0/25")        # same network address
        assert mod.load_baseline() is not None, "a netmask change started over"
        assert mod.load_baseline()["router_open_ports"] == [80, 5000]

    def test_the_chain_continues_rather_than_restarting(self, mod, net):
        self._save_under(mod, LOVESHACK, [80])
        self._save_under(mod, LOVESHACK, [80])
        mod.select_network_baseline("192.168.87.0/25")
        mod.save_baseline(state_for(LOVESHACK, ["3c:22:fb:00:00:01"], [80]))
        assert mod.load_baseline_record()["seq"] == 3, "the seal chain restarted"

    def test_the_exact_key_still_wins_when_it_exists(self, mod, net):
        # Both prefixes on disk: the one actually asked for must be used, not
        # whichever the fallback would have found.
        self._save_under(mod, "192.168.87.0/25", [443])
        self._save_under(mod, LOVESHACK, [80, 5000])
        mod.select_network_baseline(LOVESHACK)
        assert mod.load_baseline()["router_open_ports"] == [80, 5000]

    def test_two_candidate_prefixes_are_not_guessed_between(self, mod, net):
        # Ambiguous: attaching a run to the wrong chain is worse than a clean
        # start, so an unrecognised prefix gets its own file.
        #
        # The files are written directly rather than through the tool, because
        # saving under the second prefix would ADOPT the first — the fallback
        # consolidating instead of forking, which is the behaviour the tests
        # above pin. Two siblings can only arise from something outside this
        # code path: a restore from backup, or a copy from another machine.
        (net / "baseline-192-168-87-0-25.json").write_text("{}")
        (net / "baseline-192-168-87-0-26.json").write_text("{}")
        assert mod.existing_key_for_same_network(str(net), LOVESHACK) is None

    def test_a_different_network_is_never_adopted(self, mod, net):
        self._save_under(mod, LOVESHACK, [80])
        mod.select_network_baseline(PEARL)
        assert mod.load_baseline() is None, "pearl adopted loveshack's baseline"

    def test_an_unparseable_subnet_adopts_nothing(self, mod, net):
        self._save_under(mod, LOVESHACK, [80])
        assert mod.existing_key_for_same_network(str(net), "not-a-subnet") is None
        assert mod.existing_key_for_same_network(str(net), None) is None

    def test_a_missing_directory_is_not_an_error(self, mod, tmp_path):
        assert mod.existing_key_for_same_network(str(tmp_path / "nope"), LOVESHACK) is None

    def test_unrelated_files_are_not_mistaken_for_baselines(self, mod, net):
        (net / "baseline-notes.txt").write_text("x")
        (net / "baseline-192-168-87-0-backup.json").write_text("{}")
        assert mod.existing_key_for_same_network(str(net), LOVESHACK) is None
