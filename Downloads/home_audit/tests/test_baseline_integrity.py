"""Tamper-evidence for the saved baseline.

The baseline is the tool's memory. Change detection is only worth anything if
that memory cannot be quietly rewritten, and until now it could: `save_baseline`
wrote a bare JSON dict, so neutralising the entire audit cost an attacker one
`json.dump`, with nothing anywhere to show it had happened.

These tests are written as attacks rather than round-trips. Each one takes the
position of someone with write access to ~/.home_net_audit who wants the next
run to report "No changes since baseline", and asserts that the attempt is
visible afterwards.

The keyed / unkeyed distinction is load-bearing throughout. An unkeyed seal is
a bare hash the attacker can recompute; it catches corruption and carelessness,
nothing more. A test that blurred the two would be worse than no test, because
it would certify a protection that isn't there.
"""

import json
import os

import pytest


PASSPHRASE = "correct horse battery staple"
STATE = {
    "timestamp": "2026-08-11T00:00:00+00:00",
    "gateway": "192.168.1.1",
    "dns": ["1.1.1.1"],
    "router_open_ports": [80, 443],
    "devices": [{"ip": "192.168.1.42", "mac": "a4:83:e7:1b:9c:2d"}],
}


def _tamper(mod, mutate):
    """Rewrite baseline.json the way an attacker with file access would."""
    with open(mod.BASELINE_FILE) as f:
        record = json.load(f)
    mutate(record)
    with open(mod.BASELINE_FILE, "w") as f:
        json.dump(record, f)
    return record


class TestSealDetectsModification:
    def test_editing_the_state_breaks_a_keyed_seal(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        # The attacker's goal: make a newly opened port look like it was always
        # there, so the next diff reports nothing.
        _tamper(mod, lambda r: r["state"].update(router_open_ports=[80, 443, 23]))

        report = mod.verify_baseline(passphrase=PASSPHRASE)
        assert report["status"] == "modified"
        assert report["keyed"] is True

    def test_editing_the_state_breaks_an_unkeyed_seal(self, mod):
        mod.save_baseline(STATE)
        _tamper(mod, lambda r: r["state"].update(dns=["8.8.8.8"]))
        assert mod.verify_baseline()["status"] == "modified"

    def test_removing_a_device_is_detected(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        _tamper(mod, lambda r: r["state"].update(devices=[]))
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "modified"

    def test_an_untouched_baseline_verifies(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        report = mod.verify_baseline(passphrase=PASSPHRASE)
        assert report["status"] == "ok"
        assert report["keyed"] is True

    def test_verification_survives_a_resave_of_identical_state(self, mod):
        # Canonical serialisation must be stable: an identical state saved twice
        # has to verify, or the alarm becomes noise and gets ignored.
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        mod.save_baseline(dict(STATE), passphrase=PASSPHRASE)
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "ok"

    def test_key_ordering_does_not_affect_the_seal(self, mod):
        # Same content, different insertion order — must not read as tampering.
        reordered = dict(reversed(list(STATE.items())))
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        first = mod.load_baseline_record()["seal"]
        mod.save_baseline(reordered, passphrase=PASSPHRASE)
        second = mod.load_baseline_record()

        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "ok"
        # Seals differ only because the chain advanced, not because of ordering.
        assert second["prev"] == first


class TestKeyedSealResistsForgery:
    def test_an_attacker_without_the_passphrase_cannot_reseal(self, mod):
        """The property that separates keyed from unkeyed.

        Here the attacker does the thorough job: edits the state AND recomputes
        the seal the only way they can without the passphrase — unkeyed. It must
        still fail, or the passphrase is decorative.
        """
        mod.save_baseline(STATE, passphrase=PASSPHRASE)

        def rewrite(record):
            record["state"]["router_open_ports"] = [80]
            payload = {k: v for k, v in record.items() if k != "seal"}
            record["seal"] = mod.seal_payload(payload, key=None)

        _tamper(mod, rewrite)
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "modified"

    def test_a_wrong_passphrase_does_not_verify(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert mod.verify_baseline(passphrase="hunter2")["status"] == "modified"

    def test_a_keyed_baseline_reports_unverifiable_without_the_passphrase(self, mod):
        # Must not read as "ok" — an unchecked seal is not a passed check.
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        report = mod.verify_baseline()
        assert report["status"] == "unverifiable"
        assert report["status"] != "ok"

    def test_swapping_in_a_different_salt_is_detected(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        _tamper(mod, lambda r: r["kdf"].update(salt=os.urandom(16).hex()))
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "modified"

    def test_malformed_kdf_parameters_do_not_raise(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        _tamper(mod, lambda r: r["kdf"].update(salt="not-hex"))
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "modified"

    def test_downgrading_a_keyed_record_to_unkeyed_is_detected(self, mod):
        """Strip the key and claim it was never sealed — the obvious dodge."""
        mod.save_baseline(STATE, passphrase=PASSPHRASE)

        def downgrade(record):
            record["keyed"] = False
            record.pop("kdf", None)
            record["state"]["router_open_ports"] = [80]
            payload = {k: v for k, v in record.items() if k != "seal"}
            record["seal"] = mod.seal_payload(payload, key=None)

        _tamper(mod, downgrade)
        # The record now claims to be unkeyed and is internally consistent, so
        # the seal alone cannot catch it. The chain does: history recorded this
        # run as keyed, and the seal no longer matches what was chained.
        report = mod.verify_baseline(passphrase=PASSPHRASE)
        assert report["status"] in {"modified", "rolled_back"}


class TestChainDetectsReplacement:
    def test_rolling_back_to_an_earlier_baseline_is_detected(self, mod, tmp_path):
        """A perfectly valid older baseline is still an attack.

        Its seal verifies — it was genuinely written by this tool. Only the
        chain shows it is stale, which is why the seal alone is not enough.
        """
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        with open(mod.BASELINE_FILE) as f:
            old = f.read()

        newer = dict(STATE, router_open_ports=[80, 443, 23])
        mod.save_baseline(newer, passphrase=PASSPHRASE)

        with open(mod.BASELINE_FILE, "w") as f:   # put the old one back
            f.write(old)

        report = mod.verify_baseline(passphrase=PASSPHRASE)
        assert report["status"] == "rolled_back"
        assert "run 1" in report["detail"] and "run 2" in report["detail"]

    def test_deleting_the_history_is_detected(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        os.unlink(mod.HISTORY_FILE)
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "chain_missing"

    def test_the_chain_records_every_run_in_order(self, mod):
        for _ in range(3):
            mod.save_baseline(STATE, passphrase=PASSPHRASE)
        history = mod.read_history()
        assert [e["seq"] for e in history] == [1, 2, 3]
        assert all(e["keyed"] for e in history)

    def test_each_record_links_to_the_previous_seal(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        first = mod.load_baseline_record()["seal"]
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        second = mod.load_baseline_record()
        assert second["prev"] == first
        assert second["seq"] == 2

    def test_the_first_record_has_no_predecessor(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        record = mod.load_baseline_record()
        assert record["prev"] is None and record["seq"] == 1

    def test_a_corrupt_history_line_does_not_crash_verification(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        with open(mod.HISTORY_FILE, "a") as f:
            f.write("{not json at all\n\n")
        # The unreadable line is skipped; the real entry still governs.
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "ok"


class TestUnkeyedModeIsHonestlyLabelled:
    def test_unkeyed_verification_is_not_reported_as_a_passed_security_check(self, mod):
        """The most important test here.

        An unkeyed seal is recomputable by the attacker. It must verify (it
        catches corruption) while saying plainly that it is not forgery-proof —
        anything else would certify a protection the user does not have.
        """
        mod.save_baseline(STATE)
        report = mod.verify_baseline()
        assert report["status"] == "ok"
        assert report["keyed"] is False
        assert "unkeyed" in report["detail"].lower()
        assert "passphrase" in report["detail"].lower()

    def test_an_unkeyed_baseline_is_only_review_not_ok_in_the_summary(self, mod):
        mod.save_baseline(STATE)
        line = mod.describe_baseline_integrity(mod.verify_baseline())
        assert "REVIEW" in line and "[OK" not in line

    def test_a_keyed_baseline_reads_as_ok_in_the_summary(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        line = mod.describe_baseline_integrity(mod.verify_baseline(passphrase=PASSPHRASE))
        assert "OK" in line

    @pytest.mark.parametrize("status", ["modified", "rolled_back", "chain_missing"])
    def test_every_tampering_status_surfaces_as_high(self, mod, status):
        line = mod.describe_baseline_integrity({"status": status, "keyed": True, "detail": "x"})
        assert "HIGH" in line


class TestBackwardCompatibility:
    def test_a_legacy_bare_state_file_still_loads(self, mod):
        # Users upgrading have a plain dict on disk; refusing it would throw
        # away their existing history.
        mod._secure_dir()
        with open(mod.BASELINE_FILE, "w") as f:
            json.dump(STATE, f)
        assert mod.load_baseline() == STATE

    def test_a_legacy_baseline_is_flagged_as_unauthenticated(self, mod):
        mod._secure_dir()
        with open(mod.BASELINE_FILE, "w") as f:
            json.dump(STATE, f)
        report = mod.verify_baseline()
        assert report["status"] == "legacy"
        assert "unauthenticated" in report["detail"].lower()

    def test_load_baseline_returns_the_state_not_the_envelope(self, mod):
        # Every existing caller expects the bare state dict.
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert mod.load_baseline() == STATE

    def test_absent_baseline_reports_absent_rather_than_tampered(self, mod):
        assert mod.verify_baseline()["status"] == "absent"

    def test_a_truncated_baseline_does_not_crash(self, mod):
        mod._secure_dir()
        with open(mod.BASELINE_FILE, "w") as f:
            f.write('{"format": 2, "state":')
        assert mod.load_baseline() is None
        assert mod.verify_baseline()["status"] == "absent"


class TestStorageHardening:
    def test_the_write_is_atomic_so_a_crash_cannot_truncate(self, mod, monkeypatch):
        """The old implementation opened the real path with "w", emptying it
        before writing. A crash mid-write left an empty baseline that read as
        "never had one"."""
        mod.save_baseline(STATE, passphrase=PASSPHRASE)

        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(mod.json, "dump", boom)
        with pytest.raises(OSError):
            mod.save_baseline(dict(STATE, gateway="10.0.0.1"), passphrase=PASSPHRASE)

        # The previous baseline must be intact, not truncated.
        assert mod.load_baseline() == STATE

    def test_no_temp_files_are_left_behind_after_a_failed_write(self, mod, monkeypatch):
        mod.save_baseline(STATE)
        monkeypatch.setattr(mod.json, "dump", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        with pytest.raises(OSError):
            mod.save_baseline(STATE)
        leftovers = [n for n in os.listdir(mod.BASELINE_DIR) if n.startswith(".tmp-")]
        assert leftovers == []

    def test_the_baseline_is_not_world_readable(self, mod):
        # It carries MACs, topology, and any accepted credentials.
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert os.stat(mod.BASELINE_FILE).st_mode & 0o077 == 0
        assert os.stat(mod.BASELINE_DIR).st_mode & 0o077 == 0

    def test_the_history_is_not_world_readable(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert os.stat(mod.HISTORY_FILE).st_mode & 0o077 == 0


class TestKeyDerivation:
    def test_the_same_passphrase_and_salt_give_the_same_key(self, mod):
        salt = b"\x00" * 16
        a = mod.derive_baseline_key(PASSPHRASE, salt, iterations=1000)
        b = mod.derive_baseline_key(PASSPHRASE, salt, iterations=1000)
        assert a == b and len(a) == 32

    def test_a_different_salt_gives_a_different_key(self, mod):
        a = mod.derive_baseline_key(PASSPHRASE, b"\x00" * 16, iterations=1000)
        b = mod.derive_baseline_key(PASSPHRASE, b"\x01" * 16, iterations=1000)
        assert a != b

    def test_each_save_uses_a_fresh_salt(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        first = mod.load_baseline_record()["kdf"]["salt"]
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert mod.load_baseline_record()["kdf"]["salt"] != first

    def test_the_iteration_count_is_not_trivially_low(self, mod):
        # A cheap KDF makes the passphrase brute-forceable offline once the
        # attacker has the file, which they do by assumption.
        assert mod.KDF_ITERATIONS >= 100_000

    def test_keyed_and_unkeyed_seals_of_the_same_payload_differ(self, mod):
        payload = {"a": 1}
        key = mod.derive_baseline_key(PASSPHRASE, b"salt" * 4, iterations=1000)
        assert mod.seal_payload(payload, key) != mod.seal_payload(payload, None)


class TestPassphraseResolution:
    def test_the_environment_variable_is_used_when_set(self, mod, monkeypatch):
        monkeypatch.setenv(mod.PASSPHRASE_ENV, "from-env")
        assert mod.resolve_passphrase() == "from-env"

    def test_no_passphrase_anywhere_returns_none(self, mod, monkeypatch):
        monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
        assert mod.resolve_passphrase(prompt=False) is None

    def test_an_empty_environment_variable_is_treated_as_unset(self, mod, monkeypatch):
        monkeypatch.setenv(mod.PASSPHRASE_ENV, "")
        assert mod.resolve_passphrase(prompt=False) is None

    def test_the_passphrase_is_never_written_into_the_baseline(self, mod):
        """A key stored beside what it authenticates protects nothing."""
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        with open(mod.BASELINE_FILE) as f:
            blob = f.read()
        with open(mod.HISTORY_FILE) as f:
            blob += f.read()
        assert PASSPHRASE not in blob
        for word in PASSPHRASE.split():
            assert word not in blob
