"""Which program produced the report.

Everything else in this tool authenticates data. The baseline is sealed so it
cannot be rewritten, receipts survive it being deleted, heartbeats show that
observation was happening. None of them says anything about the program that
produced any of it — and that program sits on the machine being assessed.

Delete the check that would report a backdoor port and every one of those
defences keeps working perfectly, indefinitely, over a report that has quietly
stopped looking. Recording a digest of the script in the off-host record is what
turns that edit from invisible-forever into visible-afterwards.

The limit is severe and these tests pin it rather than hide it: THE SCRIPT
HASHES ITSELF. A modified script reports whatever digest it likes. This is the
same weakness the provenance work labels self-reported, it is not fixable from
inside the script, and the report has to say so — a digest that implied more
than it can carry would be worse than no digest, because it would be believed.
"""

import json


PASSPHRASE = "correct horse battery staple"
STATE = {"timestamp": "2026-08-16T00:00:00+00:00", "router_open_ports": [443]}


class TestTheDigestDescribesTheFileOnDisk:
    def test_it_is_a_sha256_of_the_file(self, mod, tmp_path):
        import hashlib
        target = tmp_path / "script.py"
        target.write_bytes(b"print('hello')\n")
        assert mod.script_digest(str(target)) == hashlib.sha256(
            b"print('hello')\n").hexdigest()

    def test_editing_the_file_changes_the_digest(self, mod, tmp_path):
        target = tmp_path / "script.py"
        target.write_bytes(b"a = 1\n")
        before = mod.script_digest(str(target))
        target.write_bytes(b"a = 2\n")
        assert mod.script_digest(str(target)) != before

    def test_an_unreadable_file_is_none_rather_than_an_exception(self, mod, tmp_path):
        # A digest that cannot be taken must not stop the audit that was going
        # to be published with it.
        assert mod.script_digest(str(tmp_path / "absent.py")) is None

    def test_the_default_is_the_running_module(self, mod):
        assert mod.script_digest() == mod.script_digest(mod.__file__)


class TestTheAttestationTravelsWithTheEvidence:
    def test_a_saved_baseline_records_the_program_that_wrote_it(self, mod):
        record = mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert record["code"] == mod.script_digest()

    def test_the_digest_is_inside_the_seal(self, mod):
        """Editing the recorded digest must not be a quiet edit.

        Worth far less than it sounds — the script computing the digest is the
        one an attacker would have edited — but it does stop the recorded value
        being changed afterwards without the passphrase.
        """
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        with open(mod.BASELINE_FILE) as f:
            record = json.load(f)
        record["code"] = "0" * 64
        with open(mod.BASELINE_FILE, "w") as f:
            json.dump(record, f)
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "modified"

    def test_a_receipt_carries_the_digest_of_the_run_it_describes(self, mod):
        record = {"seq": 1, "seal": "abc", "prev": None, "keyed": True,
                  "code": "a" * 64, "state": STATE}
        # Copied from the record, not recomputed: the receipt attests to the
        # program that wrote that baseline, not to whatever is on disk now.
        assert mod.baseline_receipt(record)["code"] == "a" * 64

    def test_a_heartbeat_carries_one_too(self, mod, tmp_path):
        target = tmp_path / "hb.jsonl"
        mod.monitor_heartbeat(destination=str(target))
        entry = json.loads(target.read_text(encoding="utf-8").splitlines()[0])
        assert entry["code"] == mod.script_digest()

    def test_the_digest_leaks_nothing_about_the_network(self, mod, tmp_path):
        sink = tmp_path / "receipts"
        sink.mkdir()
        mod.save_baseline({"gateway": "192.168.1.1", "devices": [
            {"ip": "192.168.1.42", "mac": "a4:83:e7:1b:9c:2d"}]},
            passphrase=PASSPHRASE)
        mod.publish_receipt(mod.load_baseline_record(), destination=str(sink))
        blob = (sink / "receipts.jsonl").read_text(encoding="utf-8")
        for secret in ("a4:83:e7:1b:9c:2d", "192.168.1.42", "192.168.1.1"):
            assert secret not in blob


class TestAChangedProgramShowsUpInTheOffHostRecord:
    def _receipts(self, *digests):
        return [{"seq": i + 1, "code": d, "published_at": f"2026-08-1{i}T00:00:00+00:00"}
                for i, d in enumerate(digests)]

    def test_a_steady_digest_reports_no_change(self, mod):
        assert mod.code_changes(self._receipts("a" * 64, "a" * 64)) == []

    def test_a_changed_digest_is_found_with_when(self, mod):
        changes = mod.code_changes(self._receipts("a" * 64, "b" * 64))
        assert len(changes) == 1
        assert changes[0]["from"] == "a" * 64 and changes[0]["to"] == "b" * 64
        assert changes[0]["at"] == "2026-08-11T00:00:00+00:00"

    def test_heartbeats_are_read_as_well_as_baseline_receipts(self, mod):
        """A monitor-only deployment publishes nothing else for weeks.

        That is precisely the deployment where an edited script has the longest
        to go unnoticed, so ignoring heartbeats would blind the check where it
        matters most.
        """
        beats = [{"kind": "heartbeat", "code": "a" * 64, "at": "2026-08-10T00:00:00+00:00"},
                 {"kind": "heartbeat", "code": "b" * 64, "at": "2026-08-11T00:00:00+00:00"}]
        assert len(mod.code_changes(beats)) == 1

    def test_records_predating_attestation_are_not_read_as_a_change(self, mod):
        # An older receipt carries no digest at all. Treating its absence as a
        # different program would raise a change on every upgraded install.
        mixed = [{"seq": 1, "published_at": "2026-08-10T00:00:00+00:00"},
                 {"seq": 2, "code": "a" * 64, "published_at": "2026-08-11T00:00:00+00:00"}]
        assert mod.code_changes(mixed) == []

    def test_nothing_attested_stays_silent(self, mod):
        assert mod.describe_code_attestation([]) is None
        assert mod.describe_code_attestation([{"seq": 1}]) is None

    def test_an_unchanged_program_reports_info_not_a_pass(self, mod):
        line = mod.describe_code_attestation(self._receipts("a" * 64, "a" * 64))
        assert "[INFO" in line and "[OK" not in line

    def test_a_changed_program_is_raised_for_review(self, mod):
        line = mod.describe_code_attestation(self._receipts("a" * 64, "b" * 64))
        assert "[REVIEW" in line
        assert "did not update the tool" in line


class TestTheReportDoesNotOverclaim:
    """The property that decides whether this feature is honest or harmful."""

    def test_every_verdict_carries_the_self_reported_caveat(self, mod):
        steady = [{"seq": 1, "code": "a" * 64, "published_at": "2026-08-10T00:00:00+00:00"}]
        changed = [{"seq": 1, "code": "a" * 64, "published_at": "2026-08-10T00:00:00+00:00"},
                   {"seq": 2, "code": "b" * 64, "published_at": "2026-08-11T00:00:00+00:00"}]
        for receipts in (steady, changed):
            line = mod.describe_code_attestation(receipts)
            assert "self-reported" in line.lower()
            assert "hashes itself" in line

    def test_a_script_that_lies_about_its_digest_is_not_detected(self, mod):
        """The acknowledged limit, pinned so nobody later mistakes it for a bug.

        An attacker who edits the script also edits the line that reports the
        digest, and keeps publishing the original. The off-host record stays
        perfectly consistent. Nothing in here can tell — any check the script
        runs on itself is a check the attacker has already edited — which is why
        the caveat above is load-bearing rather than decorative.
        """
        honest = "a" * 64
        forged = [{"seq": 1, "code": honest, "published_at": "2026-08-10T00:00:00+00:00"},
                  # script edited here; it keeps reporting the old digest
                  {"seq": 2, "code": honest, "published_at": "2026-08-11T00:00:00+00:00"}]
        assert mod.code_changes(forged) == []
        assert "[REVIEW" not in mod.describe_code_attestation(forged)
