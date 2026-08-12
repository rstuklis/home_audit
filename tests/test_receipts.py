"""Off-host receipts — the half of the observer story that carries the security.

Sealing (test_baseline_integrity) stops the baseline being rewritten. It cannot
stop it being *deleted*: remove ~/.home_net_audit and the next run looks exactly
like a genuine first run, and nothing on the machine can tell those apart. That
is the gap these tests are about.

A receipt for every run, appended somewhere the audited host cannot reach back
into, closes it — not by preventing the deletion, but by making it visible
afterwards, because the off-host log still says run 7 while the machine claims
run 1.

Two things the tests hold the design to, both of which are easy to get wrong in
a way that looks fine:

  * a receipt carries no audit state. Shipping MACs, topology and any accepted
    credentials to a remote endpoint would create a fresh disclosure risk for
    precisely the people this is meant to protect.
  * a failed publish is reported, never silent and never fatal. A receipt that
    quietly did not leave the machine is the same as never sending one.
"""

import json
import os

import pytest
import urllib.error
import urllib.request


PASSPHRASE = "correct horse battery staple"
STATE = {
    "timestamp": "2026-08-11T00:00:00+00:00",
    "gateway": "192.168.1.1",
    "devices": [{"ip": "192.168.1.42", "mac": "a4:83:e7:1b:9c:2d"}],
    "router_open_ports": [80, 443],
}


@pytest.fixture
def sink(tmp_path, monkeypatch, mod):
    """An off-host sink the audited machine appends to but should not own."""
    path = tmp_path / "offhost"
    path.mkdir()
    monkeypatch.setenv(mod.SINK_ENV, str(path))
    return path


class TestWipedHistoryIsDetected:
    """The attack local sealing cannot reach."""

    def test_deleting_the_local_audit_directory_is_caught(self, mod, sink):
        for _ in range(7):
            mod.save_baseline(STATE, passphrase=PASSPHRASE)

        # The attacker removes every local trace and lets the tool start clean.
        os.unlink(mod.BASELINE_FILE)
        os.unlink(mod.HISTORY_FILE)
        mod.save_baseline(STATE, passphrase=PASSPHRASE)

        # Locally this is indistinguishable from a first run...
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "ok"
        assert mod.load_baseline_record()["seq"] == 1

        # ...but the off-host log remembers otherwise.
        report = mod.compare_with_receipts(
            mod.load_baseline_record(), mod.read_receipts(str(sink)))
        assert report["status"] == "history_truncated"
        assert "7 runs" in report["detail"] and "run 1" in report["detail"]

    def test_the_truncation_warning_is_high_risk(self, mod, sink):
        line = mod.describe_receipt_status({"status": "history_truncated", "detail": "x"})
        assert "HIGH" in line

    def test_an_intact_history_agrees_with_the_receipts(self, mod, sink):
        for _ in range(3):
            mod.save_baseline(STATE, passphrase=PASSPHRASE)
        report = mod.compare_with_receipts(
            mod.load_baseline_record(), mod.read_receipts(str(sink)))
        assert report["status"] == "ok"

    def test_a_locally_replaced_baseline_is_caught_by_seal_mismatch(self, mod, sink):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        record = mod.load_baseline_record()
        # Same run number, different content — a swap after publication.
        record["seal"] = "0" * 64
        report = mod.compare_with_receipts(record, mod.read_receipts(str(sink)))
        assert report["status"] == "seal_mismatch"

    def test_no_receipts_is_reported_rather_than_assumed_fine(self, mod):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        report = mod.compare_with_receipts(mod.load_baseline_record(), [])
        assert report["status"] == "no_receipts"
        assert "REVIEW" in mod.describe_receipt_status(report)


class TestReceiptsCarryNoAuditState:
    def test_a_receipt_excludes_the_state_entirely(self, mod):
        record = {"seq": 1, "seal": "abc", "prev": None, "keyed": True, "state": STATE}
        assert "state" not in mod.baseline_receipt(record)

    def test_no_device_identifiers_reach_the_sink(self, mod, sink):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        blob = (sink / "receipts.jsonl").read_text(encoding="utf-8")
        for secret in ("a4:83:e7:1b:9c:2d", "192.168.1.42", "192.168.1.1"):
            assert secret not in blob, f"{secret} was published off-host"

    def test_the_passphrase_never_reaches_the_sink(self, mod, sink):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        blob = (sink / "receipts.jsonl").read_text(encoding="utf-8")
        assert PASSPHRASE not in blob

    def test_a_receipt_still_carries_what_detection_needs(self, mod, sink):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        entry = mod.read_receipts(str(sink))[-1]
        assert entry["seq"] == 1
        assert entry["seal"] == mod.load_baseline_record()["seal"]
        assert entry["keyed"] is True
        assert entry["published_at"]

    def test_full_mode_ships_the_state_only_when_asked(self, mod, tmp_path):
        target = tmp_path / "full.jsonl"
        record = {"seq": 1, "seal": "abc", "prev": None, "keyed": True, "state": STATE}
        mod.publish_receipt(record, destination=str(target), mode="full")
        assert "a4:83:e7:1b:9c:2d" in target.read_text(encoding="utf-8")

    def test_digest_is_the_default_mode(self, mod, tmp_path):
        target = tmp_path / "d.jsonl"
        record = {"seq": 1, "seal": "abc", "prev": None, "keyed": True, "state": STATE}
        assert mod.publish_receipt(record, destination=str(target))["mode"] == "digest"
        assert "a4:83:e7" not in target.read_text(encoding="utf-8")


class TestPublishFailsLoudlyNotSilently:
    def test_no_sink_configured_is_reported_honestly(self, mod, monkeypatch):
        monkeypatch.delenv(mod.SINK_ENV, raising=False)
        report = mod.publish_receipt({"seq": 1, "seal": "a"})
        assert report["published"] is False
        assert "no trace" in report["detail"].lower()

    def test_an_unwritable_sink_is_reported_not_raised(self, mod, tmp_path):
        # A receipt that failed to leave the machine must not look like success.
        blocked = tmp_path / "file-not-dir"
        blocked.write_text("x", encoding="utf-8")
        report = mod.publish_receipt({"seq": 1, "seal": "a"},
                                     destination=str(blocked / "nested" / "r.jsonl"))
        assert report["published"] is False
        assert "could not publish" in report["detail"].lower()

    def test_a_failing_sink_does_not_stop_the_baseline_being_saved(self, mod, monkeypatch):
        # An unreachable sink must not take the whole audit down with it.
        monkeypatch.setattr(mod, "publish_receipt",
                            lambda *a, **k: {"published": False, "mode": "digest",
                                             "detail": "sink down"})
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "ok"

    def test_an_http_error_is_reported_not_raised(self, mod, monkeypatch):
        def boom(*a, **k):
            raise urllib.error.URLError("connection refused")
        monkeypatch.setattr(urllib.request, "urlopen", boom)
        report = mod.publish_receipt({"seq": 1, "seal": "a"},
                                     destination="https://collector.example/receipts")
        assert report["published"] is False
        assert "connection refused" in report["detail"]


class TestSinkDestinations:
    def test_a_directory_becomes_an_appended_receipt_log(self, mod, tmp_path):
        mod.publish_receipt({"seq": 1, "seal": "a"}, destination=str(tmp_path))
        mod.publish_receipt({"seq": 2, "seal": "b"}, destination=str(tmp_path))
        lines = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").strip().split("\n")
        assert [json.loads(l)["seq"] for l in lines] == [1, 2]

    def test_publishing_appends_rather_than_overwrites(self, mod, tmp_path):
        target = tmp_path / "r.jsonl"
        target.write_text('{"seq": 0, "seal": "pre-existing"}\n', encoding="utf-8")
        mod.publish_receipt({"seq": 1, "seal": "a"}, destination=str(target))
        assert "pre-existing" in target.read_text(encoding="utf-8")

    def test_missing_parent_directories_are_created(self, mod, tmp_path):
        target = tmp_path / "deep" / "nested" / "r.jsonl"
        assert mod.publish_receipt({"seq": 1, "seal": "a"},
                                   destination=str(target))["published"] is True
        assert target.exists()

    def test_https_posts_json_with_a_bearer_token(self, mod, monkeypatch):
        seen = {}

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def getcode(self): return 202

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.headers.items()}
            seen["body"] = json.loads(req.data.decode())
            return FakeResponse()

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        report = mod.publish_receipt({"seq": 3, "seal": "abc"},
                                     destination="https://collector.example/r",
                                     token="write-only-token")
        assert report["published"] is True
        assert seen["url"] == "https://collector.example/r"
        assert seen["headers"]["authorization"] == "Bearer write-only-token"
        assert seen["body"]["seq"] == 3

    def test_the_token_is_read_from_the_environment_when_not_passed(self, mod, monkeypatch):
        seen = {}

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def getcode(self): return 200

        def fake_urlopen(req, timeout=None):
            seen["auth"] = req.headers.get("Authorization")
            return FakeResponse()

        monkeypatch.setenv(mod.SINK_TOKEN_ENV, "env-token")
        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        mod.publish_receipt({"seq": 1, "seal": "a"}, destination="https://x.example/r")
        assert seen["auth"] == "Bearer env-token"

    def test_no_authorization_header_when_no_token_is_available(self, mod, monkeypatch):
        seen = {}

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def getcode(self): return 200

        monkeypatch.delenv(mod.SINK_TOKEN_ENV, raising=False)
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda req, timeout=None: (seen.update(
                                auth=req.headers.get("Authorization")), FakeResponse())[1])
        mod.publish_receipt({"seq": 1, "seal": "a"}, destination="https://x.example/r")
        assert seen["auth"] is None


class TestReceiptLogReading:
    def test_a_corrupt_line_does_not_discard_the_rest(self, mod, tmp_path):
        target = tmp_path / "receipts.jsonl"
        target.write_text('{"seq": 1, "seal": "a"}\n'
                          'not json at all\n'
                          '\n'
                          '{"seq": 2, "seal": "b"}\n', encoding="utf-8")
        assert [r["seq"] for r in mod.read_receipts(str(target))] == [1, 2]

    def test_a_missing_log_reads_as_empty(self, mod, tmp_path):
        assert mod.read_receipts(str(tmp_path / "nope.jsonl")) == []

    def test_a_directory_source_finds_the_default_filename(self, mod, tmp_path):
        (tmp_path / "receipts.jsonl").write_text('{"seq": 5, "seal": "e"}\n',
                                                 encoding="utf-8")
        assert mod.read_receipts(str(tmp_path))[0]["seq"] == 5

    def test_out_of_order_receipts_still_yield_the_highest_run(self, mod):
        # An append-only log can interleave if two devices publish to it.
        receipts = [{"seq": 3, "seal": "c"}, {"seq": 1, "seal": "a"},
                    {"seq": 2, "seal": "b"}]
        report = mod.compare_with_receipts({"seq": 1, "seal": "a"}, receipts)
        assert report["status"] == "history_truncated"


class TestSealIsNotDisturbedByPublishing:
    def test_the_publish_status_never_reaches_the_sealed_file(self, mod, sink):
        # save_baseline attaches the publish result to the in-memory record for
        # the caller. Writing it to disk would break the seal it was computed
        # over, and the next verification would report a false tamper.
        returned = mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert "_receipt" in returned
        assert "_receipt" not in mod.load_baseline_record()

    def test_verification_still_passes_after_publishing(self, mod, sink):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "ok"

    def test_the_published_seal_matches_the_sealed_record(self, mod, sink):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert mod.read_receipts(str(sink))[-1]["seal"] == \
            mod.load_baseline_record()["seal"]


class TestSinkResolution:
    def test_an_explicit_destination_beats_the_environment(self, mod, monkeypatch, tmp_path):
        monkeypatch.setenv(mod.SINK_ENV, "/from/env")
        assert mod.resolve_sink(str(tmp_path)) == str(tmp_path)

    def test_the_environment_is_used_when_nothing_explicit(self, mod, monkeypatch):
        monkeypatch.setenv(mod.SINK_ENV, "/from/env")
        assert mod.resolve_sink() == "/from/env"

    def test_no_sink_anywhere_resolves_to_none(self, mod, monkeypatch):
        monkeypatch.delenv(mod.SINK_ENV, raising=False)
        assert mod.resolve_sink() is None
