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


class FakeResponse:
    """The three things _publish_https reads off a response.

    geturl() is not decoration: the publish is only counted if the URL that
    answered is the URL that was configured. See TestRedirectsAreRefused.
    """
    def __init__(self, url, code=200):
        self._url = url
        self._code = code
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def getcode(self): return self._code
    def geturl(self): return self._url


def fake_opener(monkeypatch, handler):
    """Patch build_opener so `.open(req, timeout=)` runs `handler(req, timeout)`.

    publish_receipt goes through an opener rather than urlopen because it has to
    install a redirect handler that refuses; the sandbox blocks the real
    OpenerDirector.open, so tests fake it here.
    """
    class _Opener:
        def open(self, req, timeout=None):
            return handler(req, timeout)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _Opener())


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


class TestKeyStrippingIsCaughtOffHost:
    """The downgrade the local chain cannot catch on a fully-compromised host.

    verify_baseline holds the keyed/unkeyed line only while the local history is
    honest. Against an attacker who owns the host — and so rewrites baseline AND
    history together — the cheapest forgery is not to break the passphrase but to
    strip it: replace the baseline with an unkeyed record (a seal the host can
    recompute) and extend the chain one unkeyed step, rewriting local history to
    agree. Locally that is internally consistent and verifies. Only the off-host
    receipts still remember the chain was keyed, so this is where it has to be
    caught.
    """

    def _forge_unkeyed_successor(self, mod, evil_state):
        """Return an unkeyed record that continues the current chain, no passphrase."""
        prev = mod.load_baseline_record()
        forged = {"format": mod.BASELINE_FORMAT, "seq": prev["seq"] + 1,
                  "prev": prev["seal"], "keyed": False, "state": evil_state}
        forged["seal"] = mod.seal_payload(
            {k: v for k, v in forged.items() if k != "seal"}, key=None)
        return forged

    def test_stripping_the_key_and_extending_the_chain_is_caught(self, mod, sink):
        mod.save_baseline(STATE, passphrase=PASSPHRASE)

        evil = dict(STATE, router_open_ports=[23])   # telnet, now "known good"
        forged = self._forge_unkeyed_successor(mod, evil)

        # The attacker owns the host: rewrite both local files to agree...
        mod._write_json_atomic(mod.BASELINE_FILE, forged)
        with open(mod.HISTORY_FILE, "a") as f:
            f.write(json.dumps({"seq": forged["seq"], "seal": forged["seal"],
                                "keyed": False, "ts": "t"}, sort_keys=True) + "\n")
        # ...and append a matching receipt (appending is all an append-only sink allows).
        with open(sink / "receipts.jsonl", "a") as f:
            f.write(json.dumps(mod.baseline_receipt(forged), sort_keys=True) + "\n")

        # Locally consistent: the seal verifies and the chain agrees.
        assert mod.verify_baseline(passphrase=PASSPHRASE)["status"] == "ok"

        # The off-host record still says the chain was keyed.
        report = mod.compare_with_receipts(
            mod.load_baseline_record(), mod.read_receipts(str(sink)))
        assert report["status"] == "keyed_downgrade"
        assert "HIGH" in mod.describe_receipt_status(report)

    def test_an_unkeyed_chain_that_was_always_unkeyed_is_not_flagged(self, mod, sink):
        # No passphrase ever: dropping from nothing to nothing is not a downgrade.
        for _ in range(3):
            mod.save_baseline(STATE)
        report = mod.compare_with_receipts(
            mod.load_baseline_record(), mod.read_receipts(str(sink)))
        assert report["status"] == "ok"


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
        def boom(req, timeout=None):
            raise urllib.error.URLError("connection refused")
        fake_opener(monkeypatch, boom)
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

        def handler(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.headers.items()}
            seen["body"] = json.loads(req.data.decode())
            return FakeResponse(req.full_url, 202)

        fake_opener(monkeypatch, handler)
        report = mod.publish_receipt({"seq": 3, "seal": "abc"},
                                     destination="https://collector.example/r",
                                     token="write-only-token")
        assert report["published"] is True
        assert seen["url"] == "https://collector.example/r"
        assert seen["headers"]["authorization"] == "Bearer write-only-token"
        assert seen["body"]["seq"] == 3

    def test_the_token_is_read_from_the_environment_when_not_passed(self, mod, monkeypatch):
        seen = {}

        def handler(req, timeout=None):
            seen["auth"] = req.headers.get("Authorization")
            return FakeResponse(req.full_url)

        monkeypatch.setenv(mod.SINK_TOKEN_ENV, "env-token")
        fake_opener(monkeypatch, handler)
        mod.publish_receipt({"seq": 1, "seal": "a"}, destination="https://x.example/r")
        assert seen["auth"] == "Bearer env-token"

    def test_no_authorization_header_when_no_token_is_available(self, mod, monkeypatch):
        seen = {}

        def handler(req, timeout=None):
            seen["auth"] = req.headers.get("Authorization")
            return FakeResponse(req.full_url)

        monkeypatch.delenv(mod.SINK_TOKEN_ENV, raising=False)
        fake_opener(monkeypatch, handler)
        mod.publish_receipt({"seq": 1, "seal": "a"}, destination="https://x.example/r")
        assert seen["auth"] is None


class TestRedirectsAreRefused:
    """urllib's default handler makes a redirect silently destructive.

    On 301/302/303 it turns the POST into a bodiless GET and copies every
    header except content-length and content-type to the new host. So an
    `http://collector/receipts` that redirects to https — close to universal —
    dropped the receipt body on every publish while this function reported
    "Receipt accepted (HTTP 200)". The sink stayed empty, and the one check
    that survives a wiped ~/.home_net_audit was never armed. The same handler
    carried the Authorization header to whatever host the redirect named.
    """

    def test_a_redirect_is_reported_as_a_failed_publish(self, mod, monkeypatch):
        def handler(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 301, "Moved Permanently", {}, None)

        fake_opener(monkeypatch, handler)
        report = mod.publish_receipt({"seq": 1, "seal": "a"},
                                     destination="http://collector.example/r")
        assert report["published"] is False

    def test_landing_on_a_different_url_is_not_counted_as_published(self, mod, monkeypatch):
        # Belt and braces for any handler that follows one anyway.
        def handler(req, timeout=None):
            return FakeResponse("https://elsewhere.example/r")

        fake_opener(monkeypatch, handler)
        report = mod.publish_receipt({"seq": 1, "seal": "a"},
                                     destination="https://collector.example/r")
        assert report["published"] is False
        assert "elsewhere.example" in report["detail"]

    def test_the_opener_installs_a_refusing_redirect_handler(self, mod, monkeypatch):
        installed = []
        monkeypatch.setattr(urllib.request, "build_opener",
                            lambda *a, **k: installed.extend(a) or _NullOpener())
        mod.publish_receipt({"seq": 1, "seal": "a"},
                            destination="https://collector.example/r")
        assert mod._NoRedirects in installed

    def test_a_token_is_never_sent_over_plain_http(self, mod, monkeypatch):
        # A bearer token over http is readable by anyone on the path, starting
        # with the LAN this tool is auditing.
        fake_opener(monkeypatch,
                    lambda req, timeout=None: pytest.fail("must not send at all"))
        report = mod.publish_receipt({"seq": 1, "seal": "a"},
                                     destination="http://collector.example/r",
                                     token="write-only-token")
        assert report["published"] is False
        assert "https" in report["detail"]


class _NullOpener:
    def open(self, req, timeout=None):
        return FakeResponse(req.full_url)


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

    @pytest.mark.parametrize("line", ["null", "0", '"str"', "[]"],
                             ids=["null", "int", "string", "list"])
    def test_a_line_that_is_valid_json_but_not_an_object_is_dropped(self, mod, tmp_path, line):
        # `null` parses fine and then reached compare_with_receipts as
        # `r.get(...)` — AttributeError, on every run, with no verdict, no diff,
        # no baseline saved and no report. read_heartbeats and code_attestations
        # already guarded; the guard belongs where the entries are produced.
        target = tmp_path / "receipts.jsonl"
        target.write_text(f'{{"seq": 1, "seal": "a"}}\n{line}\n', encoding="utf-8")
        receipts = mod.read_receipts(str(target))
        assert receipts == [{"seq": 1, "seal": "a"}]
        assert mod.compare_with_receipts({"seq": 1, "seal": "a"}, receipts)["status"] == "ok"


class TestALocalSeqAheadOfTheSinkIsNotAgreement:
    """A run the sink never saw cannot be evidence that the sink agrees.

    Past the history_truncated guard, `match` was empty, both remaining guards
    skipped, and execution fell through to "ok — Local baseline agrees with N
    off-host receipt(s)". So a fabricated record at seq 99 beside seven genuine
    receipts read as a clean bill of health, and so did every run made while
    publishing was quietly failing.
    """

    def test_a_seq_ahead_of_every_receipt_is_reported(self, mod):
        receipts = [{"seq": i, "seal": f"s{i}"} for i in range(1, 8)]
        report = mod.compare_with_receipts({"seq": 99, "seal": "FORGED"}, receipts)
        assert report["status"] == "unpublished_runs"
        assert "REVIEW" in mod.describe_receipt_status(report)

    def test_the_detail_names_how_many_runs_are_unaccounted_for(self, mod):
        receipts = [{"seq": 1, "seal": "a"}]
        report = mod.compare_with_receipts({"seq": 4, "seal": "d"}, receipts)
        assert "3 run(s) were never published" in report["detail"]

    def test_matching_seqs_are_still_ok(self, mod):
        receipts = [{"seq": 1, "seal": "a"}, {"seq": 2, "seal": "b"}]
        assert mod.compare_with_receipts({"seq": 2, "seal": "b"},
                                         receipts)["status"] == "ok"


class TestTheFirstReceiptForARunIsTheReference:
    """An append-only sink lets the host add lines. It cannot let it remove any.

    seal_mismatch compared against match[-1] — the newest receipt for a seq,
    which is precisely the one an attacker is able to append. Publishing a
    second receipt for run 7 carrying the forged seal therefore made the
    forgery the reference and the comparison passed. The existing test suite
    missed it only because it publishes one receipt per seq.
    """

    def test_appending_a_second_receipt_does_not_launder_a_forged_seal(self, mod):
        receipts = [{"seq": 7, "seal": "real"}, {"seq": 7, "seal": "FORGED"}]
        report = mod.compare_with_receipts({"seq": 7, "seal": "FORGED"}, receipts)
        assert report["status"] != "ok"

    def test_two_seals_for_one_run_is_itself_the_finding(self, mod):
        receipts = [{"seq": 7, "seal": "real"}, {"seq": 7, "seal": "FORGED"}]
        report = mod.compare_with_receipts({"seq": 7, "seal": "FORGED"}, receipts)
        assert report["status"] == "seal_conflict"
        assert "HIGH" in mod.describe_receipt_status(report)

    def test_a_duplicate_of_the_same_seal_is_not_a_conflict(self, mod):
        # Republishing an identical receipt is harmless bookkeeping.
        receipts = [{"seq": 7, "seal": "real"}, {"seq": 7, "seal": "real"}]
        assert mod.compare_with_receipts({"seq": 7, "seal": "real"},
                                         receipts)["status"] == "ok"


class TestAWriteOnlySinkSaysSoRatherThanNothingToCompare:
    """An https sink cannot be read back: read_receipts open()s it as a path.

    Publishing branches on the scheme; reading never did. So thirty published
    runs followed by `rm -rf ~/.home_net_audit` produced "[REVIEW] No off-host
    receipts to compare against" — which is false, and REVIEW where the truth
    is the HIGH history_truncated. --publish-to's own help advertises the URL
    alongside the guarantee that silently did not hold.
    """

    def test_an_https_sink_is_not_reported_as_an_empty_one(self, mod):
        report = mod.compare_with_receipts({"seq": 1, "seal": "a"}, [],
                                           sink="https://collector.example/r")
        assert report["status"] == "sink_unreadable"
        assert "cannot" in report["detail"] and "read" in report["detail"]

    def test_reading_an_https_sink_returns_nothing_rather_than_guessing(self, mod):
        assert mod.read_receipts("https://collector.example/r") == []

    def test_a_genuinely_empty_local_sink_is_still_no_receipts(self, mod, tmp_path):
        report = mod.compare_with_receipts({"seq": 1, "seal": "a"}, [],
                                           sink=str(tmp_path))
        assert report["status"] == "no_receipts"


class TestReceiptsForAnotherChainAreNotSilence:
    """chain_id is derived from the baseline filename, hence from the subnet.

    A renumbering rogue DHCP server therefore moves the chain, orphans every
    receipt this machine ever published, and used to leave "[REVIEW] No
    off-host receipts to compare against" — while a fresh chain was sealed at
    seq 1 under the attacker's numbering. That is the strongest evidence
    available being discarded and reported as an absence.
    """

    def test_receipts_belonging_only_to_other_chains_are_reported(self, mod):
        receipts = [{"seq": 7, "seal": "a", "chain": "another-chain"}]
        report = mod.compare_with_receipts({"seq": 1, "seal": "x"}, receipts)
        assert report["status"] == "chain_unknown"
        assert "1 receipt(s)" in report["detail"]

    def test_a_truly_empty_sink_is_still_no_receipts(self, mod):
        assert mod.compare_with_receipts({"seq": 1, "seal": "x"},
                                         [])["status"] == "no_receipts"

    def test_heartbeats_alone_do_not_count_as_another_chain(self, mod):
        # Heartbeats say nothing about baselines in any chain.
        receipts = [{"kind": "heartbeat", "chain": "another-chain", "at": "x"}]
        assert mod.compare_with_receipts({"seq": 1, "seal": "x"},
                                         receipts)["status"] == "no_receipts"


class TestAFailedPublishIsSurfaced:
    """publish_receipt has always documented that the caller must surface this.

    "A receipt that silently failed to leave the machine is the same as never
    having sent one" — and no caller checked. An unmounted sink or an expired
    token produced months of runs that published nothing and printed nothing.
    """

    def test_a_failed_publish_produces_a_review_line(self, mod):
        line = mod.describe_publish_result({"published": False, "mode": "digest",
                                            "detail": "sink down"})
        assert line is not None
        assert "REVIEW" in line and "sink down" in line

    def test_a_successful_publish_produces_no_line(self, mod):
        assert mod.describe_publish_result(
            {"published": True, "mode": "digest", "detail": "ok"}) is None

    def test_save_baseline_hands_the_result_back_to_the_caller(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "publish_receipt",
                            lambda *a, **k: {"published": False, "mode": "digest",
                                             "detail": "sink down"})
        record = mod.save_baseline(STATE, passphrase=PASSPHRASE)
        assert record["_receipt"]["published"] is False


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
