"""An interrupted save is one REVIEW, not three Sundays of HIGH.

Round 4, F28. save_baseline wrote the record, published the receipt, then
appended the history line, unguarded. One OSError in that last write — a full
disk, the Mac sleeping during the iCloud-backed fsync — left seq N+1 and its
receipt beside a chain stopping at N. The next run read "rolled_back" ("an
older baseline may have been put back") about a record that was NEWER; the
save gate refuses only "modified", so seq N+1 was saved again with a different
seal and a second receipt; the run after saw two seals for one run and said
"seal_conflict ... treat the local baseline as untrusted". Nothing had been
tampered with.

Pinned here: the write order is record, history, receipt; a record one ahead
of its chain and linked to it reads history_behind at REVIEW; the next save
repairs the chain (and the missing receipt) rather than re-issuing the seq;
an interruption after the history line leaves at worst unpublished_runs; and
a forged unkeyed record at N+1 on a keyed chain is still rolled_back, never
repaired.
"""

import errno
import json
import sys
from pathlib import Path

import pytest

PW = "correct horse battery staple"


def _state(day, **over):
    s = {"timestamp": f"2026-10-{day:02d}T22:00:00+00:00", "gateway": "10.0.0.1",
         "router_open_ports": [80], "dns": ["1.1.1.1"]}
    s.update(over)
    return s


@pytest.fixture
def sink(tmp_path, monkeypatch, mod):
    path = tmp_path / "receipts.jsonl"
    monkeypatch.setenv(mod.SINK_ENV, str(path))
    return path


def _receipts(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _history(mod):
    return [json.loads(l) for l in Path(mod.HISTORY_FILE).read_text().splitlines() if l.strip()]


class TestTheWriteOrder:
    def test_record_then_history_then_receipt(self, mod, monkeypatch):
        order = []
        real_write, real_append, real_publish = mod._write_json_atomic, mod._append_history, mod.publish_receipt
        monkeypatch.setattr(mod, "_write_json_atomic", lambda *a, **k: (order.append("record"), real_write(*a, **k))[1])
        monkeypatch.setattr(mod, "_append_history", lambda *a, **k: (order.append("history"), real_append(*a, **k))[1])
        monkeypatch.setattr(mod, "publish_receipt", lambda *a, **k: (order.append("receipt"), real_publish(*a, **k))[1])
        mod.save_baseline(_state(25), passphrase=PW)
        assert order == ["record", "history", "receipt"]


def _interrupt_before_history(mod, monkeypatch):
    """_append_history fails once, the way a full disk or a sleep does."""
    real = mod._append_history
    calls = {"n": 0}

    def failing(entry):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(entry)
    monkeypatch.setattr(mod, "_append_history", failing)


class TestInterruptedBeforeTheHistoryLine:
    def _week_one_then_interrupted_week_two(self, mod, monkeypatch):
        mod.save_baseline(_state(18), passphrase=PW)
        _interrupt_before_history(mod, monkeypatch)
        with pytest.raises(OSError):
            mod.save_baseline(_state(25), passphrase=PW)

    def test_the_record_is_one_ahead_of_its_chain_and_has_no_receipt(self, mod, monkeypatch, sink):
        self._week_one_then_interrupted_week_two(mod, monkeypatch)
        assert mod.load_baseline_record()["seq"] == 2
        assert [h["seq"] for h in _history(mod)] == [1]
        assert [r["seq"] for r in _receipts(sink)] == [1], "the receipt goes out last"

    def test_the_next_run_reads_history_behind_at_review_not_rolled_back(self, mod, monkeypatch, sink):
        self._week_one_then_interrupted_week_two(mod, monkeypatch)
        report = mod.verify_baseline(PW)
        assert report["status"] == "history_behind" and report["keyed"] is True
        line = mod.describe_baseline_integrity(report)
        assert line.startswith("  [REVIEW]") and "[HIGH" not in line
        assert "Nothing older was put back" in report["detail"]

    def test_the_receipt_comparison_is_review_too(self, mod, monkeypatch, sink):
        self._week_one_then_interrupted_week_two(mod, monkeypatch)
        status = mod.compare_with_receipts(mod.load_baseline_record(), mod.read_receipts(str(sink)), sink=str(sink))
        assert status["status"] == "unpublished_runs"
        assert mod.describe_receipt_status(status).startswith("  [REVIEW]")

    def test_the_next_save_repairs_the_chain_instead_of_reissuing_the_seq(self, mod, monkeypatch, sink):
        self._week_one_then_interrupted_week_two(mod, monkeypatch)
        interrupted = mod.load_baseline_record()
        mod.save_baseline(_state(1, timestamp="2026-11-01T22:00:00+00:00"), passphrase=PW)
        assert [h["seq"] for h in _history(mod)] == [1, 2, 3]
        assert _history(mod)[1]["seal"] == interrupted["seal"], "the missing line carries the record's own seal"
        assert _history(mod)[1]["ts"] == "2026-10-25T22:00:00+00:00"
        new = mod.load_baseline_record()
        assert new["seq"] == 3 and new["prev"] == interrupted["seal"]
        assert mod.verify_baseline(PW)["status"] == "ok"

    def test_the_repair_publishes_the_missing_receipt_once(self, mod, monkeypatch, sink):
        self._week_one_then_interrupted_week_two(mod, monkeypatch)
        mod.save_baseline(_state(1, timestamp="2026-11-01T22:00:00+00:00"), passphrase=PW)
        receipts = _receipts(sink)
        assert [r["seq"] for r in receipts] == [1, 2, 3]
        assert len({r["seal"] for r in receipts if r["seq"] == 2}) == 1

    def test_no_week_after_the_fault_reads_high(self, mod, monkeypatch, sink):
        """The three-Sunday sequence the finding reproduced: abort, rolled_back
        HIGH, seal_conflict HIGH. Now: abort, REVIEW, ok."""
        self._week_one_then_interrupted_week_two(mod, monkeypatch)
        seen = []
        for day in ("2026-11-01", "2026-11-08", "2026-11-15"):
            seen.append(mod.describe_baseline_integrity(mod.verify_baseline(PW)))
            seen.append(mod.describe_receipt_status(mod.compare_with_receipts(
                mod.load_baseline_record(), mod.read_receipts(str(sink)), sink=str(sink))))
            mod.save_baseline(_state(1, timestamp=f"{day}T22:00:00+00:00"), passphrase=PW)
        assert not any("[HIGH" in line for line in seen), seen
        assert seen[0].startswith("  [REVIEW]") and seen[1].startswith("  [REVIEW]")
        assert all(line.startswith("  [OK    ]") for line in seen[2:]), seen
        assert "seal_conflict" not in " ".join(seen)

    def test_the_cli_gate_lets_the_repairing_save_through_and_says_so(self, mod, monkeypatch, sink):
        self._week_one_then_interrupted_week_two(mod, monkeypatch)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PW)
        state = _state(1, timestamp="2026-11-01T22:00:00+00:00")
        monkeypatch.setattr(mod, "action_full_audit", lambda **k: state)
        monkeypatch.setattr(sys, "argv", ["home_net_audit.py", "--no-speedtest", "--no-names"])
        mod._main()
        assert any(l.startswith("Baseline saved to") for l in state["_comparison"])
        assert not any("NOT saved" in l for l in state["_comparison"])
        assert [h["seq"] for h in _history(mod)] == [1, 2, 3]

    def test_the_abort_line_says_the_baseline_was_written(self, mod, monkeypatch, sink, capsys):
        # main() used to read _RUN_PROGRESS, set only after save_baseline
        # returned, so an interruption inside it was reported as "No baseline
        # was saved" while the sealed chain had already moved on.
        mod.save_baseline(_state(18), passphrase=PW)
        _interrupt_before_history(mod, monkeypatch)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PW)
        monkeypatch.setattr(mod, "action_full_audit", lambda **k: _state(25))
        monkeypatch.setattr(sys, "argv", ["home_net_audit.py", "--no-speedtest", "--no-names"])
        with pytest.raises(SystemExit):
            mod.main()
        assert "The baseline WAS saved before the error" in capsys.readouterr().out


class TestInterruptedAfterTheHistoryLine:
    class _Killed(Exception):
        pass

    def test_a_run_the_sink_never_saw_is_review_and_heals(self, mod, monkeypatch, sink):
        mod.save_baseline(_state(18), passphrase=PW)
        real = mod.publish_receipt

        def killed(*a, **k):
            monkeypatch.setattr(mod, "publish_receipt", real)
            raise self._Killed()
        monkeypatch.setattr(mod, "publish_receipt", killed)
        with pytest.raises(self._Killed):
            mod.save_baseline(_state(25), passphrase=PW)
        assert [h["seq"] for h in _history(mod)] == [1, 2] and [r["seq"] for r in _receipts(sink)] == [1]
        assert mod.verify_baseline(PW)["status"] == "ok"
        status = mod.compare_with_receipts(mod.load_baseline_record(), mod.read_receipts(str(sink)), sink=str(sink))
        assert status["status"] == "unpublished_runs"
        mod.save_baseline(_state(1, timestamp="2026-11-01T22:00:00+00:00"), passphrase=PW)
        assert mod.compare_with_receipts(mod.load_baseline_record(), mod.read_receipts(str(sink)), sink=str(sink))["status"] == "ok"
        assert [h["seq"] for h in _history(mod)] == [1, 2, 3]


class TestWhatIsNotALag:
    def test_a_forged_unkeyed_record_ahead_of_a_keyed_chain_is_rolled_back(self, mod):
        # An attacker without the passphrase writes an unkeyed seq 2 chained
        # to the real seal. Unkeyed seals verify by construction; the position
        # check must not call that an interrupted save and repair it in.
        mod.save_baseline(_state(18), passphrase=PW)
        last = _history(mod)[-1]
        forged = {"format": mod.BASELINE_FORMAT, "seq": 2, "prev": last["seal"], "keyed": False,
                  "code": None, "state": _state(25, router_open_ports=[80, 4444])}
        forged["seal"] = mod.seal_payload(forged, key=None)
        Path(mod.BASELINE_FILE).write_text(json.dumps(forged))
        assert mod.verify_baseline(PW)["status"] == "rolled_back"
        assert mod.verify_baseline()["status"] == "rolled_back"
        assert mod._history_lags_record(forged, last) is False
        mod.save_baseline(_state(1, timestamp="2026-11-01T22:00:00+00:00"), passphrase=PW)
        assert [h["seq"] for h in _history(mod)] == [1, 2]
        assert not any(h["seal"] == forged["seal"] for h in _history(mod)), "the forgery never joins the chain"

    def test_a_record_that_does_not_link_to_the_chain_is_rolled_back(self, mod):
        mod.save_baseline(_state(18), passphrase=PW)
        record = mod.load_baseline_record()
        record["seq"] = 2
        record["prev"] = "0" * 64
        Path(mod.BASELINE_FILE).write_text(json.dumps(record))
        assert mod.verify_baseline()["status"] != "history_behind"

    def test_a_record_two_ahead_is_not_a_lag(self, mod):
        mod.save_baseline(_state(18), passphrase=PW)
        last = _history(mod)[-1]
        assert mod._history_lags_record({"seq": 3, "prev": last["seal"], "keyed": True}, last) is False

    def test_an_unkeyed_to_keyed_upgrade_interrupted_is_a_lag(self, mod, monkeypatch):
        # seal_baseline.py sealing an unkeyed chain for the first time, cut off
        # before its history line: a lag, repaired, not a rollback.
        mod.save_baseline(_state(18))
        _interrupt_before_history(mod, monkeypatch)
        with pytest.raises(OSError):
            mod.save_baseline(_state(25), passphrase=PW)
        assert mod.verify_baseline(PW)["status"] == "history_behind"

    @pytest.mark.parametrize("record", [None, 3, {"seq": "2", "prev": "x"}, {"seq": True, "prev": "x"}])
    def test_hostile_records_are_not_lags(self, mod, record):
        assert mod._history_lags_record(record, {"seq": 1, "seal": "x"}) is False

    def test_history_behind_without_the_passphrase_is_still_said(self, mod, monkeypatch):
        mod.save_baseline(_state(18), passphrase=PW)
        _interrupt_before_history(mod, monkeypatch)
        with pytest.raises(OSError):
            mod.save_baseline(_state(25), passphrase=PW)
        assert mod.verify_baseline()["status"] == "history_behind"
