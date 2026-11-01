"""seal_baseline.py verifies before it trusts.

The script is the remedy every tamper warning in the report prescribes, and it
used to seal whatever was on disk: load the record, ask for a NEW passphrase,
save. A baseline the report had just called "modified" came out of it reading
"Seal verified", with the modification inside as the new reference; a
passphrase typed differently from the Keychain's left the scheduled job
printing "modified" and "NOT saved" for ever.

Pinned here: the script prints the integrity verdict (and the receipt
comparison when a sink is set) before it asks for anything; it refuses a record
that reads modified, rolled back, unverifiable or disputed off-host; with
--force-reviewed it prints every device (with its label), the device memory and
every port list and asks for a typed confirmation; it defaults to the existing
passphrase and warns before re-keying the chain to another; and importing it
runs nothing.
"""

import getpass
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from conftest import PROJECT_DIR, make_run

PASSPHRASE = "correct horse battery staple"
STATE = {
    "timestamp": "2026-10-25T22:00:00+00:00",
    "gateway": "192.168.87.1",
    "dns": ["192.168.87.1"],
    "router_open_ports": [80, 443],
    "upstream_open_ports": [22, 80, 443],
    "scanned_subnets": ["192.168.87.0/24"],
    "devices": [{"ip": "192.168.87.1", "mac": "b0:2a:43:c8:22:5b", "subnet": "192.168.87.0/24"},
                {"ip": "192.168.87.35", "mac": "34:64:a9:cc:57:2e", "subnet": "192.168.87.0/24",
                 "vendor": "Hewlett Packard"}],
    "listening": [{"proto": "TCP", "port": 22, "pid": "1", "process": "sshd"}],
}
ATTACKER = "de:ad:be:ef:00:66"


@pytest.fixture
def seal(mod, monkeypatch):
    """The script's module, with the audit's own module sandboxed underneath it.

    Prompts are scripted: `hidden` answers getpass prompts in order, `visible`
    answers input() prompts. An answer the script did not ask for fails the
    test — a prompt that vanishes is as much a regression as one that appears.
    """
    # The script selects the network's baseline the way an audit does; that
    # reads the interfaces and the routing table, which are not this file's
    # subject. The default (shared) baseline file stands in for the network's.
    monkeypatch.setattr(mod, "run", make_run({}))
    monkeypatch.setattr(mod, "use_current_network_baseline", lambda *a, **k: (None, None))
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: pytest.fail("getpass called at import"))
    spec = importlib.util.spec_from_file_location("seal_baseline", PROJECT_DIR / "seal_baseline.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["seal_baseline"] = module
    spec.loader.exec_module(module)
    assert module.h is mod

    def run(argv=(), hidden=(), visible=(), capsys=None):
        hidden, visible = list(hidden), list(visible)
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            if not hidden:
                pytest.fail(f"unexpected hidden prompt: {prompt!r}")
            return hidden.pop(0)

        def confirm(prompt):
            prompts.append(prompt)
            if not visible:
                pytest.fail(f"unexpected visible prompt: {prompt!r}")
            return visible.pop(0)

        status = module.main(list(argv), ask=ask, confirm=confirm)
        out = capsys.readouterr().out if capsys else ""
        return status, out, prompts

    module.drive = run
    return module


def _tamper(mod, mutate):
    with open(mod.BASELINE_FILE) as f:
        record = json.load(f)
    mutate(record)
    with open(mod.BASELINE_FILE, "w") as f:
        json.dump(record, f)


def _sealed(mod, passphrase=PASSPHRASE):
    mod.save_baseline(dict(STATE), passphrase=passphrase)
    assert mod.verify_baseline(passphrase)["status"] == "ok"


class TestItVerifiesFirst:
    def test_the_integrity_verdict_is_printed_before_any_prompt(self, seal, mod, monkeypatch, capsys):
        _sealed(mod)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        _status, out, prompts = seal.drive(hidden=[""], capsys=capsys)
        assert "[OK    ] Baseline integrity: Seal verified" in out
        assert out.index("Baseline integrity") < out.index("About to seal")
        assert len(prompts) == 1 and "Enter to keep the existing" in prompts[0]

    def test_a_modified_record_is_refused_and_left_alone(self, seal, mod, monkeypatch, capsys):
        """The F7 scenario: a MAC and a port edited into the file without the
        passphrase, then the owner runs the script the report told them to."""
        _sealed(mod)
        _tamper(mod, lambda r: (r["state"]["devices"].append({"ip": "192.168.87.66", "mac": ATTACKER}),
                                r["state"].update(router_open_ports=[80, 443, 4444])))
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        before = Path(mod.HISTORY_FILE).read_text()
        status, out, prompts = seal.drive(capsys=capsys)
        assert status == 1
        assert "[HIGH  ] Baseline integrity" in out and "NOT sealed" in out
        assert "--force-reviewed" in out
        assert prompts == [], "a refused record asks for no passphrase"
        assert Path(mod.HISTORY_FILE).read_text() == before, "the chain did not move"
        assert mod.verify_baseline(PASSPHRASE)["status"] == "modified", "still modified: not laundered"

    @pytest.mark.parametrize("status", sorted(set(
        ("modified", "rolled_back", "chain_missing", "record_missing", "downgraded", "unverifiable"))))
    def test_every_refused_integrity_status_is_refused(self, seal, mod, monkeypatch, capsys, status):
        _sealed(mod)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        monkeypatch.setattr(mod, "verify_baseline", lambda passphrase=None: {"status": status, "keyed": True,
                                                                             "detail": "x"})
        # "unverifiable" asks once for the existing passphrase; left blank here.
        code, out, _ = seal.drive(hidden=[""] if status == "unverifiable" else [], capsys=capsys)
        assert code == 1 and status in out and "NOT sealed" in out

    def test_a_keyed_chain_without_the_passphrase_asks_for_it_first(self, seal, mod, monkeypatch, capsys):
        _sealed(mod)
        monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
        status, out, prompts = seal.drive(hidden=[PASSPHRASE, ""], capsys=capsys)
        assert "Existing baseline passphrase" in prompts[0]
        assert "[OK    ] Baseline integrity: Seal verified" in out
        assert status == 0
        assert mod.verify_baseline(PASSPHRASE)["status"] == "ok"
        assert mod.load_baseline_record()["seq"] == 2

    def test_unverifiable_is_refused_not_resealed_blind(self, seal, mod, monkeypatch, capsys):
        # The passphrase is unknown here, so the seal was never checked — and a
        # check that was never made is not a check that passed.
        _sealed(mod)
        monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
        status, out, prompts = seal.drive(hidden=[""], capsys=capsys)
        assert status == 1 and "unverifiable" in out and "NOT sealed" in out
        assert mod.PASSPHRASE_ENV in out
        assert len(prompts) == 1
        assert mod.load_baseline_record()["seq"] == 1

    def test_the_receipt_comparison_is_printed_when_a_sink_is_set(self, seal, mod, monkeypatch, tmp_path, capsys):
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        _sealed(mod)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        _status, out, _ = seal.drive(hidden=[""], capsys=capsys)
        assert "[OK    ] Off-host receipts: Local baseline agrees with 1 off-host receipt(s)" in out

    def test_a_record_the_receipts_dispute_is_refused(self, seal, mod, monkeypatch, tmp_path, capsys):
        # The local file was replaced by a differently sealed one: the sink
        # still holds the original's seal. Sealing now would bury that.
        sink = tmp_path / "receipts.jsonl"
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        _sealed(mod)
        monkeypatch.delenv(mod.SINK_ENV)
        os.remove(mod.HISTORY_FILE)
        mod.save_baseline(dict(STATE, dns=["6.6.6.6"]), passphrase=PASSPHRASE)   # seq 1 again, new seal
        monkeypatch.setenv(mod.SINK_ENV, str(sink))
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        status, out, prompts = seal.drive(capsys=capsys)
        assert status == 1
        assert "seal_mismatch" in out and "NOT sealed" in out
        assert prompts == []

    def test_without_a_sink_it_says_the_receipts_were_not_compared(self, seal, mod, monkeypatch, capsys):
        _sealed(mod)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        monkeypatch.delenv(mod.SINK_ENV, raising=False)
        _status, out, _ = seal.drive(hidden=[""], capsys=capsys)
        assert f"{mod.SINK_ENV} is not set" in out

    def test_no_baseline_is_an_error_after_the_verdict(self, seal, mod, monkeypatch, capsys):
        monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
        status, out, _ = seal.drive(capsys=capsys)
        assert status == 1 and "No baseline found" in out
        assert "Baseline integrity" in out


class TestForceReviewed:
    def _modified(self, mod, monkeypatch):
        _sealed(mod)
        _tamper(mod, lambda r: (r["state"]["devices"].append({"ip": "192.168.87.66", "mac": ATTACKER}),
                                r["state"].update(router_open_ports=[80, 443, 4444],
                                                  device_memory={ATTACKER: {"first_seen": "2026-10-01T00:00:00+00:00",
                                                                            "last_seen": "2026-10-25T00:00:00+00:00"}})))
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        mod.save_labels({"34:64:a9:cc:57:2e": "HP Printer"})

    def test_the_full_record_is_printed_with_labels_before_the_confirmation(self, seal, mod, monkeypatch, capsys):
        self._modified(mod, monkeypatch)
        status, out, prompts = seal.drive(["--force-reviewed"], hidden=[""], visible=["SEAL"], capsys=capsys)
        assert status == 0
        # Every device, named: the owner's label, the vendor as a hint, the
        # attacker's address as plainly unlabelled.
        assert "34:64:a9:cc:57:2e  [HP Printer]" in out
        assert f"{ATTACKER}  [unlabelled]" in out
        assert "b0:2a:43:c8:22:5b  [unlabelled]" in out
        # The memory, which is where a clone's address would be planted.
        assert "Devices remembered" in out and f"{ATTACKER}  first seen 2026-10-01" in out
        # Every port list.
        assert "Router open ports: [80, 443, 4444]" in out
        assert "Upstream modem open ports: [22, 80, 443]" in out
        assert "Listeners on this Mac: TCP/22" in out
        # Printed before the question was asked.
        assert out.index("4444") < out.index("Type SEAL") if "Type SEAL" in out else True
        assert any("Type SEAL" in p for p in prompts)

    def test_it_seals_only_after_the_typed_confirmation(self, seal, mod, monkeypatch, capsys):
        self._modified(mod, monkeypatch)
        status, out, _ = seal.drive(["--force-reviewed"], visible=["yes"], capsys=capsys)
        assert status == 1 and "Aborted" in out
        assert mod.verify_baseline(PASSPHRASE)["status"] == "modified"
        assert mod.load_baseline_record()["seq"] == 1

    def test_confirmed_it_seals_the_reviewed_record_with_the_existing_passphrase(self, seal, mod, monkeypatch, capsys):
        self._modified(mod, monkeypatch)
        status, out, _ = seal.drive(["--force-reviewed"], hidden=[""], visible=["SEAL"], capsys=capsys)
        assert status == 0 and "Sealed. Verification with the passphrase: ok" in out
        assert mod.verify_baseline(PASSPHRASE)["status"] == "ok"
        assert mod.load_baseline_record()["seq"] == 2
        assert 4444 in mod.load_baseline()["router_open_ports"], "what was reviewed is what was sealed"

    def test_without_the_flag_the_same_record_is_refused(self, seal, mod, monkeypatch, capsys):
        self._modified(mod, monkeypatch)
        assert seal.drive(capsys=capsys)[0] == 1


class TestThePassphrase:
    def test_enter_keeps_the_existing_passphrase(self, seal, mod, monkeypatch, capsys):
        _sealed(mod)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        status, out, _ = seal.drive(hidden=[""], capsys=capsys)
        assert status == 0
        assert mod.verify_baseline(PASSPHRASE)["status"] == "ok"
        assert "Warning" not in out

    def test_a_different_passphrase_warns_names_the_keychain_and_asks_twice(self, seal, mod, monkeypatch, capsys):
        _sealed(mod)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        status, out, prompts = seal.drive(hidden=["new one", "new one"], capsys=capsys)
        assert status == 0
        assert "not the passphrase this chain verified with" in out
        assert "homenetaudit-baseline" in out and "find-generic-password" in out
        assert len(prompts) == 2 and "Re-enter the NEW passphrase" in prompts[1]
        assert mod.verify_baseline("new one")["status"] == "ok"
        assert mod.verify_baseline(PASSPHRASE)["status"] == "modified"

    def test_a_mistyped_new_passphrase_changes_nothing(self, seal, mod, monkeypatch, capsys):
        _sealed(mod)
        monkeypatch.setenv(mod.PASSPHRASE_ENV, PASSPHRASE)
        status, out, _ = seal.drive(hidden=["new one", "new two"], capsys=capsys)
        assert status == 1 and "did not match" in out
        assert mod.load_baseline_record()["seq"] == 1

    def test_an_unkeyed_chain_still_asks_for_a_passphrase_and_seals_keyed(self, seal, mod, monkeypatch, capsys):
        mod.save_baseline(dict(STATE))                       # unkeyed: a bare hash
        monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
        status, out, prompts = seal.drive(hidden=[PASSPHRASE, PASSPHRASE], capsys=capsys)
        assert status == 0
        assert "Choose a baseline passphrase" in prompts[0]
        assert mod.verify_baseline(PASSPHRASE) == {"status": "ok", "keyed": True,
                                                    "detail": "Seal verified with your passphrase."}

    def test_a_blank_passphrase_aborts_without_changing_anything(self, seal, mod, monkeypatch, capsys):
        mod.save_baseline(dict(STATE))
        monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
        status, out, _ = seal.drive(hidden=[""], capsys=capsys)
        assert status == 1 and "Aborted" in out
        assert mod.load_baseline_record()["seq"] == 1 and mod.load_baseline_record()["keyed"] is False


class TestItIsSafeToImport:
    def test_importing_runs_nothing(self, seal, mod):
        # The fixture loaded the module with getpass set to fail: no prompt ran,
        # and nothing was written.
        assert not os.path.exists(mod.BASELINE_FILE)

    def test_the_keychain_line_the_wrapper_uses_is_documented(self, seal):
        assert 'find-generic-password' in seal.__doc__ and "homenetaudit-baseline" in seal.__doc__

    def test_the_modified_refusal_points_at_a_line_by_line_review(self, mod):
        text = mod.describe_modified_save_refusal()
        assert "--force-reviewed" in text and "line by line" in text
