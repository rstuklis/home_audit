"""Contract tests for ``run(cmd, timeout=10)`` — home_net_audit.py lines 125-131.

``run`` is the single choke point every other check funnels through, and every
other test in this suite monkeypatches it away. That makes its contract the one
thing nothing else can catch a regression in, while simultaneously being the
assumption the rest of the suite is built on:

  * ``conftest.make_run`` returns ``""`` for an unmatched command *because* the
    real ``run`` returns ``""`` on timeout or a missing binary. Every parser
    fixture test that feeds ``""`` to mean "the command failed" is only valid as
    long as that stays true.
  * The parsers treat the result as text: ``run(...) + run(...)`` at line 1326
    concatenates two results directly, so a ``None`` return would be a
    ``TypeError`` in production while the mocked suite stayed green.
  * ``check_sharing_services`` (line 1459) reads ``systemsetup``'s admin-access
    message out of *stdout*; if ``run`` ever appended stderr, that string match
    would start matching noise.

So this module drives the real ``run`` and fakes ``subprocess.run`` underneath
it. The autouse sandbox blocks the real ``subprocess.run``, so each test
installs its own stand-in with ``monkeypatch.setattr(subprocess, "run", ...)``.
"""

import subprocess

import pytest

from conftest import make_run

CMD = ["/usr/sbin/arp", "-a"]


def _completed(cmd, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=cmd, returncode=returncode, stdout=stdout, stderr=stderr
    )


def _raiser(exc):
    """A subprocess.run stand-in that always raises `exc`."""

    def _fake(*args, **kwargs):
        raise exc

    return _fake


class Recorder:
    """A subprocess.run stand-in that records exactly how it was called."""

    def __init__(self, result=None):
        self.args = None
        self.kwargs = None
        self.call_count = 0
        self._result = result

    def __call__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.call_count += 1
        if self._result is not None:
            return self._result
        return _completed(self.cmd)

    @property
    def cmd(self):
        """The command, whether it was passed positionally or as `args=`."""
        return self.args[0] if self.args else self.kwargs.get("args")


# Every failure mode listed in the `except` clause at line 130. FileNotFoundError
# and PermissionError are OSError subclasses, but they are the ones that actually
# happen: socketfilterfw / launchctl / systemsetup simply do not exist off macOS,
# and an unreadable binary raises PermissionError.
FAILURES = [
    pytest.param(subprocess.TimeoutExpired(CMD, 10), id="timeout_expired"),
    pytest.param(FileNotFoundError(2, "No such file or directory"), id="file_not_found"),
    pytest.param(OSError("generic os failure"), id="oserror"),
    pytest.param(PermissionError(13, "Permission denied"), id="permission_error"),
]


class TestRunSwallowsCommandFailures:
    @pytest.mark.parametrize("exc", FAILURES)
    def test_failure_returns_empty_string_rather_than_raising(self, mod, monkeypatch, exc):
        monkeypatch.setattr(subprocess, "run", _raiser(exc))
        assert mod.run(CMD) == ""

    @pytest.mark.parametrize("exc", FAILURES)
    def test_failure_return_is_a_string_never_none(self, mod, monkeypatch, exc):
        # Line 1326 does `run([...]) + run([...])`; a None return would raise
        # TypeError in production while every mocked parser test stayed green.
        monkeypatch.setattr(subprocess, "run", _raiser(exc))
        result = mod.run(CMD)
        assert result is not None
        assert isinstance(result, str)

    def test_timeout_expired_is_caught_even_though_it_is_not_an_oserror(self, mod, monkeypatch):
        # subprocess.TimeoutExpired derives from SubprocessError, not OSError, so
        # it has to be named separately in the except clause — dropping it would
        # let a slow `system_profiler` (timeout=15, line 618) kill the audit.
        assert not issubclass(subprocess.TimeoutExpired, OSError)
        monkeypatch.setattr(subprocess, "run", _raiser(subprocess.TimeoutExpired(CMD, 10)))
        assert mod.run(CMD) == ""

    def test_unexpected_errors_are_not_silently_turned_into_empty_string(self, mod, monkeypatch):
        # The except clause is deliberately narrow. subprocess.run raises
        # ValueError for an invalid argument combination — a programming error,
        # which must surface rather than masquerade as "the command failed".
        monkeypatch.setattr(subprocess, "run", _raiser(ValueError("bad argument combo")))
        with pytest.raises(ValueError):
            mod.run(CMD)


class TestRunReturnsStdout:
    def test_returns_stdout_and_not_stderr(self, mod, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run",
            Recorder(_completed(CMD, 0, stdout="hello\n", stderr="ERR")),
        )
        result = mod.run(CMD)
        assert result == "hello\n"
        assert "ERR" not in result

    def test_returns_the_stdout_string_not_the_completedprocess(self, mod, monkeypatch):
        completed = _completed(CMD, 0, stdout="hello\n", stderr="ERR")
        monkeypatch.setattr(subprocess, "run", Recorder(completed))
        result = mod.run(CMD)
        assert isinstance(result, str)
        assert result is not completed

    def test_nonzero_exit_still_returns_stdout(self, mod, monkeypatch):
        # run() never inspects .returncode, and that is load-bearing: several
        # macOS tools print usable output on stdout while exiting non-zero —
        # `lsof -nP -iTCP -sTCP:LISTEN` (line 1322) exits 1 when it cannot stat
        # some processes yet still lists every socket it could see. Adding a
        # `if out.returncode: return ""` would blank those listings.
        monkeypatch.setattr(
            subprocess, "run", Recorder(_completed(CMD, 1, stdout="partial\n", stderr="warn")),
        )
        assert mod.run(CMD) == "partial\n"

    def test_stdout_is_returned_verbatim_without_stripping(self, mod, monkeypatch):
        # Callers do their own normalising (`.lower()`, `.strip()`, `.splitlines()`);
        # run() must not pre-chew the text or fixture-based parser tests would be
        # testing a different string than production sees.
        raw = "  Wi-Fi Power (en0): On\n\n"
        monkeypatch.setattr(subprocess, "run", Recorder(_completed(CMD, 0, stdout=raw)))
        assert mod.run(CMD) == raw

    def test_success_with_empty_stdout_is_indistinguishable_from_failure(self, mod, monkeypatch):
        # A documented consequence of the contract, not an accident:
        # check_sharing_services treats `not rae_out.strip()` as UNKNOWN at line
        # 1459 precisely because "" can mean either "no output" or "no binary".
        monkeypatch.setattr(subprocess, "run", Recorder(_completed(CMD, 0, stdout="")))
        assert mod.run(CMD) == ""


class TestRunInvokesSubprocessCorrectly:
    def test_command_list_is_passed_through_unchanged(self, mod, monkeypatch):
        rec = Recorder()
        monkeypatch.setattr(subprocess, "run", rec)
        cmd = ["systemsetup", "-getremoteappleevents"]
        mod.run(cmd)
        assert rec.cmd == cmd
        assert isinstance(rec.cmd, list), "the argv list must not be flattened to a string"

    def test_shell_is_never_enabled(self, mod, monkeypatch):
        # These argv lists are built from user-influenced values (gateway IPs,
        # interface names, labels). shell=True would turn any of them into an
        # injection point, and would also require the string form above.
        rec = Recorder()
        monkeypatch.setattr(subprocess, "run", rec)
        mod.run(CMD)
        assert rec.kwargs.get("shell", False) is False

    def test_check_is_never_enabled(self, mod, monkeypatch):
        # check=True raises CalledProcessError, which is NOT in the except clause
        # at line 130, so every non-zero exit would become an uncaught crash.
        rec = Recorder()
        monkeypatch.setattr(subprocess, "run", rec)
        mod.run(CMD)
        assert rec.kwargs.get("check", False) is False

    def test_capture_output_is_requested(self, mod, monkeypatch):
        # Without it, .stdout is None and the command's output goes to the
        # terminal instead of to the parsers.
        rec = Recorder()
        monkeypatch.setattr(subprocess, "run", rec)
        mod.run(CMD)
        assert rec.kwargs.get("capture_output") is True

    def test_text_mode_is_requested_so_parsers_get_str_not_bytes(self, mod, monkeypatch):
        # Every parser does regex/`in` tests against str patterns; bytes stdout
        # would make all of them silently match nothing.
        rec = Recorder()
        monkeypatch.setattr(subprocess, "run", rec)
        mod.run(CMD)
        assert rec.kwargs.get("text") is True

    def test_subprocess_is_invoked_exactly_once(self, mod, monkeypatch):
        rec = Recorder()
        monkeypatch.setattr(subprocess, "run", rec)
        mod.run(CMD)
        assert rec.call_count == 1


class TestRunForwardsTimeout:
    @pytest.mark.parametrize(
        "kwargs, expected",
        [
            pytest.param({}, 10, id="default_is_10s"),
            pytest.param({"timeout": 3}, 3, id="explicit_3s"),
            pytest.param({"timeout": 15}, 15, id="explicit_15s_system_profiler"),
            pytest.param({"timeout": 5}, 5, id="explicit_5s_socketfilterfw"),
        ],
    )
    def test_timeout_reaches_subprocess(self, mod, monkeypatch, kwargs, expected):
        # Callers pass timeout=5 for socketfilterfw (line 1520) and timeout=15
        # for system_profiler (line 618); dropping the forward would give every
        # command the same budget and hang the audit on the slow one.
        rec = Recorder()
        monkeypatch.setattr(subprocess, "run", rec)
        mod.run(CMD, **kwargs)
        assert rec.kwargs["timeout"] == expected


class TestRunMatchesTheSuitesOwnFakes:
    """The invariant that makes every parser fixture test in this repo valid."""

    def test_failure_value_equals_make_run_unmatched_default(self, mod, monkeypatch):
        # conftest.make_run returns this value for any command a test did not
        # stub, and dozens of parser tests feed exactly that to mean "the command
        # failed". If run()'s failure value and make_run's default ever diverge,
        # those tests would be exercising a state production can never reach.
        monkeypatch.setattr(subprocess, "run", _raiser(subprocess.TimeoutExpired(CMD, 10)))
        real_failure = mod.run(CMD)
        fake_failure = make_run({})(CMD)
        assert real_failure == fake_failure

    def test_failure_value_is_falsy_so_the_or_guards_work(self, mod, monkeypatch):
        # Lines 618 and 1458 write `run([...]) or ""`; that idiom only defends
        # against a falsy failure value.
        monkeypatch.setattr(subprocess, "run", _raiser(FileNotFoundError(2, "nope")))
        assert not mod.run(CMD)

    def test_make_run_stands_in_for_run_with_the_same_signature(self, mod, monkeypatch):
        # Parser tests swap make_run in for mod.run wholesale, so the fake has to
        # accept the same call shapes the production callers use.
        fake = make_run({"arp -a": "OUT"})
        assert fake(["arp", "-a"]) == "OUT"
        assert fake(["arp", "-a"], timeout=5) == "OUT"

        rec = Recorder(_completed(CMD, 0, stdout="OUT"))
        monkeypatch.setattr(subprocess, "run", rec)
        assert mod.run(["arp", "-a"]) == "OUT"
        assert mod.run(["arp", "-a"], timeout=5) == "OUT"
