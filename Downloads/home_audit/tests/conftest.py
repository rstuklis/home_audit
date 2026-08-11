"""Shared test scaffolding for home_net_audit.

Three things happen here, and every test in the suite depends on all three:

1.  The module under test is imported by path as ``hna`` (it lives beside this
    package but is not an installed package).
2.  Every test is made hermetic — no real subprocess, no real socket, no real
    HTTP, and no access to the user's real ~/.home_net_audit directory. The
    guards raise a BaseException subclass on purpose: the production code is
    full of ``except Exception`` and ``except OSError`` handlers that would
    otherwise swallow the guard and turn an escape into a silent pass.
3.  Fakes for the two system-call choke points (``hna.run`` and
    ``subprocess.run``) are provided as command-dispatching helpers, so tests
    read as "this command produced this output" rather than as a positional
    list of side effects that breaks whenever call order changes.
"""

import importlib.util
import os
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TESTS_DIR.parent
FIXTURE_DIR = TESTS_DIR / "fixtures"


# ---------------------------------------------------------------------------
# Import the module under test by path
# ---------------------------------------------------------------------------

def _load_module():
    """Import home_net_audit.py as `hna` without requiring it to be packaged."""
    path = PROJECT_DIR / "home_net_audit.py"
    spec = importlib.util.spec_from_file_location("home_net_audit", path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so the module can be found by name if it ever
    # imports itself (and so repeated collection reuses one instance).
    sys.modules["home_net_audit"] = module
    spec.loader.exec_module(module)
    return module


hna = _load_module()


@pytest.fixture
def mod():
    """The module under test.

    Prefer this over importing `hna` directly in a test module: it makes the
    dependency explicit and keeps monkeypatching scoped to the test.
    """
    return hna


# ---------------------------------------------------------------------------
# Hermeticity guards
# ---------------------------------------------------------------------------

class EscapedSandbox(BaseException):
    """Raised when a test reaches for a real system resource.

    Deliberately derived from BaseException, not Exception: home_net_audit
    catches Exception/OSError almost everywhere, so an Exception-derived guard
    would be swallowed by the code under test and the escape would go unnoticed.
    """


def _forbid(what):
    def _blocked(*args, **kwargs):
        raise EscapedSandbox(
            f"test attempted real {what} with args={args!r} kwargs={kwargs!r}. "
            "Patch hna.run / subprocess.run / the relevant helper instead."
        )
    return _blocked


@pytest.fixture(autouse=True)
def sandbox(monkeypatch, tmp_path):
    """Autouse: isolate every test from the network, subprocesses and $HOME."""
    # --- real command execution -------------------------------------------
    monkeypatch.setattr(subprocess, "run", _forbid("subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", _forbid("subprocess.Popen"))
    monkeypatch.setattr(subprocess, "check_output", _forbid("subprocess.check_output"))

    # --- real network ------------------------------------------------------
    # Block the operations that would leave the machine, not the socket module
    # itself: socket.inet_ntoa/inet_aton are pure byte conversions used by the
    # parsers under test and must keep working.
    monkeypatch.setattr(socket.socket, "connect", _forbid("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", _forbid("socket.connect_ex"))
    monkeypatch.setattr(socket.socket, "sendto", _forbid("socket.sendto"))
    monkeypatch.setattr(socket.socket, "send", _forbid("socket.send"))
    monkeypatch.setattr(socket, "create_connection", _forbid("socket.create_connection"))
    monkeypatch.setattr(socket, "gethostbyaddr", _forbid("socket.gethostbyaddr"))
    monkeypatch.setattr(socket, "gethostbyname", _forbid("socket.gethostbyname"))
    monkeypatch.setattr(socket, "getaddrinfo", _forbid("socket.getaddrinfo"))
    monkeypatch.setattr(urllib.request, "urlopen", _forbid("urllib urlopen"))
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _forbid("urllib opener"))

    # --- the user's real audit data ---------------------------------------
    # These are read through module globals at call time, so patching the
    # attributes is enough to redirect every load_*/save_* helper.
    data_dir = tmp_path / "home_net_audit_data"
    monkeypatch.setattr(hna, "BASELINE_DIR", str(data_dir))

    # Redirect every *_FILE path constant by name rather than listing them.
    # Listing them meant that adding HISTORY_FILE to the module left it pointing
    # at the real ~/.home_net_audit while every test looked like it passed; the
    # write only failed because that directory happened not to exist.
    # test_scaffold asserts this covers the module completely.
    for attr in dir(hna):
        if attr.endswith("_FILE") and isinstance(getattr(hna, attr), str):
            basename = os.path.basename(getattr(hna, attr))
            monkeypatch.setattr(hna, attr, str(data_dir / basename))

    # Anything that still resolves ~ lands in the tmp dir rather than $HOME.
    monkeypatch.setenv("HOME", str(tmp_path))

    # --- the working tree ---------------------------------------------------
    # Pin cwd so a relative-path write lands in tmp rather than in the repo.
    # Without this the suite is hermetic against the network and subprocesses
    # but not against its own filesystem writes: generate_html_report builds a
    # default path and writes it, and .gitignore's `audit_report_*.html` rule
    # would hide any escapee from `git status`. Found by mutating BASELINE_DIR
    # to os.getcwd(), which silently wrote a report into the working tree.
    # PROJECT_DIR / TESTS_DIR / FIXTURE_DIR are absolute and resolved at import,
    # so fixture loading is unaffected.
    monkeypatch.chdir(tmp_path)

    yield data_dir


# ---------------------------------------------------------------------------
# Fixture-file loading
# ---------------------------------------------------------------------------

def load_fixture(name):
    """Read a captured command-output fixture from tests/fixtures/.

    Fixtures use the .out extension rather than .txt because the project's
    .gitignore ignores *.txt as scan output; .out keeps them tracked.
    """
    path = FIXTURE_DIR / name
    if not path.exists():
        raise FileNotFoundError(
            f"missing fixture {name!r} in {FIXTURE_DIR}. "
            f"Available: {sorted(p.name for p in FIXTURE_DIR.glob('*.out'))}"
        )
    return path.read_text(encoding="utf-8")


@pytest.fixture
def fixture():
    """Function fixture: `fixture("firewall_on.out")` -> file contents."""
    return load_fixture


# ---------------------------------------------------------------------------
# Command-dispatching fakes
# ---------------------------------------------------------------------------

def _match(mapping, joined):
    """Exact match wins; otherwise first substring match in insertion order.

    Exact-first matters because several real commands are prefixes of others
    ('ifconfig' vs 'ifconfig -a', 'netstat -rn' vs 'netstat -anp tcp').
    """
    if joined in mapping:
        return mapping[joined], True
    for pattern, value in mapping.items():
        if pattern in joined:
            return value, True
    return None, False


def make_run(mapping, default=""):
    """Build a replacement for ``hna.run`` that dispatches on the command.

        monkeypatch.setattr(mod, "run", make_run({
            "socketfilterfw --getglobalstate": "Firewall is enabled. (State = 1)",
            "socketfilterfw --getstealthmode": "... stealth mode is on",
        }))

    Unmatched commands return `default` (""), which is exactly what the real
    ``run`` returns when a command is missing or times out.
    """
    calls = []

    def _run(cmd, timeout=10, merge_stderr=False):
        joined = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        calls.append(joined)
        value, found = _match(mapping, joined)
        return value if found else default

    _run.calls = calls
    return _run


def make_subprocess_run(mapping, default=(1, "")):
    """Build a replacement for ``subprocess.run`` dispatching on the command.

    Mapping values are either a plain string (stdout, returncode 0) or a
    ``(returncode, stdout)`` tuple — `_launchd_running` branches on the return
    code before it ever looks at stdout, so tests need control over both.
    """
    calls = []

    def _run(cmd, *args, **kwargs):
        joined = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        calls.append(joined)
        value, found = _match(mapping, joined)
        if not found:
            value = default
        code, out = value if isinstance(value, tuple) else (0, value)
        return subprocess.CompletedProcess(args=cmd, returncode=code,
                                           stdout=out, stderr="")

    _run.calls = calls
    return _run


def make_check_port(open_ports=()):
    """Build a replacement for ``hna.check_port``; only listed ports are open."""
    wanted = set(open_ports)

    def _check_port(host, port, timeout=0.6):
        return port in wanted

    return _check_port


@pytest.fixture
def run_fake():
    """Factory fixture for `make_run`."""
    return make_run


@pytest.fixture
def subprocess_fake():
    """Factory fixture for `make_subprocess_run`."""
    return make_subprocess_run


@pytest.fixture
def check_port_fake():
    """Factory fixture for `make_check_port`."""
    return make_check_port
