# Test suite

Tests for `home_net_audit.py`. Run them from the project directory:

```sh
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/                       # everything
python3 -m pytest tests/test_firewall.py -q    # one module
python3 -m pytest tests/ --cov=home_net_audit --cov-report=term-missing
```

## Why the suite is shaped this way

Every bug this project has fixed so far was a **parsing or classification error in
pure logic** — a regex that didn't match real macOS output, a substring test that
misfired, a tri-state collapsed into a boolean. None of them needed a network or a
Mac to reproduce; all of them needed one captured string and one assertion.

So the suite is built around that: capture what a command really prints, feed it to
the parser, and assert on the classification. It runs in well under a second, needs
no network, and passes on Linux despite the tool targeting macOS.

## The three things `conftest.py` provides

**1. The module, imported by path.** `home_net_audit.py` isn't a package, so
`conftest.py` loads it via `importlib` and exposes it as the `mod` fixture. Use
`mod`, don't re-import.

**2. An autouse sandbox.** Every test is isolated from the real world: `subprocess`,
outbound sockets, DNS resolution and `urllib` all raise `EscapedSandbox`, and
`BASELINE_DIR` and friends are redirected into `tmp_path` so tests can never touch
`~/.home_net_audit`.

`EscapedSandbox` derives from `BaseException`, not `Exception`, and that detail is
load-bearing. The code under test wraps most system calls in `except Exception` or
`except OSError`; an `Exception`-derived guard would be swallowed by the very code
it's watching, and a test that escaped the sandbox would look like a pass.
`test_scaffold.py` asserts this property directly.

If a test raises `EscapedSandbox`, something wasn't patched. Patch it — never weaken
the sandbox.

**3. Command-dispatching fakes.** The tool funnels nearly all system access through
one function, `run(cmd, timeout)`, which is what makes it so testable. Rather than
a positional `side_effect` list that breaks whenever call order changes, fakes
dispatch on the command itself:

```python
monkeypatch.setattr(mod, "run", make_run({
    "socketfilterfw --getglobalstate": "Firewall is enabled. (State = 1)",
    "socketfilterfw --getstealthmode": "Firewall stealth mode is on",
}))
```

Exact command matches win over substring matches, which matters because several real
commands are prefixes of others (`ifconfig` vs `ifconfig -a`). Unmatched commands
return `""`, exactly like the real `run()` does on timeout or a missing binary. Each
fake records a `.calls` list, so a test can assert *which* commands ran and in what
order — that's how the `route` → `netstat` gateway fallback gets pinned.

Companions: `make_subprocess_run` (for `_launchd_running`, which calls
`subprocess.run` directly and branches on the return code before reading stdout) and
`make_check_port`.

## Fixtures

Captured command output lives in `tests/fixtures/` with a **`.out` extension**.

This is not cosmetic. The project `.gitignore` ignores `*.txt` and `*.json` as scan
output, so a fixture named `.txt` would be silently untracked and CI would fail on a
clean checkout with a confusing "missing fixture" error. Use `.out`.

Load them with the `fixture` fixture: `fixture("lsof_tcp_listen.out")`. A missing
file raises an error listing what *is* available.

Short one-off strings belong inline in the test. Files are for realistic multi-line
command output, where the column layout is part of what's being tested.

## Testing logic that sits behind a socket or HTTP call

Most of the suite feeds captured strings to a parser. A handful of checks reach the
network directly — `check_router_hostname` (reverse DNS), `lookup_vendor`
(macvendors.com), `get_upnp_port_mappings` (SSDP + SOAP), `check_rogue_dhcp` and
`check_arp_spoofing` (raw UDP), `probe_default_credentials` (HTTP). Each still has a
worthwhile parser or classifier underneath the I/O — a regex over vendor XML, a
cloud-provider substring match, a "is this an admin page or a login form" decision —
which is the same bug surface the rest of the suite guards.

The sandbox forbids the real I/O, so these tests fake only the boundary and let the
logic run:

- **`urllib.request.urlopen`** — patch it to return a tiny response object with the
  `read()` / `getcode()` / context-manager methods the code calls, or raise
  `urllib.error.HTTPError` / `URLError` to drive an error branch. `test_receipts.py`
  and `test_vendor_lookup.py` show the shape.
- **`urllib.request.build_opener`** — `probe_default_credentials` fetches through an
  opener, not `urlopen`, so patch `build_opener` to return a fake whose `.open(req)`
  dispatches on `req.get_method()` and `req.get_header("Authorization")`. See
  `test_default_creds.py`.
- **`mod.socket.socket`** — for SSDP/DHCP, return a fake socket that replays a
  scripted list of datagrams from `recvfrom` and then raises `socket.timeout` to end
  the collection loop (`test_upnp.py`, `test_rogue_dhcp.py`).
- **`mod.time.sleep`** and **`mod.ssl.create_default_context`** — stub these to keep a
  many-request sweep instant; the credential probe drops from ~18 s to well under one
  when the TLS-context build is stubbed out.

What's left uncovered in these functions is the physical I/O itself (the `except
OSError` around a real `sendto`, a `recvfrom` that genuinely blocks) — deliberately,
since faking that tests the mock, not the tool.

> **Provenance:** these fixtures were written from knowledge of the real output
> formats, not captured from a live Mac — this repo's CI has no macOS host to capture
> from. They're faithful to the documented layouts and to the output shapes described
> in the commit history, but if you ever run the tool on a real Mac, replacing them
> with genuine captures would strengthen the suite. That is the single highest-value
> follow-up here.

## Known-bug tests

Some tests assert behaviour the code **does not currently have**. They're marked:

```python
@pytest.mark.known_bug
@pytest.mark.xfail(strict=True, reason="upnp note is interpolated without _esc(), line 1755")
```

The test states what the code *should* do. While the bug is present the test reports
`XFAIL` and the suite stays green.

`xfail_strict = true` is set in `pytest.ini`, so the moment someone fixes the bug the
test `XPASS`es and **the suite goes red** — forcing whoever fixed it to delete the
marker. That turns each one into an executable specification with an expiry date,
rather than a permanent suppression that quietly rots.

Run `python3 -m pytest tests/ -rxX` to list every known bug the suite is tracking.

## Conventions

- Plain classes for grouping (`class TestCheckFirewall:`), no `unittest.TestCase`.
- One behaviour per test, named so the failure line alone explains the defect.
- Every test must be able to fail. Never assert on a value the test itself fed
  through a mock unchanged.
- Where a test pins a historical regression, say which one in a comment. Future
  readers need to know the assertion is load-bearing and not an arbitrary choice.
- `filterwarnings = error` is set — a warning is a failure.
- Use `is None` / `is False` where the code distinguishes "unknown" from "off". That
  tri-state distinction was a deliberate bug fix and truthiness testing erases it.
