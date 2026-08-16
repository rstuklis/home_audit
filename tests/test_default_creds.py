"""Default-credential probing (`probe_default_credentials`).

This is the most safety-critical classifier in the tool: it decides whether a
router accepted a guessed password. A false positive tells the owner their
router is wide open when it isn't; a false negative misses a real one. The whole
judgement lives in the nested `_body_is_authed` — a response counts as an
authenticated admin session only if it carries admin-console content *and* shows
no sign of a login form or an error. On top of that sit two guards: Basic Auth
is only claimed when the server actually issued a 401 challenge first, and any
lockout / rate-limit signal aborts the sweep before the owner is locked out of
their own router.

None of that needs a network. `check_port` and the HTTP opener are faked; the
classification runs for real.
"""

import types
import urllib.error
import urllib.request


class _R:
    """A minimal stand-in for the object opener.open() yields."""
    def __init__(self, code, body):
        self.code = code
        self._body = body.encode()
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def getcode(self): return self.code
    def read(self, n=None): return self._body


class _FakeOpener:
    """Routes every request through a test-supplied handler.

    handler(req) returns (code, body) for a normal response, or an
    HTTPError/other exception instance to be raised — mirroring what
    urllib's real opener does on an error status.
    """
    def __init__(self, handler):
        self._handler = handler
    def open(self, req, timeout=None):
        result = self._handler(req)
        if isinstance(result, BaseException):
            raise result
        return _R(*result)


def _wire(monkeypatch, mod, handler, open_ports=(80,), blocked_ports=()):
    # probe_port, not check_port: the probe needs the three-state answer so that
    # "the OS refused to let me connect" stays distinct from "nothing is
    # listening". None is the blocked case.
    def _probe(host, port, timeout=1.0):
        if port in blocked_ports:
            return None
        return port in open_ports
    monkeypatch.setattr(mod, "probe_port", _probe)
    monkeypatch.setattr(urllib.request, "build_opener",
                        lambda *a, **k: _FakeOpener(handler))
    # the probe paces itself with time.sleep between attempts; don't actually wait
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    # _fetch builds a real TLS context on every call; with build_opener faked
    # the context is never used, so hand back a throwaway. Skipping the system
    # trust-store load is what keeps a many-hundred-request sweep sub-second.
    monkeypatch.setattr(mod.ssl, "create_default_context",
                        lambda *a, **k: types.SimpleNamespace())


def _is_post(req):
    return req.get_method() == "POST"


ADMIN_PAGE = "<html><body>Welcome. <a href=/logout>logout</a> — Dashboard, Firmware</body></html>"
LOGIN_PAGE = '<html><body><form><input type="password" name="pw"></form></body></html>'


class TestNoOpenPort:
    def test_a_router_with_no_open_admin_port_yields_nothing(self, mod, monkeypatch):
        _wire(monkeypatch, mod, lambda req: (200, ADMIN_PAGE), open_ports=())
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert successes == []
        assert note is None


class TestBasicAuth:
    def test_a_401_then_admin_page_is_recorded_as_basic_auth(self, mod, monkeypatch):
        def handler(req):
            # Unauthenticated probe is challenged; presenting any creds lands on
            # the admin page. That is a genuine default-credential hit.
            if req.get_header("Authorization") is None:
                return (401, "")
            return (200, ADMIN_PAGE)

        _wire(monkeypatch, mod, handler)
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert len(successes) == 1
        user, pwd, port, method = successes[0]
        assert (port, method) == (80, "Basic Auth")
        assert (user, pwd) == mod.DEFAULT_CREDS[0]  # first pair tried, stops there

    def test_an_open_page_that_never_challenges_is_not_a_basic_auth_hit(self, mod, monkeypatch):
        # No 401 means the page isn't Basic-Auth protected at all; treating a
        # plain 200 as "accepted" would flag every open router status page.
        def handler(req):
            if _is_post(req):
                return (200, "")          # form attempts find nothing either
            return (200, "<html>status page, no login</html>")

        _wire(monkeypatch, mod, handler)
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert successes == []

    def test_a_challenge_that_still_returns_a_login_form_is_not_a_hit(self, mod, monkeypatch):
        # The response carries an admin word (Dashboard) but also a password
        # form: authentication did not actually succeed. _body_is_authed must
        # veto it — this is the false-positive the login-form check exists for.
        def handler(req):
            if req.get_header("Authorization") is None and not _is_post(req):
                return (401, "")
            return (200, '<html>Dashboard <input type="password"></html>')

        _wire(monkeypatch, mod, handler)
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert successes == []

    def test_credentials_rejected_with_another_401_are_not_a_hit(self, mod, monkeypatch):
        # Challenge issued, but every credential pair is bounced with a second
        # 401 — the correct (and common) outcome for a well-secured router.
        _wire(monkeypatch, mod, lambda req: (401, ""))
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert successes == []


class TestFormLogin:
    def test_a_form_post_reaching_an_admin_page_is_recorded(self, mod, monkeypatch):
        # No Basic-Auth challenge (GET is 200), a login form is present, and a
        # POST lands on the admin console: a Form POST hit.
        def handler(req):
            if _is_post(req):
                return (200, ADMIN_PAGE)
            return (200, LOGIN_PAGE)

        _wire(monkeypatch, mod, handler)
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert len(successes) == 1
        assert successes[0][2:] == (80, "Form POST")

    def test_a_form_post_that_bounces_back_to_the_login_form_is_not_a_hit(self, mod, monkeypatch):
        # Wrong password: the POST response is the login form again. No admin
        # content, so nothing is recorded.
        _wire(monkeypatch, mod, lambda req: (200, LOGIN_PAGE))
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert successes == []


class TestLockout:
    def test_a_rate_limit_signal_aborts_and_is_reported(self, mod, monkeypatch):
        # If the router starts rate-limiting we must stop immediately rather
        # than keep guessing and lock the owner out. A 429 raises LockoutError
        # inside _fetch; the probe catches it and hands back the note.
        _wire(monkeypatch, mod, lambda req: (429, ""))
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert successes == []
        assert note is not None
        assert "lockout" in note.lower() or "rate" in note.lower()

    def test_a_lockout_phrase_in_the_body_also_aborts(self, mod, monkeypatch):
        # Some routers answer 200 with "too many login attempts" in the body
        # rather than a 429 status; that phrase must trip the same guard.
        _wire(monkeypatch, mod,
              lambda req: (200, "Too many login attempts, please wait"))
        successes, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert note is not None


class TestAnEmptyResultIsNotAutomaticallyAPass:
    """`successes == []` had four meanings and printed one line for all of them.

    "No default credentials accepted (or admin page not reachable)." names the
    ambiguity in its own parenthetical and then badges the result OK. Only one
    of the four is a finding about the router's password:

      * credentials were submitted and refused          -> genuinely OK
      * no admin port answered                          -> nothing was tested
      * ports answered but offered no login to drive    -> nothing was submitted
      * the OS refused to let this process connect      -> nothing was reachable

    The last three are an absence of testing. Reporting them as a pass tells the
    reader the probe checked something it never touched — the same mistake as an
    unswept device list reporting no changes, in the one check that actively
    guesses passwords.
    """

    def test_refused_credentials_are_counted_as_actually_tested(self, mod, monkeypatch):
        _wire(monkeypatch, mod, lambda req: (200, LOGIN_PAGE))
        _s, _n, coverage = mod.probe_default_credentials("192.168.1.1")
        assert coverage["attempts"] > 0
        assert coverage["open"] == [80]
        assert "[OK" in mod.describe_credential_coverage(coverage)

    def test_no_open_admin_port_records_no_attempts(self, mod, monkeypatch):
        _wire(monkeypatch, mod, lambda req: (200, ADMIN_PAGE), open_ports=())
        _s, _n, coverage = mod.probe_default_credentials("192.168.1.1")
        assert coverage["attempts"] == 0
        assert coverage["open"] == []

    def test_nothing_listening_is_not_reported_as_a_passed_check(self, mod):
        line = mod.describe_credential_coverage(
            {"attempts": 0, "open": [], "blocked": [], "closed": [80, 8080, 8443, 443]})
        assert "[OK" not in line
        assert "no credentials were tested" in line
        assert "another port would be missed" in line

    def test_a_port_that_offers_no_login_form_is_not_a_passed_check(self, mod):
        # The page answered but never challenged and never showed a form, so the
        # sweep had nothing to submit. Silence from the router is not a refusal.
        line = mod.describe_credential_coverage(
            {"attempts": 0, "open": [80], "blocked": [], "closed": []})
        assert "[OK" not in line
        assert "no credentials were submitted" in line
        assert "not a finding that the password is strong" in line

    def test_a_blocked_probe_says_so_rather_than_reporting_nothing_found(self, mod):
        """macOS Local Network privacy, which this tool already knows about.

        The check used check_port, whose boolean folds an OS denial into "not
        open" — the collapse probe_port's own docstring was written to prevent.
        """
        line = mod.describe_credential_coverage(
            {"attempts": 0, "open": [], "blocked": [80, 443], "closed": []})
        assert "[REVIEW" in line
        assert "refused by the OS" in line
        assert "sudo does not help" in line

    def test_a_blocked_port_is_not_recorded_as_closed(self, mod, monkeypatch):
        _wire(monkeypatch, mod, lambda req: (200, ADMIN_PAGE),
              open_ports=(), blocked_ports=(80, 8080, 8443, 443))
        _s, _n, coverage = mod.probe_default_credentials("192.168.1.1")
        assert coverage["blocked"] == [80, 8080, 8443, 443]
        assert coverage["closed"] == []

    def test_a_successful_guess_still_reports_high(self, mod, monkeypatch):
        """The coverage work must not soften the finding that matters."""
        def handler(req):
            return (200, ADMIN_PAGE) if _is_post(req) else (200, LOGIN_PAGE)
        _wire(monkeypatch, mod, handler)
        monkeypatch.setattr(mod, "get_default_gateway", lambda: "192.168.1.1")
        lines = []
        monkeypatch.setattr("builtins.print",
                            lambda *a, **k: lines.append(" ".join(map(str, a))))
        result = mod.action_default_creds()
        assert result["successes"]
        assert "[HIGH]" in "\n".join(lines)

    def test_the_action_reports_coverage_when_nothing_was_accepted(self, mod, monkeypatch):
        _wire(monkeypatch, mod, lambda req: (200, ADMIN_PAGE), open_ports=())
        monkeypatch.setattr(mod, "get_default_gateway", lambda: "192.168.1.1")
        lines = []
        monkeypatch.setattr("builtins.print",
                            lambda *a, **k: lines.append(" ".join(map(str, a))))
        result = mod.action_default_creds()
        printed = "\n".join(lines)
        assert "[OK" not in printed
        assert "no credentials were tested" in printed
        assert result["coverage"]["attempts"] == 0

    def test_a_missing_coverage_dict_does_not_crash_the_report(self, mod):
        # A baseline written before coverage existed still has to render.
        assert mod.describe_credential_coverage(None)
        assert mod.describe_credential_coverage({})


class TestATruncatedSweepIsNotAPass:
    """A sweep that stopped early says nothing about the router's password.

    probe_default_credentials returns (successes, lockout_note, coverage), and
    action_default_creds returned only {gateway, successes, coverage} — so
    `lockout_note` never crossed the boundary. The terminal hid the coverage
    line behind `elif not lockout_note`, and the HTML report called
    credential_coverage_verdict(coverage) unconditionally, whose first live
    branch was `if attempts:`. A router that starts rate-limiting after eight
    guesses therefore rendered a green "8 credential pair(s) submitted on
    port(s) 80 and every one was refused", and the sealed baseline kept saying
    it — with no mention that the sweep aborted, that most of DEFAULT_CREDS was
    never tried, or that the admin account may now be locked.
    """

    def test_the_abort_is_recorded_inside_coverage(self, mod, monkeypatch):
        _wire(monkeypatch, mod, lambda req: (429, ""))
        _s, note, coverage = mod.probe_default_credentials("192.168.1.1")
        assert note is not None
        assert coverage["aborted"] == note, \
            "the report only ever sees coverage, so the abort has to live there"

    def test_a_truncated_sweep_is_not_badged_ok(self, mod):
        line = mod.describe_credential_coverage(
            {"attempts": 8, "open": [80], "blocked": [], "closed": [],
             "aborted": "router signalled lockout/rate-limit (HTTP 429)"})
        assert "[OK" not in line
        assert "[REVIEW" in line
        assert "stopped early" in line

    def test_the_message_warns_about_the_account_being_locked(self, mod):
        _risk, message = mod.credential_coverage_verdict(
            {"attempts": 8, "open": [80], "aborted": "rate-limited"})
        assert "locked" in message
        assert "never tried" in message

    def test_the_terminal_still_prints_the_verdict_after_a_lockout(self, mod, monkeypatch):
        _wire(monkeypatch, mod, lambda req: (429, ""))
        monkeypatch.setattr(mod, "get_default_gateway", lambda: "192.168.1.1")
        lines = []
        monkeypatch.setattr("builtins.print",
                            lambda *a, **k: lines.append(" ".join(map(str, a))))
        mod.action_default_creds()
        printed = "\n".join(lines)
        assert "[STOPPED]" in printed
        assert "stopped early" in printed, \
            "the coverage verdict used to be suppressed on exactly this path"

    def test_an_uncompleted_sweep_still_reports_ok_when_it_finished(self, mod):
        # The clean case must stay clean, or the fix is just noise.
        line = mod.describe_credential_coverage(
            {"attempts": 8, "open": [80], "blocked": [], "closed": [],
             "aborted": None})
        assert "[OK" in line


class TestADroppedConnectionIsNotARefusal:
    """`attempts` was incremented before the request, not after.

    _fetch returns (None, "") from a bare `except Exception`, so a router that
    silently drops connections after repeated failures — no 429, no lockout
    phrase, nothing for LockoutError to catch — produced a counted "attempt"
    that was never submitted and never refused. The verdict then reported those
    as credentials the router had rejected.
    """

    def test_a_dropped_request_is_not_counted_as_an_attempt(self, mod, monkeypatch):
        _wire(monkeypatch, mod,
              lambda req: urllib.error.URLError("connection reset"))
        _s, _n, coverage = mod.probe_default_credentials("192.168.1.1")
        assert coverage["attempts"] == 0
        assert coverage["unanswered"] > 0

    def test_a_router_that_only_drops_is_not_badged_ok(self, mod, monkeypatch):
        _wire(monkeypatch, mod,
              lambda req: urllib.error.URLError("connection reset"))
        _s, _n, coverage = mod.probe_default_credentials("192.168.1.1")
        line = mod.describe_credential_coverage(coverage)
        assert "[OK" not in line
        assert "no response at all" in line

    def test_a_basic_auth_challenge_that_then_drops_is_not_an_attempt(self, mod, monkeypatch):
        state = {"n": 0}

        def handler(req):
            state["n"] += 1
            if req.get_header("Authorization") is None:
                return (401, "")
            raise urllib.error.URLError("connection reset")

        _wire(monkeypatch, mod, handler)
        _s, _n, coverage = mod.probe_default_credentials("192.168.1.1")
        assert coverage["attempts"] == 0


class TestTheSweepDoesNotFanOutPerCredential:
    """10 endpoints x 4 payloads x 16 pairs = 640 POSTs per port.

    Times four open ports, 2560 — while the menu announced "Testing 16 common
    credential pairs", which is the number the user consented to. The
    time.sleep(0.05) calls paced only the outer loop, so 40 POSTs per pair went
    back to back, and a router that locks silently is not caught by
    LockoutError at all. The first pair now discovers which (endpoint, payload)
    shapes this router answers; the rest reuse only those.
    """

    def test_the_request_count_does_not_scale_with_the_credential_list(
            self, mod, monkeypatch):
        posts = []

        def handler(req):
            if _is_post(req):
                posts.append(req.full_url)
            return (200, LOGIN_PAGE)

        _wire(monkeypatch, mod, handler)
        mod.probe_default_credentials("192.168.1.1")
        # Without the shape cache this was len(DEFAULT_CREDS) * 40.
        assert len(posts) < len(mod.DEFAULT_CREDS) * 10, \
            f"{len(posts)} POSTs for {len(mod.DEFAULT_CREDS)} credential pairs"

    def test_every_credential_pair_is_still_submitted(self, mod, monkeypatch):
        bodies = []

        def handler(req):
            if _is_post(req):
                bodies.append(req.data.decode())
            return (200, LOGIN_PAGE)

        _wire(monkeypatch, mod, handler)
        mod.probe_default_credentials("192.168.1.1")
        joined = "\n".join(bodies)
        for user, _pwd in mod.DEFAULT_CREDS:
            assert user in joined, f"{user} was never tried"

    def test_a_working_login_is_still_found_after_the_shape_is_cached(
            self, mod, monkeypatch):
        # The last pair in the list must still be able to succeed.
        last_user, last_pwd = mod.DEFAULT_CREDS[-1]

        def handler(req):
            if not _is_post(req):
                return (200, LOGIN_PAGE)
            body = req.data.decode()
            if urllib.parse.quote(last_user) in body:
                return (200, ADMIN_PAGE)
            return (200, LOGIN_PAGE)

        _wire(monkeypatch, mod, handler)
        successes, _n, _c = mod.probe_default_credentials("192.168.1.1")
        assert successes, "the cached shape must still be able to succeed"
        assert successes[0][0] == last_user


class TestTheArpPollIsGuarded:
    """The only subprocess call site in the file with no timeout and no guard.

    A Linux observer with iproute2 but no iputils raised FileNotFoundError
    straight out of action_full_audit, taking roughly nine later checks, the
    baseline save and the report with it. ping() also picks the flag that means
    "give up quickly" per platform — -t is a TTL on Linux, so this loop was
    sending TTL-1 probes there and seeing nothing beyond the first hop.
    """

    def test_the_poll_goes_through_ping(self, mod, monkeypatch):
        pinged = []
        monkeypatch.setattr(mod, "ping", lambda ip: pinged.append(ip))
        monkeypatch.setattr(mod, "read_arp_table", lambda: {"192.168.1.1": "aa:bb:cc:dd:ee:ff"})
        monkeypatch.setattr(mod.time, "sleep", lambda s: None)
        mod.check_arp_spoofing("192.168.1.1", polls=3, interval=0)
        assert pinged == ["192.168.1.1"] * 3

    def test_a_missing_ping_binary_does_not_abort_the_audit(self, mod, monkeypatch):
        def no_ping(cmd, **kw):
            raise FileNotFoundError("ping")
        monkeypatch.setattr(mod.subprocess, "run", no_ping)
        monkeypatch.setattr(mod, "read_arp_table", lambda: {})
        monkeypatch.setattr(mod.time, "sleep", lambda s: None)
        result = mod.check_arp_spoofing("192.168.1.1", polls=2, interval=0)
        assert result["macs_seen"] == []
        assert result["spoofing_suspected"] is False
