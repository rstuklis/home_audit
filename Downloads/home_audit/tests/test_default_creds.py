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


def _wire(monkeypatch, mod, handler, open_ports=(80,)):
    monkeypatch.setattr(mod, "check_port",
                        lambda host, port, timeout=1.0: port in open_ports)
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
        successes, note = mod.probe_default_credentials("192.168.1.1")
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
        successes, note = mod.probe_default_credentials("192.168.1.1")
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
        successes, note = mod.probe_default_credentials("192.168.1.1")
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
        successes, note = mod.probe_default_credentials("192.168.1.1")
        assert successes == []

    def test_credentials_rejected_with_another_401_are_not_a_hit(self, mod, monkeypatch):
        # Challenge issued, but every credential pair is bounced with a second
        # 401 — the correct (and common) outcome for a well-secured router.
        _wire(monkeypatch, mod, lambda req: (401, ""))
        successes, note = mod.probe_default_credentials("192.168.1.1")
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
        successes, note = mod.probe_default_credentials("192.168.1.1")
        assert len(successes) == 1
        assert successes[0][2:] == (80, "Form POST")

    def test_a_form_post_that_bounces_back_to_the_login_form_is_not_a_hit(self, mod, monkeypatch):
        # Wrong password: the POST response is the login form again. No admin
        # content, so nothing is recorded.
        _wire(monkeypatch, mod, lambda req: (200, LOGIN_PAGE))
        successes, note = mod.probe_default_credentials("192.168.1.1")
        assert successes == []


class TestLockout:
    def test_a_rate_limit_signal_aborts_and_is_reported(self, mod, monkeypatch):
        # If the router starts rate-limiting we must stop immediately rather
        # than keep guessing and lock the owner out. A 429 raises LockoutError
        # inside _fetch; the probe catches it and hands back the note.
        _wire(monkeypatch, mod, lambda req: (429, ""))
        successes, note = mod.probe_default_credentials("192.168.1.1")
        assert successes == []
        assert note is not None
        assert "lockout" in note.lower() or "rate" in note.lower()

    def test_a_lockout_phrase_in_the_body_also_aborts(self, mod, monkeypatch):
        # Some routers answer 200 with "too many login attempts" in the body
        # rather than a 429 status; that phrase must trip the same guard.
        _wire(monkeypatch, mod,
              lambda req: (200, "Too many login attempts, please wait"))
        successes, note = mod.probe_default_credentials("192.168.1.1")
        assert note is not None
