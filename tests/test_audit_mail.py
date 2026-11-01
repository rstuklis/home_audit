"""tools/audit_mail.py — the one email both Macs send.

The city Mac's email is the one the owner reads on a phone: the TL;DR, a
version check, then each network's report as cards, text and HTML in one
message and nothing attached. The beach Mac attached a PDF and sent the rest
through Mail.app. This tool composes and sends the city email for both, from
the iCloud address in the Keychain, the way the SMSF screener already does.
"""

import importlib.util
import smtplib
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"


@pytest.fixture(scope="module")
def am():
    spec = importlib.util.spec_from_file_location("audit_mail", TOOLS / "audit_mail.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit_mail"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def eh():
    spec = importlib.util.spec_from_file_location("report_email_html_am", TOOLS / "report_email_html.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = """================================================================
NETWORK INTERFACES
================================================================
  Your Mac's primary IP : 192.168.86.21
  Default gateway       : 192.168.86.1

================================================================
ROUTER / GATEWAY PORT SCAN
================================================================
  [MEDIUM]    80  HTTP admin     Unencrypted web admin page.

================================================================
CONNECTED DEVICES
================================================================
  Total: 18 device(s) across 1 subnet(s) scanned.
  5 unidentified device(s). Tag them with:

================================================================
CHANGE DETECTION (vs saved baseline)
================================================================
  [OK    ] Baseline integrity: Seal verified.
Baseline from: 2026-10-20T11:12:56+00:00
{verdict}

================================================================
Full audit complete. This is a snapshot, not a guarantee.
"""


@pytest.fixture
def report(tmp_path):
    def write(name="loveshack-h", verdict="No changes since baseline."):
        path = tmp_path / f"{name}.txt"
        path.write_text(REPORT.format(verdict=verdict), encoding="utf-8")
        return f"{name}={path}"
    return write


# ---------------------------------------------------------------------------
# Composing: the city layout
# ---------------------------------------------------------------------------

class TestCompose:
    def test_the_layout_is_the_city_one(self, am, report):
        body = am.compose([report()], site="beach house")
        lines = body.splitlines()
        assert lines[0] == "#" * 64 and lines[1].startswith("# Home network audit — 20") and lines[2] == "#" * 64
        assert any(line.startswith("TL;DR") for line in lines)
        assert "# NETWORK: loveshack-h — " in body and "   ip 192.168.86.21" in body
        # The section itself (its boxed header), not its mention in the TL;DR.
        assert body.index("TL;DR") < body.index("# NETWORK:") < body.index("ROUTER / GATEWAY PORT SCAN\n====")

    def test_the_digest_names_the_network_not_the_file(self, am, report):
        body = am.compose([report()])
        assert "Networks audited : 1 of 1   (loveshack-h)" in body
        assert "loveshack-h  no changes   18 devices, 5 unidentified" in body

    def test_three_networks_in_the_order_given(self, am, report):
        body = am.compose([report("loveshack"), report("loveshack-iot"), report("pearl")])
        assert "Networks audited : 3 of 3   (loveshack, loveshack-iot, pearl)" in body
        assert body.index("# NETWORK: loveshack —") < body.index("# NETWORK: loveshack-iot —") < body.index("# NETWORK: pearl —")

    def test_an_unreadable_report_is_named_as_not_audited(self, am, report, tmp_path):
        body = am.compose([report(), f"pearl={tmp_path / 'absent.txt'}"])
        assert "Networks audited : 1 of 2" in body and "pearl" in body and "NOT AUDITED" in body

    def test_the_version_check_card_follows_the_digest(self, am, report):
        def git(cmd, **kw):
            text = " ".join(cmd)
            out = "0\t0\n" if "rev-list" in text else ""
            return subprocess.CompletedProcess(cmd, 0, out, "")
        body = am.compose([report()], repo="/some/checkout", runner=git)
        assert "\nVERSION CHECK\n  Up to date with origin/master.\n" in body
        assert body.index("TL;DR") < body.index("VERSION CHECK") < body.index("# NETWORK:")

    def test_no_repo_no_version_card(self, am, report):
        assert "VERSION CHECK" not in am.compose([report()])

    def test_a_spec_must_name_the_network(self, am):
        with pytest.raises(am.MailError):
            am.parse_spec("=x.txt")
        assert am.parse_spec("/tmp/pearl.txt") == ("pearl", "/tmp/pearl.txt")


class TestVersionCheck:
    def _runner(self, behind=0, ahead=0, dirty="", fetch_rc=0):
        def git(cmd, **kw):
            text = " ".join(cmd)
            if "fetch" in text:
                return subprocess.CompletedProcess(cmd, fetch_rc, "", "could not resolve host" if fetch_rc else "")
            if "rev-list" in text:
                return subprocess.CompletedProcess(cmd, 0, f"{ahead}\t{behind}\n", "")
            return subprocess.CompletedProcess(cmd, 0, dirty, "")
        return git

    def test_up_to_date(self, am):
        assert am.version_check("/r", self._runner()) == "Up to date with origin/master."

    def test_behind_says_to_update(self, am):
        assert am.version_check("/r", self._runner(behind=3)) == "3 commit(s) behind origin/master — run the update."

    def test_local_edits_are_named(self, am):
        assert "local edits" in am.version_check("/r", self._runner(dirty=" M home_net_audit.py"))

    def test_a_failed_fetch_is_a_line_not_an_error(self, am):
        assert am.version_check("/r", self._runner(fetch_rc=128)).startswith("Could not fetch origin/master")

    def test_a_hung_git_is_a_line_not_an_error(self, am):
        def hang(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 20)
        assert am.version_check("/r", hang).startswith("Could not check the version")


# ---------------------------------------------------------------------------
# The subject
# ---------------------------------------------------------------------------

class TestSubject:
    def test_changes_detected_wins(self, am, report):
        body = am.compose([report("a"), report("b", "CHANGES DETECTED:\n  ! NEW device(s) since baseline: aa:bb")])
        assert am.subject_for(body, None, "2026-10-25") == "[Home Net Audit] 2026-10-25 — CHANGES DETECTED"

    def test_no_changes_and_the_site(self, am, report):
        body = am.compose([report()])
        assert am.subject_for(body, "beach house", "2026-10-25") == "[Home Net Audit] 2026-10-25 — beach house — no changes"

    def test_an_unreadable_network_makes_it_incomplete(self, am, report, tmp_path):
        body = am.compose([report(), f"pearl={tmp_path / 'absent.txt'}"])
        assert am.verdict(body) == "AUDIT INCOMPLETE"

    def test_a_first_audit(self, am, report):
        body = am.compose([report(verdict="No baseline saved yet.")])
        assert am.verdict(body) == "first audit"

    def test_a_device_cannot_write_the_subject(self, am, report):
        # Only the per-network lines above "Flagged items" are read.
        body = am.compose([report()]).replace("FLAGGED ITEMS: 1", "FLAGGED ITEMS: 1 CHANGES DETECTED")
        assert am.verdict(body) == "no changes"

    def test_no_digest_no_verdict(self, am):
        assert am.verdict("just text") == "report"


# ---------------------------------------------------------------------------
# The message and the send
# ---------------------------------------------------------------------------

class TestMessage:
    def test_text_and_html_in_one_message_nothing_attached(self, am, report):
        body = am.compose([report()], site="beach house")
        msg = am.build_message("me@mac.com", ["you@mac.com"], body, site="beach house", today="2026-10-25")
        assert msg.get_content_type() == "multipart/alternative"
        assert [p.get_content_type() for p in msg.iter_parts()] == ["text/plain", "text/html"]
        assert list(msg.iter_attachments()) == []
        assert msg["From"] == "me@mac.com" and msg["To"] == "you@mac.com"
        assert msg["Subject"] == "[Home Net Audit] 2026-10-25 — beach house — no changes"
        assert msg["Date"] and msg["Message-ID"].endswith("@mac.com>")
        assert msg.get_body(preferencelist=("plain",)).get_content() == body
        html = msg.get_body(preferencelist=("html",)).get_content()
        assert "Home Network Audit Report — beach house" in html and "loveshack-h" in html

    def test_the_html_heading_names_the_site_only_when_given(self, eh):
        plain = eh.render("TL;DR — x\n  Networks audited : 1 of 1\n")
        assert "Home Network Audit Report</h1>" in plain and " — " not in plain.split("</h1>")[0].rsplit(">", 1)[1]
        assert "Home Network Audit Report — beach house</h1>" in eh.render("TL;DR — x\n", site="beach house")
        assert "<title>Home Network Audit Report — beach house</title>" in eh.render("x", site="beach house")


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None, fail=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append("starttls")
        assert context is not None

    def login(self, user, password):
        self.calls.append(("login", user, password))
        if password == "wrong":
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Authentication failed")

    def send_message(self, msg):
        self.calls.append(("send", msg["Subject"]))


class TestSend:
    def test_starttls_login_send(self, am):
        FakeSMTP.instances.clear()
        msg = am.new_message("me@mac.com", ["you@mac.com"], "s")
        am.send(msg, "me@mac.com", "pw", smtp_class=FakeSMTP)
        smtp = FakeSMTP.instances[-1]
        assert (smtp.host, smtp.port, smtp.timeout) == ("smtp.mail.me.com", 587, 60)
        assert smtp.calls == ["ehlo", "starttls", "ehlo", ("login", "me@mac.com", "pw"), ("send", "s")]

    def test_a_refused_sign_in_says_how_to_fix_it(self, am):
        msg = am.new_message("me@mac.com", ["you@mac.com"], "s")
        with pytest.raises(am.MailError, match="app-specific password.*--install --reset-mail"):
            am.send(msg, "me@mac.com", "wrong", smtp_class=FakeSMTP)

    def test_a_network_failure_is_retried_once_on_a_scheduled_run(self, am, monkeypatch):
        attempts = []

        class Flaky(FakeSMTP):
            def __init__(self, host, port, timeout=None):
                super().__init__(host, port, timeout)
                attempts.append(1)
                if len(attempts) == 1:
                    raise OSError("Network is unreachable")
        monkeypatch.setattr(am.time, "sleep", lambda s: None)
        msg = am.new_message("me@mac.com", ["you@mac.com"], "s")
        am.send(msg, "me@mac.com", "pw", retry_wait=90.0, smtp_class=Flaky)
        assert len(attempts) == 2

    def test_without_a_retry_wait_a_failure_is_an_error(self, am):
        class Down(FakeSMTP):
            def __init__(self, host, port, timeout=None):
                raise OSError("Network is unreachable")
        msg = am.new_message("me@mac.com", ["you@mac.com"], "s")
        with pytest.raises(am.MailError, match="could not send through smtp.mail.me.com:587"):
            am.send(msg, "me@mac.com", "pw", smtp_class=Down)


# ---------------------------------------------------------------------------
# The Keychain
# ---------------------------------------------------------------------------

class FakeSecurity:
    def __init__(self, items=None):
        self.items = dict(items or {})        # service -> (account, password)
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        verb, args = cmd[1], cmd[2:]
        service = args[args.index("-s") + 1] if "-s" in args else None
        if verb == "find-generic-password":
            if service not in self.items:
                return subprocess.CompletedProcess(cmd, 44, "", "security: SecKeychainSearchCopyNext: The specified item could not be found.")
            acct, pw = self.items[service]
            if "-w" in args:
                return subprocess.CompletedProcess(cmd, 0, pw + "\n", "")
            return subprocess.CompletedProcess(cmd, 0, f'attributes:\n    "acct"<blob>="{acct}"\n    "svce"<blob>="{service}"\n', "")
        if verb == "delete-generic-password":
            if service in self.items:
                del self.items[service]
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 44, "", "not found")
        if verb == "add-generic-password":
            self.items[service] = (args[args.index("-a") + 1], args[args.index("-w") + 1])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(cmd)


class TestKeychain:
    def test_nothing_stored_is_none(self, am, monkeypatch):
        monkeypatch.setattr(am.subprocess, "run", FakeSecurity())
        assert am.keychain_mail_account() is None

    def test_store_read_forget(self, am, monkeypatch):
        fake = FakeSecurity()
        monkeypatch.setattr(am.subprocess, "run", fake)
        am.keychain_store("rob@mac.com", "abcd-efgh-ijkl-mnop")
        assert am.keychain_mail_account() == ("rob@mac.com", "abcd-efgh-ijkl-mnop")
        assert fake.items == {"home_net_audit-mail": ("rob@mac.com", "abcd-efgh-ijkl-mnop")}
        assert am.keychain_forget() == 1 and am.keychain_mail_account() is None

    def test_a_locked_keychain_is_an_error_not_nothing_stored(self, am, monkeypatch):
        monkeypatch.setattr(am.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 36, "", "security: SecKeychainSearchCopyNext: User interaction is not allowed."))
        with pytest.raises(am.MailError, match="Lock when sleeping"):
            am.keychain_mail_account()

    def test_another_service_can_be_named(self, am, monkeypatch):
        monkeypatch.setattr(am.subprocess, "run", FakeSecurity({"homenetaudit-smtp": ("r@gmail.com", "pw")}))
        assert am.keychain_mail_account("homenetaudit-smtp") == ("r@gmail.com", "pw")
        assert am.keychain_mail_account() is None


# ---------------------------------------------------------------------------
# The command line, as the wrappers call it
# ---------------------------------------------------------------------------

class TestCli:
    @pytest.fixture
    def wired(self, am, monkeypatch):
        sent = []
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=am.KEYCHAIN_SERVICE: ("me@mac.com", "pw"))
        monkeypatch.setattr(am, "send", lambda msg, sender, pw, host, port, retry_wait=None, smtp_class=None:
                            sent.append((msg, sender, host, port, retry_wait)))
        return sent

    def test_send_composes_sends_and_keeps_the_body(self, am, wired, report, tmp_path, capsys):
        saved = tmp_path / "last_run.txt"
        rc = am.main(["send", "--to", "rstuklis@mac.com", "--site", "beach house",
                      "--save-body", str(saved), report()])
        assert rc == 0
        msg, sender, host, port, retry = wired[0]
        assert msg["To"] == "rstuklis@mac.com" and sender == "me@mac.com" and (host, port) == ("smtp.mail.me.com", 587)
        assert retry == 90.0
        assert msg["Subject"].startswith("[Home Net Audit] ") and msg["Subject"].endswith(" — beach house — no changes")
        assert saved.read_text(encoding="utf-8").startswith("#" * 64)
        assert "EMAIL SENT to rstuklis@mac.com  (subject: [Home Net Audit]" in capsys.readouterr().out

    def test_send_takes_an_assembled_body(self, am, wired, tmp_path):
        body = tmp_path / "body.txt"
        body.write_text("TL;DR — x\n  Networks audited : 1 of 1   (loveshack)\n    loveshack  CHANGES DETECTED\n", encoding="utf-8")
        assert am.main(["send", "--to", "a@b", "--body", str(body)]) == 0
        assert wired[0][0]["Subject"].endswith(" — CHANGES DETECTED")

    def test_to_before_or_after_the_command_both_count(self, am, wired, report):
        assert am.main(["--to", "a@b", "send", "--to", "c@d", report()]) == 0
        assert wired[0][0]["To"] == "a@b, c@d"

    def test_the_sender_is_the_recipient_when_none_is_given(self, am, wired, report):
        assert am.main(["send", report()]) == 0
        assert wired[0][0]["To"] == "me@mac.com"

    def test_another_server_and_keychain_item(self, am, monkeypatch, report):
        seen = {}
        monkeypatch.setattr(am, "keychain_mail_account", lambda service: seen.setdefault("service", service) and ("r@gmail.com", "pw"))
        monkeypatch.setattr(am, "send", lambda msg, sender, pw, host, port, **k: seen.update(host=host, port=port))
        assert am.main(["--smtp", "smtp.gmail.com:587", "--keychain", "homenetaudit-smtp", "send", "--to", "a@b", report()]) == 0
        assert seen == {"service": "homenetaudit-smtp", "host": "smtp.gmail.com", "port": 587}

    def test_notify_appends_the_tail_of_a_log(self, am, wired, tmp_path):
        log = tmp_path / "run.log"
        log.write_text("\n".join(f"line {n}" for n in range(100)), encoding="utf-8")
        rc = am.main(["notify", "--to", "a@b", "--subject", "[Home Net Audit] the audit did not run",
                      "--message", "exit 2", "--text", str(log), "--tail", "3"])
        assert rc == 0
        msg = wired[0][0]
        assert msg["Subject"] == "[Home Net Audit] the audit did not run"
        assert msg.get_content() == "exit 2\n\nline 97\nline 98\nline 99\n"
        assert msg.get_content_type() == "text/plain"

    def test_nothing_in_the_keychain_is_a_plain_message_and_exit_1(self, am, monkeypatch, report, tmp_path, capsys):
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=None: None)
        assert am.main(["--outbox", str(tmp_path / "outbox"), "send", "--to", "a@b", report()]) == 1
        # Said on stdout, where the wrapper's log is, in the one EMAIL NOT SENT line.
        assert "EMAIL NOT SENT: no password in the Keychain" in capsys.readouterr().out

    def test_send_needs_reports_or_a_body(self, am, wired, capsys):
        assert am.main(["send", "--to", "a@b"]) == 1
        assert "NAME=REPORT.txt" in capsys.readouterr().err

    def test_forget_mail(self, am, monkeypatch, capsys):
        monkeypatch.setattr(am.subprocess, "run", FakeSecurity({"home_net_audit-mail": ("a@b", "pw")}))
        assert am.main(["--forget-mail"]) == 0
        assert "Removed 1 stored item(s)." in capsys.readouterr().out

    def test_install_outside_a_terminal_refuses_plainly(self, am, monkeypatch, capsys):
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=None: None)
        monkeypatch.setattr(am.sys.stdin, "isatty", lambda: False)
        assert am.main(["--install"]) == 1
        assert "run --install in Terminal" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Through Mail.app: the beach Mac's way, addresses as they are, nothing stored
# ---------------------------------------------------------------------------

class TestMailApp:
    def _runner(self, calls, rc=0, stderr=""):
        def run(cmd, **kw):
            body_path = cmd[2]
            calls.append({"cmd": cmd, "script": kw.get("input"), "body": Path(body_path).read_text(encoding="utf-8"),
                          "timeout": kw.get("timeout")})
            return subprocess.CompletedProcess(cmd, rc, "", stderr)
        return run

    def test_the_message_goes_to_osascript_with_the_body_in_a_file(self, am):
        calls = []
        am.send_via_mail_app("[Home Net Audit] s", "line one — “quoted”\nline two\n", ["rstuklis@yahoo.com"],
                             sender="robert@stuklis.net", runner=self._runner(calls))
        call = calls[0]
        assert call["cmd"][:2] == ["osascript", "-"]
        assert call["cmd"][3:] == ["[Home Net Audit] s", "robert@stuklis.net", "rstuklis@yahoo.com"]
        assert call["body"] == "line one — “quoted”\nline two\n"
        assert 'tell application "Mail"' in call["script"] and "send msg" in call["script"]
        assert "«class utf8»" in call["script"] and "attachment" not in call["script"]
        assert not Path(call["cmd"][2]).exists()          # the temporary file is gone

    def test_no_sender_means_mail_apps_default_account(self, am):
        calls = []
        am.send_via_mail_app("s", "b", ["a@b", "c@d"], runner=self._runner(calls))
        assert calls[0]["cmd"][4:] == ["", "a@b", "c@d"]

    def test_a_recipient_is_required(self, am):
        with pytest.raises(am.MailError, match="--to"):
            am.send_via_mail_app("s", "b", [], runner=self._runner([]))

    def test_a_refusal_is_an_error_in_mails_words(self, am):
        with pytest.raises(am.MailError, match="Mail.app refused the message: .*Can’t get account"):
            am.send_via_mail_app("s", "b", ["a@b"], runner=self._runner([], rc=1, stderr="execution error: Mail got an error: Can’t get account. (-1728)"))

    def test_a_missing_automation_grant_says_where_it_is_made(self, am):
        err = "execution error: Not authorized to send Apple events to Mail. (-1743)"
        with pytest.raises(am.MailError, match="Privacy & Security > Automation"):
            am.send_via_mail_app("s", "b", ["a@b"], runner=self._runner([], rc=1, stderr=err))

    def test_a_hung_mail_app_is_an_error_not_a_hang(self, am):
        def hang(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        with pytest.raises(am.MailError, match="dialog"):
            am.send_via_mail_app("s", "b", ["a@b"], runner=hang)


class TestCliViaMailApp:
    @pytest.fixture
    def wired(self, am, monkeypatch):
        sent = []
        monkeypatch.setattr(am, "send_via_mail_app",
                            lambda subject, body, recipients, sender=None, runner=None:
                            sent.append((subject, body, recipients, sender)))
        monkeypatch.setattr(am, "keychain_mail_account",
                            lambda service=None: pytest.fail("Mail.app needs nothing from the Keychain"))
        monkeypatch.setattr(am, "send", lambda *a, **k: pytest.fail("no SMTP on the Mail.app way"))
        return sent

    def test_send_through_mail_app_keeps_the_addresses_and_attaches_nothing(self, am, wired, report, tmp_path):
        html = tmp_path / "last_run.html"
        rc = am.main(["--via", "mail-app", "--from", "robert@stuklis.net", "send", "--to", "rstuklis@yahoo.com",
                      "--site", "beach house", "--save-html", str(html), report()])
        assert rc == 0
        subject, body, recipients, sender = wired[0]
        assert subject.startswith("[Home Net Audit] ") and subject.endswith(" — beach house — no changes")
        assert body.startswith("#" * 64) and "# NETWORK: loveshack-h" in body
        assert (recipients, sender) == (["rstuklis@yahoo.com"], "robert@stuklis.net")
        assert "Home Network Audit Report — beach house" in html.read_text(encoding="utf-8")

    def test_notify_through_mail_app(self, am, wired, tmp_path):
        log = tmp_path / "run.log"
        log.write_text("a\nb\nc\n", encoding="utf-8")
        rc = am.main(["--via", "mail-app", "--from", "robert@stuklis.net", "notify", "--to", "rstuklis@yahoo.com",
                      "--subject", "[Home Net Audit] AUDIT DID NOT RUN", "--message", "exit 2", "--text", str(log), "--tail", "2"])
        assert rc == 0
        assert wired[0] == ("[Home Net Audit] AUDIT DID NOT RUN", "exit 2\n\nb\nc", ["rstuklis@yahoo.com"], "robert@stuklis.net")

    def test_test_email_through_mail_app(self, am, wired):
        assert am.main(["--via", "mail-app", "--to", "rstuklis@yahoo.com", "--test-email"]) == 0
        subject, body, recipients, sender = wired[0]
        assert subject == "[Home Net Audit] test email" and "Mail.app" in body and sender is None

    def test_mail_app_without_a_recipient_is_a_plain_error(self, am, monkeypatch, report, tmp_path, capsys):
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=None: pytest.fail("not the Keychain"))
        assert am.main(["--via", "mail-app", "--outbox", str(tmp_path / "outbox"), "send", report()]) == 1
        assert "EMAIL NOT SENT: --via mail-app needs at least one --to address" in capsys.readouterr().out

    def test_an_unreadable_log_is_said_in_the_note_not_an_error(self, am, wired, tmp_path):
        rc = am.main(["--via", "mail-app", "notify", "--to", "a@b", "--subject", "s", "--text", str(tmp_path / "absent.log")])
        assert rc == 0 and "could not be read" in wired[0][1]


class TestSmtpWithAnExistingKeychainItem:
    def test_a_password_only_item_sends_from_the_given_address(self, am, monkeypatch, report):
        # The city Mac's Gmail item was stored by another script, password only.
        monkeypatch.setattr(am, "keychain_mail_account", lambda service: (None, "app-pw") if service == "homenetaudit-smtp" else None)
        seen = {}
        monkeypatch.setattr(am, "send", lambda msg, sender, pw, host, port, **k: seen.update(sender=sender, pw=pw, host=host, to=msg["To"]))
        rc = am.main(["--smtp", "smtp.gmail.com:587", "--keychain", "homenetaudit-smtp", "--from", "robert.stuklis@gmail.com",
                      "send", "--to", "robert.stuklis@gmail.com", report()])
        assert rc == 0
        assert seen == {"sender": "robert.stuklis@gmail.com", "pw": "app-pw", "host": "smtp.gmail.com", "to": "robert.stuklis@gmail.com"}

    def test_a_password_only_item_without_from_says_so(self, am, monkeypatch, report, tmp_path, capsys):
        monkeypatch.setattr(am, "keychain_mail_account", lambda service: (None, "app-pw"))
        assert am.main(["--outbox", str(tmp_path / "outbox"), "send", "--to", "a@b", report()]) == 1
        assert "--from" in capsys.readouterr().out

    def test_the_keychain_reader_returns_a_password_only_item(self, am, monkeypatch):
        def security(cmd, **kw):
            if "-w" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "app-pw\n", "")
            return subprocess.CompletedProcess(cmd, 0, 'attributes:\n    "svce"<blob>="homenetaudit-smtp"\n', "")
        monkeypatch.setattr(am.subprocess, "run", security)
        assert am.keychain_mail_account("homenetaudit-smtp") == (None, "app-pw")

    def test_a_missing_body_file_is_a_plain_error(self, am, monkeypatch, capsys):
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=None: ("me@mac.com", "pw"))
        assert am.main(["send", "--to", "a@b", "--body", "/nowhere/body.txt"]) == 1
        assert "could not read --body" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Round 5. The subject (F8): its verdict comes from the TL;DR's per-network
# lines, never from a substring of the body; an aborted or unjoinable network
# makes it AUDIT INCOMPLETE; the run number goes in so a lost week shows as a gap.
# ---------------------------------------------------------------------------

import email as email_lib
import json
import os

ABORT_LINE = ("  [HIGH  ] AUDIT ABORTED by an unexpected error before it completed. No baseline was saved and no "
              "report was written for this run.")


@pytest.fixture
def numbered(tmp_path):
    """A report that saved its baseline: the run number is on the last line."""
    def write(name="loveshack-h", run=18, verdict="No changes since baseline."):
        path = tmp_path / f"{name}.txt"
        path.write_text(REPORT.format(verdict=verdict) + f"\nBaseline saved to /x/baseline-{name}.json  (run {run})\n",
                        encoding="utf-8")
        return f"{name}={path}"
    return write


class TestSubjectRunNumberAndIncomplete:
    def test_the_run_number_goes_in_the_subject(self, am, numbered):
        body = am.compose([numbered()])
        assert am.run_number(body) == 18
        assert am.subject_for(body, None, "2026-11-01") == "[Home Net Audit] 2026-11-01 — run 18 — no changes"
        assert am.subject_for(body, "beach house", "2026-11-01") == "[Home Net Audit] 2026-11-01 — beach house — run 18 — no changes"

    def test_the_first_networks_run_number_is_the_one(self, am, numbered):
        body = am.compose([numbered("loveshack", 18), numbered("pearl", 7)])
        assert "— run 18 —" in am.subject_for(body, None, "2026-11-01")

    def test_no_run_number_no_run_in_the_subject(self, am, report):
        body = am.compose([report()])
        assert am.run_number(body) is None
        assert am.subject_for(body, None, "2026-11-01") == "[Home Net Audit] 2026-11-01 — no changes"

    def test_the_run_number_is_read_from_the_tldr_not_the_body(self, am):
        assert am.run_number('a device announces "run 5" here\n') is None

    def test_an_aborted_network_makes_the_subject_incomplete(self, am, report, tmp_path):
        broken = tmp_path / "pearl.txt"
        broken.write_text("\n" + ABORT_LINE + "\nTraceback (most recent call last):\n", encoding="utf-8")
        body = am.compose([report(), f"pearl={broken}"])
        assert "pearl        NOT AUDITED — AUDIT ABORTED" in body
        assert am.verdict(body) == "AUDIT INCOMPLETE"

    def test_changes_and_an_abort_both_go_in_the_subject(self, am, report, tmp_path):
        broken = tmp_path / "pearl.txt"
        broken.write_text("\n" + ABORT_LINE + "\n", encoding="utf-8")
        body = am.compose([report("a", "CHANGES DETECTED:\n  ! NEW device(s) since baseline: aa:bb"), f"pearl={broken}"])
        assert am.verdict(body) == "CHANGES DETECTED, AUDIT INCOMPLETE"

    def test_a_banner_only_report_is_incomplete_not_no_changes(self, am, tmp_path):
        # The old city mailer's substring test over the body said "no changes" for this.
        empty = tmp_path / "pearl.txt"
        empty.write_text("python3: command not found\n", encoding="utf-8")
        assert am.verdict(am.compose([f"pearl={empty}"])) == "AUDIT INCOMPLETE"

    def test_a_device_named_changes_detected_does_not_write_the_subject(self, am, tmp_path):
        # Round 4 F8: send_report.py tested `"CHANGES DETECTED" in body`.
        path = tmp_path / "loveshack-h.txt"
        path.write_text(REPORT.format(verdict="No changes since baseline.").replace(
            "  5 unidentified device(s). Tag them with:\n",
            '  5 unidentified device(s). Tag them with:\n    192.168.86.30  aa:bb:cc:dd:ee:ff  Acme  announces "CHANGES DETECTED" [mdns]\n'),
            encoding="utf-8")
        body = am.compose([f"loveshack-h={path}"])
        assert 'announces "CHANGES DETECTED"' in body and am.verdict(body) == "no changes"


# ---------------------------------------------------------------------------
# Round 5. The memory moves on only when the email has gone (F3), and a lost
# email is kept and said.
# ---------------------------------------------------------------------------

LOUD = REPORT.format(verdict="CHANGES DETECTED:\n  ! NEW open port 23 on the router").replace(
    "  [MEDIUM]    80  HTTP admin     Unencrypted web admin page.\n",
    "  [MEDIUM]    80  HTTP admin     Unencrypted web admin page.\n"
    "  [HIGH  ]    23  Telnet         Unencrypted remote login; should not be exposed.\n")


class TestTheMemoryMovesOnlyWithTheEmail:
    @pytest.fixture
    def keychain(self, am, monkeypatch):
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=am.KEYCHAIN_SERVICE: ("me@mac.com", "pw"))

    @pytest.fixture
    def outbox(self, tmp_path):
        return tmp_path / "outbox"

    def _send_that(self, am, monkeypatch, outcome, sent=None):
        def fake(msg, sender, pw, host, port, retry_wait=None, smtp_class=None):
            if outcome == "fails":
                raise am.MailError("could not send through smtp.gmail.com:587: [Errno 54] Connection reset by peer")
            if sent is not None:
                sent.append(msg)
        monkeypatch.setattr(am, "send", fake)

    def test_a_failed_send_leaves_the_memory_where_it_was_and_keeps_the_email(self, am, monkeypatch, keychain, outbox, report, tmp_path, capsys):
        state, last = tmp_path / "digest_state.json", tmp_path / "last_run.txt"
        # Week 1 goes: one MEDIUM on record, the memory moved into place.
        self._send_that(am, monkeypatch, "works")
        assert am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), "--save-body", str(last), report()]) == 0
        week1_state, week1_body = state.read_bytes(), last.read_text(encoding="utf-8")
        assert not (tmp_path / "digest_state.json.pending").exists()
        assert capsys.readouterr().out.startswith("EMAIL SENT")
        # Week 2 adds a HIGH and the send fails after its retry.
        self._send_that(am, monkeypatch, "fails")
        loud_path = tmp_path / "loud.txt"
        loud_path.write_text(LOUD, encoding="utf-8")
        rc = am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), "--save-body", str(last), f"loveshack-h={loud_path}"])
        assert rc == 1
        out = capsys.readouterr()
        assert out.out.count("\n") == 1 and out.out.startswith("EMAIL NOT SENT: could not send through smtp.gmail.com:587")
        assert "Kept at " in out.out and "resend" in out.out and out.err == ""
        assert state.read_bytes() == week1_state                      # the memory did not move on
        assert last.read_text(encoding="utf-8") == week1_body         # the last email SENT is still there
        kept = sorted(outbox.glob("*.eml"))
        assert len(kept) == 1 and kept[0].name.endswith("-CHANGES-DETECTED.eml")
        msg = email_lib.message_from_bytes(kept[0].read_bytes(), policy=email_lib.policy.default)
        assert msg["Subject"].endswith(" — CHANGES DETECTED") and msg["To"] == "a@b" and msg[am.STATE_HEADER] == str(state)
        assert "Telnet" in msg.get_body(preferencelist=("plain",)).get_content()
        assert (outbox / (kept[0].name + ".state.json")).exists()     # the memory that email should move
        # Week 3 goes and still calls week 2's HIGH new.
        self._send_that(am, monkeypatch, "works")
        assert am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), "--save-body", str(last), f"loveshack-h={loud_path}"]) == 0
        body = last.read_text(encoding="utf-8")
        assert "1 new since the previous report" in body and "[HIGH] loveshack-h · ROUTER / GATEWAY PORT SCAN · 23 Telnet" in body

    def test_a_first_run_that_fails_leaves_no_memory_behind(self, am, monkeypatch, keychain, outbox, report, tmp_path):
        state = tmp_path / "digest_state.json"
        self._send_that(am, monkeypatch, "fails")
        assert am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), report()]) == 1
        assert not state.exists()

    def test_a_body_send_moves_the_pending_memory_when_it_goes(self, am, monkeypatch, keychain, outbox, tmp_path):
        # The city Mac's way: report_digest.py wrote the memory as .pending, the wrapper sends the assembled body.
        state, pending = tmp_path / "digest_state.json", tmp_path / "digest_state.json.pending"
        state.write_text('{"flagged": ["old"]}', encoding="utf-8")
        pending.write_text('{"flagged": ["new"], "alerts_until": {}}', encoding="utf-8")
        body = tmp_path / "last_run.txt"
        body.write_text("TL;DR — x\n  Networks audited : 1 of 1   (loveshack)\n    loveshack  no changes   run 18\n", encoding="utf-8")
        self._send_that(am, monkeypatch, "works")
        assert am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), "--body", str(body)]) == 0
        assert json.loads(state.read_text()) == {"flagged": ["new"], "alerts_until": {}} and not pending.exists()

    def test_a_body_send_that_fails_moves_nothing(self, am, monkeypatch, keychain, outbox, tmp_path):
        state, pending = tmp_path / "digest_state.json", tmp_path / "digest_state.json.pending"
        state.write_text('{"flagged": ["old"]}', encoding="utf-8")
        pending.write_text('{"flagged": ["new"]}', encoding="utf-8")
        body = tmp_path / "last_run.txt"
        body.write_text("TL;DR — x\n  Networks audited : 1 of 1   (loveshack)\n    loveshack  no changes\n", encoding="utf-8")
        self._send_that(am, monkeypatch, "fails")
        assert am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), "--body", str(body)]) == 1
        assert state.read_text(encoding="utf-8") == '{"flagged": ["old"]}' and pending.exists()
        sidecars = list(outbox.glob("*.state.json"))
        assert len(sidecars) == 1 and sidecars[0].read_text(encoding="utf-8") == '{"flagged": ["new"]}'

    def test_the_mail_app_way_is_covered_too(self, am, monkeypatch, outbox, report, tmp_path, capsys):
        state = tmp_path / "digest_state.json"
        state.write_text('{"flagged": ["before"]}', encoding="utf-8")
        monkeypatch.setattr(am, "send_via_mail_app",
                            lambda *a, **k: (_ for _ in ()).throw(am.MailError("Mail.app refused the message")))
        assert am.main(["--via", "mail-app", "--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), report()]) == 1
        assert state.read_text(encoding="utf-8") == '{"flagged": ["before"]}'
        assert "EMAIL NOT SENT: Mail.app refused the message" in capsys.readouterr().out
        assert len(list(outbox.glob("*.eml"))) == 1

    def test_a_successful_send_keeps_both_copies(self, am, monkeypatch, keychain, outbox, report, tmp_path):
        last, html = tmp_path / "last_run.txt", tmp_path / "last_run.html"
        self._send_that(am, monkeypatch, "works")
        assert am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--save-body", str(last), "--save-html", str(html), report()]) == 0
        assert last.exists() and html.exists() and not outbox.exists()

    def test_a_copy_that_cannot_be_kept_does_not_undo_a_sent_email(self, am, monkeypatch, keychain, outbox, report, tmp_path, capsys):
        self._send_that(am, monkeypatch, "works")
        rc = am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--save-body", str(tmp_path / "nodir" / "last_run.txt"), report()])
        assert rc == 0
        out = capsys.readouterr()
        assert "EMAIL SENT" in out.out and "could not keep a copy" in out.err

    def test_a_memory_that_cannot_be_moved_does_not_undo_a_sent_email(self, am, monkeypatch, keychain, outbox, tmp_path, capsys):
        state = tmp_path / "digest_state.json"
        (tmp_path / "digest_state.json.pending").mkdir()           # a directory cannot replace a file
        state.write_text("{}", encoding="utf-8")
        body = tmp_path / "b.txt"
        body.write_text("TL;DR — x\n  Networks audited : 1 of 1   (l)\n    l  no changes\n", encoding="utf-8")
        self._send_that(am, monkeypatch, "works")
        assert am.main(["--outbox", str(outbox), "send", "--to", "a@b", "--state", str(state), "--body", str(body)]) == 0
        out = capsys.readouterr()
        assert "EMAIL SENT" in out.out and "could not be moved into place" in out.err

    def test_a_notify_that_fails_is_kept_too(self, am, monkeypatch, keychain, outbox, capsys):
        self._send_that(am, monkeypatch, "fails")
        rc = am.main(["--outbox", str(outbox), "notify", "--to", "a@b", "--subject", "[Home Net Audit] AUDIT DID NOT RUN", "--message", "exit 2"])
        assert rc == 1 and "EMAIL NOT SENT" in capsys.readouterr().out
        assert [p.name.endswith("-AUDIT-DID-NOT-RUN.eml") for p in outbox.glob("*.eml")] == [True]

    def test_the_pending_suffix_agrees_with_the_digests(self, am):
        spec = importlib.util.spec_from_file_location("report_digest_am", TOOLS / "report_digest.py")
        dg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dg)
        assert am.PENDING_SUFFIX == dg.PENDING_SUFFIX == ".pending"


class TestOutboxAndResend:
    @pytest.fixture
    def keychain(self, am, monkeypatch):
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=am.KEYCHAIN_SERVICE: ("me@mac.com", "pw"))

    def _spooled(self, am, outbox, subject="[Home Net Audit] 2026-11-01 — run 18 — CHANGES DETECTED", state=None):
        return am.spool(str(outbox), subject, "the body\n", ["a@b"], "me@mac.com", "<html>x</html>", state)

    def test_resend_sends_what_the_outbox_holds_with_a_fresh_stamp_and_the_old_subject(self, am, monkeypatch, keychain, tmp_path, capsys):
        outbox, sent = tmp_path / "outbox", []
        monkeypatch.setattr(am, "send", lambda msg, sender, pw, host, port, retry_wait=None, smtp_class=None: sent.append((msg, sender, host, retry_wait)))
        self._spooled(am, outbox)
        assert am.main(["--outbox", str(outbox), "resend"]) == 0
        msg, sender, host, retry = sent[0]
        assert msg["Subject"] == "[Home Net Audit] 2026-11-01 — run 18 — CHANGES DETECTED" and msg["To"] == "a@b"
        assert msg["Date"] and msg["Message-ID"].endswith("@mac.com>") and sender == "me@mac.com" and retry == 90.0
        assert [p.get_content_type() for p in msg.iter_parts()] == ["text/plain", "text/html"]
        assert list(outbox.glob("*")) == []
        assert "EMAIL RESENT to a@b  (subject: [Home Net Audit] 2026-11-01 — run 18 — CHANGES DETECTED)" in capsys.readouterr().out

    def test_resend_moves_the_memory_the_email_carried(self, am, monkeypatch, keychain, tmp_path, capsys):
        outbox, state = tmp_path / "outbox", tmp_path / "digest_state.json"
        (tmp_path / "digest_state.json.pending").write_text('{"flagged": ["week2"]}', encoding="utf-8")
        monkeypatch.setattr(am, "send", lambda *a, **k: None)
        self._spooled(am, outbox, state=str(state))
        assert am.main(["--outbox", str(outbox), "resend"]) == 0
        assert state.read_text(encoding="utf-8") == '{"flagged": ["week2"]}'
        assert "the memory of that report is now in place" in capsys.readouterr().out

    def test_resend_does_not_overwrite_a_memory_a_later_email_already_moved(self, am, monkeypatch, keychain, tmp_path):
        outbox, state = tmp_path / "outbox", tmp_path / "digest_state.json"
        (tmp_path / "digest_state.json.pending").write_text('{"flagged": ["week2"]}', encoding="utf-8")
        monkeypatch.setattr(am, "send", lambda *a, **k: None)
        path = self._spooled(am, outbox, state=str(state))
        state.write_text('{"flagged": ["week3"]}', encoding="utf-8")   # week 3 went out meanwhile
        later = os.path.getmtime(path + am.SIDECAR_SUFFIX) + 60
        os.utime(state, (later, later))
        assert am.main(["--outbox", str(outbox), "resend"]) == 0
        assert state.read_text(encoding="utf-8") == '{"flagged": ["week3"]}' and list(outbox.glob("*")) == []

    def test_resend_stops_at_the_first_failure_and_leaves_the_rest(self, am, monkeypatch, keychain, tmp_path, capsys):
        outbox = tmp_path / "outbox"
        monkeypatch.setattr(am, "send", lambda *a, **k: (_ for _ in ()).throw(am.MailError("could not send: Network is unreachable")))
        self._spooled(am, outbox, "[Home Net Audit] first")
        self._spooled(am, outbox, "[Home Net Audit] second")
        assert am.main(["--outbox", str(outbox), "resend"]) == 1
        out = capsys.readouterr().out
        assert out.startswith("EMAIL NOT RESENT: could not send: Network is unreachable. 2 message(s) stay in")
        assert len(list(outbox.glob("*.eml"))) == 2

    def test_an_empty_or_absent_outbox_is_silent(self, am, keychain, tmp_path, capsys):
        assert am.main(["--outbox", str(tmp_path / "nothing"), "resend"]) == 0
        (tmp_path / "empty").mkdir()
        assert am.main(["--outbox", str(tmp_path / "empty"), "resend"]) == 0
        assert capsys.readouterr().out == ""

    def test_resend_through_mail_app(self, am, monkeypatch, tmp_path):
        outbox, sent = tmp_path / "outbox", []
        monkeypatch.setattr(am, "send_via_mail_app", lambda subject, body, recipients, sender=None, runner=None: sent.append((subject, body, recipients, sender)))
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=None: pytest.fail("Mail.app needs nothing from the Keychain"))
        am.spool(str(outbox), "[Home Net Audit] s", "plain body\n", ["rstuklis@yahoo.com"], None, None, None)
        assert am.main(["--via", "mail-app", "--from", "robert@stuklis.net", "--outbox", str(outbox), "resend"]) == 0
        assert sent == [("[Home Net Audit] s", "plain body\n", ["rstuklis@yahoo.com"], "robert@stuklis.net")]

    def test_two_spools_in_one_second_do_not_overwrite_each_other(self, am, tmp_path):
        outbox = tmp_path / "outbox"
        a, b = self._spooled(am, outbox), self._spooled(am, outbox)
        assert a != b and len(list(outbox.glob("*.eml"))) == 2

    def test_the_default_outbox_is_in_the_audits_data_folder(self, am, tmp_path):
        assert am.outbox_dir(None, {"HOME_NET_AUDIT_DIR": "/d"}) == "/d/outbox"
        assert am.outbox_dir(None, {}) == str(tmp_path / ".home_net_audit" / "outbox")     # HOME is tmp_path in tests
        assert am.outbox_dir("/given", {"HOME_NET_AUDIT_DIR": "/d"}) == "/given"


# ---------------------------------------------------------------------------
# Round 5. The HTML part stays out of a message Gmail would clip (F8 parity
# with the city Mac's send_report.py), and the plain text goes alone.
# ---------------------------------------------------------------------------

class TestHtmlClipGuard:
    @pytest.fixture
    def wired(self, am, monkeypatch):
        sent = []
        monkeypatch.setattr(am, "keychain_mail_account", lambda service=am.KEYCHAIN_SERVICE: ("me@mac.com", "pw"))
        monkeypatch.setattr(am, "send", lambda msg, sender, pw, host, port, retry_wait=None, smtp_class=None: sent.append(msg))
        return sent

    def test_under_the_limit_text_and_html_go(self, am, wired, report):
        assert am.main(["send", "--to", "a@b", report()]) == 0
        assert [p.get_content_type() for p in wired[0].iter_parts()] == ["text/plain", "text/html"]

    def test_a_html_part_gmail_would_clip_stays_out_and_is_said(self, am, wired, report, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(am, "HTML_MAX_BYTES", 2_000)
        html = tmp_path / "last_run.html"
        assert am.main(["send", "--to", "a@b", "--save-html", str(html), report()]) == 0
        assert wired[0].get_content_type() == "text/plain"
        out = capsys.readouterr().out
        assert "HTML part left out:" in out and "bytes would be clipped by Gmail; the plain text goes alone" in out
        assert html.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")        # the copy on disk is whole

    def test_plain_text_only_on_request(self, am, wired, report, monkeypatch, capsys):
        monkeypatch.setenv("HOME_NET_AUDIT_PLAIN_EMAIL", "1")
        assert am.main(["send", "--to", "a@b", report()]) == 0
        assert wired[0].get_content_type() == "text/plain" and "HOME_NET_AUDIT_PLAIN_EMAIL=1" in capsys.readouterr().out

    def test_the_limit_is_the_one_the_city_mailer_had(self, am):
        assert am.HTML_MAX_BYTES == 100_000
        html, note = am.html_for_message("x" * 100_000, {})
        assert html and note is None
        html, note = am.html_for_message("x" * 100_001, {})
        assert html is None and "100001 bytes" in note


# ---------------------------------------------------------------------------
# The monitor's alerts in the composed email, and the hardenings carried over
# from the owner's draft pull request #41.
# ---------------------------------------------------------------------------

class TestAlertsInTheEmail:
    def test_the_monitor_alerts_reach_the_email_and_its_html(self, am, eh, report, tmp_path, monkeypatch):
        alerts = tmp_path / "alerts.jsonl"
        alerts.write_text(json.dumps({"at": "2026-10-24T22:30:41+00:00", "severity": "HIGH", "kind": "gateway_mac_changed",
                                      "detail": "The gateway's MAC changed from 1a:4b:9f:2b:a2:ab to 38:8b:59:e0:f1:70."}) + "\n")
        monkeypatch.setenv("HOME_NET_AUDIT_ALERT", str(alerts))
        body = am.compose([report()])
        assert "MONITOR ALERTS SINCE THE PREVIOUS REPORT: 1 HIGH" in body
        assert "Flagged items    : 2 (1 HIGH, 1 MEDIUM)" in body
        assert ">HIGH</span>" in eh.render(body) and "gateway_mac_changed" in eh.render(body)

    def test_without_an_alert_file_the_email_says_so(self, am, report):
        assert "MONITOR ALERTS SINCE THE PREVIOUS REPORT: not read — no alert file is configured" in am.compose([report()])


class TestSmallHardenings:
    def test_a_failed_git_status_is_not_up_to_date(self, am):
        def git(cmd, **kw):
            text = " ".join(cmd)
            if "rev-list" in text:
                return subprocess.CompletedProcess(cmd, 0, "0\t0\n", "")
            if "status" in text:
                return subprocess.CompletedProcess(cmd, 128, "", "fatal: not a git repository")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        line = am.version_check("/r", git)
        assert "Up to date" not in line and "could not check for local edits" in line

    def test_an_unwritable_memory_file_keeps_the_facts(self, am, report, tmp_path):
        body = am.compose([report()], state=str(tmp_path / "nodir" / "state.json"))
        assert "Networks audited : 1 of 1   (loveshack-h)" in body
        assert "could not be kept" in body and am.verdict(body) == "no changes"

    def test_a_missing_sibling_tool_is_a_plain_error(self, am, monkeypatch, tmp_path):
        monkeypatch.setattr(am, "HERE", tmp_path)
        with pytest.raises(am.MailError, match="could not load tools/report_email_html.py"):
            am._load("report_email_html")
