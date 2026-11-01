#!/usr/bin/env python3
"""Send the audit email the way the city Mac's reads: one message, the whole
report in it, nothing attached.

Both Macs run the same audit; this makes them send the same email. The
wrapper on each Mac captures the audit's output to a file per network and
hands the files here. This composes the email the city Mac has been sending
since September — a title line, the TL;DR block from tools/report_digest.py,
a version check, then every network's report under its own banner — and
sends it one of two ways:

  --via mail-app   through Mail.app, from the account it already has, by the
                   same AppleScript the beach Mac's wrapper has used all along.
                   No password to store. Mail.app takes the body as plain
                   text, so the email carries the report's text and layout;
                   the coloured cards of the HTML version are kept on disk
                   with --save-html, or come with the other way.
  --via smtp       as text and HTML in one message, through a mail server,
                   from an address whose app-specific password is in the
                   Mac's login keychain (iCloud by default; --smtp and
                   --keychain for another). The arrangement the SMSF
                   screener's weekly email uses.

    audit_mail.py send --via mail-app --from ADDR --to ADDR [--site "beach house"]
                       [--state FILE] [--claude] [--repo DIR] [--save-body FILE]
                       [--save-html FILE] NAME=REPORT.txt ...
    audit_mail.py send --to ADDR [--state FILE] --body FILE    send a body another tool composed
    audit_mail.py notify --to ADDR --subject "…" [--text FILE | --message "…"]
    audit_mail.py resend [--outbox DIR]            send what an earlier failure left in the outbox
    audit_mail.py --test-email [--via mail-app --from ADDR] [--to ADDR]
    audit_mail.py --install                        store an address and app-specific password (smtp)

What a failed send leaves behind. The send is tried twice (--retry-wait apart);
when it still fails the message is kept in the outbox (--outbox, by default
outbox/ in the audit's data folder) for `resend`, one line says so, and the
exit status is 1. The TL;DR's memory of the previous report — written by
tools/report_digest.py as STATE.pending — is moved into place only once the
email has gone, here or by `resend`; a week whose email was lost used to file
its new HIGHs as "standing" the week after. The subject carries the run number
from the report, so a week with no email shows as a gap, and its verdict comes
from the TL;DR's per-network lines, never from a substring of the body: a
network whose audit aborted or could not be joined makes it AUDIT INCOMPLETE.

Stdlib only.
"""

import argparse
import datetime as dt
import email
import email.policy
import email.utils
import getpass
import importlib.util
import os
import re
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEYCHAIN_SERVICE = "home_net_audit-mail"
KEYCHAIN_LABEL = "Home network audit email (iCloud app-specific password)"
NOT_FOUND = 44                  # the security tool's exit code for "item not found"
SECURITY_TIMEOUT = 120.0        # longer than this means a dialog nobody can see
SMTP_HOST, SMTP_PORT = "smtp.mail.me.com", 587
SUBJECT_PREFIX = "[Home Net Audit]"
BANNER = "#" * 64
VERSION_TIMEOUT = 20.0
HTML_MAX_BYTES = 100_000        # Gmail clips a message past about 102 KB; the HTML part stays out above this
PLAIN_ENV = "HOME_NET_AUDIT_PLAIN_EMAIL"
DIR_ENV = "HOME_NET_AUDIT_DIR"  # the audit's data folder, ~/.home_net_audit unless set
PENDING_SUFFIX = ".pending"     # report_digest.py writes its memory as STATE.pending; the send moves it
STATE_HEADER = "X-Home-Net-Audit-State"
SIDECAR_SUFFIX = ".state.json"


class MailError(Exception):
    """Something the person has to put right; printed, never a traceback."""


def _load(name):
    """A sibling tool, loaded by path so this works from any directory."""
    try:
        spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    except Exception as exc:                                    # noqa: BLE001 - a broken checkout
        raise MailError(f"could not load tools/{name}.py beside this script ({exc.__class__.__name__}: "
                        f"{str(exc)[:120]}); is the checkout complete?") from None
    return module


# ---------------------------------------------------------------------------
# The Keychain: the address and the app-specific password
# ---------------------------------------------------------------------------

def _security(*args, timeout=SECURITY_TIMEOUT):
    try:
        return subprocess.run(["security", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise MailError("the Keychain did not answer within two minutes, which usually means the login "
                        "keychain is locked and is showing an unlock dialog nobody can see. In Keychain "
                        'Access, select the login keychain, choose Edit > Change Settings for Keychain '
                        '"login", and turn off "Lock when sleeping" and "Lock after ... minutes of '
                        'inactivity"; then run python3 tools/audit_mail.py --test-email') from None


def _keychain_error(done):
    detail = done.stderr.strip().replace("security: ", "", 1) or f"exit code {done.returncode}"
    return MailError(f"the Keychain could not be read ({detail}). The address and password are probably "
                     "still there, so nothing needs to be re-entered. If the login keychain is set to lock "
                     "when the Mac sleeps, the scheduled run cannot open it: in Keychain Access select the "
                     'login keychain, choose Edit > Change Settings for Keychain "login", and clear "Lock '
                     'when sleeping"; then run python3 tools/audit_mail.py --test-email')


def keychain_mail_account(service=KEYCHAIN_SERVICE):
    """(address, password) from the login keychain; None when nothing is stored
    yet. Any other failure of the security tool is an error in its own words,
    never mistaken for "nothing stored"."""
    attrs = _security("find-generic-password", "-s", service)
    if attrs.returncode == NOT_FOUND:
        return None
    if attrs.returncode != 0:
        raise _keychain_error(attrs)
    m = re.search(r'"acct"<blob>="([^"]*)"', attrs.stdout)
    pw = _security("find-generic-password", "-s", service, "-w")
    if pw.returncode == NOT_FOUND:
        return None
    if pw.returncode != 0:
        raise _keychain_error(pw)
    # An item written by hand or by another tool may carry no account; the
    # password is still the password, and --from supplies the address.
    return (m.group(1) if m else None), pw.stdout.rstrip("\n")


def keychain_forget(service=KEYCHAIN_SERVICE):
    """Remove every item kept under the service (the security tool deletes one
    per call). A generic password is keyed by service AND account, so a
    corrected address would otherwise sit beside the old one. Returns how
    many went."""
    for n in range(20):
        if _security("delete-generic-password", "-s", service).returncode != 0:
            return n
    return 20


def keychain_store(address, password, service=KEYCHAIN_SERVICE):
    """Keep the pair in the login keychain as its only item under the service."""
    keychain_forget(service)
    done = _security("add-generic-password", "-U", "-a", address, "-s", service, "-l", KEYCHAIN_LABEL,
                     "-j", "Used by tools/audit_mail.py to send the audit report", "-w", password)
    if done.returncode != 0:
        raise MailError(f"could not store the password in the Keychain: {done.stderr.strip()}")


# ---------------------------------------------------------------------------
# Composing the body: the city layout
# ---------------------------------------------------------------------------

IP_RE = re.compile(r"^\s*Your Mac's primary IP\s*:\s*(\S+)", re.M)


def banner(text):
    return f"{BANNER}\n# {text}\n{BANNER}"


def parse_spec(spec):
    """'loveshack-h=/path/report.txt' -> (name, path). A bare path takes its
    name from the file's stem."""
    name, sep, path = spec.partition("=")
    if not sep:
        path, name = spec, Path(spec).stem
    name, path = name.strip(), path.strip()
    if not name or not path:
        raise MailError(f"{spec!r} is not NAME=REPORT.txt")
    return name, path


def network_banner(name, path, text):
    when = dt.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%H:%M:%S")
    m = IP_RE.search(text)
    return banner(f"NETWORK: {name} — {when}" + (f"   ip {m.group(1)}" if m else ""))


def version_check(repo, runner=subprocess.run):
    """One line on whether the checkout that ran the audit is current.

    Never a reason for the email not to go: every failure becomes a line that
    says the check could not be made, and why.
    """
    if not repo:
        return None

    def git(*args, timeout=VERSION_TIMEOUT):
        return runner(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=timeout)
    try:
        fetched = git("fetch", "-q", "origin", "master")
        if fetched.returncode != 0:
            return f"Could not fetch origin/master: {fetched.stderr.strip()[:120] or 'git failed'}."
        ahead_behind = git("rev-list", "--left-right", "--count", "HEAD...origin/master")
        if ahead_behind.returncode != 0:
            return f"Could not compare with origin/master: {ahead_behind.stderr.strip()[:120] or 'git failed'}."
        ahead, behind = (int(x) for x in ahead_behind.stdout.split())
        status = git("status", "--porcelain", "--untracked-files=no")
    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return f"Could not check the version ({exc.__class__.__name__}: {str(exc)[:100]})."
    # A status that failed is not a clean one.
    dirty = status.stdout.strip() if status.returncode == 0 else None
    if behind == 0 and ahead == 0 and dirty == "":
        return "Up to date with origin/master."
    parts = []
    if behind:
        parts.append(f"{behind} commit(s) behind origin/master — run the update")
    if ahead:
        parts.append(f"{ahead} commit(s) not on origin/master")
    if dirty:
        parts.append("local edits in the checkout")
    if dirty is None:
        parts.append("could not check for local edits")
    return "; ".join(parts) + "."


def digest_block(reports, state=None, claude=False, skipped=()):
    """The TL;DR block, from tools/report_digest.py, the same code the command
    line runs: the facts, Claude's paragraph when asked for, and the state
    file's marker moved on."""
    try:
        return _load("report_digest").digest([str(p) for p in reports], state, skipped, claude).rstrip("\n")
    except Exception as exc:                                    # noqa: BLE001 - the email still goes
        return f"TL;DR — could not be computed ({exc.__class__.__name__}: {str(exc)[:160]})."


def compose(specs, site=None, title="Home network audit", state=None, claude=False, skipped=(),
            repo=None, now=None, runner=subprocess.run):
    """The plain-text email, in the layout the city Mac has sent since September."""
    now = now or dt.datetime.now().astimezone()
    parts = [banner(f"{title} — {now.strftime('%Y-%m-%d %H:%M:%S %Z')}"), ""]
    reports = []
    for spec in specs:
        name, path = parse_spec(spec)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as exc:
            skipped = list(skipped) + [f"{name}: report unreadable ({exc.strerror or exc})"]
            continue
        reports.append((name, path, text))
    # The digest names each network from the banner above its report, so each
    # report is handed over under its banner, the way the email carries it.
    sections = [(name, network_banner(name, path, text) + "\n" + text.rstrip("\n") + "\n")
                for name, path, text in reports]
    with tempfile.TemporaryDirectory(prefix="audit-mail-") as tmp:
        files = []
        for n, (name, section) in enumerate(sections):
            target = Path(tmp) / f"{n:02d}-{re.sub(r'[^A-Za-z0-9._-]+', '_', name)[:40]}.txt"
            target.write_text(section, encoding="utf-8")
            files.append(target)
        facts = digest_block(files, state, claude, skipped)
    parts += [facts, ""]
    check = version_check(repo, runner)
    if check:
        parts += ["VERSION CHECK", f"  {check}", ""]
    for _name, section in sections:
        parts += [section]
    return "\n".join(parts).rstrip("\n") + "\n"


def network_lines(body):
    """The TL;DR's per-network lines — between "Networks audited" and "Flagged
    items" — or None when the body has no TL;DR. They carry one verdict and
    one run number per network, and nothing a device chose: a device name
    sits in the reports below, and the old city mailer, which tested the
    whole body for a substring, could be made to say CHANGES DETECTED every
    Sunday by a device called that."""
    lines = body.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("TL;DR")), None)
    if start is None:
        return None
    block = []
    for line in lines[start + 1:]:
        if line.strip().startswith("Flagged items") or line.startswith(BANNER):
            break
        block.append(line)
    return "\n".join(block)


def verdict(body):
    """The words for the subject. CHANGES DETECTED when any network changed;
    AUDIT INCOMPLETE when any network was not audited — not joined, aborted,
    its report unreadable or without its closing line — and both when both,
    since an abort is how a change goes unseen; first audit; else no changes."""
    text = network_lines(body)
    if text is None:
        return "report"
    words = []
    if "CHANGES DETECTED" in text:
        words.append("CHANGES DETECTED")
    if "NOT AUDITED" in text or "AUDIT DID NOT COMPLETE" in text:
        words.append("AUDIT INCOMPLETE")
    if "first audit" in text:
        words.append("first audit")
    if words:
        return ", ".join(words)
    return "no changes" if "no changes" in text else "report"


def run_number(body):
    """The run number the TL;DR's first per-network line carries — the home
    network's baseline sequence number — or None when none does. In the
    subject it makes a week whose email never arrived show as a gap."""
    text = network_lines(body)
    m = re.search(r"\brun (\d+)\s*$", text or "", re.M)
    return int(m.group(1)) if m else None


def subject_for(body, site=None, today=None, prefix=SUBJECT_PREFIX):
    today = today or dt.date.today().isoformat()
    parts = [f"{prefix} {today}"]
    if site:
        parts.append(site)
    run = run_number(body)
    if run is not None:
        parts.append(f"run {run}")
    parts.append(verdict(body))
    return " — ".join(parts)


def html_for_message(html, environ=None):
    """The HTML part to send, or None and the reason it stays out: the plain
    text goes alone when asked (HOME_NET_AUDIT_PLAIN_EMAIL=1) or when the HTML
    would be big enough for Gmail to clip the message — the guard the city
    Mac's mailer has always had. The copy kept with --save-html is the full
    rendering either way."""
    environ = os.environ if environ is None else environ
    if html is None:
        return None, None
    if environ.get(PLAIN_ENV) == "1":
        return None, f"HTML part left out: {PLAIN_ENV}=1; the plain text goes alone"
    size = len(html.encode("utf-8"))
    if size > HTML_MAX_BYTES:
        return None, f"HTML part left out: {size} bytes would be clipped by Gmail; the plain text goes alone"
    return html, None


# ---------------------------------------------------------------------------
# The message and the send
# ---------------------------------------------------------------------------

def new_message(sender, recipients, subject):
    """Headed and stamped: a Date is required of every email and a Message-ID
    expected, and filters notice when either is missing."""
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=sender.rpartition("@")[2] or None)
    return msg


def build_message(sender, recipients, body, site=None, today=None, html_renderer=None):
    """Text and HTML of the same report, nothing attached."""
    html_renderer = html_renderer or _load("report_email_html").render
    msg = new_message(sender, recipients, subject_for(body, site, today))
    msg.set_content(body)
    msg.add_alternative(html_renderer(body, site=site), subtype="html")
    return msg


def send(msg, sender, password, host=SMTP_HOST, port=SMTP_PORT, retry_wait=None, smtp_class=None):
    """Send through the mail server. With `retry_wait` set (a scheduled run) a
    failure that is not a refused sign-in is tried once more after the pause,
    since a Mac that has just woken may not have its network back."""
    smtp_class = smtp_class or smtplib.SMTP
    context = ssl.create_default_context()
    for attempt in (1, 2):
        try:
            with smtp_class(host, port, timeout=60) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                smtp.login(sender, password)
                smtp.send_message(msg)
            return
        except smtplib.SMTPAuthenticationError:
            raise MailError(f"{host} refused the sign-in for {sender}. It needs the full email address and an "
                            "app-specific password, not the account password; run "
                            "python3 tools/audit_mail.py --install --reset-mail to store a new pair") from None
        except (smtplib.SMTPException, OSError) as exc:
            if attempt == 1 and retry_wait is not None:
                print(f"could not send through {host}:{port} ({exc}); waiting {retry_wait:.0f} s and "
                      "trying once more", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            hint = (" (a python.org Python needs 'Install Certificates.command' run once from its folder "
                    "in Applications)" if "CERTIFICATE_VERIFY_FAILED" in str(exc) else "")
            raise MailError(f"could not send through {host}:{port}: {exc}{hint}") from None


MAIL_APP_SCRIPT = """\
on run argv
    set bodyPath to item 1 of argv
    set theSubject to item 2 of argv
    set theSender to item 3 of argv
    set theRecipients to items 4 thru -1 of argv
    set theBody to read (POSIX file bodyPath) as «class utf8»
    tell application "Mail"
        set msg to make new outgoing message with properties {subject:theSubject, content:theBody, visible:false}
        if theSender is not "" then set sender of msg to theSender
        repeat with addr in theRecipients
            tell msg to make new to recipient at end of to recipients with properties {address:(addr as text)}
        end repeat
        send msg
    end tell
end run
"""
MAIL_APP_TIMEOUT = 180.0


def send_via_mail_app(subject, body, recipients, sender=None, runner=subprocess.run):
    """Hand the message to Mail.app, which sends it from the account it has.

    The AppleScript the beach Mac's wrapper has always used, minus the
    attachment: Mail.app holds the account, so nothing is stored here. The
    body goes through a file read as UTF-8, not through the argument list,
    which has a size limit a long report would meet. Mail's dictionary takes
    the content as plain text; it cannot be given HTML.
    """
    if not recipients:
        raise MailError("--via mail-app needs at least one --to address")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="audit-mail-", suffix=".txt",
                                     delete=False) as f:
        f.write(body)
        path = f.name
    try:
        try:
            done = runner(["osascript", "-", path, subject, sender or "", *recipients],
                          input=MAIL_APP_SCRIPT, capture_output=True, text=True, timeout=MAIL_APP_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise MailError("Mail.app did not take the message within three minutes; is it waiting on a "
                            "dialog (an account password, or a permission prompt) nobody can see?") from None
        except OSError as exc:
            raise MailError(f"could not run osascript: {exc}") from None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip()[:300] or f"exit code {done.returncode}"
        hint = (" — the program running the audit is not allowed to control Mail.app: on a scheduled run "
                "that is the launcher app, and the grant is made under System Settings > Privacy & "
                "Security > Automation, or by running the wrapper once by hand and allowing the prompt"
                if "Not authorized" in detail or "-1743" in detail else "")
        raise MailError(f"Mail.app refused the message: {detail}{hint}")


def recipients_for(args, sender):
    """--to before or after the subcommand, in the order given; the sender when none."""
    return list(args.to) + list(getattr(args, "sub_to", [])) or ([sender] if sender else [])


def account_for(args):
    """(sender, password) for the smtp way: the Keychain's address unless
    --from names one, which an item stored without an account needs."""
    account = keychain_mail_account(args.keychain)
    if account is None:
        raise MailError(f"no password in the Keychain under {args.keychain!r} yet; run "
                        "python3 tools/audit_mail.py --install first")
    sender = args.from_addr or account[0]
    if not sender:
        raise MailError(f"the Keychain item {args.keychain!r} carries no address; give the sender with --from")
    return sender, account[1]


def write_file(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def deliver(args, subject, body, html=None):
    """Send by whichever way --via names. Returns the recipients."""
    if args.via == "mail-app":
        recipients = recipients_for(args, args.from_addr)
        send_via_mail_app(subject, body, recipients, args.from_addr)
        return recipients
    sender, password = account_for(args)
    recipients = recipients_for(args, sender)
    msg = new_message(sender, recipients, subject)
    msg.set_content(body)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    host, port = host_port(args.smtp)
    send(msg, sender, password, host, port, retry_wait=getattr(args, "retry_wait", None))
    return recipients


def host_port(text):
    host, _, port = text.partition(":")
    try:
        return host or SMTP_HOST, int(port) if port else SMTP_PORT
    except ValueError:
        raise MailError(f"{text!r} is not HOST[:PORT]") from None


# ---------------------------------------------------------------------------
# What a failed send leaves behind: the outbox, and the memory that waits
# ---------------------------------------------------------------------------

def outbox_dir(given=None, environ=None):
    """Where an email that could not be sent waits for `resend`: --outbox,
    else outbox/ in the audit's data folder (HOME_NET_AUDIT_DIR, or
    ~/.home_net_audit)."""
    if given:
        return str(given)
    environ = os.environ if environ is None else environ
    return os.path.join(os.path.expanduser(environ.get(DIR_ENV) or "~/.home_net_audit"), "outbox")


def spool(outbox, subject, body, recipients, sender=None, html=None, state=None):
    """Keep an email that could not be sent as a message file `resend` can
    send later — with the subject and date of the week it is about — and
    beside it a copy of the memory it should move into place when it goes.
    Returns the message file's path."""
    os.makedirs(outbox, exist_ok=True)
    # Headed like the email but not stamped: `resend` gives it the Date and
    # Message-ID of the moment it goes (and a Message-ID with no sender domain
    # would have meant a hostname lookup here).
    msg = EmailMessage()
    msg["From"] = sender or ""
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg.set_content(body)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    if state:
        msg[STATE_HEADER] = state
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", subject).strip("-")[:60] or "message"
    base = os.path.join(outbox, f"{stamp}-{slug}")
    path, n = base + ".eml", 1
    while os.path.exists(path):
        n += 1
        path = f"{base}-{n}.eml"
    with open(path + ".tmp", "wb") as f:
        f.write(msg.as_bytes())
    os.replace(path + ".tmp", path)
    if state:
        try:
            shutil.copyfile(state + PENDING_SUFFIX, path + SIDECAR_SUFFIX)
        except OSError:
            pass                    # no memory waiting to move; nothing to carry
    return path


def commit_memory(state):
    """Move report_digest.py's STATE.pending into place: the email has gone,
    so next week's TL;DR may call its items standing. Returns whether there
    was one. A memory that cannot be moved is a line on stderr, not an undone
    email."""
    if not state:
        return False
    try:
        os.replace(state + PENDING_SUFFIX, state)
    except FileNotFoundError:
        return False
    except OSError as exc:
        print(f"audit_mail: sent, but the memory of this report could not be moved into place "
              f"({exc.strerror or exc})", file=sys.stderr)
        return False
    return True


def promote_sidecar(sidecar, target):
    """The memory an unsent email carried, put in place now that it has gone
    — unless a later email already moved the memory past it, in which case
    this one is history and goes."""
    try:
        if os.path.exists(target) and os.path.getmtime(target) > os.path.getmtime(sidecar):
            os.unlink(sidecar)
            return False
        os.replace(sidecar, target)
    except OSError:
        return False
    return True


def not_sent(args, exc, subject, body, html=None):
    """The send failed after its retry: keep the message for `resend`, say so
    in one line on stdout — where the wrapper's log is — and exit 1. Nothing
    else moves: the memory of the previous report stays where it was."""
    recipients = recipients_for(args, args.from_addr)
    try:
        path = spool(outbox_dir(args.outbox), subject, body, recipients, args.from_addr, html,
                     getattr(args, "state", None))
    except OSError as e:
        print(f"EMAIL NOT SENT: {exc}. It could not be kept for a resend either ({e.strerror or e}).")
        return 1
    print(f"EMAIL NOT SENT: {exc}. Kept at {path}; python3 tools/audit_mail.py … resend sends it once "
          "the Mac can.")
    return 1


def keep_copies(args, body, html):
    """--save-body and --save-html, written once the email has gone, so the
    copy on disk is of the email that was sent. One that cannot be kept is a
    line on stderr, not an undone email."""
    try:
        if args.save_body:
            write_file(args.save_body, body)
        if args.save_html:
            write_file(args.save_html, html)
    except OSError as exc:
        print(f"audit_mail: sent, but could not keep a copy: {exc.strerror or exc} ({exc.filename})",
              file=sys.stderr)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def do_install(args):
    interactive = sys.stdin.isatty()
    account = None if args.reset_mail else keychain_mail_account(args.keychain)
    if account is None:
        if not interactive:
            raise MailError("run --install in Terminal the first time: it needs to ask for the email "
                            "address and the app-specific password")
        print("The report is sent from your iCloud account. Two things are needed; the password is kept "
              "in this Mac's Keychain, never in a file.")
        address = input("  1. Your iCloud email address (the @icloud.com, @me.com or @mac.com one; a Hide My "
                        "Email address cannot send): ").strip()
        if "@" not in address:
            raise MailError(f"{address!r} is not an email address")
        print("  2. An app-specific password. Make one at account.apple.com: Sign-In and Security, "
              "App-Specific Passwords, then the plus sign; call it Home network audit.")
        password = getpass.getpass("     Paste it here (it is not shown as you type): ").strip()
        if not password:
            raise MailError("no password was entered")
        keychain_store(address, password, args.keychain)
        print("  Stored in the Keychain.")
    else:
        print(f"Using the Keychain item already there ({account[0] or 'no address; give one with --from'}); "
              "--reset-mail to change it.")
    print("Now send yourself a test: python3 tools/audit_mail.py --test-email")
    return 0


def do_test_email(args):
    way = "Mail.app" if args.via == "mail-app" else "the mail server"
    text = (f"This is a test from the home network audit on {socket.gethostname()}, sent "
            f"{dt.datetime.now():%Y-%m-%d %H:%M} through {way}. If you can read this, the weekly "
            "report is sent the same way.")
    recipients = deliver(args, f"{SUBJECT_PREFIX} test email", text)
    print(f"Test email sent to {', '.join(recipients)}.")
    return 0


def do_send(args):
    if args.body:
        try:
            with open(args.body, encoding="utf-8", errors="replace") as f:
                body = f.read()
        except OSError as exc:
            raise MailError(f"could not read --body {args.body}: {exc.strerror or exc}") from None
    else:
        if not args.reports:
            raise MailError("give the reports as NAME=REPORT.txt, or an assembled body with --body FILE")
        body = compose(args.reports, site=args.site, title=args.title, state=args.state,
                       claude=args.claude, skipped=args.skipped, repo=args.repo)
    html = _load("report_email_html").render(body, site=args.site)
    sent_html, note = html_for_message(html)
    if note:
        print(note)
    subject = subject_for(body, args.site)
    try:
        recipients = deliver(args, subject, body, sent_html)
    except MailError as exc:
        return not_sent(args, exc, subject, body, sent_html)
    commit_memory(args.state)
    keep_copies(args, body, html)
    print(f"EMAIL SENT to {', '.join(recipients)}  (subject: {subject})")
    return 0


def do_notify(args):
    """A plain note — the wrapper's 'the audit did not run' message."""
    text = args.message or ""
    if args.text:
        try:
            with open(args.text, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError as exc:
            lines = [f"(the log {args.text} could not be read: {exc.strerror or exc})"]
        text += ("\n\n" if text else "") + "\n".join(lines[-args.tail:])
    text = text or "(no message)"
    try:
        recipients = deliver(args, args.subject, text)
    except MailError as exc:
        return not_sent(args, exc, args.subject, text)
    print(f"EMAIL SENT to {', '.join(recipients)}  (subject: {args.subject})")
    return 0


def do_resend(args):
    """Send what the outbox holds, oldest first, each with a fresh Date and
    Message-ID under its own subject; move the memory an email carried into
    place once it has gone. The first failure stops the pass — the network is
    still down — and leaves the rest for next time. An empty outbox is silent,
    so this can run on a schedule."""
    outbox = outbox_dir(args.outbox)
    files = sorted(Path(outbox).glob("*.eml")) if os.path.isdir(outbox) else []
    for path in files:
        try:
            with open(path, "rb") as f:
                msg = email.message_from_bytes(f.read(), policy=email.policy.default)
        except OSError as exc:
            raise MailError(f"could not read {path}: {exc.strerror or exc}") from None
        subject = msg["Subject"] or "(no subject)"
        recipients = [a.strip() for a in (msg["To"] or "").split(",") if a.strip()]
        plain = msg.get_body(preferencelist=("plain",))
        body = plain.get_content() if plain is not None else ""
        html_part = msg.get_body(preferencelist=("html",))
        html = html_part.get_content() if html_part is not None else None
        try:
            if args.via == "mail-app":
                recipients = recipients or recipients_for(args, args.from_addr)
                send_via_mail_app(subject, body, recipients, args.from_addr)
            else:
                sender, password = account_for(args)
                recipients = recipients or [sender]
                fresh = new_message(sender, recipients, subject)
                fresh.set_content(body)
                if html is not None:
                    fresh.add_alternative(html, subtype="html")
                host, port = host_port(args.smtp)
                send(fresh, sender, password, host, port, retry_wait=args.retry_wait)
        except MailError as exc:
            left = len(files) - files.index(path)
            print(f"EMAIL NOT RESENT: {exc}. {left} message(s) stay in {outbox}.")
            return 1
        sidecar, target = str(path) + SIDECAR_SUFFIX, msg[STATE_HEADER]
        moved = promote_sidecar(sidecar, target) if target and os.path.exists(sidecar) else False
        try:
            os.unlink(path)
        except OSError:
            pass
        print(f"EMAIL RESENT to {', '.join(recipients)}  (subject: {subject})"
              + ("; the memory of that report is now in place" if moved else ""))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(description="Send the audit report as the city-style email.")
    ap.add_argument("--keychain", default=KEYCHAIN_SERVICE, metavar="SERVICE",
                    help="Keychain service holding the address and app-specific password")
    ap.add_argument("--smtp", default=f"{SMTP_HOST}:{SMTP_PORT}", metavar="HOST[:PORT]",
                    help="mail server (STARTTLS); iCloud by default")
    ap.add_argument("--via", choices=("smtp", "mail-app"), default="smtp",
                    help="smtp: text and HTML through a mail server, password from the Keychain; "
                         "mail-app: plain text through Mail.app's own account, nothing stored")
    ap.add_argument("--from", dest="from_addr", metavar="ADDR",
                    help="the sending address: Mail.app's account to send from, or the address for "
                         "a Keychain item stored without one")
    ap.add_argument("--install", action="store_true", help="store the sending address and password")
    ap.add_argument("--reset-mail", action="store_true", help="with --install: ask again")
    ap.add_argument("--forget-mail", action="store_true", help="remove the stored pair")
    ap.add_argument("--test-email", action="store_true", help="send a one-line test")
    ap.add_argument("--to", action="append", default=[], metavar="ADDR",
                    help="recipient (repeatable); the sender itself when omitted")
    ap.add_argument("--outbox", metavar="DIR",
                    help=f"where an email that could not be sent waits for `resend` (default: outbox/ in "
                         f"{DIR_ENV} or ~/.home_net_audit)")
    sub = ap.add_subparsers(dest="command")

    s = sub.add_parser("send", help="compose and send the report")
    s.add_argument("--to", dest="sub_to", action="append", default=[], metavar="ADDR")
    s.add_argument("--site", help='named in the subject and heading, e.g. "beach house"')
    s.add_argument("--title", default="Home network audit")
    s.add_argument("--state", metavar="FILE",
                   help="report_digest.py's memory of the previous report; its FILE.pending is moved into "
                        "place once the email has gone (with --body too)")
    s.add_argument("--claude", action="store_true", help="add Claude's paragraph to the TL;DR")
    s.add_argument("--skipped", action="append", default=[], metavar="NET: REASON")
    s.add_argument("--repo", metavar="DIR", help="checkout to version-check against origin/master")
    s.add_argument("--body", metavar="FILE", help="send this assembled text instead of composing one")
    s.add_argument("--save-body", metavar="FILE", help="keep the composed text here (last_run.txt)")
    s.add_argument("--save-html", metavar="FILE", help="keep the HTML rendering here, to open in a browser")
    s.add_argument("--retry-wait", type=float, default=90.0, metavar="SECONDS",
                   help="wait and try once more on a network failure (0 to never)")
    s.add_argument("reports", nargs="*", metavar="NAME=REPORT.txt")

    n = sub.add_parser("notify", help="send a plain note, e.g. that the audit did not run")
    n.add_argument("--to", dest="sub_to", action="append", default=[], metavar="ADDR")
    n.add_argument("--subject", required=True)
    n.add_argument("--message", help="the note")
    n.add_argument("--text", metavar="FILE", help="append the last lines of this file")
    n.add_argument("--tail", type=int, default=60, help="how many lines of --text (default 60)")
    n.add_argument("--retry-wait", type=float, default=90.0, metavar="SECONDS")

    r = sub.add_parser("resend", help="send the emails an earlier failure left in the outbox")
    r.add_argument("--retry-wait", type=float, default=90.0, metavar="SECONDS")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if hasattr(args, "retry_wait") and args.retry_wait is not None and args.retry_wait <= 0:
        args.retry_wait = None
    try:
        if args.forget_mail:
            print(f"Removed {keychain_forget(args.keychain)} stored item(s).")
            return 0
        if args.install:
            return do_install(args)
        if args.test_email:
            return do_test_email(args)
        if args.command == "send":
            return do_send(args)
        if args.command == "notify":
            return do_notify(args)
        if args.command == "resend":
            return do_resend(args)
        build_parser().print_help()
        return 2
    except MailError as exc:
        print(f"audit_mail: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
