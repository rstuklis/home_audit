"""Sharing-services surface: `_launchd_running` and `check_sharing_services`.

These two functions decide whether the audit tells the user "SSH is off" or
"SSH is on". Every defect here is a security-relevant *lie*, so the tests are
weighted towards the two failure directions that matter:

  * a false OFF  - the audit says a listener is disabled when it is not, or when
    it simply could not tell (must be reported as UNKNOWN / None instead), and
  * a misread launchd state - `state = not running` read as running.

Three historical bugs from commit 4c349fd are pinned by name below.
"""

import subprocess

import pytest

from conftest import make_check_port, make_run, make_subprocess_run

SSHD = "com.openssh.sshd"
SCREENSHARING = "com.apple.screensharing"
SMBD = "com.apple.smbd"

PRINT_DISABLED = "launchctl print-disabled system"
SYSTEMSETUP_RAE = "systemsetup -getremoteappleevents"

# `systemsetup` prints this to *stdout* and exits 0 when run without admin
# rights. Reading it as a value is the false-OFF bug fixed in 4c349fd.
NEEDS_ADMIN = "You need administrator access to run this tool... exiting!\n"

EXPECTED_SERVICE_NAMES = [
    "Remote Login (SSH)",
    "Screen Sharing / VNC",
    "File Sharing (SMB)",
    "Remote Apple Events",
    "mDNS / Bonjour",
]


def _print_dump(label, state):
    """A minimal-but-shaped `launchctl print system/<label>` body.

    Used for the state-value table; the full captured dumps live in
    tests/fixtures/launchctl_print_*.out.
    """
    return (
        f"system/{label} = {{\n"
        f"\tactive count = 0\n"
        f"\tpath = /System/Library/LaunchDaemons/{label}.plist\n"
        f"\ttype = LaunchDaemon\n"
        f"\tstate = {state}\n"
        f"\tdomain = system\n"
        f"}}\n"
    )


def _recording_check_port(open_ports=()):
    """make_check_port, plus a record of every (host, port) probed."""
    inner = make_check_port(open_ports)
    calls = []

    def _check_port(host, port, timeout=0.6):
        calls.append((host, port))
        return inner(host, port, timeout)

    _check_port.calls = calls
    return _check_port


def _patch_sharing(monkeypatch, mod, launchd=None, print_disabled=None,
                   systemsetup="", open_ports=()):
    """Patch the three system-call choke points check_sharing_services uses.

    `launchd` maps a launchd label to the stdout (or (returncode, stdout)) of
    `launchctl print system/<label>`; an absent label defaults to returncode 1,
    which is what the real launchctl does for a label that is not loaded.
    """
    mapping = {}
    for label, out in (launchd or {}).items():
        mapping["launchctl print system/" + label] = out
    if print_disabled is not None:
        mapping[PRINT_DISABLED] = print_disabled

    fake_subprocess = make_subprocess_run(mapping)
    fake_run = make_run({SYSTEMSETUP_RAE: systemsetup})
    fake_check_port = _recording_check_port(open_ports)

    monkeypatch.setattr(subprocess, "run", fake_subprocess)
    monkeypatch.setattr(mod, "run", fake_run)
    monkeypatch.setattr(mod, "check_port", fake_check_port)
    return fake_subprocess, fake_run, fake_check_port


def _by_name(services, name):
    matches = [s for s in services if s["name"] == name]
    assert len(matches) == 1, f"expected exactly one {name!r}, got {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# _launchd_running
# ---------------------------------------------------------------------------

class TestLaunchdRunning:
    def test_state_running_reports_true(self, mod, monkeypatch, fixture):
        monkeypatch.setattr(subprocess, "run", make_subprocess_run(
            {"launchctl print system/" + SSHD: fixture("launchctl_print_sshd_running.out")}))
        assert mod._launchd_running(SSHD) is True

    def test_state_not_running_reports_false(self, mod, monkeypatch, fixture):
        """Regression, commit 4c349fd (home_net_audit.py:1402).

        The pre-fix check was a loose substring test, so 'state = not running'
        contained 'running' and a stopped daemon was reported as an enabled
        listener. The value after 'state =' must be compared exactly.
        """
        dump = fixture("launchctl_print_sshd_not_running.out")
        assert "not running" in dump, "fixture must carry the substring trap"
        monkeypatch.setattr(subprocess, "run", make_subprocess_run(
            {"launchctl print system/" + SSHD: dump}))
        assert mod._launchd_running(SSHD) is False

    @pytest.mark.parametrize("state, expected", [
        ("running", True),
        ("not running", False),
        ("waiting for initial exec", False),
        ("spawn scheduled", False),
    ], ids=["running", "not-running", "waiting", "spawn-scheduled"])
    def test_state_value_is_matched_exactly(self, mod, monkeypatch, state, expected):
        monkeypatch.setattr(subprocess, "run", make_subprocess_run(
            {"launchctl print system/" + SMBD: _print_dump(SMBD, state)}))
        assert mod._launchd_running(SMBD) is expected

    def test_unloaded_label_reports_false(self, mod, monkeypatch):
        # Real launchctl exits non-zero with "Could not find service ... in
        # domain for system" on stderr and nothing on stdout.
        monkeypatch.setattr(subprocess, "run", make_subprocess_run(
            {"launchctl print system/" + SCREENSHARING: (113, "")}))
        assert mod._launchd_running(SCREENSHARING) is False

    def test_nonzero_exit_wins_over_stale_stdout(self, mod, monkeypatch, fixture):
        # A failed print must not be believed even if stdout happens to carry a
        # 'state = running' line; the exit code is checked first.
        monkeypatch.setattr(subprocess, "run", make_subprocess_run(
            {"launchctl print system/" + SSHD:
                (113, fixture("launchctl_print_sshd_running.out"))}))
        assert mod._launchd_running(SSHD) is False

    def test_output_without_a_state_line_reports_false(self, mod, monkeypatch):
        # Defensive: a successful print whose body has no 'state =' key at all.
        no_state = (
            "system/com.apple.smbd = {\n"
            "\tpath = /System/Library/LaunchDaemons/com.apple.smbd.plist\n"
            "\ttype = LaunchDaemon\n"
            "\tdomain = system\n"
            "}\n"
        )
        monkeypatch.setattr(subprocess, "run", make_subprocess_run(
            {"launchctl print system/" + SMBD: no_state}))
        assert mod._launchd_running(SMBD) is False

    def test_timeout_reports_unknown_not_off(self, mod, monkeypatch):
        def _timeout(cmd, *args, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 5)

        monkeypatch.setattr(subprocess, "run", _timeout)
        assert mod._launchd_running(SSHD) is None

    def test_oserror_reports_unknown_not_off(self, mod, monkeypatch):
        def _missing_binary(cmd, *args, **kwargs):
            raise FileNotFoundError(2, "No such file or directory: 'launchctl'")

        monkeypatch.setattr(subprocess, "run", _missing_binary)
        assert mod._launchd_running(SSHD) is None

    def test_unknown_and_off_are_distinct_values(self, mod, monkeypatch):
        """None ('could not determine') must never collapse into False ('off').

        Callers branch on `is True` / `is None`, so returning a falsey stand-in
        for an error would silently downgrade an undeterminable service to OFF.
        """
        monkeypatch.setattr(subprocess, "run", make_subprocess_run(
            {"launchctl print system/" + SSHD: (113, "")}))
        off = mod._launchd_running(SSHD)

        def _timeout(cmd, *args, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 5)

        monkeypatch.setattr(subprocess, "run", _timeout)
        unknown = mod._launchd_running(SSHD)

        assert off is False
        assert unknown is None
        assert unknown is not off

    def test_probes_the_system_domain_with_print_not_list(self, mod, monkeypatch, fixture):
        """Regression, commit 4c349fd (home_net_audit.py:1393).

        `launchctl list <label>` fails for system-domain daemons when run
        unprivileged, so an unprivileged audit reported every daemon as off.
        The replacement is `launchctl print system/<label>`.
        """
        fake = make_subprocess_run(
            {"launchctl print system/" + SSHD: fixture("launchctl_print_sshd_running.out")})
        monkeypatch.setattr(subprocess, "run", fake)
        mod._launchd_running(SSHD)
        assert fake.calls == ["launchctl print system/com.openssh.sshd"]

    def test_output_is_captured_as_bounded_text(self, mod, monkeypatch):
        # text=True is load-bearing: bytes stdout would blow up on the
        # str-prefixed 'state =' scan. The timeout stops one wedged daemon from
        # hanging the whole audit.
        seen = {}

        def _record(cmd, *args, **kwargs):
            seen["cmd"] = cmd
            seen.update(kwargs)
            return subprocess.CompletedProcess(cmd, 0, stdout="\tstate = running\n", stderr="")

        monkeypatch.setattr(subprocess, "run", _record)
        assert mod._launchd_running(SMBD) is True
        assert seen["cmd"] == ["launchctl", "print", "system/com.apple.smbd"]
        assert seen.get("text") is True
        assert seen.get("capture_output") is True
        assert 0 < seen.get("timeout", 0) <= 10


# ---------------------------------------------------------------------------
# check_sharing_services - Remote Login (SSH)
# ---------------------------------------------------------------------------

class TestSharingServicesSSH:
    def test_launchd_running_reports_enabled_for_review(self, mod, monkeypatch, fixture):
        _patch_sharing(monkeypatch, mod,
                       launchd={SSHD: fixture("launchctl_print_sshd_running.out")})
        ssh = _by_name(mod.check_sharing_services(), "Remote Login (SSH)")
        assert ssh["enabled"] is True
        assert ssh["risk"] == "REVIEW"

    def test_launchd_off_and_port_closed_reports_disabled(self, mod, monkeypatch, fixture):
        _patch_sharing(monkeypatch, mod,
                       launchd={SSHD: fixture("launchctl_print_sshd_not_running.out")},
                       open_ports=[])
        ssh = _by_name(mod.check_sharing_services(), "Remote Login (SSH)")
        assert ssh["enabled"] is False
        assert ssh["risk"] == "OK"

    def test_open_port_22_enables_ssh_when_launchd_says_off(self, mod, monkeypatch, fixture):
        # The listener half of the OR: something is answering on 22 even though
        # launchd reports the Apple daemon stopped (e.g. a third-party sshd).
        _patch_sharing(monkeypatch, mod,
                       launchd={SSHD: fixture("launchctl_print_sshd_not_running.out")},
                       open_ports=[22])
        ssh = _by_name(mod.check_sharing_services(), "Remote Login (SSH)")
        assert ssh["enabled"] is True
        assert ssh["risk"] == "REVIEW"

    def test_launchd_running_enables_ssh_when_port_probe_finds_nothing(self, mod, monkeypatch, fixture):
        # The launchd half of the OR, with the port probe returning False.
        _patch_sharing(monkeypatch, mod,
                       launchd={SSHD: fixture("launchctl_print_sshd_running.out")},
                       open_ports=[])
        ssh = _by_name(mod.check_sharing_services(), "Remote Login (SSH)")
        assert ssh["enabled"] is True

    def test_unloaded_sshd_with_open_port_still_enables_ssh(self, mod, monkeypatch):
        # No launchd mapping at all -> `launchctl print` exits non-zero, the
        # same as a label that was never loaded.
        _patch_sharing(monkeypatch, mod, open_ports=[22])
        ssh = _by_name(mod.check_sharing_services(), "Remote Login (SSH)")
        assert ssh["enabled"] is True

    def test_enabled_flag_is_a_real_bool_not_a_launchctl_string(self, mod, monkeypatch, fixture):
        # action_sharing_services renders `s["enabled"] is None` as '?', so the
        # flag has to be True/False/None and never a truthy string.
        _patch_sharing(monkeypatch, mod,
                       launchd={SSHD: fixture("launchctl_print_sshd_running.out")})
        ssh = _by_name(mod.check_sharing_services(), "Remote Login (SSH)")
        assert isinstance(ssh["enabled"], bool)


# ---------------------------------------------------------------------------
# check_sharing_services - Screen Sharing / VNC
# ---------------------------------------------------------------------------

class TestSharingServicesScreenSharing:
    def test_running_screensharingd_is_high_risk(self, mod, monkeypatch, fixture):
        _patch_sharing(monkeypatch, mod,
                       launchd={SCREENSHARING: fixture("launchctl_print_screensharing_running.out")})
        vnc = _by_name(mod.check_sharing_services(), "Screen Sharing / VNC")
        assert vnc["enabled"] is True
        assert vnc["risk"] == "HIGH"

    def test_absent_label_and_closed_port_is_ok(self, mod, monkeypatch):
        _patch_sharing(monkeypatch, mod, open_ports=[])
        vnc = _by_name(mod.check_sharing_services(), "Screen Sharing / VNC")
        assert vnc["enabled"] is False
        assert vnc["risk"] == "OK"

    def test_open_port_5900_enables_screen_sharing(self, mod, monkeypatch):
        # A third-party VNC server holds 5900 without com.apple.screensharing
        # ever being loaded; that is still a remote-control surface.
        _patch_sharing(monkeypatch, mod, open_ports=[5900])
        vnc = _by_name(mod.check_sharing_services(), "Screen Sharing / VNC")
        assert vnc["enabled"] is True
        assert vnc["risk"] == "HIGH"

    def test_ssh_listener_does_not_leak_into_screen_sharing(self, mod, monkeypatch):
        # Guards against the two loopback probes sharing a port constant.
        _patch_sharing(monkeypatch, mod, open_ports=[22])
        services = mod.check_sharing_services()
        assert _by_name(services, "Remote Login (SSH)")["enabled"] is True
        assert _by_name(services, "Screen Sharing / VNC")["enabled"] is False


# ---------------------------------------------------------------------------
# check_sharing_services - File Sharing (SMB)
# ---------------------------------------------------------------------------

class TestSharingServicesSMB:
    def test_print_disabled_enabled_flag_is_authoritative(self, mod, monkeypatch, fixture):
        # smbd is launch-on-demand: with File Sharing on but idle it is neither
        # running nor listening in-process, so the config flag must win.
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: fixture("launchctl_print_smbd_not_running.out")},
                       print_disabled=fixture("launchctl_print_disabled_smb_enabled.out"),
                       open_ports=[])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is True
        assert smb["risk"] == "REVIEW"

    def test_word_dialect_disabled_flag_with_no_listener_reports_disabled(
            self, mod, monkeypatch, fixture):
        # '"com.apple.smbd" => disabled' inside the *disabled services* dict
        # means smbd really is disabled, and nothing is listening, so OFF is the
        # truthful answer. This is the arm home_net_audit.py:1444 gets right.
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: fixture("launchctl_print_smbd_not_running.out")},
                       print_disabled=fixture("launchctl_print_disabled_smb_disabled.out"),
                       open_ports=[])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is False
        assert smb["risk"] == "OK"

    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "home_net_audit.py:1444 computes smb_cfg = (m.group(1) == 'enabled') over the "
        "output of `launchctl print-disabled system`, which is a dict of DISABLED "
        "services. In the boolean dialect of that dict '=> false' means 'NOT disabled', "
        "i.e. File Sharing is ON, yet the comparison yields False. Line 1447's "
        "`smb_on = bool(smb_cfg) or ...` cannot rescue it: smbd is launch-on-demand, so an "
        "idle Mac that is genuinely sharing shows 'state = not running' and a closed port "
        "445, and the audit prints a confident false OFF (risk OK, note 'Disabled.'). "
        "The inversion is confined to the boolean dialect: '=> true' and '=> disabled' "
        "both correctly yield off, '=> enabled' correctly yields on, and only '=> false' "
        "-- the one token that means ON -- is read backwards. A maintainer who establishes "
        "that '=> false' is unreachable on every supported macOS version may therefore "
        "delete this marker with that justification rather than by changing line 1444."))
    def test_boolean_dialect_false_means_not_disabled_so_smb_is_on(
            self, mod, monkeypatch, fixture):
        """`"com.apple.smbd" => false` in the disabled-services dict means SMB is ON.

        The four tokens that appear across launchctl dialects map like this:

            "=> true"     -> listed as disabled     -> SMB off
            "=> disabled" -> listed as disabled     -> SMB off
            "=> enabled"  -> listed as NOT disabled -> SMB on
            "=> false"    -> listed as NOT disabled -> SMB on   <-- read backwards

        launchd not-running and port 445 closed is the *normal* state of an
        enabled-but-idle launch-on-demand smbd, so the config flag is the only
        signal that can tell the truth here, and it is inverted.
        """
        dump = fixture("launchctl_print_disabled_legacy_bools.out")
        assert '"com.apple.smbd" => false' in dump, "fixture must carry the boolean dialect"
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: fixture("launchctl_print_smbd_not_running.out")},
                       print_disabled=dump,
                       open_ports=[])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is True
        assert smb["risk"] == "REVIEW"

    def test_boolean_dialect_true_means_disabled_so_smb_is_off(self, mod, monkeypatch, fixture):
        # The other half of the boolean dialect, and the guard against an
        # over-broad repair of line 1444: rewriting the test as
        # `m.group(1) != "disabled"` would satisfy the '=> false' case above
        # while turning '=> true' (genuinely disabled) into a false ON.
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: fixture("launchctl_print_smbd_not_running.out")},
                       print_disabled='disabled services = {\n\t"com.apple.smbd" => true\n}\n',
                       open_ports=[])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is False
        assert smb["risk"] == "OK"

    def test_open_port_445_overrides_a_disabled_flag(self, mod, monkeypatch, fixture):
        # Config says off but something is serving SMB right now - believe the
        # wire, not the plist.
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: fixture("launchctl_print_smbd_not_running.out")},
                       print_disabled=fixture("launchctl_print_disabled_smb_disabled.out"),
                       open_ports=[445])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is True

    def test_running_smbd_enables_smb_when_flag_is_absent(self, mod, monkeypatch):
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: _print_dump(SMBD, "running")},
                       print_disabled=None,
                       open_ports=[])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is True

    def test_print_disabled_without_an_smbd_entry_falls_back_to_live_state(
            self, mod, monkeypatch, fixture):
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: _print_dump(SMBD, "running")},
                       print_disabled=fixture("launchctl_print_disabled_no_smbd.out"),
                       open_ports=[])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is True

    def test_all_signals_negative_reports_disabled(self, mod, monkeypatch, fixture):
        _patch_sharing(monkeypatch, mod,
                       launchd={SMBD: fixture("launchctl_print_smbd_not_running.out")},
                       print_disabled=fixture("launchctl_print_disabled_no_smbd.out"),
                       open_ports=[])
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is False

    @pytest.mark.parametrize("failure", [
        lambda cmd: subprocess.TimeoutExpired(cmd, 5),
        lambda cmd: FileNotFoundError(2, "No such file or directory: 'launchctl'"),
    ], ids=["timeout", "missing-binary"])
    def test_print_disabled_failure_does_not_abort_the_check(self, mod, monkeypatch, failure):
        # Both arms of the except clause at home_net_audit.py:1445: a wedged
        # `launchctl print-disabled` (TimeoutExpired) and a launchctl that is not
        # there at all (FileNotFoundError, an OSError - what happens off macOS).
        # Either way the check must degrade to the live listener probe rather
        # than propagate out of check_sharing_services.
        def _fail(cmd, *args, **kwargs):
            raise failure(cmd)

        monkeypatch.setattr(subprocess, "run", _fail)
        monkeypatch.setattr(mod, "run", make_run({SYSTEMSETUP_RAE: "Remote Apple Events: Off"}))
        monkeypatch.setattr(mod, "check_port", make_check_port([445]))
        smb = _by_name(mod.check_sharing_services(), "File Sharing (SMB)")
        assert smb["enabled"] is True

    def test_smb_flag_is_read_from_print_disabled_not_launchctl_list(
            self, mod, monkeypatch, fixture):
        """Regression, commit 4c349fd (home_net_audit.py:1440).

        The old code shelled out to `launchctl list com.apple.smbd`, which an
        unprivileged user cannot use on system-domain daemons.
        """
        fake_subprocess, _, _ = _patch_sharing(
            monkeypatch, mod,
            print_disabled=fixture("launchctl_print_disabled_smb_enabled.out"))
        mod.check_sharing_services()
        assert PRINT_DISABLED in fake_subprocess.calls
        assert not [c for c in fake_subprocess.calls if c.startswith("launchctl list")]


# ---------------------------------------------------------------------------
# check_sharing_services - Remote Apple Events
# ---------------------------------------------------------------------------

class TestSharingServicesRemoteAppleEvents:
    def test_admin_access_message_reports_unknown_not_off(self, mod, monkeypatch):
        """Regression, commit 4c349fd (home_net_audit.py:1459).

        `systemsetup -getremoteappleevents` needs admin rights and otherwise
        prints an admin-access notice on stdout with EXIT CODE 0. The old code
        parsed that as a value and reported a confident, false OFF.
        """
        _patch_sharing(monkeypatch, mod, systemsetup=NEEDS_ADMIN)
        rae = _by_name(mod.check_sharing_services(), "Remote Apple Events")
        assert rae["enabled"] is None
        assert rae["risk"] == "UNKNOWN"
        assert "sudo" in rae["note"]

    @pytest.mark.parametrize("output", ["", "\n", "   \n\t\n"],
                             ids=["empty", "newline-only", "whitespace-only"])
    def test_empty_systemsetup_output_reports_unknown(self, mod, monkeypatch, output):
        # run() returns "" when the binary is missing or the call timed out;
        # "no answer" is not the same as "off".
        _patch_sharing(monkeypatch, mod, systemsetup=output)
        rae = _by_name(mod.check_sharing_services(), "Remote Apple Events")
        assert rae["enabled"] is None
        assert rae["risk"] == "UNKNOWN"

    def test_remote_apple_events_on_reports_enabled_for_review(self, mod, monkeypatch):
        _patch_sharing(monkeypatch, mod, systemsetup="Remote Apple Events: On\n")
        rae = _by_name(mod.check_sharing_services(), "Remote Apple Events")
        assert rae["enabled"] is True
        assert rae["risk"] == "REVIEW"

    def test_remote_apple_events_off_reports_disabled(self, mod, monkeypatch):
        _patch_sharing(monkeypatch, mod, systemsetup="Remote Apple Events: Off\n")
        rae = _by_name(mod.check_sharing_services(), "Remote Apple Events")
        assert rae["enabled"] is False
        assert rae["risk"] == "OK"

    def test_unknown_is_not_reported_as_off(self, mod, monkeypatch):
        # The whole point of the tri-state: the admin-blocked answer and the
        # genuine Off answer must not produce the same row.
        _patch_sharing(monkeypatch, mod, systemsetup=NEEDS_ADMIN)
        blocked = _by_name(mod.check_sharing_services(), "Remote Apple Events")
        _patch_sharing(monkeypatch, mod, systemsetup="Remote Apple Events: Off\n")
        genuinely_off = _by_name(mod.check_sharing_services(), "Remote Apple Events")
        assert blocked["enabled"] is not genuinely_off["enabled"]
        assert blocked["risk"] != genuinely_off["risk"]

    def test_state_is_read_from_systemsetup(self, mod, monkeypatch):
        _, fake_run, _ = _patch_sharing(monkeypatch, mod,
                                        systemsetup="Remote Apple Events: On\n")
        mod.check_sharing_services()
        assert SYSTEMSETUP_RAE in fake_run.calls


# ---------------------------------------------------------------------------
# check_sharing_services - shape of the whole report
# ---------------------------------------------------------------------------

class TestSharingServicesReportShape:
    ALL_OFF = dict(launchd=None, print_disabled=None, systemsetup="Remote Apple Events: Off\n",
                   open_ports=[])
    ALL_ON = dict(launchd=None, print_disabled=None, systemsetup="Remote Apple Events: On\n",
                  open_ports=[22, 445, 5900])
    BLOCKED = dict(launchd=None, print_disabled=None, systemsetup=NEEDS_ADMIN, open_ports=[])

    @pytest.mark.parametrize("config", [ALL_OFF, ALL_ON, BLOCKED],
                             ids=["all-off", "all-on", "systemsetup-blocked"])
    def test_every_service_is_reported_in_every_configuration(self, mod, monkeypatch, config):
        _patch_sharing(monkeypatch, mod, **config)
        services = mod.check_sharing_services()
        assert [s["name"] for s in services] == EXPECTED_SERVICE_NAMES

    @pytest.mark.parametrize("config", [ALL_OFF, ALL_ON, BLOCKED],
                             ids=["all-off", "all-on", "systemsetup-blocked"])
    def test_every_row_is_renderable(self, mod, monkeypatch, config):
        # action_sharing_services indexes all four keys and pads risk to 7
        # columns; a missing key or a novel risk word breaks the report.
        _patch_sharing(monkeypatch, mod, **config)
        for s in mod.check_sharing_services():
            assert set(s) == {"name", "enabled", "risk", "note"}
            assert s["enabled"] in (True, False, None)
            assert s["risk"] in {"OK", "INFO", "REVIEW", "HIGH", "UNKNOWN"}
            assert s["note"].strip()

    def test_an_enabled_service_never_reads_the_same_as_a_disabled_one(self, mod, monkeypatch):
        """Each probed service must say something different when on than when off.

        Replaces three `note == "Disabled."` equalities that were dropped as
        brittle. Pinning the exact prose went red on any harmless copy edit;
        dropping it entirely let a note swap survive. Comparing the on-state
        against the off-state pins the behaviour — that the note actually
        tracks the state — without pinning a single word of the copy.
        """
        _patch_sharing(monkeypatch, mod, **self.ALL_OFF)
        off = {s["name"]: s["note"] for s in mod.check_sharing_services()}
        _patch_sharing(monkeypatch, mod, **self.ALL_ON)
        on = {s["name"]: s["note"] for s in mod.check_sharing_services()}

        for name in ("Remote Login (SSH)", "Screen Sharing / VNC",
                     "File Sharing (SMB)", "Remote Apple Events"):
            assert off[name] != on[name], f"{name} reads identically on and off"

    def test_an_undetermined_service_never_reads_as_a_confident_off(self, mod, monkeypatch):
        # The whole point of the UNKNOWN tri-state (commit 4c349fd) is that the
        # audit must not claim a listener is disabled when it could not look.
        _patch_sharing(monkeypatch, mod, **self.ALL_OFF)
        off_note = _by_name(mod.check_sharing_services(), "Remote Apple Events")["note"]
        _patch_sharing(monkeypatch, mod, **self.BLOCKED)
        blocked = _by_name(mod.check_sharing_services(), "Remote Apple Events")
        assert blocked["enabled"] is None
        assert blocked["note"] != off_note

    @pytest.mark.parametrize("config", [ALL_OFF, ALL_ON],
                             ids=["all-off", "all-on"])
    def test_mdns_is_always_present_and_informational(self, mod, monkeypatch, config):
        _patch_sharing(monkeypatch, mod, **config)
        mdns = _by_name(mod.check_sharing_services(), "mDNS / Bonjour")
        assert mdns["enabled"] is True
        assert mdns["risk"] == "INFO"

    def test_all_listeners_open_flags_every_probed_service(self, mod, monkeypatch):
        _patch_sharing(monkeypatch, mod, **self.ALL_ON)
        services = mod.check_sharing_services()
        assert [s["enabled"] for s in services] == [True, True, True, True, True]
        assert _by_name(services, "Screen Sharing / VNC")["risk"] == "HIGH"

    def test_nothing_listening_reports_ok_for_every_probed_service(self, mod, monkeypatch):
        _patch_sharing(monkeypatch, mod, **self.ALL_OFF)
        services = mod.check_sharing_services()
        probed = [s for s in services if s["name"] != "mDNS / Bonjour"]
        assert all(s["enabled"] is False for s in probed)
        assert all(s["risk"] == "OK" for s in probed)

    def test_listener_probes_never_leave_loopback(self, mod, monkeypatch):
        """The sharing check inspects *this* Mac; probing anything but 127.0.0.1
        would turn a read-only audit into a scan of another host."""
        _, _, fake_check_port = _patch_sharing(monkeypatch, mod, **self.ALL_OFF)
        mod.check_sharing_services()
        assert fake_check_port.calls, "no listener probe was attempted"
        assert {host for host, _ in fake_check_port.calls} == {"127.0.0.1"}
        assert sorted(port for _, port in fake_check_port.calls) == [22, 445, 5900]
