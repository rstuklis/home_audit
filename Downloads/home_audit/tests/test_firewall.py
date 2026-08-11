"""Tests for check_firewall (home_net_audit.py lines 1512-1562).

The function shells out to socketfilterfw three times and folds the three
outputs into {enabled, stealth_mode, block_all, note}. Every value is
tri-state: None means "the command said something we could not parse", and
must never be rendered as a confident OFF.

Commit 4c349fd is the reference point for most of what is pinned here. The
pre-fix body was:

    result["enabled"]      = "enabled" in global_out.lower() or "state = 1" in ...
    result["stealth_mode"] = "enabled" in stealth_out.lower()
    result["block_all"]    = "enabled" in blockall_out.lower()

which reported stealth OFF on every Mac (the real ON string carries no
"enabled" token) and reported the firewall OFF whenever the command produced
nothing at all.
"""

import pytest

from conftest import load_fixture, make_run

FW_BIN = "/usr/libexec/ApplicationFirewall/socketfilterfw"

# Substrings make_run dispatches on; none is a prefix of another.
GLOBAL_CMD = "socketfilterfw --getglobalstate"
STEALTH_CMD = "socketfilterfw --getstealthmode"
BLOCKALL_CMD = "socketfilterfw --getblockall"

# Realistic captures, loaded from tests/fixtures/ so the trailing newline that
# real `run()` stdout always carries is part of every parse under test.
GLOBAL_ON = load_fixture("firewall_globalstate_on.out")
GLOBAL_OFF = load_fixture("firewall_globalstate_off.out")
GLOBAL_BLOCKALL = load_fixture("firewall_globalstate_blockall.out")
STEALTH_ON = load_fixture("firewall_stealth_on.out")
STEALTH_OFF = load_fixture("firewall_stealth_off.out")
BLOCKALL_ON = load_fixture("firewall_blockall_on.out")
BLOCKALL_OFF = load_fixture("firewall_blockall_off.out")

# (branch key of TestNoteBranchSelection._notes, token that identifies that
# branch's note). Every token must be unique to its own branch — a token that
# also occurs in a sibling note cannot detect two notes being swapped, which is
# the whole point of the class. TestNoteBranchSelection enforces that property
# directly, so a future edit cannot quietly reintroduce a dead-weight token.
NOTE_BRANCH_TOKENS = [
    ("unknown", "could not determine"),
    ("off", "firewall is off"),
    ("block_all", "block all"),
    ("stealth_on", "good configuration"),
    ("plain_on", "stealth mode off"),
]
NOTE_BRANCH_IDS = ["unknown", "off", "block-all", "stealth-on", "plain-on"]


@pytest.fixture
def fw(mod, monkeypatch):
    """Call check_firewall() with the three socketfilterfw outputs supplied.

    Anything not passed defaults to "" — exactly what run() yields when the
    binary is missing or the call times out.
    """
    def _fw(global_out="", stealth_out="", blockall_out=""):
        fake = make_run({
            GLOBAL_CMD: global_out,
            STEALTH_CMD: stealth_out,
            BLOCKALL_CMD: blockall_out,
        })
        monkeypatch.setattr(mod, "run", fake)
        _fw.calls = fake.calls
        return mod.check_firewall()

    _fw.calls = []
    return _fw


class TestResultShape:
    def test_returns_the_four_documented_keys(self, fw):
        assert set(fw(global_out=GLOBAL_ON)) == {
            "enabled", "stealth_mode", "block_all", "note",
        }

    def test_note_is_never_empty(self, fw):
        assert fw(global_out=GLOBAL_ON, stealth_out=STEALTH_ON)["note"] != ""


class TestGlobalStateInteger:
    @pytest.mark.parametrize(
        "global_out, expected",
        [
            (GLOBAL_OFF, False),
            (GLOBAL_ON, True),
            (GLOBAL_BLOCKALL, True),
        ],
        ids=["state0-off", "state1-on", "state2-block-all-on"],
    )
    def test_state_integer_decides_enabled(self, fw, global_out, expected):
        assert fw(global_out=global_out)["enabled"] is expected

    def test_state_two_is_on_so_the_test_is_ge_one_not_eq_one(self, fw):
        # State 2 is "on, block all incoming". An `== 1` rule would report the
        # most locked-down configuration as OFF.
        assert fw(global_out="Firewall is enabled. (State = 2)")["enabled"] is True

    def test_state_one_is_the_lowest_on_value(self, fw):
        # The >= 1 boundary from below: 0 is the only integer that means OFF.
        assert fw(global_out="Firewall is disabled. (State = 0)")["enabled"] is False
        assert fw(global_out="Firewall is enabled. (State = 1)")["enabled"] is True

    @pytest.mark.parametrize(
        "global_out",
        ["(State = 1)", "(State=1)", "Firewall is enabled. (State  =  1)"],
        ids=["spaced", "tight", "extra-space"],
    )
    def test_whitespace_around_the_equals_sign_is_tolerated(self, fw, global_out):
        assert fw(global_out=global_out)["enabled"] is True

    def test_integer_outranks_contradictory_prose(self, fw):
        # The word "enabled" is present but State says 0. The documented
        # integer is the authoritative signal (commit 4c349fd).
        assert fw(global_out="Firewall is enabled. (State = 0)")["enabled"] is False

    def test_missing_state_integer_is_unknown_not_off(self, fw):
        assert fw(global_out="Firewall is enabled.")["enabled"] is None

    def test_empty_global_output_is_unknown_not_off(self, fw):
        # Regression, commit 4c349fd: the old substring rule turned "no output"
        # (binary missing, command timed out) into a confident "firewall OFF".
        assert fw(global_out="")["enabled"] is None


class TestStealthMode:
    def test_on_string_is_detected_although_it_contains_no_enabled_token(self, fw):
        # THE historical regression, commit 4c349fd. The old rule was
        # `result["stealth_mode"] = "enabled" in stealth_out.lower()` and the
        # real macOS ON string is "Firewall stealth mode is on", so stealth was
        # reported OFF on every Mac regardless of the actual setting.
        assert "enabled" not in STEALTH_ON.lower(), "fixture no longer reproduces the trap"
        assert fw(global_out=GLOBAL_ON, stealth_out=STEALTH_ON)["stealth_mode"] is True

    @pytest.mark.parametrize(
        "stealth_out, expected",
        [
            (STEALTH_ON, True),
            (STEALTH_OFF, False),
            ("Stealth mode enabled\n", True),
            ("Stealth mode disabled\n", False),
            ("FIREWALL STEALTH MODE IS ON\n", True),
        ],
        ids=["is-on", "is-off", "set-enabled", "set-disabled", "uppercase-on"],
    )
    def test_stealth_strings(self, fw, stealth_out, expected):
        result = fw(global_out=GLOBAL_ON, stealth_out=stealth_out)
        assert result["stealth_mode"] is expected

    @pytest.mark.parametrize(
        "stealth_out",
        ["", "socketfilterfw: unrecognized option `--getstealthmode'\n", "\n"],
        ids=["empty", "unrecognized-option", "blank-line"],
    )
    def test_unparseable_stealth_output_is_unknown(self, fw, stealth_out):
        assert fw(global_out=GLOBAL_ON, stealth_out=stealth_out)["stealth_mode"] is None

    def test_a_stray_enabled_token_currently_forces_stealth_on(self, fw):
        # AMBIGUOUS - documenting actual behaviour, NOT asserting it is right.
        # Line 1534 tests `"enabled" in sl` before line 1536 tests `"is off"`,
        # the reverse of the guard applied to block-all on lines 1544-1547. Any
        # stealth output that mentions "enabled" for some other reason resolves
        # to stealth ON even when it also says "is off". No macOS version is
        # known to emit both tokens from --getstealthmode, so this is a latent
        # asymmetry rather than a confirmed field defect - left unxfailed for
        # that reason. If the branches are ever reordered, delete this test.
        out = "Firewall is enabled. Stealth mode is off\n"
        assert fw(global_out=GLOBAL_ON, stealth_out=out)["stealth_mode"] is True

    def test_stealth_is_independent_of_the_global_state(self, fw):
        # Stealth mode has its own getter; a firewall that is off can still
        # report a stored stealth setting, and the two must not be conflated.
        result = fw(global_out=GLOBAL_OFF, stealth_out=STEALTH_ON)
        assert (result["enabled"], result["stealth_mode"]) == (False, True)


class TestBlockAll:
    @pytest.mark.parametrize(
        "blockall_out, expected",
        [
            (BLOCKALL_OFF, False),
            (BLOCKALL_ON, True),
            ("Firewall has block all state set to disabled.\n", False),
            ("Firewall has block all state set to enabled.\n", True),
            ("Block all is on\n", True),
        ],
        ids=["DISABLED!", "ENABLED!", "state-set-to-disabled", "state-set-to-enabled",
             "block-all-is-on"],
    )
    def test_block_all_strings(self, fw, blockall_out, expected):
        result = fw(global_out=GLOBAL_ON, blockall_out=blockall_out)
        assert result["block_all"] is expected

    def test_disabled_is_tested_before_enabled(self, fw):
        # Ordering guard for lines 1544-1547: "disabled" is matched first, so an
        # output that also carries an "enabled" token still resolves to OFF.
        # Swapping the two branches flips this to True and mislabels a wide-open
        # firewall as maximum restriction.
        out = "Firewall is enabled. Block all state set to disabled.\n"
        assert "enabled" in out.lower() and "disabled" in out.lower()
        assert fw(global_out=GLOBAL_ON, blockall_out=out)["block_all"] is False

    @pytest.mark.parametrize(
        "blockall_out",
        ["", "Block all state unknown\n"],
        ids=["empty", "unparseable"],
    )
    def test_unparseable_block_all_output_is_unknown(self, fw, blockall_out):
        assert fw(global_out=GLOBAL_ON, blockall_out=blockall_out)["block_all"] is None


class TestUnknownEverything:
    def test_all_three_commands_silent_gives_a_full_tri_state(self, fw):
        result = fw()
        assert (result["enabled"], result["stealth_mode"], result["block_all"]) \
            == (None, None, None)

    def test_unknown_note_says_the_state_could_not_be_determined(self, fw):
        assert "could not determine" in fw()["note"].lower()

    def test_unknown_note_does_not_claim_the_firewall_is_off(self, fw):
        # Regression, commit 4c349fd: unparseable output used to fall into the
        # "Firewall is OFF" branch and scare the user about a firewall that was
        # very possibly on.
        unknown_note = fw()["note"]
        off_note = fw(global_out=GLOBAL_OFF)["note"]
        assert unknown_note != off_note
        assert "is off" not in unknown_note.lower()


class TestNoteBranchSelection:
    """The note names one of five mutually exclusive situations."""

    def _notes(self, fw):
        return {
            "unknown": fw()["note"],
            "off": fw(global_out=GLOBAL_OFF, stealth_out=STEALTH_OFF,
                      blockall_out=BLOCKALL_OFF)["note"],
            "block_all": fw(global_out=GLOBAL_BLOCKALL, stealth_out=STEALTH_OFF,
                            blockall_out=BLOCKALL_ON)["note"],
            "stealth_on": fw(global_out=GLOBAL_ON, stealth_out=STEALTH_ON,
                             blockall_out=BLOCKALL_OFF)["note"],
            "plain_on": fw(global_out=GLOBAL_ON, stealth_out=STEALTH_OFF,
                           blockall_out=BLOCKALL_OFF)["note"],
        }

    def test_the_five_branches_produce_five_different_notes(self, fw):
        notes = self._notes(fw)
        assert len(set(notes.values())) == 5, f"branches collapsed: {notes}"

    @pytest.mark.parametrize("branch, token", NOTE_BRANCH_TOKENS, ids=NOTE_BRANCH_IDS)
    def test_each_branch_names_its_situation(self, fw, branch, token):
        assert token in self._notes(fw)[branch].lower()

    @pytest.mark.parametrize("branch, token", NOTE_BRANCH_TOKENS, ids=NOTE_BRANCH_IDS)
    def test_each_branch_token_is_unique_to_that_branch(self, fw, branch, token):
        # Systemic guard for the table above. A token that also appears in a
        # sibling note makes test_each_branch_names_its_situation dead weight:
        # it keeps passing when lines 1551-1560 hand a branch the wrong note.
        # The stealth-on case was exactly that — "stealth mode" is also in the
        # plain-on note ("Enabled (stealth mode off)..."), so swapping lines
        # 1558 and 1560 left the assertion green.
        notes = self._notes(fw)
        intruders = sorted(
            other for other, note in notes.items()
            if other != branch and token in note.lower()
        )
        assert intruders == [], (
            f"token {token!r} for branch {branch!r} also matches {intruders}; "
            f"it cannot detect those notes being swapped"
        )

    def test_off_note_wins_over_block_all_and_stealth(self, fw):
        # A firewall that is off makes the other two settings irrelevant; the
        # note must lead with the OFF finding.
        notes = self._notes(fw)
        result = fw(global_out=GLOBAL_OFF, stealth_out=STEALTH_ON,
                    blockall_out=BLOCKALL_ON)
        assert result["note"] == notes["off"]

    def test_block_all_note_wins_over_stealth(self, fw):
        notes = self._notes(fw)
        result = fw(global_out=GLOBAL_BLOCKALL, stealth_out=STEALTH_ON,
                    blockall_out=BLOCKALL_ON)
        assert result["note"] == notes["block_all"]

    def test_unknown_note_wins_even_when_stealth_and_block_all_parsed(self, fw):
        notes = self._notes(fw)
        result = fw(global_out="socketfilterfw: command not understood\n",
                    stealth_out=STEALTH_ON, blockall_out=BLOCKALL_ON)
        assert result["note"] == notes["unknown"]

    @pytest.mark.known_bug
    @pytest.mark.xfail(strict=True, reason=(
        "home_net_audit.py:1557-1560 picks the note with a truthiness test — "
        "`elif result['stealth_mode']:` ... `else: 'Enabled (stealth mode off). ...'` — "
        "so stealth_mode=None falls into the else and the note states as fact that "
        "stealth is off. None is reachable whenever --getstealthmode output is "
        "unparseable (see test_unparseable_stealth_output_is_unknown); the branch needs "
        "`is True` / `is False` like the tri-state it is reading. The claim is not "
        "terminal-only: action_firewall_check prints 'Stealth Mode : UNKNOWN' two lines "
        "above the same note (lines 1570/1574/1576), and generate_html_report copies the "
        "note verbatim into the shareable report at line 1712."))
    def test_unknown_stealth_is_not_reported_as_off_in_the_note(self, fw):
        result = fw(global_out=GLOBAL_ON, stealth_out="", blockall_out=BLOCKALL_OFF)
        assert result["stealth_mode"] is None
        assert "stealth mode off" not in result["note"].lower(), (
            "note claims stealth is off for a stealth_mode that is None (unknown)"
        )


class TestCommandsIssued:
    def test_exactly_the_three_getters_run_in_order(self, mod, monkeypatch):
        fake = make_run({})
        monkeypatch.setattr(mod, "run", fake)
        mod.check_firewall()
        assert fake.calls == [
            f"{FW_BIN} --getglobalstate",
            f"{FW_BIN} --getstealthmode",
            f"{FW_BIN} --getblockall",
        ]

    def test_the_binary_is_addressed_by_absolute_path(self, mod, monkeypatch):
        # socketfilterfw is not on the default PATH; a bare name would make
        # every getter return "" and the whole check read as UNKNOWN.
        fake = make_run({})
        monkeypatch.setattr(mod, "run", fake)
        mod.check_firewall()
        assert all(c.startswith(FW_BIN + " ") for c in fake.calls)

    def test_every_getter_uses_a_short_timeout(self, mod, monkeypatch):
        # A wedged socketfilterfw must not stall the audit for run()'s 10s
        # default three times over.
        timeouts = []

        def recording_run(cmd, timeout=10):
            timeouts.append(timeout)
            return ""

        monkeypatch.setattr(mod, "run", recording_run)
        mod.check_firewall()
        assert timeouts == [5, 5, 5]
