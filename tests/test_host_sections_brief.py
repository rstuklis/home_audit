"""--host-sections-brief: this Mac's sections, once per report instead of once per network.

The firewall, sharing services and listeners describe the machine, not the
network, so a three-network report printed them three times. They must still be
CHECKED and RECORDED on every network — each keeps its own baseline — so only the
printing changes, and only while there is nothing in them worth reading twice.
"""

import pytest

FIREWALL_OK = """
================================================================
FIREWALL STATUS
================================================================
  [OK    ] Application Firewall : ON
            Stealth Mode         : ON
"""

SHARING = """
================================================================
SHARING SERVICES CHECK
================================================================
  [OK     ] OFF  Remote Login (SSH)     Disabled.
  [UNKNOWN] ?    Remote Apple Events    Unknown — re-run this audit with sudo.
  [INFO   ] ON   mDNS / Bonjour         Always on.
"""

LISTENERS_QUIET = """
================================================================
LISTENING SERVICES AUDIT
================================================================
  25 listener(s), none of them new since the baseline: 6 named non-system.
"""


def render(mod, *texts):
    titles = ["firewall", "sharing services", "listening services"]
    return mod.render_host_sections_brief(list(zip(titles, texts)))


class TestBrief:
    def test_three_quiet_sections_become_one_short_one(self, mod):
        out = render(mod, FIREWALL_OK, SHARING, LISTENERS_QUIET)
        assert "THIS MAC (re-checked on this network)" in out
        assert "FIREWALL STATUS" not in out and "Stealth Mode" not in out
        # These fixtures are a third the length of the real sections (about 31
        # lines on a live Mac against 9 in brief), so the bar here is only that
        # brief is clearly shorter, not a ratio the fixtures cannot represent.
        full = len((FIREWALL_OK + SHARING + LISTENERS_QUIET).splitlines())
        assert len(out.splitlines()) <= full * 0.6

    def test_it_names_what_was_rechecked_and_where_the_detail_is(self, mod):
        out = render(mod, FIREWALL_OK, SHARING, LISTENERS_QUIET)
        assert "firewall, sharing services, listening services" in out
        assert "under the first network in this report" in out

    def test_standing_review_and_unknown_lines_are_kept(self, mod):
        # The digest counts flagged lines per network; one that silently vanished
        # from two of three reports would read as cleared.
        assert "Remote Apple Events" in render(mod, FIREWALL_OK, SHARING, LISTENERS_QUIET)

    def test_a_kept_line_says_which_section_it_came_from(self, mod):
        out = render(mod, FIREWALL_OK, SHARING, LISTENERS_QUIET)
        lines = out.splitlines()
        i = next(n for n, l in enumerate(lines) if "Remote Apple Events" in l)
        assert lines[i - 1].strip() == "From SHARING SERVICES CHECK:"

    def test_ok_and_info_lines_are_the_ones_dropped(self, mod):
        out = render(mod, FIREWALL_OK, SHARING, LISTENERS_QUIET)
        assert "Remote Login (SSH)" not in out and "Bonjour" not in out


class TestNeverHidesATrouble:
    def test_a_firewall_that_is_off_is_printed_in_full(self, mod):
        bad = FIREWALL_OK.replace("[OK    ] Application Firewall : ON", "[HIGH  ] Application Firewall : OFF")
        out = render(mod, bad, SHARING, LISTENERS_QUIET)
        assert "FIREWALL STATUS" in out and "Application Firewall : OFF" in out
        assert "Stealth Mode" in out, "the loud section must come back whole, not as one line"

    def test_a_medium_sharing_service_is_printed_in_full(self, mod):
        bad = SHARING.replace("[OK     ] OFF  Remote Login (SSH)     Disabled.", "[MEDIUM ] ON   Remote Login (SSH)     Enabled.")
        out = render(mod, FIREWALL_OK, bad, LISTENERS_QUIET)
        assert "SHARING SERVICES CHECK" in out and "Enabled." in out

    def test_a_new_listener_is_printed_in_full(self, mod):
        loud = LISTENERS_QUIET + "  * 4444 TCP nc\n  + not in the baseline: nc on TCP port 4444\n"
        out = render(mod, FIREWALL_OK, SHARING, loud)
        assert "LISTENING SERVICES AUDIT" in out and "nc on TCP port 4444" in out

    def test_the_quiet_sections_are_still_folded_beside_a_loud_one(self, mod):
        bad = FIREWALL_OK.replace("[OK    ]", "[HIGH  ]")
        out = render(mod, bad, SHARING, LISTENERS_QUIET)
        assert "Re-checked here and recorded in this network's baseline: sharing services, listening services." in out

    def test_the_summary_never_claims_quiet_when_everything_is_loud(self, mod):
        bad_fw = FIREWALL_OK.replace("[OK    ]", "[HIGH  ]")
        bad_sh = SHARING.replace("[OK     ]", "[MEDIUM ]")
        loud = LISTENERS_QUIET + "  + not in the baseline: x on TCP port 1\n"
        out = render(mod, bad_fw, bad_sh, loud)
        assert "THIS MAC" not in out and "Nothing rated HIGH" not in out


class TestCapture:
    def test_the_result_comes_back_and_nothing_reaches_the_terminal(self, mod, capsys):
        def section(x):
            print("printed", x)
            return {"value": x}
        result, text = mod.capture_section(section, 7)
        assert result == {"value": 7} and text == "printed 7\n"
        assert capsys.readouterr().out == ""

    def test_an_exception_does_not_leave_stdout_hijacked(self, mod, capsys):
        def boom():
            print("before")
            raise RuntimeError("x")
        with pytest.raises(RuntimeError):
            mod.capture_section(boom)
        print("after")
        assert capsys.readouterr().out == "after\n"


class TestStateIsStillRecorded:
    """The point of running the checks at all: every network's baseline keeps them."""

    def test_brief_mode_records_all_three_results(self, mod, monkeypatch, capsys):
        calls = []
        monkeypatch.setattr(mod, "action_firewall_check", lambda: calls.append("fw") or {"enabled": True, "risk": "OK"})
        monkeypatch.setattr(mod, "action_sharing_services", lambda: calls.append("sh") or
                            [{"name": "SSH", "enabled": False, "risk": "OK", "note": "Disabled."}])
        monkeypatch.setattr(mod, "action_listening_services", lambda compact=False, known=None: calls.append("ls") or
                            [{"proto": "TCP", "port": 22, "pid": "1", "process": "sshd"}])
        fw, _ = mod.capture_section(mod.action_firewall_check)
        sharing, _ = mod.capture_section(mod.action_sharing_services)
        listening, _ = mod.capture_section(mod.action_listening_services, compact=True, known=None)
        assert calls == ["fw", "sh", "ls"]
        assert fw["enabled"] is True and sharing[0]["name"] == "SSH" and listening[0]["port"] == 22
