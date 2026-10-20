"""One-line section headers for the emailed report.

The boxed header costs three lines plus a blank, about twenty times per audit,
three audits per email: a third of the message was rules. The line style says
the same in one line. Two other things read headers back — the email digest and
the brief THIS MAC block — so both styles must parse, and the style must never
leak from one run (or one test) into the next.
"""

import pytest


class TestDrawing:
    def test_boxed_is_the_default_and_unchanged(self, mod, capsys):
        mod.hr("FIREWALL STATUS")
        assert capsys.readouterr().out == "\n" + "=" * 64 + "\nFIREWALL STATUS\n" + "=" * 64 + "\n"

    def test_line_style_is_one_line_after_the_blank(self, mod, capsys):
        with mod.header_style(mod.HEADER_LINE):
            mod.hr("FIREWALL STATUS")
        out = capsys.readouterr().out
        assert out.count("\n") == 2 and out.startswith("\n── FIREWALL STATUS ─")
        assert len(out.strip()) == mod.HEADER_WIDTH

    def test_a_title_longer_than_the_width_still_closes(self, mod):
        with mod.header_style(mod.HEADER_LINE):
            line = mod.section_header("X" * 90)
        assert line.endswith(" ──")

    def test_an_untitled_rule_is_one_line_in_both_styles(self, mod):
        assert mod.section_header() == "=" * 64
        with mod.header_style(mod.HEADER_LINE):
            assert mod.section_header() == "─" * 64

    def test_the_style_is_restored_afterwards_even_on_an_exception(self, mod):
        with pytest.raises(RuntimeError):
            with mod.header_style(mod.HEADER_LINE):
                raise RuntimeError("x")
        assert mod.section_header("T").startswith("=")

    def test_an_unknown_style_falls_back_to_boxed(self, mod):
        with mod.header_style("sparkly"):
            assert mod.section_header("T").startswith("=")

    def test_styles_nest(self, mod):
        with mod.header_style(mod.HEADER_LINE):
            with mod.header_style(mod.HEADER_BOXED):
                assert mod.section_header("T").startswith("=")
            assert mod.section_header("T").startswith("──")


class TestParsing:
    @pytest.mark.parametrize("style", ["boxed", "line"])
    def test_a_header_round_trips_in_either_style(self, mod, style):
        title = "CHANGE DETECTION (vs saved baseline)"
        with mod.header_style(style):
            lines = mod.section_header(title).split("\n")
        assert mod.parse_section_header(lines, 0) == (title, len(lines))

    def test_a_title_containing_dashes_survives(self, mod):
        with mod.header_style(mod.HEADER_LINE):
            lines = [mod.section_header("DSL LINE STATS (TP-Link VX420-G2h)")]
        assert mod.parse_section_header(lines, 0)[0] == "DSL LINE STATS (TP-Link VX420-G2h)"

    @pytest.mark.parametrize("line", ["  ── not a header ──", "──no space──", "plain text", "", "── ──"])
    def test_lookalikes_are_not_headers(self, mod, line):
        assert mod.parse_section_header([line], 0) is None


class TestTheBriefBlockFollowsTheStyle:
    def _sections(self, mod):
        def fw():
            mod.hr("SHARING SERVICES CHECK")
            print("  [UNKNOWN] ?    Remote Apple Events    Unknown — re-run with sudo.")
        _, text = mod.capture_section(fw)
        return [("sharing services", text)]

    def test_line_style_in_line_style_out(self, mod):
        with mod.header_style(mod.HEADER_LINE):
            out = mod.render_host_sections_brief(self._sections(mod))
        assert "── THIS MAC (re-checked on this network) ─" in out and "====" not in out
        assert "From SHARING SERVICES CHECK:" in out, "the origin title must be read from a one-line header too"

    def test_boxed_stays_boxed(self, mod):
        out = mod.render_host_sections_brief(self._sections(mod))
        assert "=" * 64 in out and "From SHARING SERVICES CHECK:" in out
