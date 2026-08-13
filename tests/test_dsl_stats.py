"""DSL line statistics parsing (`_dsl_rows` + `_DSL_PATTERNS`).

The numbers this reads are the ones that tell a DSL owner whether their line is
healthy — the audit prints "healthy >6 dB" beside the SNR — so a wrong figure
here is not a cosmetic problem, it is a false diagnosis in either direction.

Two defects lived in it, and both produced a plausible-looking wrong number
rather than a missing one, which is why neither was ever noticed:

  * The quantifier before each capture group was greedy, so it consumed as much
    of "SNR: 6.5 dB" as it could and handed back only what `([\\d.]+)` needed to
    match: the digit AFTER the decimal point. 6.5 read as 5, 24.8 as 8, 13.1 as
    1. A healthy 6.5 dB line reported itself as failing the tool's own
    threshold.
  * The patterns cannot cross a `<`, and a router serves a table, so on the
    actual pages this code is pointed at nothing matched at all.

Fixing the second without care reintroduces the first in a new form: flatten a
page to one string and "Upstream Rate 1024 Kbps Downstream SNR 6.5" lets the
upstream pattern capture the downstream value. Rows are what keep measurements
apart, so rows are what the parser preserves.
"""

import pytest


EXPECTED = {
    "downstream_kbps": 12345.0,
    "upstream_kbps": 1024.0,
    "downstream_snr_db": 6.5,
    "upstream_snr_db": 8.2,
    "downstream_attn_db": 24.8,
    "upstream_attn_db": 13.1,
}

TABLE_PAGE = """<html><body><table>
<tr><td>Downstream Rate</td><td>12345 Kbps</td></tr>
<tr><td>Upstream Rate</td><td>1024 Kbps</td></tr>
<tr><td>Downstream SNR</td><td>6.5</td></tr>
<tr><td>Upstream SNR</td><td>8.2</td></tr>
<tr><td>Downstream Attenuation</td><td>24.8</td></tr>
<tr><td>Upstream Attenuation</td><td>13.1</td></tr>
</table></body></html>"""

PLAIN_PAGE = (
    "Downstream Rate: 12345 Kbps\n"
    "Upstream Rate: 1024 Kbps\n"
    "Downstream SNR: 6.5 dB\n"
    "Upstream SNR: 8.2 dB\n"
    "Downstream Attenuation: 24.8 dB\n"
    "Upstream Attenuation: 13.1 dB\n"
)


def parse(mod, raw):
    """Run the real row split and pattern table over `raw`."""
    out = {}
    rows = mod._dsl_rows(raw)
    for key, pats in mod._DSL_PATTERNS.items():
        for pat in pats:
            hit = next((pat.search(r) for r in rows if pat.search(r)), None)
            if hit:
                out[key] = float(hit.group(1))
                break
    return out


class TestValuesAreReadWhole:
    """The greedy-quantifier defect: a decimal reading truncated to one digit."""

    @pytest.mark.parametrize("key", sorted(EXPECTED))
    def test_each_field_parses_to_its_full_value(self, mod, key):
        assert parse(mod, PLAIN_PAGE)[key] == EXPECTED[key]

    def test_a_decimal_snr_is_not_truncated_to_its_last_digit(self, mod):
        # The specific regression: "6.5" read as 5. Named separately because
        # this is the value the audit compares against "healthy >6 dB", so the
        # bug turned a passing line into a failing one.
        assert parse(mod, "Downstream SNR: 6.5 dB")["downstream_snr_db"] == 6.5

    def test_a_two_digit_reading_survives(self, mod):
        # "12.3" used to read as 3.
        assert parse(mod, "Downstream SNR Margin 12.3 dB")["downstream_snr_db"] == 12.3

    def test_an_integer_reading_still_works(self, mod):
        assert parse(mod, "Downstream SNR: 7 dB")["downstream_snr_db"] == 7.0


class TestRealRouterMarkup:
    """The pages this code is actually pointed at are tables, not prose."""

    @pytest.mark.parametrize("key", sorted(EXPECTED))
    def test_a_table_page_parses_every_field(self, mod, key):
        assert parse(mod, TABLE_PAGE)[key] == EXPECTED[key]

    def test_a_label_and_value_in_separate_cells_are_joined(self, mod):
        got = parse(mod, "<tr><td>Downstream SNR</td><td>6.5</td></tr>")
        assert got.get("downstream_snr_db") == 6.5

    def test_nbsp_entities_do_not_block_a_match(self, mod):
        got = parse(mod, "Downstream&nbsp;SNR:&nbsp;6.5&nbsp;dB")
        assert got.get("downstream_snr_db") == 6.5

    def test_cells_are_not_glued_into_a_word_that_never_appeared(self, mod):
        # Tags become spaces, not nothing: "Down" and "stream" in adjacent
        # columns must not be read as the label "Downstream".
        rows = mod._dsl_rows("<tr><td>Down</td><td>stream SNR 6.5</td></tr>")
        assert "Down stream" in rows[0]


class TestMeasurementsStayApart:
    """Reaching a value that belongs to a different field is the worst outcome:
    it is wrong rather than absent, and nothing downstream can tell."""

    def test_upstream_does_not_capture_the_downstream_value_across_rows(self, mod):
        got = parse(mod, TABLE_PAGE)
        assert got["upstream_snr_db"] == 8.2, "upstream reported downstream's SNR"
        assert got["upstream_attn_db"] == 13.1

    def test_two_fields_in_one_row_do_not_bleed(self, mod):
        # The digits of the first field's value sit between the second label and
        # the number, and a number in that gap means another field was passed.
        got = parse(mod, "<tr><td>Upstream Rate 1024 Kbps Downstream SNR 6.5</td></tr>")
        assert got.get("upstream_snr_db") != 6.5

    def test_a_page_with_only_downstream_leaves_upstream_unset(self, mod):
        got = parse(mod, "Downstream SNR: 6.5 dB")
        assert "upstream_snr_db" not in got


class TestRowSplitting:
    def test_table_rows_break_on_tr(self, mod):
        assert len(mod._dsl_rows("<tr><td>a 1</td></tr><tr><td>b 2</td></tr>")) == 2

    def test_line_breaks_and_br_tags_both_split(self, mod):
        assert len(mod._dsl_rows("a 1<br>b 2")) == 2
        assert len(mod._dsl_rows("a 1\nb 2")) == 2

    def test_empty_rows_are_dropped(self, mod):
        assert mod._dsl_rows("<tr></tr>\n\n<tr><td>a 1</td></tr>") == ["a 1"]

    def test_a_page_with_no_markup_is_one_row_per_line(self, mod):
        assert mod._dsl_rows("first line\nsecond line") == ["first line", "second line"]


class TestFirmwareDiagnosis:
    """Telling "wrong password" apart from "protocol this tool cannot speak".

    Both fail identically — no page retrieved — so the note was the only thing
    distinguishing them, and it named the two remedies that cannot work. A real
    VX420-G2h sent an afternoon after the password before its login page gave
    the answer away.
    """

    @pytest.mark.parametrize("marker", ["tpEncrypt.js", "cryptoJS.min.js",
                                        "gdprProxy.js", "/cgi_gdpr"])
    def test_each_modern_firmware_marker_is_recognised(self, mod, marker):
        page = f'<html><head><script src="../js/{marker}"></script></head></html>'
        assert mod._tplink_uses_encrypted_login(page) is True

    def test_a_legacy_login_page_is_not_misreported(self, mod):
        # The old builds this module's login actually works against.
        legacy = ('<html><body><form action="/cgi/login" method="get">'
                  '<input name="UserName"><input name="Passwd" type="password">'
                  '</form></body></html>')
        assert mod._tplink_uses_encrypted_login(legacy) is False

    def test_an_empty_or_unreachable_page_is_not_a_diagnosis(self, mod):
        # fetch() returns "" on any error; that is an absence of evidence and
        # must not be reported as a positive finding about the firmware.
        assert mod._tplink_uses_encrypted_login("") is False
        assert mod._tplink_uses_encrypted_login(None) is False

    def test_detection_is_case_insensitive(self, mod):
        assert mod._tplink_uses_encrypted_login("<script src=TPENCRYPT.JS>") is True


class TestLinkStateIsNotADirection:
    """Confirmed by adversarial review, and a regression introduced by _dsl_rows.

    Excluding digits from the gap is necessary and not sufficient, because what
    most often sits between a direction word and someone else's number carries
    no digit at all: the link state. A status row reads

        DSL Status | Up | Downstream SNR Margin | 6.5

    and once the cells are merged into one row, an unanchored [Uu]p matched the
    bare state word, crossed a digit-free gap and reported 6.5 as the UPSTREAM
    figure — a number the modem never gave for that direction, then written into
    the baseline. Before rows existed the "<" between cells blocked it and
    nothing was reported, so adding row support turned "no value" into "wrong
    value": the trade this module refuses to make everywhere else.
    """

    @pytest.mark.parametrize("row, fabricated", [
        ("<tr><td>DSL Status</td><td>Up</td><td>Downstream SNR Margin</td><td>6.5</td></tr>",
         "upstream_snr_db"),
        ("<tr><td>Line State</td><td>Down</td><td>Upstream SNR</td><td>12.3</td></tr>",
         "downstream_snr_db"),
        ("<tr><td>Status</td><td>Up</td><td>Downstream Rate</td><td>1024 Kbps</td></tr>",
         "upstream_kbps"),
        ("<tr><td>Link</td><td>Up</td><td>Downstream Attenuation</td><td>24.8</td></tr>",
         "upstream_attn_db"),
    ], ids=["snr-up", "snr-down", "rate", "attenuation"])
    def test_a_link_state_does_not_donate_its_word_to_the_other_direction(
            self, mod, row, fabricated):
        assert fabricated not in parse(mod, row), \
            "a link-state cell was read as a direction label"

    def test_the_real_direction_in_that_row_is_still_read(self, mod):
        # Suppressing the fabrication must not cost the genuine reading beside it.
        got = parse(mod, "<tr><td>DSL Status</td><td>Up</td>"
                         "<td>Downstream SNR Margin</td><td>6.5</td></tr>")
        assert got["downstream_snr_db"] == 6.5

    @pytest.mark.parametrize("word", ["Setup", "Group", "Backup", "Startup"])
    def test_a_word_merely_containing_up_is_not_a_direction(self, mod, word):
        got = parse(mod, f"<tr><td>{word}</td><td>Downstream SNR</td><td>6.5</td></tr>")
        assert "upstream_snr_db" not in got

    def test_a_directionless_label_is_not_assigned_to_a_direction(self, mod):
        # "Showtime | Up | SNR Margin | 6.5" names no direction for that figure.
        # Guessing one is fabrication; reporting nothing is the honest answer.
        assert parse(mod, "<tr><td>Showtime</td><td>Up</td>"
                          "<td>SNR Margin</td><td>6.5</td></tr>") == {}

    def test_a_minified_page_without_row_tags_is_also_safe(self, mod):
        # No </tr>, </p>, <br> or newline to split on, so the whole page is one
        # row and the state word sits beside the figure.
        got = parse(mod, "<ul><li>Line Status: Up</li><li>Downstream SNR: 6.5 dB</li></ul>")
        assert "upstream_snr_db" not in got
        assert got["downstream_snr_db"] == 6.5

    def test_a_digit_free_field_between_two_directions_does_not_bleed(self, mod):
        # The digit exclusion cannot see this one: "N/A" carries no number, so
        # only the opposite-direction guard stops upstream reaching downstream's
        # figure.
        got = parse(mod, "<tr><td>Upstream Rate N/A Downstream SNR 6.5</td></tr>")
        assert got.get("upstream_snr_db") != 6.5
