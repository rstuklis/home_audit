"""HTML report rendering: escaping, tri-state fidelity, secrets and structure.

The report is a file the user opens in a browser, and several of the strings it
renders arrive from third parties the tool does not control — macvendors.com
vendor names, a broadcast Wi-Fi SSID, reverse-DNS hostnames, UPnP mapping
descriptions. Commit 9db3ab7 added ``_esc`` for exactly that reason. These tests
hold that line field by field, and pin the places where the renderer still
disagrees with the terminal output about what the audit actually found.
"""

import fnmatch
import os
import re
from html.parser import HTMLParser

import pytest


# The canonical injection probe. Chosen because it contains no quote characters,
# so its escaped form is a single deterministic string that can be asserted on
# directly rather than matched loosely.
PAYLOAD = "<img src=x onerror=alert(1)>"
ESCAPED_PAYLOAD = "&lt;img src=x onerror=alert(1)&gt;"


def render(mod, tmp_path, state, name="report.html"):
    """Generate a report into tmp_path and return its text."""
    out = tmp_path / name
    mod.generate_html_report(state, str(out))
    return out.read_text(encoding="utf-8")


def render_path(mod, tmp_path, state, name="report.html"):
    """Generate a report into tmp_path and return its path, for stat() checks."""
    out = tmp_path / name
    return mod.generate_html_report(state, str(out))


def row_or_text(text, heading):
    """Return just the section whose <h2> is `heading`.

    Asserting on the whole document would pass on a badge belonging to some
    other section, which is exactly the confusion these tri-state tests exist
    to rule out.
    """
    m = re.search(rf"<h2>{re.escape(heading)}</h2>(.*?)(?=<div class=\"section\"|\Z)",
                  text, re.S)
    assert m, f"no section headed {heading!r}"
    return m.group(1)


def row_cells(text, first_cell):
    """Return the <td> texts of the table row whose first cell is `first_cell`."""
    for tr in re.finditer(r"<tr[^>]*>(.*?)</tr>", text, re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", tr.group(1), re.S)
        if cells and cells[0] == first_cell:
            return cells
    raise AssertionError(
        f"no table row whose first cell is {first_cell!r}; "
        f"rows found: {re.findall(r'<td[^>]*>(.*?)</td>', text, re.S)!r}"
    )


def speed_values(text):
    """Return (download, upload) as rendered in the Speed Test section."""
    dl = re.search(r"Download:\s*<strong>(.*?)</strong>", text, re.S)
    ul = re.search(r"Upload:\s*<strong>(.*?)</strong>", text, re.S)
    assert dl and ul, "Speed Test section did not render both measurements"
    return dl.group(1), ul.group(1)


# ---------------------------------------------------------------------------
# Well-formedness checking
# ---------------------------------------------------------------------------

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}


class _TagBalance(HTMLParser):
    """Records every place a close tag does not match the innermost open tag."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID_ELEMENTS:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in VOID_ELEMENTS:
            return
        if not self.stack:
            self.errors.append(f"</{tag}> with nothing open")
        elif self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f"</{tag}> closes <{self.stack[-1]}>")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass


def tag_errors(text):
    parser = _TagBalance()
    parser.feed(text)
    parser.close()
    return parser.errors + [f"<{t}> never closed" for t in parser.stack]


# ---------------------------------------------------------------------------
# Realistic states used by more than one test
# ---------------------------------------------------------------------------

RICH_STATE = {
    "timestamp": "2026-06-10T14:30:00+00:00",
    "gateway": "192.168.1.1",
    "router_open_ports": [53, 80, 443, 23],
    "dns": ["192.168.1.1", "1.1.1.1"],
    "devices": [
        {"ip": "192.168.1.1", "mac": "3c:37:86:1a:2b:0c",
         "vendor": "NETGEAR", "subnet": "192.168.1.0/24"},
        {"ip": "192.168.1.42", "mac": "a4:83:e7:9f:11:d2",
         "vendor": "Apple, Inc.", "subnet": "192.168.1.0/24"},
    ],
    "wifi": {"ssid": "Stuklis-5G", "auth": "WPA3 Personal",
             "risk": "OK", "note": "WPA3 — current best practice."},
    "arp_spoof": {"gateway": "192.168.1.1",
                  "macs_seen": ["3c:37:86:1a:2b:0c"],
                  "spoofing_suspected": False},
    "firewall": {"enabled": True, "stealth_mode": True, "block_all": False,
                 "note": "Enabled with stealth mode — good configuration."},
    "sharing": [
        {"name": "Remote Login (SSH)", "enabled": False,
         "risk": "OK", "note": "Disabled."},
        {"name": "mDNS / Bonjour", "enabled": True,
         "risk": "INFO", "note": "Normal on a home LAN."},
    ],
    "default_creds": {"successes": []},
    "speed_download_mbps": 94.3,
    "speed_upload_mbps": 18.7,
    "upnp": {"mappings": [
        {"ext_port": 32400, "protocol": "TCP", "int_ip": "192.168.1.42",
         "int_port": 32400, "description": "Plex Media Server"},
    ]},
    "dhcp": {"responders": [{"ip": "192.168.1.1", "offered_ip": "192.168.1.87"}]},
    "listening": [{"port": 5000, "proto": "TCP", "process": "ControlCenter"}],
    "router_hostname": {"gateway": "192.168.1.1", "hostname": "orbi.lan",
                        "note": "Hostname looks like a consumer router.",
                        "suspicious": False},
}

# One state per untrusted field, with the payload in exactly that field.
ESCAPING_CASES = [
    # The Gateway section (home_net_audit.py:1652) is the only _esc() call in
    # generate_html_report that nothing else in this suite exercises: every other
    # test feeds it a dotted quad, which escaping leaves untouched. Without this
    # case the _esc there could be deleted and the suite would stay green.
    ("gateway", {"gateway": PAYLOAD}),
    ("devices/vendor", {"devices": [{"ip": "192.168.1.42",
                                     "mac": "a4:83:e7:9f:11:d2",
                                     "vendor": PAYLOAD,
                                     "subnet": "192.168.1.0/24"}]}),
    ("devices/mac", {"devices": [{"ip": "192.168.1.42",
                                  "mac": PAYLOAD,
                                  "vendor": "Apple, Inc.",
                                  "subnet": "192.168.1.0/24"}]}),
    ("devices/ip", {"devices": [{"ip": PAYLOAD,
                                 "mac": "a4:83:e7:9f:11:d2",
                                 "vendor": "Apple, Inc.",
                                 "subnet": "192.168.1.0/24"}]}),
    ("devices/subnet", {"devices": [{"ip": "192.168.1.42",
                                     "mac": "a4:83:e7:9f:11:d2",
                                     "vendor": "Apple, Inc.",
                                     "subnet": PAYLOAD}]}),
    ("wifi/ssid", {"wifi": {"ssid": PAYLOAD, "auth": "WPA2 Personal",
                            "risk": "OK", "note": "Fine."}}),
    ("wifi/auth", {"wifi": {"ssid": "Stuklis-5G", "auth": PAYLOAD,
                            "risk": "REVIEW", "note": "Fine."}}),
    ("wifi/note", {"wifi": {"ssid": "Stuklis-5G", "auth": "WPA2 Personal",
                            "risk": "OK", "note": PAYLOAD}}),
    ("router_hostname/hostname", {"router_hostname": {
        "gateway": "192.168.1.1", "hostname": PAYLOAD,
        "note": "Reverse DNS returned a name.", "suspicious": False}}),
    ("router_hostname/note", {"router_hostname": {
        "gateway": "192.168.1.1", "hostname": "orbi.lan",
        "note": PAYLOAD, "suspicious": False}}),
    ("router_hostname/gateway", {"router_hostname": {
        "gateway": PAYLOAD, "hostname": "orbi.lan",
        "note": "Fine.", "suspicious": False}}),
    ("upnp/description", {"upnp": {"mappings": [
        {"ext_port": 32400, "protocol": "TCP", "int_ip": "192.168.1.42",
         "int_port": 32400, "description": PAYLOAD}]}}),
    ("arp_spoof/gateway", {"arp_spoof": {"gateway": PAYLOAD,
                                         "macs_seen": ["3c:37:86:1a:2b:0c"],
                                         "spoofing_suspected": False}}),
    ("arp_spoof/macs_seen", {"arp_spoof": {"gateway": "192.168.1.1",
                                           "macs_seen": [PAYLOAD],
                                           "spoofing_suspected": True}}),
    ("dns/server", {"dns": [PAYLOAD]}),
    ("firewall/note", {"firewall": {"enabled": True, "stealth_mode": True,
                                    "block_all": False, "note": PAYLOAD}}),
]


# ---------------------------------------------------------------------------
# _esc and _SafeHTML
# ---------------------------------------------------------------------------

class TestEsc:
    @pytest.mark.parametrize("raw,expected", [
        ("<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"),
        ("Tom & Jerry", "Tom &amp; Jerry"),
        ('say "hello"', "say &quot;hello&quot;"),
        ("it's fine", "it&#x27;s fine"),
        (PAYLOAD, ESCAPED_PAYLOAD),
        ("NETGEAR", "NETGEAR"),
    ], ids=["angle-brackets", "ampersand", "double-quote", "single-quote",
            "img-onerror", "harmless-passes-through"])
    def test_markup_characters_are_escaped(self, mod, raw, expected):
        assert mod._esc(raw) == expected

    def test_ampersand_is_escaped_before_the_brackets_it_introduces(self, mod):
        # Escaping < before & would produce &amp;lt; — double-escaped and wrong.
        assert mod._esc("&<") == "&amp;&lt;"

    @pytest.mark.parametrize("value,expected", [
        (42, "42"),
        (0, "0"),
        (3.5, "3.5"),
        (None, "None"),
        (True, "True"),
        (["<b>"], "[&#x27;&lt;b&gt;&#x27;]"),
    ], ids=["int", "zero", "float", "none", "bool", "list-repr"])
    def test_non_strings_are_coerced_then_escaped(self, mod, value, expected):
        assert mod._esc(value) == expected

    def test_object_whose_str_returns_markup_is_still_escaped(self, mod):
        class Sneaky:
            def __str__(self):
                return PAYLOAD

        assert mod._esc(Sneaky()) == ESCAPED_PAYLOAD

    def test_escaping_is_idempotent_only_by_re_escaping_the_entity(self, mod):
        # Documents that _esc is not idempotent: callers must escape exactly
        # once, which is why risk_badge marks its output _SafeHTML instead.
        assert mod._esc(mod._esc("<b>")) == "&amp;lt;b&amp;gt;"


class TestSafeHTMLPassthrough:
    def test_safehtml_is_a_str_subclass(self, mod):
        assert issubclass(mod._SafeHTML, str)
        assert mod._SafeHTML("<b>x</b>") == "<b>x</b>"

    def test_safehtml_passes_through_esc_unchanged(self, mod):
        markup = '<span style="background:#e74c3c">HIGH</span>'
        assert mod._esc(mod._SafeHTML(markup)) == markup

    def test_safehtml_is_returned_as_the_same_object(self, mod):
        marked = mod._SafeHTML("<b>x</b>")
        assert mod._esc(marked) is marked

    def test_a_plain_str_with_identical_content_is_escaped(self, mod):
        # The passthrough must key on the _SafeHTML type, not on the content;
        # otherwise every string that looks like a badge would be trusted.
        markup = '<span style="background:#e74c3c">HIGH</span>'
        assert mod._esc(markup) != markup
        assert "&lt;span" in mod._esc(markup)

    def test_safehtml_carrying_a_payload_is_trusted_by_design(self, mod):
        # Not a bug: _SafeHTML is the "I built this markup myself" marker. This
        # pins the contract so a future refactor cannot quietly start escaping
        # it (which would render risk badges as visible tag soup).
        assert mod._esc(mod._SafeHTML(PAYLOAD)) == PAYLOAD

    def test_risk_badges_reach_the_report_as_live_markup(self, mod, tmp_path):
        text = render(mod, tmp_path, {"firewall": {"enabled": True,
                                                   "stealth_mode": True,
                                                   "note": "Good."}})
        assert '<span style="background:' in text
        assert "&lt;span" not in text, "risk badge was escaped instead of passed through"


# ---------------------------------------------------------------------------
# Escaping of untrusted fields
# ---------------------------------------------------------------------------

class TestUntrustedFieldEscaping:
    @pytest.mark.parametrize(
        "state", [case[1] for case in ESCAPING_CASES],
        ids=[case[0] for case in ESCAPING_CASES])
    def test_injected_markup_never_reaches_the_report_raw(self, mod, tmp_path, state):
        text = render(mod, tmp_path, state)
        assert PAYLOAD not in text
        assert ESCAPED_PAYLOAD in text, "payload vanished instead of being escaped"

    def test_an_escaped_payload_is_parsed_as_text_not_as_an_element(self, mod, tmp_path):
        text = render(mod, tmp_path, {"wifi": {"ssid": PAYLOAD, "auth": "WPA2",
                                               "risk": "OK", "note": "x"}})

        found = []

        class _ImgHunter(HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag == "img":
                    found.append(dict(attrs))

        parser = _ImgHunter()
        parser.feed(text)
        parser.close()
        assert found == [], "the SSID payload became a real <img> element"

    def test_quote_in_an_ssid_cannot_break_out_of_an_attribute(self, mod, tmp_path):
        ssid = '" onmouseover="alert(1)'
        text = render(mod, tmp_path, {"wifi": {"ssid": ssid, "auth": "WPA2",
                                               "risk": "OK", "note": "x"}})
        assert 'onmouseover="alert(1)' not in text
        assert "&quot; onmouseover=&quot;alert(1)" in text

    def test_a_vendor_name_with_an_ampersand_is_not_double_escaped(self, mod, tmp_path):
        # "AT&T" is a real macvendors.com response; over-escaping would show
        # "AT&amp;T" to the reader instead of "AT&T".
        text = render(mod, tmp_path, {"devices": [
            {"ip": "192.168.1.5", "mac": "00:1a:2b:3c:4d:5e",
             "vendor": "AT&T Inc.", "subnet": "192.168.1.0/24"}]})
        assert "<td>AT&amp;T Inc.</td>" in text
        assert "&amp;amp;" not in text


class TestUpnpNoteEscaping:
    def test_a_upnp_mapping_description_is_escaped(self, mod, tmp_path):
        text = render(mod, tmp_path, {"upnp": {"mappings": [
            {"ext_port": 8080, "protocol": "TCP", "int_ip": "192.168.1.9",
             "int_port": 80, "description": PAYLOAD}]}})
        assert PAYLOAD not in text

    def test_a_upnp_note_is_escaped(self, mod, tmp_path):
        # Fixed regression: the note was rendered as f'<p>{note}</p>' with no
        # _esc() call while every sibling interpolation went through _esc. The
        # note is built from the SOAP fault or error text the ROUTER returned,
        # so its content is chosen by the device under audit — raw
        # interpolation was markup injection into a report the owner is likely
        # to forward, from the one participant with a reason to shape it.
        text = render(mod, tmp_path, {"upnp": {"mappings": [], "note": PAYLOAD}})
        assert PAYLOAD not in text
        assert ESCAPED_PAYLOAD in text

    def test_the_default_upnp_note_is_used_when_none_is_supplied(self, mod, tmp_path):
        text = render(mod, tmp_path, {"upnp": {"mappings": []}})
        assert "No UPnP port mappings found." in text


# ---------------------------------------------------------------------------
# Tri-state fidelity: UNKNOWN must not be rendered as a definite answer
# ---------------------------------------------------------------------------

UNKNOWN_FIREWALL = {
    "enabled": None,
    "stealth_mode": None,
    "block_all": None,
    "note": "Could not determine firewall state (unexpected command output).",
}


class TestFirewallTriState:
    def test_an_enabled_firewall_renders_ok_and_on(self, mod, tmp_path):
        text = render(mod, tmp_path, {"firewall": {
            "enabled": True, "stealth_mode": True, "block_all": False,
            "note": "Enabled with stealth mode — good configuration."}})
        assert "Firewall: ON" in text
        assert "Stealth mode: ON" in text
        assert '<span style="background:#27ae60;' in text

    def test_a_disabled_firewall_renders_high_and_off(self, mod, tmp_path):
        text = render(mod, tmp_path, {"firewall": {
            "enabled": False, "stealth_mode": False, "block_all": False,
            "note": "Firewall is OFF. Enable it in System Settings."}})
        assert "Firewall: OFF" in text
        assert '<span style="background:#e74c3c;' in text

    def test_an_unknown_firewall_is_not_flagged_high(self, mod, tmp_path):
        # Fixed regression: the risk used to be `'OK' if fw.get('enabled') else
        # 'HIGH'`, collapsing the tri-state commit 4c349fd introduced — an
        # undetermined firewall (enabled=None) rendered as a red HIGH badge,
        # asserting it was off. Now REVIEW, matching action_firewall_check's
        # `'REVIEW' if fw['enabled'] is None else ...`.
        text = render(mod, tmp_path, {"firewall": dict(UNKNOWN_FIREWALL)})
        assert "#e74c3c" not in text, "unknown firewall state painted as a HIGH risk"
        assert ">HIGH</span>" not in text

    def test_an_unknown_firewall_does_not_claim_to_be_off(self, mod, tmp_path):
        # Fixed regression: rendered `{'ON' if fw.get('enabled') else 'OFF'}`,
        # so an undetermined firewall was reported to the reader as a definite
        # OFF while the terminal path printed UNKNOWN for the same value.
        text = render(mod, tmp_path, {"firewall": dict(UNKNOWN_FIREWALL)})
        assert "Firewall: OFF" not in text

    def test_an_unknown_stealth_mode_does_not_claim_to_be_off(self, mod, tmp_path):
        # Fixed regression: rendered `{'ON' if fw.get('stealth_mode') else
        # 'OFF'}`, so stealth_mode=None (unparseable socketfilterfw output) was
        # reported as a definite OFF.
        text = render(mod, tmp_path, {"firewall": dict(UNKNOWN_FIREWALL)})
        assert "Stealth mode: OFF" not in text


class TestSharingTriState:
    def test_an_enabled_service_renders_on(self, mod, tmp_path):
        text = render(mod, tmp_path, {"sharing": [
            {"name": "Remote Login (SSH)", "enabled": True,
             "risk": "REVIEW", "note": "SSH enabled."}]})
        assert row_cells(text, "Remote Login (SSH)")[1] == "ON"

    def test_a_disabled_service_renders_off(self, mod, tmp_path):
        text = render(mod, tmp_path, {"sharing": [
            {"name": "Remote Login (SSH)", "enabled": False,
             "risk": "OK", "note": "Disabled."}]})
        assert row_cells(text, "Remote Login (SSH)")[1] == "OFF"

    def test_an_enabled_services_row_is_tinted_with_its_risk_colour(self, mod, tmp_path):
        text = render(mod, tmp_path, {"sharing": [
            {"name": "Screen Sharing / VNC", "enabled": True,
             "risk": "HIGH", "note": "Screen visible to anyone with credentials."}]})
        assert 'style="background:#e74c3c22"' in text

    def test_an_unknown_service_is_not_rendered_as_a_definite_off(self, mod, tmp_path):
        # Fixed regression: rendered `'ON' if s['enabled'] else 'OFF'`, so a
        # service whose state could not be determined (Remote Apple Events
        # without sudo sets enabled=None) was reported as a definite OFF while
        # action_sharing_services printed '?' for the same value. Observed on a
        # real run: the terminal showed "[UNKNOWN] ? Remote Apple Events" while
        # the report for that same run would have said "OFF".
        text = render(mod, tmp_path, {"sharing": [
            {"name": "Remote Apple Events", "enabled": None, "risk": "UNKNOWN",
             "note": "Unknown — re-run this audit with sudo to determine its state."}]})
        assert row_cells(text, "Remote Apple Events")[1] != "OFF"

    def test_an_unknown_service_reads_differently_from_a_disabled_one(self, mod, tmp_path):
        # Fixed regression: enabled=None and enabled=False shared one 'OFF'
        # cell, so a reader could not tell a service that is genuinely disabled
        # from one the audit was never able to inspect.
        text = render(mod, tmp_path, {"sharing": [
            {"name": "Remote Apple Events", "enabled": None, "risk": "UNKNOWN",
             "note": "Unknown — re-run with sudo."},
            {"name": "Remote Login (SSH)", "enabled": False,
             "risk": "OK", "note": "Disabled."},
        ]})
        unknown = row_cells(text, "Remote Apple Events")[1]
        disabled = row_cells(text, "Remote Login (SSH)")[1]
        assert unknown != disabled


class TestSpeedTest:
    def test_a_real_measurement_renders_to_one_decimal(self, mod, tmp_path):
        text = render(mod, tmp_path, {"speed_download_mbps": 94.27,
                                      "speed_upload_mbps": 18.75})
        assert speed_values(text) == ("94.3 Mbps", "18.8 Mbps")

    def test_a_failed_measurement_renders_na(self, mod, tmp_path):
        text = render(mod, tmp_path, {"speed_download_mbps": None,
                                      "speed_upload_mbps": None})
        assert speed_values(text) == ("n/a", "n/a")

    @pytest.mark.parametrize("state,index", [
        ({"speed_download_mbps": 0.04, "speed_upload_mbps": 18.7}, 0),
        ({"speed_download_mbps": 94.3, "speed_upload_mbps": 0.04}, 1),
    ], ids=["download", "upload"])
    def test_a_near_zero_measurement_is_still_reported_as_a_measurement(
            self, mod, tmp_path, state, index):
        # The genuine near-zero edge of the truthiness test at lines 1742-1743.
        # 0.04 Mbps rounds to "0.0 Mbps" under :.1f but must NOT collapse to
        # "n/a": a link that measured almost nothing is a finding, whereas "n/a"
        # means the test never produced a number at all.
        #
        # An exact 0.0 is deliberately not tested: it is unreachable. speed_test
        # is the only producer of these fields (state is built in-session at
        # lines 2111/2273 and set at 2177-2178 / 2352-2353; load_baseline output
        # never reaches the report). _download only returns a value under
        # `if elapsed > 0 and total > 0` (line 464) and otherwise returns None
        # (line 468); _upload divides a fixed 5_000_000-byte payload (line 472)
        # and is likewise None or strictly positive. For every reachable value
        # `if dl` and `if dl is not None` behave identically.
        text = render(mod, tmp_path, state)
        assert speed_values(text)[index] == "0.0 Mbps"

    def test_a_near_zero_measurement_is_distinguishable_from_a_failure(
            self, mod, tmp_path):
        measured = render(mod, tmp_path, {"speed_download_mbps": 0.04,
                                          "speed_upload_mbps": 0.04}, "near_zero.html")
        failed = render(mod, tmp_path, {"speed_download_mbps": None,
                                        "speed_upload_mbps": None}, "none.html")
        assert speed_values(measured) != speed_values(failed)

    def test_the_section_is_keyed_off_the_download_field_only(self, mod, tmp_path):
        # Upload alone renders nothing: line 1739 gates on "speed_download_mbps".
        text = render(mod, tmp_path, {"speed_upload_mbps": 18.7})
        assert "<h2>Speed Test</h2>" not in text


# ---------------------------------------------------------------------------
# Secret redaction (commit 9db3ab7)
# ---------------------------------------------------------------------------

class TestSecretRedaction:
    SUCCESSES = [("admin", "hunter2", 80, "Basic Auth")]

    def test_an_accepted_password_never_reaches_the_report_file(self, mod, tmp_path):
        # The report is a shareable file; the accepted password is shown in the
        # terminal only (home_net_audit.py:1729-1731).
        text = render(mod, tmp_path,
                      {"default_creds": {"successes": list(self.SUCCESSES)}})
        assert "hunter2" not in text

    def test_the_password_is_absent_from_the_raw_bytes_too(self, mod, tmp_path):
        out = tmp_path / "creds.html"
        mod.generate_html_report(
            {"default_creds": {"successes": list(self.SUCCESSES)}}, str(out))
        assert b"hunter2" not in out.read_bytes()

    @pytest.mark.parametrize("expected", [
        "<td>admin</td>", "<td>80</td>", "<td>Basic Auth</td>",
    ], ids=["username", "port", "method"])
    def test_the_non_secret_columns_are_still_reported(self, mod, tmp_path, expected):
        text = render(mod, tmp_path,
                      {"default_creds": {"successes": list(self.SUCCESSES)}})
        assert expected in text

    def test_the_password_column_says_the_value_was_withheld(self, mod, tmp_path):
        text = render(mod, tmp_path,
                      {"default_creds": {"successes": list(self.SUCCESSES)}})
        assert row_cells(text, "admin")[1] == "(accepted — shown in terminal only)"

    def test_an_accepted_credential_is_flagged_high(self, mod, tmp_path):
        text = render(mod, tmp_path,
                      {"default_creds": {"successes": list(self.SUCCESSES)}})
        assert "Default credentials accepted!" in text
        assert '<span style="background:#e74c3c;' in text

    def test_no_successes_without_coverage_does_not_claim_a_clean_result(self, mod,
                                                                        tmp_path):
        # This used to badge OK on "No default credentials accepted." alone. A
        # record with no coverage predates the tracking, so whether anything was
        # ever submitted is unknown — and unknown must not render as a pass in
        # the artefact most likely to be read by someone who did not run it.
        text = render(mod, tmp_path, {"default_creds": {"successes": []}})
        assert "is unknown" in text
        assert '<span style="background:#27ae60;' not in text

    def test_credentials_actually_submitted_and_refused_renders_a_pass(self, mod,
                                                                      tmp_path):
        text = render(mod, tmp_path, {"default_creds": {
            "successes": [],
            "coverage": {"attempts": 12, "open": [80], "blocked": [], "closed": []}}})
        assert "every one was refused" in text
        assert '<span style="background:#27ae60;' in text

    def test_a_probe_that_found_nothing_to_try_is_not_a_pass(self, mod, tmp_path):
        text = render(mod, tmp_path, {"default_creds": {
            "successes": [],
            "coverage": {"attempts": 0, "open": [], "blocked": [],
                         "closed": [80, 8080, 8443, 443]}}})
        assert "no credentials were tested" in text
        assert '<span style="background:#27ae60;' not in text

    def test_a_password_containing_markup_is_still_withheld(self, mod, tmp_path):
        text = render(mod, tmp_path, {"default_creds": {
            "successes": [("admin", PAYLOAD, 8080, "Form POST")]}})
        assert PAYLOAD not in text
        assert ESCAPED_PAYLOAD not in text, "the password leaked in escaped form"


# ---------------------------------------------------------------------------
# Document structure and file output
# ---------------------------------------------------------------------------

class TestOutputFile:
    def test_the_returned_path_is_the_file_that_was_written(self, mod, tmp_path):
        out = tmp_path / "audit.html"
        returned = mod.generate_html_report({"gateway": "192.168.1.1"}, str(out))
        assert returned == str(out)
        assert out.exists()
        assert "192.168.1.1" in out.read_text(encoding="utf-8")

    def test_missing_parent_directories_are_created(self, mod, tmp_path):
        out = tmp_path / "reports" / "2026" / "june" / "audit.html"
        assert not out.parent.exists()
        mod.generate_html_report({"gateway": "192.168.1.1"}, str(out))
        assert out.is_file()

    def test_an_existing_report_is_overwritten_not_appended(self, mod, tmp_path):
        out = tmp_path / "audit.html"
        mod.generate_html_report(dict(RICH_STATE), str(out))
        mod.generate_html_report({"gateway": "10.0.0.1"}, str(out))
        text = out.read_text(encoding="utf-8")
        assert text.count("<!DOCTYPE html>") == 1
        assert "Connected Devices" not in text

    # --- the default output path (home_net_audit.py:1606-1611) ---------------
    # Both production call sites — action_html_report (line 1832) and the
    # --html-report branch of main (line 2508) — call generate_html_report(state)
    # with no output_path, so this branch is the one users actually get. It
    # carries a security rationale in its own comment: reports land outside the
    # git repo, in the gitignored data dir, so a file full of MACs, topology and
    # accepted credentials cannot be committed by accident. The autouse sandbox
    # redirects BASELINE_DIR into tmp_path, so these stay hermetic.

    def test_no_output_path_writes_into_the_gitignored_data_dir(self, mod, tmp_path):
        path = mod.generate_html_report({"gateway": "192.168.1.1"})
        reports_dir = os.path.join(mod.BASELINE_DIR, "reports")
        assert os.path.dirname(path) == reports_dir
        assert os.path.isfile(path)

    def test_the_default_basename_matches_the_gitignore_rule(self, mod, tmp_path):
        # .gitignore excludes "audit_report_*.html". Renaming the prefix here
        # would silently make every generated report committable, which is the
        # exact accident the default path exists to prevent.
        name = os.path.basename(mod.generate_html_report({"gateway": "192.168.1.1"}))
        assert fnmatch.fnmatch(name, "audit_report_*.html")

    def test_the_default_basename_is_timestamped_to_the_second(self, mod, tmp_path):
        # Two reports generated in one session must not clobber each other.
        name = os.path.basename(mod.generate_html_report({"gateway": "192.168.1.1"}))
        assert re.fullmatch(r"audit_report_\d{8}_\d{6}\.html", name)

    def test_the_file_is_written_as_utf8(self, mod, tmp_path):
        out = tmp_path / "audit.html"
        mod.generate_html_report({"wifi": {"ssid": "Café-5G", "auth": "WPA3",
                                           "risk": "OK", "note": "ok"}}, str(out))
        assert "Café-5G" in out.read_text(encoding="utf-8")
        assert "🏠".encode("utf-8") in out.read_bytes()


class TestDocumentStructure:
    def test_the_document_starts_with_a_doctype(self, mod, tmp_path):
        assert render(mod, tmp_path, dict(RICH_STATE)).startswith("<!DOCTYPE html>")

    def test_the_title_carries_the_report_date(self, mod, tmp_path):
        text = render(mod, tmp_path, dict(RICH_STATE))
        title = re.search(r"<title>(.*?)</title>", text, re.S)
        assert title is not None
        assert "Home Network Audit Report" in title.group(1)
        # The template slices the ISO timestamp to its date component.
        assert "2026-06-10" in title.group(1)
        assert "14:30" not in title.group(1)

    def test_every_tag_is_balanced(self, mod, tmp_path):
        assert tag_errors(render(mod, tmp_path, dict(RICH_STATE))) == []

    def test_every_tag_is_balanced_when_untrusted_input_is_hostile(self, mod, tmp_path):
        hostile = {
            "devices": [{"ip": PAYLOAD, "mac": "</td></tr></table><script>x</script>",
                         "vendor": '"><b>', "subnet": "192.168.1.0/24"}],
            "wifi": {"ssid": "</body></html>", "auth": PAYLOAD,
                     "risk": "OK", "note": "<!-- comment -->"},
        }
        assert tag_errors(render(mod, tmp_path, hostile)) == []

    def test_table_open_and_close_counts_match(self, mod, tmp_path):
        text = render(mod, tmp_path, dict(RICH_STATE))
        assert text.count("<table>") == text.count("</table>")
        assert text.count("<table>") > 1, "rich state should render several tables"

    def test_each_table_row_has_as_many_cells_as_the_header(self, mod, tmp_path):
        # Scoped per table rather than over the whole document. A device list
        # carrying vendor names now also renders the provenance table — the
        # vendors were fetched from a third party whatever else the run did — so
        # collecting every <th> on the page mixed two headers into one list.
        # Comparing each table against its own header is what this is for.
        text = render(mod, tmp_path, {"devices": RICH_STATE["devices"]})
        tables = re.findall(r"<table>(.*?)</table>", text, re.S)
        assert tables, "expected at least one table"
        seen = []
        for tbl in tables:
            headers = re.findall(r"<th>(.*?)</th>", tbl, re.S)
            seen.append(headers)
            for tr in re.finditer(r"<tr[^>]*>(.*?)</tr>", tbl, re.S):
                cells = re.findall(r"<td[^>]*>", tr.group(1))
                if cells:
                    assert len(cells) == len(headers)
        assert ["IP", "MAC", "Vendor", "Subnet"] in seen

    def test_the_charset_is_declared_before_any_content(self, mod, tmp_path):
        text = render(mod, tmp_path, dict(RICH_STATE))
        assert text.index('<meta charset="UTF-8">') < text.index("<body>")


class TestSectionSelection:
    def test_an_empty_state_still_produces_a_valid_document(self, mod, tmp_path):
        text = render(mod, tmp_path, {})
        assert text.startswith("<!DOCTYPE html>")
        assert "</html>" in text
        assert tag_errors(text) == []

    def test_an_empty_state_renders_no_sections(self, mod, tmp_path):
        text = render(mod, tmp_path, {})
        assert 'class="section"' not in text
        assert "<h2>" not in text

    def test_an_empty_state_keeps_the_report_chrome(self, mod, tmp_path):
        # The behaviour is "the surrounding document survives when there are no
        # sections", so assert on the chrome's structure rather than on the
        # wording of the heading and footer, which a copy edit may change.
        text = render(mod, tmp_path, {})
        assert "<h1>" in text
        assert 'class="footer"' in text

    ALL_HEADINGS = [
        "Gateway", "Router Open Ports", "DNS Settings", "Connected Devices",
        "Wi-Fi Security", "ARP Spoofing Check", "Firewall Status",
        "Sharing Services", "Default Credentials Probe", "Speed Test",
        "UPnP Port Mappings", "Rogue DHCP Check", "Listening Services",
        "Router Hostname Check",
        # Renders whenever the run produced any finding the gateway supplied.
        # RICH_STATE holds several (upnp, default_creds, router_hostname, and
        # devices carrying vendor names), so dropping any single key below still
        # leaves this section standing and the count arithmetic holds.
        "Evidence Provenance",
    ]

    def test_a_full_state_renders_every_section(self, mod, tmp_path):
        text = render(mod, tmp_path, dict(RICH_STATE))
        missing = [h for h in self.ALL_HEADINGS if f"<h2>{h}</h2>" not in text]
        assert missing == []

    @pytest.mark.parametrize("key,heading", [
        ("gateway", "Gateway"),
        ("router_open_ports", "Router Open Ports"),
        ("dns", "DNS Settings"),
        ("devices", "Connected Devices"),
        ("wifi", "Wi-Fi Security"),
        ("arp_spoof", "ARP Spoofing Check"),
        ("firewall", "Firewall Status"),
        ("sharing", "Sharing Services"),
        ("default_creds", "Default Credentials Probe"),
        ("speed_download_mbps", "Speed Test"),
        ("upnp", "UPnP Port Mappings"),
        ("dhcp", "Rogue DHCP Check"),
        ("listening", "Listening Services"),
        ("router_hostname", "Router Hostname Check"),
    ])
    def test_a_section_is_absent_when_its_key_is_absent(self, mod, tmp_path,
                                                        key, heading):
        state = {k: v for k, v in RICH_STATE.items() if k != key}
        text = render(mod, tmp_path, state)
        assert f"<h2>{heading}</h2>" not in text
        assert text.count('class="section"') == len(self.ALL_HEADINGS) - 1

    def test_only_the_requested_section_is_rendered_in_isolation(self, mod, tmp_path):
        text = render(mod, tmp_path, {"gateway": "192.168.1.1"})
        assert text.count('class="section"') == 1
        assert "<h2>Gateway</h2>" in text

    def test_an_empty_open_ports_list_still_renders_the_section(self, mod, tmp_path):
        text = render(mod, tmp_path, {"router_open_ports": []})
        assert "<h2>Router Open Ports</h2>" in text
        assert "No open ports found." in text

    def test_an_empty_listening_list_renders_no_section_at_all(self, mod, tmp_path):
        # Asymmetry with router_open_ports above: line 1774 guards the whole
        # section on `if svcs:` rather than rendering an empty-state message, so
        # "we looked and found nothing" is indistinguishable from "we never
        # looked". Documented as actual behaviour, not xfailed — the intent is
        # ambiguous from the source alone.
        text = render(mod, tmp_path, {"listening": []})
        assert "<h2>Listening Services</h2>" not in text
        assert 'class="section"' not in text

    def test_no_dhcp_responders_reports_that_nothing_answered(self, mod, tmp_path):
        text = render(mod, tmp_path, {"dhcp": {"responders": []}})
        assert "No DHCP responses captured." in text

    def test_multiple_dhcp_responders_are_flagged_high(self, mod, tmp_path):
        text = render(mod, tmp_path, {"dhcp": {"responders": [
            {"ip": "192.168.1.1", "offered_ip": "192.168.1.87"},
            {"ip": "192.168.1.66", "offered_ip": "10.0.0.5"},
        ]}})
        assert "Multiple DHCP servers detected!" in text
        assert '<span style="background:#e74c3c;' in text
        assert "192.168.1.66" in text

    def test_suspected_arp_spoofing_adds_the_warning_paragraph(self, mod, tmp_path):
        text = render(mod, tmp_path, {"arp_spoof": {
            "gateway": "192.168.1.1",
            "macs_seen": ["3c:37:86:1a:2b:0c", "de:ad:be:ef:00:01"],
            "spoofing_suspected": True}})
        assert "possible ARP poisoning" in text
        assert "3c:37:86:1a:2b:0c, de:ad:be:ef:00:01" in text

    def test_no_macs_seen_renders_the_none_placeholder(self, mod, tmp_path):
        text = render(mod, tmp_path, {"arp_spoof": {"gateway": "192.168.1.1",
                                                    "macs_seen": [],
                                                    "spoofing_suspected": False}})
        assert "MACs seen: none" in text

    def test_a_missing_router_hostname_renders_the_none_placeholder(self, mod, tmp_path):
        text = render(mod, tmp_path, {"router_hostname": {
            "gateway": "192.168.1.1", "hostname": None,
            "note": "No reverse DNS record.", "suspicious": False}})
        assert "Hostname: (none)" in text

    def test_a_known_dns_provider_is_labelled_and_an_unknown_one_is_dashed(
            self, mod, tmp_path):
        text = render(mod, tmp_path, {"dns": ["1.1.1.1", "192.168.1.1"]})
        assert row_cells(text, "1.1.1.1")[1] == "Cloudflare"
        assert row_cells(text, "192.168.1.1")[1] == "—"

    def test_an_unlisted_open_port_is_described_as_needing_investigation(
            self, mod, tmp_path):
        text = render(mod, tmp_path, {"router_open_ports": [31337]})
        cells = row_cells(text, "31337")
        assert cells[0:2] == ["31337", "unknown"]
        assert cells[3] == "Investigate."

    def test_a_known_open_port_carries_its_catalogued_service_and_note(
            self, mod, tmp_path):
        # Pin the column mapping against the catalogue itself (line 1662 builds
        # the row as [port, service, badge, note]), not against the note's
        # wording — the behaviour under test is which cell gets which field.
        text = render(mod, tmp_path, {"router_open_ports": [23]})
        cells = row_cells(text, "23")
        assert cells[1] == mod.PORTS_OF_INTEREST[23][0]
        assert cells[3] == mod.PORTS_OF_INTEREST[23][2]

    def test_a_dhcp_server_ip_is_escaped_like_every_other_value(self, mod, tmp_path):
        """This was the one bare interpolation left in the function.

        It was deliberate and defensible at the time: the IP comes from a
        recvfrom() peer address, so a live run can only ever put a dotted quad
        there. The tripwire that used to sit here pinned that reasoning.

        It is escaped now because "where the value comes from" is not the whole
        story once it has been through the baseline. generate_html_report is
        called with state loaded from baseline.json, which is hand-editable
        file on disk that this module elsewhere assumes an attacker may have
        written — _split in diff_baseline is built entirely around surviving
        exactly that. An argument that holds for the live path and not the
        round-tripped one is not worth the single remaining exception.
        """
        text = render(mod, tmp_path, {"dhcp": {"responders": [
            {"ip": PAYLOAD, "offered_ip": "192.168.1.87"}]}})
        assert PAYLOAD not in text
        assert ESCAPED_PAYLOAD in text


class TestEveryCheckFamilyReachesTheFile:
    """Six families were populated by the audit and rendered nowhere.

    generate_html_report carried fifteen hand-written `if "<key>" in state`
    sections while action_full_audit populated twenty-one keys. The evil-twin
    check, IPv6 router advertisements, DNS interception, the trust store, the
    router certificate and the upstream modem's ports appeared in none of them
    — and four of those can return HIGH.

    So a run with a rogue Router Advertisement and intercepted port 53 printed
    two HIGH findings in the terminal and produced a file containing neither,
    while the provenance footer still counted them among the findings resting
    on "measurements this tool made itself". This file is the artefact people
    forward to someone else; it was the one that lied.
    """

    @pytest.mark.parametrize("state,heading,expected", [
        ({"evil_twin": {"ssid": "HomeNet", "risk": "HIGH", "bssids": ["aa:bb:cc:dd:ee:ff"],
                        "unexpected": ["aa:bb:cc:dd:ee:ff"],
                        "note": "advertised by a second AP"}},
         "Evil Twin Check", "advertised by a second AP"),
        ({"ipv6": {"risk": "HIGH", "routers": ["fe80::bad%en0"],
                   "note": "a rogue Router Advertisement"}},
         "IPv6 Router Advertisements", "rogue Router Advertisement"),
        ({"interception": {"dns_interception": {"risk": "HIGH",
                                                "note": "10.0.0.9 answered a DNS query"}}},
         "Interception Checks", "answered a DNS query"),
        ({"interception": {"trust_store": {"risk": "HIGH", "entries": ["Corporate Proxy Root CA"],
                                           "note": "an added root certificate"}}},
         "Interception Checks", "Corporate Proxy Root CA"),
        ({"router_tls": {"present": True, "sha256": "a" * 64}},
         "Router Certificate", "a" * 64),
        ({"upstream_open_ports": [23]},
         "Upstream Modem Ports", "faces the internet"),
        ({"dsl": {"downstream_kbps": 17000, "upstream_kbps": 1000,
                  "downstream_snr_db": 9, "upstream_snr_db": 8}},
         "DSL Line", "17000"),
    ], ids=["evil_twin", "ipv6", "dns_interception", "trust_store",
            "router_tls", "upstream_ports", "dsl"])
    def test_the_section_is_rendered(self, mod, tmp_path, state, heading, expected):
        text = render(mod, tmp_path, state)
        assert f"<h2>{heading}</h2>" in text
        assert expected in text

    def test_a_high_finding_is_badged_high_in_the_file(self, mod, tmp_path):
        text = render(mod, tmp_path, {"ipv6": {"risk": "HIGH", "routers": ["fe80::bad%en0"],
                                               "note": "rogue RA"}})
        assert "HIGH" in row_or_text(text, "IPv6 Router Advertisements")

    def test_an_unrendered_risk_bearing_key_is_reported_not_dropped(self, mod, tmp_path):
        # The guard that stops this recurring: a future check whose section
        # nobody wrote shows up as a finding about the report itself.
        text = render(mod, tmp_path, {"some_new_check": {"risk": "HIGH", "note": "x"}})
        assert "<h2>Not Included In This Report</h2>" in text
        assert "some_new_check" in text

    def test_a_rendered_key_does_not_trigger_the_guard(self, mod, tmp_path):
        text = render(mod, tmp_path, dict(RICH_STATE))
        assert "<h2>Not Included In This Report</h2>" not in text

    def test_bookkeeping_keys_do_not_trigger_the_guard(self, mod, tmp_path):
        text = render(mod, tmp_path, {"gateway": "192.168.1.1",
                                      "carried_forward": ["devices"],
                                      "measured_at": {"devices": "2026-08-01"}})
        assert "<h2>Not Included In This Report</h2>" not in text

    def test_an_ssid_in_an_unrendered_section_is_still_escaped(self, mod, tmp_path):
        text = render(mod, tmp_path, {"evil_twin": {"ssid": PAYLOAD, "risk": "HIGH",
                                                    "bssids": [], "unexpected": [],
                                                    "note": ""}})
        assert PAYLOAD not in text
        assert ESCAPED_PAYLOAD in text


class TestArpSpoofTriState:
    """`spoofing_suspected` is len(macs_seen) > 1 — False for two different things.

    Stable and never-observed both came out False and both badged green OK. And
    action_arp_spoof_check returns a bare {} when the gateway cannot be
    determined, which callers store unconditionally, so `"arp_spoof" in state`
    was true and a green OK rendered next to "Gateway: ?" for a check that never
    ran. The terminal has always returned early before its [OK] line.
    """

    def test_multiple_macs_is_high(self, mod, tmp_path):
        text = render(mod, tmp_path, {"arp_spoof": {
            "gateway": "192.168.1.1", "macs_seen": ["a", "b"],
            "spoofing_suspected": True}})
        assert "HIGH" in row_or_text(text, "ARP Spoofing Check")

    def test_one_mac_seen_is_ok(self, mod, tmp_path):
        text = render(mod, tmp_path, {"arp_spoof": {
            "gateway": "192.168.1.1", "macs_seen": ["a4:83:e7:01:01:01"],
            "spoofing_suspected": False}})
        section = row_or_text(text, "ARP Spoofing Check")
        assert "OK" in section and "HIGH" not in section

    def test_no_macs_at_all_is_review_not_ok(self, mod, tmp_path):
        text = render(mod, tmp_path, {"arp_spoof": {
            "gateway": "192.168.1.1", "macs_seen": [], "spoofing_suspected": False}})
        section = row_or_text(text, "ARP Spoofing Check")
        assert "REVIEW" in section
        assert "nothing was compared" in section

    def test_an_empty_result_dict_is_review(self, mod, tmp_path):
        # What action_arp_spoof_check returns when there is no gateway at all.
        text = render(mod, tmp_path, {"arp_spoof": {}})
        assert "REVIEW" in row_or_text(text, "ARP Spoofing Check")


class TestRogueDhcpReportsWhetherItRan:
    """Binding port 68 needs root, so this is the default non-sudo outcome.

    action_rogue_dhcp returns {"responders": [], "error": ...} for the
    permission and Local-Network-denial paths, and the report read only
    `responders` — rendering "No DHCP responses captured." That is a statement
    about the network, made by a check that never sent a packet. The "error"
    key had two producers in the module and no consumer anywhere.
    """

    def test_a_check_that_could_not_run_says_so(self, mod, tmp_path):
        text = render(mod, tmp_path, {"dhcp": {
            "responders": [], "error": "Needs root to bind port 68"}})
        section = row_or_text(text, "Rogue DHCP Check")
        assert "REVIEW" in section
        assert "Needs root" in section
        assert "No DHCP responses captured" not in section

    def test_a_genuine_empty_result_still_reads_as_clean(self, mod, tmp_path):
        text = render(mod, tmp_path, {"dhcp": {"responders": []}})
        assert "No DHCP responses captured" in row_or_text(text, "Rogue DHCP Check")


class TestReportFilePermissions:
    """The same data the baseline is protected at 0600 for.

    MACs, topology, hostnames, the SSID and which credential/port/method
    combinations the router accepted — written 0644 into a 0755 directory,
    readable by every account on the machine. _secure_dir was reachable only
    from a baseline or history write, so `--html-report --no-save-baseline`
    never called it at all.
    """

    def test_the_report_is_not_world_readable(self, mod, tmp_path):
        path = render_path(mod, tmp_path, {"gateway": "192.168.1.1"})
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    def test_the_reports_directory_is_not_world_readable(self, mod, tmp_path):
        path = render_path(mod, tmp_path, {"gateway": "192.168.1.1"})
        assert oct(os.stat(os.path.dirname(path)).st_mode & 0o777) == "0o700"

    def test_an_existing_world_readable_report_is_tightened(self, mod, tmp_path):
        path = render_path(mod, tmp_path, {"gateway": "192.168.1.1"})
        os.chmod(path, 0o644)
        mod.generate_html_report({"gateway": "192.168.1.1"}, output_path=path)
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


class TestRiskBadgeColours:
    @pytest.mark.parametrize("risk,colour", [
        ("HIGH", "#e74c3c"),
        ("MEDIUM", "#e67e22"),
        ("REVIEW", "#f39c12"),
        ("INFO", "#3498db"),
        ("OK", "#27ae60"),
        ("GOOD", "#27ae60"),
        ("UNKNOWN", "#95a5a6"),
    ], ids=["high-red", "medium-orange", "review-amber", "info-blue",
            "ok-green", "good-green", "unknown-grey"])
    def test_each_known_risk_maps_to_its_colour(self, mod, tmp_path, risk, colour):
        text = render(mod, tmp_path, {"wifi": {"ssid": "Stuklis-5G",
                                               "auth": "WPA2 Personal",
                                               "risk": risk, "note": "n"}})
        assert f'<span style="background:{colour};' in text
        assert f">{risk}</span>" in text

    def test_the_risk_name_is_matched_case_insensitively(self, mod, tmp_path):
        # RISK_COLOUR is keyed in upper case and the lookup upper-cases first.
        text = render(mod, tmp_path, {"wifi": {"ssid": "Stuklis-5G",
                                               "auth": "WPA2 Personal",
                                               "risk": "high", "note": "n"}})
        assert '<span style="background:#e74c3c;' in text
        assert ">high</span>" in text

    @pytest.mark.parametrize("risk", ["BANANA", "", "  ", "0"],
                             ids=["unlisted", "empty", "whitespace", "zero-str"])
    def test_an_unmapped_risk_falls_back_to_grey_without_raising(
            self, mod, tmp_path, risk):
        text = render(mod, tmp_path, {"wifi": {"ssid": "Stuklis-5G",
                                               "auth": "WPA2 Personal",
                                               "risk": risk, "note": "n"}})
        assert '<span style="background:#95a5a6;' in text

    def test_a_non_string_risk_falls_back_to_grey_without_raising(self, mod, tmp_path):
        text = render(mod, tmp_path, {"wifi": {"ssid": "Stuklis-5G",
                                               "auth": "WPA2 Personal",
                                               "risk": None, "note": "n"}})
        assert '<span style="background:#95a5a6;' in text
        assert ">None</span>" in text

    def test_markup_in_a_risk_name_is_escaped_inside_the_badge(self, mod, tmp_path):
        text = render(mod, tmp_path, {"wifi": {"ssid": "Stuklis-5G",
                                               "auth": "WPA2 Personal",
                                               "risk": PAYLOAD, "note": "n"}})
        assert PAYLOAD not in text
        assert ESCAPED_PAYLOAD in text

    def test_an_open_port_row_is_tinted_with_its_risk_colour(self, mod, tmp_path):
        text = render(mod, tmp_path, {"router_open_ports": [23]})
        assert 'style="background:#e74c3c22"' in text
