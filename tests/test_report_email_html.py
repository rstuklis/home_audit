"""tools/report_email_html.py — the audit email dressed as the HTML report.

The renderer changes how the plain-text email looks, not what it says. These
tests hold it to that: every line of the text survives, in order, escaped; the
report's own markers (network banners, section rules, ratings) become the
bands, cards and badges of --html-report; and text chosen by a device on the
network — an announced name, say — can never become markup in the reader's
mail client.
"""

import html
import importlib.util
import re
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"


@pytest.fixture(scope="module")
def eh():
    spec = importlib.util.spec_from_file_location("report_email_html", TOOLS / "report_email_html.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["report_email_html"] = module
    spec.loader.exec_module(module)
    return module


REPORT = """
################################################################
# Home network audit — 2026-09-20 16:21:17 ACST
################################################################
TL;DR — computed by the audit script from its own results. Not written by an AI.
  Networks audited : 2 of 2   (loveshack, pearl)
    loveshack      CHANGES DETECTED   11 devices, 2 unidentified
    pearl          no changes         14 devices, 0 unidentified
  Flagged items    : 1 (1 MEDIUM) — 0 new since the previous report
    [MEDIUM] ROUTER / GATEWAY PORT SCAN · 80 HTTP admin Unencrypted web admin page.

VERSION CHECK
  Up to date with origin/master.

################################################################
# NETWORK: loveshack — 16:18:29   ip 192.168.87.25
################################################################

── ROUTER / GATEWAY PORT SCAN ──────────────────────────────────
  [INFO  ]    53  DNS            Router DNS resolver. Normal on the LAN side.
  [MEDIUM]    80  HTTP admin     Unencrypted web admin page. Prefer HTTPS for the admin UI.

── CONNECTED DEVICES ───────────────────────────────────────────
    192.168.87.28   da:6e:3f:91:5b:c0  (randomized/private MAC)  <-- unlabelled
    192.168.87.29   c4:f7:c1:10:53:b8  Apple TV  announces "<script>alert(1)</script>.local" [mdns]

── CHANGE DETECTION (vs saved baseline) ────────────────────────
  [OK    ] Baseline integrity: Seal verified with your passphrase.
CHANGES DETECTED:
  ! Device(s) gone since baseline: f4:a3:10:30:14:8c [iPhone (i-m-free)]

────────────────────────────────────────────────────────────────
Full audit complete. This is a snapshot, not a guarantee.
"""


def strip_tags(doc):
    return html.unescape(re.sub(r"<[^>]+>", "", doc))


def test_every_text_line_survives_in_order(eh):
    doc = eh.render(REPORT)
    text = strip_tags(doc)
    markers = ("####", "──", "# Home network audit", "# NETWORK:", "VERSION CHECK")
    wanted = [l for l in REPORT.splitlines() if l.strip() and not l.startswith(markers)]
    pos = 0
    for line in wanted:
        # A badge shows the rating without its brackets; the words are all kept.
        line = re.sub(r"\[(HIGH|MEDIUM|REVIEW|INFO|OK|UNKNOWN)\s*\]", r"\1", line.rstrip())
        found = text.find(line, pos)
        assert found >= 0, f"line missing or out of order: {line!r}"
        pos = found


def test_headings_become_title_cased_cards(eh):
    doc = eh.render(REPORT)
    headings = re.findall(r"<h2[^>]*>(.*?)</h2>", doc)
    # Exactly these: the bare rule before "Full audit complete." is a
    # separator, not a section, so it adds no card of its own.
    assert headings == [
        "TL;DR", "Version Check", "Router / Gateway Port Scan",
        "Connected Devices", "Change Detection (vs saved baseline)",
    ]


def test_network_banner_becomes_a_band_and_the_first_banner_the_page_date(eh):
    doc = eh.render(REPORT)
    band = re.search(r'<div style="[^"]*background:#0071e3[^"]*">(.*?)</div>', doc)
    assert band and "loveshack" in band.group(1)
    assert "16:18:29" in band.group(1) and "192.168.87.25" in band.group(1)
    assert "Generated: 2026-09-20 16:21:17 ACST" in doc
    assert "# Home network audit" not in strip_tags(doc)


def test_ratings_become_badges_in_the_report_palette(eh):
    doc = eh.render(REPORT)
    assert 'background:#e67e22' in doc and ">MEDIUM</span>" in doc
    assert 'background:#27ae60' in doc and ">OK</span>" in doc
    assert 'background:#3498db' in doc and ">INFO</span>" in doc
    assert "[OK    ]" not in doc and "[MEDIUM]" not in doc


def test_verdicts_are_coloured_wherever_they_appear(eh):
    doc = eh.render(REPORT)
    assert doc.count('color:#e74c3c;font-weight:700">CHANGES DETECTED') == 2  # TL;DR + section
    assert 'color:#27ae60;font-weight:700">no changes' in doc
    assert "&lt;-- unlabelled" in doc


BOXED_REPORT = """
================================================================
NETWORK INTERFACES
================================================================
Your Mac's primary IP : 192.168.1.10
Default gateway       : 192.168.1.1

================================================================
WI-FI SECURITY MODE
================================================================
  SSID (network name) : loveshack-H
  Risk                : [OK]

================================================================
Full audit complete. This is a snapshot, not a guarantee.
"""


def test_boxed_headers_of_a_plain_run_or_the_beach_variant(eh):
    """The beach-house repo still prints ==== / TITLE / ==== headers."""
    doc = eh.render(BOXED_REPORT)
    assert re.findall(r"<h2[^>]*>(.*?)</h2>", doc) == ["Network Interfaces", "Wi-Fi Security Mode"]
    text = strip_tags(doc)
    assert "=====" not in text
    assert "loveshack-H" in text and "Full audit complete." in text
    assert ">OK</span>" in doc


def test_device_chosen_text_is_never_markup(eh):
    doc = eh.render(REPORT)
    assert "<script>" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc


@pytest.mark.parametrize("raw, want", [
    ("ROUTER / GATEWAY PORT SCAN", "Router / Gateway Port Scan"),
    ("IPv6 ROUTER ADVERTISEMENTS", "IPv6 Router Advertisements"),
    ("UPnP PORT MAPPING DUMP", "UPnP Port Mapping Dump"),
    ("WI-FI SECURITY MODE", "Wi-Fi Security Mode"),
    ("DSL LINE STATS (TP-Link VX420-G2h)", "DSL Line Stats (TP-Link VX420-G2h)"),
    ("THIS MAC (re-checked on this network)", "This MAC (re-checked on this network)"),
    ("CHANGE DETECTION (vs saved baseline)", "Change Detection (vs saved baseline)"),
])
def test_title_case(eh, raw, want):
    assert eh.title_case(raw) == want


def test_cli_writes_the_document(eh, tmp_path, capsys):
    src = tmp_path / "r.txt"
    src.write_text(REPORT)
    assert eh.main(["report_email_html.py", str(src)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("<!DOCTYPE html>") and "Router / Gateway Port Scan" in out
