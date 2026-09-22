#!/usr/bin/env python3
"""Dress the plain-text audit email in the HTML report's clothes.

The emailed report is plain text, and stays plain text: it is the file the
audit wrote, with its change detection, integrity checks and TL;DR intact.
This script only changes how that text LOOKS in a mail client, borrowing the
styling of `--html-report` — the system font, the grey page, white rounded
cards, blue section headings and the coloured risk badges — so the Sunday
email reads like the report the user opens on a phone.

It is a renderer, not a summariser. Every line of the text goes into the HTML
in order; nothing is dropped, reworded or reordered. The text is grouped by the
markers the report already carries:

    ####…  # NETWORK: …  ####…    the wrapper's network banner  -> a blue band
    ── TITLE ──────────            a section header (--compact) -> a white card
    ====== / TITLE / ======        the boxed header of a plain run, and of the
                                   beach-house variant           -> the same card
    [MEDIUM] / [OK    ] / …        a rating                     -> a coloured badge

The body of each card is kept in a monospace face, because the report's port
lines and device lists are aligned by column and a proportional font would
undo that. Section headings and the page chrome use the system font, as the
HTML report does.

Mail clients are the hard part. Gmail drops a <style> block for some readers
and clips a message over about 100 KB, so the card and badge styles are inline
and the per-line markup is kept small. The plain text is always sent alongside
as the fallback part, so a client that shows no HTML loses nothing.

Stdlib only.

    report_email_html.py REPORT.txt > report.html
"""

import html
import re
import sys

# --- the palette of generate_html_report, kept identical on purpose ---------
PAGE_BG = "#f5f5f7"
TEXT = "#1d1d1f"
MUTED = "#86868b"
BLUE = "#0071e3"
RULE = "#d2d2d7"

RISK_COLOUR = {
    "HIGH": "#e74c3c",
    "MEDIUM": "#e67e22",
    "REVIEW": "#f39c12",
    "INFO": "#3498db",
    "OK": "#27ae60",
    "GOOD": "#27ae60",
    "UNKNOWN": "#95a5a6",
    "SKIP": "#95a5a6",
}

FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"

# Printing (Apple Mail's "Export as PDF", say) drops background colours
# unless asked to keep them; the badges are unreadable without theirs.
KEEP_COLOUR = "-webkit-print-color-adjust:exact;print-color-adjust:exact;"
CARD = (f"background:#ffffff;border-radius:12px;padding:20px 24px;"
        f"margin:0 0 20px 0;box-shadow:0 2px 8px rgba(0,0,0,0.08);")
# The page div sets the font and colour once; cards, headings and bands
# inherit them. Every byte here is repeated per card, and Gmail clips a message
# at about 100 KB, so these are kept to what cannot be inherited.
H2 = f"color:{BLUE};font-size:20px;font-weight:600;margin:0 0 12px 0;"
PRE = (f"font-family:{MONO};font-size:12.5px;line-height:1.5;margin:0;"
       f"white-space:pre-wrap;overflow-wrap:break-word;word-wrap:break-word;")
BAND = (f"background:{BLUE};color:#ffffff;border-radius:12px;{KEEP_COLOUR}"
        f"padding:14px 24px;margin:28px 0 20px 0;font-size:18px;font-weight:600;")
BAND_SUB = "font-weight:400;font-size:14px;opacity:0.85;"

BANNER_RE = re.compile(r"^#{20,}\s*$")
BANNER_TEXT_RE = re.compile(r"^#\s*(.*?)\s*$")
NETWORK_RE = re.compile(r"^NETWORK:\s*(.+?)\s*—\s*(\S+)\s*(?:ip\s+(\S+))?\s*$")
SECTION_RE = re.compile(r"^──\s*(.+?)\s*─+\s*$")
RULE_RE = re.compile(r"^─{20,}\s*$")
BOX_RE = re.compile(r"^={20,}\s*$")
# The report writes "[OK    ]" and "[MEDIUM]" alike: a rating padded to the
# widest one so its columns line up. The badge takes the same width back.
BADGE_RE = re.compile(r"\[(HIGH|MEDIUM|REVIEW|INFO|OK|GOOD|UNKNOWN|SKIP)\s*\]")
# The per-network verdict, wherever the report repeats it (the TL;DR puts it
# mid-line). Group 1 matches only the bad one.
VERDICT_RE = re.compile(r"(CHANGES DETECTED)|\bNO CHANGES\b|\bno changes\b")

# Words the section titles spell in capitals because they are not words.
ACRONYMS = {
    "arp", "dns", "dhcp", "dsl", "http", "https", "ip", "mac", "ssid", "tls",
    "vnc", "ssh", "smb", "url", "nbn", "wan", "lan", "ssdp", "bssid",
}
MIXED_CASE = {"ipv6": "IPv6", "upnp": "UPnP", "wi-fi": "Wi-Fi", "tl;dr": "TL;DR", "mdns": "mDNS"}
SMALL_WORDS = {"vs", "of", "the", "on", "a", "an", "and", "in", "for"}


def title_case(title):
    """'ROUTER / GATEWAY PORT SCAN' -> 'Router / Gateway Port Scan', keeping acronyms.

    The HTML report writes its headings in title case; the text report shouts
    them so they stand out in a terminal. Same words, quieter. Only words the
    report wrote in capitals are touched: "(re-checked on this network)" and
    "(TP-Link VX420-G2h)" already read as the author meant them.
    """
    out = []
    for word in title.split(" "):
        if word != word.upper():
            out.append(word)
            continue
        low = word.lower()
        core = low.strip("()")
        if core in MIXED_CASE:
            out.append(low.replace(core, MIXED_CASE[core]))
        elif core in ACRONYMS:
            out.append(word)
        elif core in SMALL_WORDS and out:
            out.append(low)
        else:
            out.append(low[:1].upper() + low[1:])
    return " ".join(out)


def badge(rating):
    colour = RISK_COLOUR.get(rating, RISK_COLOUR["UNKNOWN"])
    return (f'<span style="display:inline-block;min-width:60px;text-align:center;'
            f'background:{colour};color:#fff;padding:0 6px;border-radius:3px;'
            f'font-size:11px;font-weight:700;{KEEP_COLOUR}">{rating}</span>')


def mark_line(line):
    """One escaped line of body text, with its rating turned into a badge and
    the report's own emphasis kept: change lines red, unlabelled devices amber,
    file paths and closing remarks muted."""
    esc = html.escape(line)
    esc = BADGE_RE.sub(lambda m: badge(m.group(1)), esc)
    esc = VERDICT_RE.sub(
        lambda m: (f'<span style="color:{RISK_COLOUR["HIGH"] if m.group(1) else RISK_COLOUR["OK"]};'
                   f'font-weight:700">{m.group(0)}</span>'), esc)
    stripped = line.strip()
    if stripped.startswith("! "):
        return f'<span style="color:{RISK_COLOUR["HIGH"]};font-weight:700">{esc}</span>'
    if "&lt;-- unlabelled" in esc or "not in the baseline" in esc:
        return f'<span style="color:{RISK_COLOUR["MEDIUM"]};font-weight:700">{esc}</span>'
    if (stripped.startswith("Baseline saved to") or stripped.startswith("Baseline from:")
            or stripped.startswith("Full audit complete")):
        return f'<span style="color:{MUTED}">{esc}</span>'
    return esc


class _Page:
    """Accumulates cards; a card is a heading plus the lines under it."""

    def __init__(self):
        self.parts = []
        self.title = None
        self.lines = []

    def open(self, title):
        self.close()
        self.title = title

    def add(self, line):
        self.lines.append(line)

    def close(self):
        # Trim blank lines at either end; the card's padding does that job.
        lines = list(self.lines)
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        if self.title is None and not lines:
            self.title, self.lines = None, []
            return
        heading = f'<h2 style="{H2}">{html.escape(self.title)}</h2>' if self.title else ""
        body = "\n".join(mark_line(l) for l in lines)
        self.parts.append(f'<div style="{CARD}">{heading}<pre style="{PRE}">{body}</pre></div>')
        self.title, self.lines = None, []

    def band(self, name, when, ip):
        self.close()
        sub = f" &nbsp;·&nbsp; {html.escape(when)}" if when else ""
        if ip:
            sub += f" &nbsp;·&nbsp; {html.escape(ip)}"
        self.parts.append(
            f'<div style="{BAND}">{html.escape(name)}'
            f'<span style="{BAND_SUB}">{sub}</span></div>')


def render(text):
    """The full HTML document for one plain-text audit email."""
    lines = text.splitlines()
    page = _Page()
    generated = ""
    i = 0
    n = len(lines)
    seen_first_banner = False
    while i < n:
        line = lines[i]
        # A wrapper banner: ####… / # text / ####…
        if BANNER_RE.match(line) and i + 2 < n and BANNER_RE.match(lines[i + 2]):
            inner = BANNER_TEXT_RE.match(lines[i + 1])
            inner = inner.group(1) if inner else lines[i + 1].strip()
            m = NETWORK_RE.match(inner)
            if m:
                page.band(m.group(1), m.group(2), m.group(3))
            elif not seen_first_banner:
                # "Home network audit — 2026-09-20 16:21:17 ACST": the page's own
                # heading carries the title; the date goes under it.
                seen_first_banner = True
                generated = inner.split("—", 1)[1].strip() if "—" in inner else inner
                page.open(None)
            else:
                page.band(inner, "", "")
            i += 3
            continue
        if RULE_RE.match(line):
            i += 1
            continue
        m = SECTION_RE.match(line)
        if m:
            page.open(title_case(m.group(1)))
            i += 1
            continue
        # The boxed header (====== / TITLE / ======) of a plain run, and of the
        # beach-house variant, which predates the one-line style.
        if BOX_RE.match(line):
            if i + 2 < n and BOX_RE.match(lines[i + 2]) and lines[i + 1].strip():
                page.open(title_case(lines[i + 1].strip()))
                i += 3
            else:
                i += 1
            continue
        if line.startswith("TL;DR"):
            page.open("TL;DR")
            page.add(line)
            i += 1
            continue
        if line.startswith("VERSION CHECK") and not line.startswith("  "):
            page.open("Version Check")
            i += 1
            continue
        page.add(line)
        i += 1
    page.close()

    head_sub = html.escape(generated) if generated else ""
    body = "\n".join(page.parts)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home Network Audit Report</title>
</head>
<body style="margin:0;padding:0;background:{PAGE_BG};{KEEP_COLOUR}">
<div style="max-width:960px;margin:0 auto;padding:24px 16px;background:{PAGE_BG};font-family:{FONT};color:{TEXT};{KEEP_COLOUR}">
<h1 style="font-family:{FONT};color:{TEXT};font-size:26px;font-weight:700;border-bottom:3px solid {BLUE};padding-bottom:10px;margin:0 0 10px 0;">&#127968; Home Network Audit Report</h1>
<p style="font-family:{FONT};color:{TEXT};font-size:14px;margin:0 0 20px 0;">Generated: {head_sub} &nbsp;|&nbsp; Tool: home_net_audit.py</p>
{body}
<div style="font-family:{FONT};text-align:center;color:{MUTED};font-size:12px;margin-top:32px;">
  This is a point-in-time snapshot, not a guarantee of security.
  The plain-text version of this report is attached as the fallback part of this email.
</div>
</div>
</body>
</html>
"""


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8", errors="replace") as f:
        sys.stdout.write(render(f.read()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
