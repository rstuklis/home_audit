#!/usr/bin/env python3
"""
smsf_screener.py
================
A transparent, rule-based screener for ASX-listed investments, written for a
self-directed trustee of a Self-Managed Super Fund (SMSF) whose account is in
retirement phase and who deploys money in parcels of roughly AUD 10,000-25,000.

GENERAL INFORMATION ONLY. This program does not consider your objectives,
financial situation or needs, so it cannot and does not recommend anything. It
ranks products against explicit, printed rules that you can change, and shows
its arithmetic. Decisions about your fund remain yours as trustee, and some of
them (transfer balance cap, commutations, estate planning, Division 296) are
worth a licensed adviser's or an SMSF specialist's time.

Runs on the Python standard library only, like its sibling home_net_audit.py,
including the --fetch step (Yahoo Finance's public chart endpoint via urllib).
The third-party `yfinance` package is an optional alternative backend.

What it does
------------
1. Loads a hand-curated universe (smsf_universe.csv) of ASX-listed products
   with the static facts that free data sources do NOT provide reliably:
   management fee, fund size, typical franking level, growth/defensive split,
   structure and role. Every row carries an as-at date and the tool warns
   when it is stale.
2. Loads price and distribution history per ticker from CSV files:
       <data-dir>/<TICKER>.csv             date,close,volume
       <data-dir>/<TICKER>.dividends.csv   date,amount
   `--fetch` fills that directory from Yahoo Finance (no packages needed).
3. Computes, per product: last price, 1-year volatility and 3-year maximum
   drawdown on a distribution-adjusted (total-return) series, median daily
   value traded, trailing 12-month cash yield, and the grossed-up yield a 0%
   taxpayer actually receives once franking credits are refunded.
4. Applies hard filters and prints the reason for every exclusion.
5. Scores survivors 0-100 within their role with a visible component
   breakdown (`--explain TICKER` shows the arithmetic).
6. Shows what a parcel of AUD 10k and 25k buys (units, leftover, brokerage).
7. Optionally lays out an illustrative multi-parcel structure (`--illustrate`).

What it deliberately does not do
--------------------------------
* It does not pull fees, fund sizes or franking live. Those live in the CSV
  because no free, stable, machine-readable source exists for all of them.
* It does not compute a Listed Investment Company's premium or discount to net
  tangible assets; it flags every LIC so you check that by hand.
* It does not model your whole portfolio, your drawdown schedule or your tax
  position beyond "retirement phase = 0% on earnings and gains".

Acronyms used below:
  SMSF  = Self-Managed Super Fund
  ASX   = Australian Securities Exchange
  ETF   = Exchange-Traded Fund
  LIC   = Listed Investment Company
  MER   = Management Expense Ratio (annual fee as a percent of assets)
  NTA   = Net Tangible Assets (what a LIC's shares are worth per share)
  TTM   = Trailing Twelve Months
  APRA  = Australian Prudential Regulation Authority (bank regulator)
  AT1   = Additional Tier 1 capital (the bank "hybrids" APRA is phasing out)
  eTB   = Exchange-traded Treasury Bond (Commonwealth bond tradeable on ASX)
  ATO   = Australian Taxation Office
  ASIC  = Australian Securities and Investments Commission
  PDS   = Product Disclosure Statement
  DRP   = Distribution (or Dividend) Reinvestment Plan
  iNAV  = Indicative Net Asset Value (the fair price of an ETF unit intraday)
  CHESS = Clearing House Electronic Subregister System (ASX settlement)
  HIN   = Holder Identification Number (your CHESS-sponsored holding id)
  AUD   = Australian dollars
"""

from __future__ import annotations

import argparse
import csv
import http.client
import json
import math
import os
import re
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone

__version__ = "0.2.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DISCLAIMER = (
    "GENERAL INFORMATION ONLY - NOT PERSONAL FINANCIAL ADVICE.\n"
    "This screener applies fixed, printed rules to public data. It does not\n"
    "consider your objectives, financial situation or needs, and it does not\n"
    "recommend any product. Consider whether anything here is appropriate for\n"
    "you, read each product's PDS and target market determination, check every\n"
    "figure against the issuer's current documents, and record your own\n"
    "reasoning in the fund's investment strategy as SIS Regulation 4.09 requires."
)

ILLUSTRATION_NOTE = ("An illustration is an example of shape produced by fixed rules from the parcel size, "
                     "balance and age you typed in. It is not a recommendation and not personal advice.")

# Franking credits are refundable in full to a fund whose income is exempt
# current pension income. A dividend franked at the 30% company rate carries a
# credit of 30/70 of the cash amount. Smaller "base rate entity" companies
# frank at 25% (credit 25/75); the large companies that dominate ASX index
# funds and the traditional LICs pay 30%, which is the default here
# (--company-tax-rate changes it). The full refund assumes the whole fund is
# in retirement phase; a member with an accumulation interest gets part of it.
COMPANY_TAX_RATE = 0.30

# ASX Operating Rules: a parcel below this value cannot normally be bought as a
# new holding (it can be sold or topped up).
MIN_MARKETABLE_PARCEL_AUD = 500.0

TRADING_DAYS_PER_YEAR = 252

# A trailing cash yield above this is more likely to be capital being returned,
# option premium or a one-off than sustainable income, so it earns a warning
# and a neutral income score rather than a high one.
YIELD_SANITY_CAP_PCT = 12.0

# Static (hand-curated) facts older than this trigger a warning.
STATIC_STALE_DAYS = 400

# The drawdown column is labelled 3-year; shorter histories are flagged.
DRAWDOWN_WINDOW_DAYS = 3 * 365

# A retirement-phase pension needs a condition of release; preservation age is
# 60 for everyone born after 30 June 1964, so nobody under 60 can hold one now.
PRESERVATION_AGE = 60
MAX_AGE = 120

# Cell values that mean "no number here" in a hand-made or downloaded CSV.
BLANK_TOKENS = {"", "null", "nan", "n/a", "na", "none", "-", "--"}

# Minimum pension drawdown factors, SIS Regulations Schedule 7, by the
# member's age on 1 July of the financial year (or at commencement). Percent of
# the account balance; the minimum is rounded to the nearest AUD 10 (cl 4).
MINIMUM_DRAWDOWN_FACTORS = (
    (95, 14.0),
    (90, 11.0),
    (85, 9.0),
    (80, 7.0),
    (75, 6.0),
    (65, 5.0),
    (0, 4.0),
)

ROLES = ("cash", "defensive", "core_au", "core_intl", "income", "diversifier", "all_in_one")
ROLE_LABELS = {
    "cash": "Cash bucket",
    "defensive": "Defensive bonds / credit",
    "core_au": "Core Australian equities",
    "core_intl": "Core international equities",
    "income": "Income tilt (dividend ETFs, LICs)",
    "diversifier": "Diversifiers (gold, property, infrastructure)",
    "all_in_one": "All-in-one diversified",
}
STRUCTURES = ("etf", "active_etf", "lic", "etb", "hybrid_etf")
ASSET_CLASSES = ("growth", "defensive", "mixed")
FREQUENCIES = {"monthly": 12, "quarterly": 4, "semi-annual": 2, "annual": 1, "irregular": 0, "none": 0}

# Structures with no market maker quoting against an underlying basket: for
# these, on-screen volume IS the liquidity, so thin volume is a hard exclusion.
# For ETFs the tradeable liquidity is that of the underlying market, so thin
# on-screen volume is only a warning (use limit orders near iNAV).
HARD_LIQUIDITY_STRUCTURES = ("lic", "etb")

# Growth share of each role when the CSV leaves growth_pct blank. all_in_one
# rows must state theirs (it is the whole point of the product).
DEFAULT_GROWTH_PCT = {"cash": 0.0, "defensive": 0.0, "core_au": 100.0, "core_intl": 100.0,
                      "income": 100.0, "diversifier": 100.0}

# Per-role rules. Caps drive the hard filters AND the 0-100 component scores;
# weights (which must sum to 100) combine the components. Every number here is
# a policy choice, not a fact, and is printed by --rules so it can be argued
# with. Rationale in brief:
#   mer_cap            what the cheapest mainstream product in the role costs,
#                      times roughly three; anything dearer needs a reason.
#   vol_cap / mdd_cap  the annualised volatility and 3-year drawdown at which
#                      the stability/drawdown component reaches zero.
#   target_gross_yield the grossed-up yield that earns a full income score.
# Franking is not a separate component: the income component already uses the
# grossed-up yield, and a 0% taxpayer is indifferent between cash and credits.
ROLE_RULES = {
    "cash": dict(mer_cap=0.30, vol_cap=2.0, mdd_cap=1.0, target_gross_yield=4.5,
                 weights=dict(cost=30, liquidity=20, size=10, income=25, stability=10, drawdown=5)),
    "defensive": dict(mer_cap=0.35, vol_cap=8.0, mdd_cap=15.0, target_gross_yield=4.5,
                      weights=dict(cost=25, liquidity=15, size=10, income=15, stability=20, drawdown=15)),
    "core_au": dict(mer_cap=0.25, vol_cap=25.0, mdd_cap=40.0, target_gross_yield=5.5,
                    weights=dict(cost=30, liquidity=15, size=15, income=30, stability=5, drawdown=5)),
    "core_intl": dict(mer_cap=0.35, vol_cap=25.0, mdd_cap=40.0, target_gross_yield=2.5,
                      weights=dict(cost=35, liquidity=15, size=20, income=5, stability=15, drawdown=10)),
    "income": dict(mer_cap=0.60, vol_cap=25.0, mdd_cap=40.0, target_gross_yield=7.0,
                   weights=dict(cost=20, liquidity=15, size=10, income=40, stability=10, drawdown=5)),
    "diversifier": dict(mer_cap=0.60, vol_cap=30.0, mdd_cap=45.0, target_gross_yield=3.0,
                        weights=dict(cost=30, liquidity=20, size=15, income=5, stability=15, drawdown=15)),
    "all_in_one": dict(mer_cap=0.35, vol_cap=20.0, mdd_cap=35.0, target_gross_yield=3.5,
                       weights=dict(cost=30, liquidity=15, size=15, income=10, stability=15, drawdown=15)),
}
COMPONENTS = ("cost", "liquidity", "size", "income", "stability", "drawdown")

for _role, _rule in ROLE_RULES.items():
    assert _role in ROLES, _role
    assert tuple(_rule["weights"]) == COMPONENTS, _role
    assert sum(_rule["weights"].values()) == 100, (_role, sum(_rule["weights"].values()))

# Illustrative role mixes for --illustrate, in percent of the money deployed.
# These are EXAMPLES OF STRUCTURE drawn from the kinds of growth/defensive
# splits mainstream Australian sources describe for retirees; they are not a
# recommendation and the right split depends on facts this tool never sees.
# all_in_one_max_growth_pct restricts the all-in-one sleeve to products whose
# own growth share fits the template, so 'simple' cannot be filled with a
# 100%-growth fund.
TEMPLATES = {
    "conservative": {"mix": {"cash": 20, "defensive": 40, "core_au": 15, "core_intl": 15, "diversifier": 10},
                     "all_in_one_max_growth_pct": None},
    "balanced": {"mix": {"cash": 10, "defensive": 30, "core_au": 25, "core_intl": 25, "diversifier": 10},
                 "all_in_one_max_growth_pct": None},
    "growth": {"mix": {"cash": 5, "defensive": 20, "core_au": 30, "core_intl": 35, "diversifier": 10},
               "all_in_one_max_growth_pct": None},
    "income_tilt": {"mix": {"cash": 10, "defensive": 30, "core_au": 15, "income": 15, "core_intl": 20,
                            "diversifier": 10}, "all_in_one_max_growth_pct": None},
    "simple": {"mix": {"cash": 10, "defensive": 20, "all_in_one": 70}, "all_in_one_max_growth_pct": 70},
}
for _name, _spec in TEMPLATES.items():
    assert sum(_spec["mix"].values()) == 100, (_name, sum(_spec["mix"].values()))
    assert all(r in ROLES for r in _spec["mix"]), _name

DEFAULT_FILTERS = dict(
    min_size_aud_m=100.0,       # below this, closure risk and wide spreads
    min_adv_aud=250_000.0,      # median daily value traded; hard for LICs/eTBs, a warning for ETFs
    max_price_age_days=10,      # last price older than this relative to as-of = not really trading
    allow_hybrids=False,
    static_stale_days=STATIC_STALE_DAYS,
)

UNIVERSE_COLUMNS = (
    "ticker", "name", "issuer", "structure", "role", "category", "asset_class", "growth_pct",
    "mer_pct", "size_aud_m", "franking_pct", "distribution_frequency", "hedged",
    "notes", "as_at",
)

TICKER_RE = re.compile(r"^[A-Z0-9]{3,6}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
THOUSANDS_RE = re.compile(r"^-?\d{1,3}(,\d{3})+(\.\d+)?$")


class ScreenerError(Exception):
    """Any input problem the user has to fix (bad CSV, missing file, bad flag)."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def is_blank(text) -> bool:
    return str(text if text is not None else "").strip().lower() in BLANK_TOKENS


def parse_date(text, what: str = "date") -> date:
    """Strict YYYY-MM-DD, the same on every Python version (3.11+ fromisoformat
    also accepts '20260906' and ISO-week forms; 3.9 does not)."""
    s = str(text if text is not None else "").strip()
    if not DATE_RE.match(s):
        raise ScreenerError(f"{what}: expected YYYY-MM-DD, got {text!r}")
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise ScreenerError(f"{what}: not a real calendar date: {text!r}")


def parse_float(text, what: str, lo: float | None = None, hi: float | None = None,
                required: bool = True) -> float | None:
    s = "" if text is None else str(text).strip()
    if s == "":
        if required:
            raise ScreenerError(f"{what}: value is required")
        return None
    if THOUSANDS_RE.match(s):
        s = s.replace(",", "")   # '20,000' yes; '0,07' (decimal comma) is NOT a number here
    try:
        value = float(s)
    except ValueError:
        raise ScreenerError(f"{what}: expected a number, got {text!r}")
    if math.isnan(value) or math.isinf(value):
        raise ScreenerError(f"{what}: expected a finite number, got {text!r}")
    if lo is not None and value < lo:
        raise ScreenerError(f"{what}: {value} is below the minimum {lo}")
    if hi is not None and value > hi:
        raise ScreenerError(f"{what}: {value} is above the maximum {hi}")
    return value


def parse_tristate(text, what: str) -> bool | None:
    t = str(text or "").strip().lower()
    if t in ("yes", "y", "true", "1", "hedged"):
        return True
    if t in ("no", "n", "false", "0", "unhedged"):
        return False
    if t in ("", "na", "n/a", "none", "-"):
        return None
    raise ScreenerError(f"{what}: expected yes/no/na, got {text!r}")


def tristate_text(value) -> str:
    return "yes" if value is True else "no" if value is False else "n/a"


def clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def fmt_money(value: float | None, decimals: int = 0) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.{decimals}f}"


def fmt_pct(value: float | None, decimals: int = 2) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{decimals}f}%"


def fmt_parcel_label(parcel_aud: float) -> str:
    """'u@10k', 'u@12.5k', 'u@0.5k' rather than truncating to whole thousands."""
    return f"u@{parcel_aud / 1000:g}k"


def shorten(name: str, width: int) -> str:
    """Cut at a word boundary and mark the cut, so '(managed fund)' is not lost silently."""
    if len(name) <= width:
        return name
    head = name[: width - 2]
    if " " in head:
        head = head.rsplit(" ", 1)[0]
    return head + ".."


def minimum_drawdown_factor(age: int) -> float:
    """Minimum annual pension payment, percent of balance, for the member's age at 1 July."""
    if age < 0:
        raise ScreenerError(f"age must be non-negative, got {age}")
    for floor_age, factor in MINIMUM_DRAWDOWN_FACTORS:
        if age >= floor_age:
            return factor
    return MINIMUM_DRAWDOWN_FACTORS[-1][1]


def minimum_annual_pension(balance_aud: float, age: int) -> float:
    """Schedule 7: balance x factor, rounded to the nearest AUD 10."""
    if balance_aud <= 0:
        raise ScreenerError(f"balance must be positive, got {balance_aud}")
    raw = balance_aud * minimum_drawdown_factor(age) / 100.0
    return float(int(round(raw / 10.0)) * 10)


def grossed_up_yield(cash_yield_pct: float, franking_pct: float,
                     tax_rate: float = COMPANY_TAX_RATE) -> tuple[float, float]:
    """Return (grossed-up yield %, franking-credit yield %) for a 0% taxpayer.

    A distribution of C franked at f (0-1) carries a credit of C * f * t/(1-t)
    where t is the company tax rate. In retirement phase the whole credit is
    refunded, so the fund actually receives C plus the credit.
    """
    if not 0 <= franking_pct <= 100:
        raise ScreenerError(f"franking must be 0-100 percent, got {franking_pct}")
    if not 0 <= tax_rate < 1:
        raise ScreenerError(f"tax rate must be in [0, 1), got {tax_rate}")
    credit = cash_yield_pct * (franking_pct / 100.0) * tax_rate / (1.0 - tax_rate)
    return cash_yield_pct + credit, credit


# ---------------------------------------------------------------------------
# CSV reading (shared by the universe and the history files)
# ---------------------------------------------------------------------------

def read_csv_rows(path: str) -> tuple[list[str], list[tuple[int, dict]]]:
    """Header names and (line number, row) pairs with keys lower-cased and
    stripped, surplus cells dropped, a UTF-8 BOM removed, and every decoding
    or CSV problem reported as a ScreenerError naming the file."""
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            header = [(h or "").strip().lower() for h in (reader.fieldnames or [])]
            rows: list[tuple[int, dict]] = []
            for raw in reader:
                row = {(k or "").strip().lower(): (v if isinstance(v, str) else "").strip()
                       for k, v in raw.items() if k is not None}
                rows.append((reader.line_num, row))
    except UnicodeDecodeError as exc:
        raise ScreenerError(f"{path}: not readable as UTF-8 text (bad byte at position {exc.start}); "
                            "re-save it as 'CSV UTF-8'")
    except csv.Error as exc:
        raise ScreenerError(f"{path}: malformed CSV ({exc}); re-save it as 'CSV UTF-8'")
    except OSError as exc:
        raise ScreenerError(f"{path}: cannot read ({exc})")
    return header, rows


# ---------------------------------------------------------------------------
# Universe (hand-curated static facts)
# ---------------------------------------------------------------------------

def load_universe(path: str) -> list[dict]:
    """Read and validate the product universe CSV. Raises ScreenerError."""
    if not os.path.isfile(path):
        raise ScreenerError(f"universe file not found: {path}")
    header, rows = read_csv_rows(path)
    missing = [c for c in UNIVERSE_COLUMNS if c not in header]
    if missing:
        raise ScreenerError(f"{path}: missing columns {missing}")

    products: list[dict] = []
    seen: set[str] = set()
    for n, row in rows:
        where = f"{path} line {n}"
        ticker = row.get("ticker", "").upper()
        if not TICKER_RE.match(ticker):
            raise ScreenerError(f"{where}: ticker {row.get('ticker')!r} is not a 3-6 character ASX code")
        if ticker in seen:
            raise ScreenerError(f"{where}: duplicate ticker {ticker}")
        seen.add(ticker)
        if not row.get("name"):
            raise ScreenerError(f"{where}: name is required")
        structure = row.get("structure", "").lower()
        if structure not in STRUCTURES:
            raise ScreenerError(f"{where}: structure {row.get('structure')!r} not one of {STRUCTURES}")
        role = row.get("role", "").lower()
        if role not in ROLES:
            raise ScreenerError(f"{where}: role {row.get('role')!r} not one of {ROLES}")
        asset_class = row.get("asset_class", "").lower()
        if asset_class not in ASSET_CLASSES:
            raise ScreenerError(f"{where}: asset_class {row.get('asset_class')!r} not one of {ASSET_CLASSES}")
        freq = row.get("distribution_frequency", "").lower()
        if freq not in FREQUENCIES:
            raise ScreenerError(f"{where}: distribution_frequency {row.get('distribution_frequency')!r} "
                                f"not one of {tuple(FREQUENCIES)}")
        growth = parse_float(row.get("growth_pct"), f"{where}: growth_pct", 0.0, 100.0, required=False)
        if growth is None:
            if role == "all_in_one":
                raise ScreenerError(f"{where}: growth_pct is required for an all_in_one product")
            growth = DEFAULT_GROWTH_PCT[role]
        products.append({
            "ticker": ticker,
            "name": row["name"],
            "issuer": row.get("issuer", ""),
            "structure": structure,
            "role": role,
            "category": row.get("category", ""),
            "asset_class": asset_class,
            "growth_pct": growth,
            "mer_pct": parse_float(row.get("mer_pct"), f"{where}: mer_pct", 0.0, 5.0),
            "size_aud_m": parse_float(row.get("size_aud_m"), f"{where}: size_aud_m", 0.0, None),
            "franking_pct": parse_float(row.get("franking_pct"), f"{where}: franking_pct", 0.0, 100.0),
            "distribution_frequency": freq,
            "hedged": parse_tristate(row.get("hedged"), f"{where}: hedged"),
            "notes": row.get("notes", ""),
            "as_at": parse_date(row.get("as_at"), f"{where}: as_at"),
        })
    if not products:
        raise ScreenerError(f"{path}: no products")
    return products


def audit_universe(products: list[dict], today: date) -> list[str]:
    """Cross-checks on the hand-curated data. Returns human-readable anomalies.

    These catch the kind of copy-paste error that would otherwise silently
    flatter or sink a product: a hedged fund marked unhedged, franking on a
    bond fund, a fee an order of magnitude off for its role.
    """
    findings: list[str] = []
    names: dict[str, str] = {}
    for p in products:
        t = p["ticker"]
        low = p["name"].lower()
        if "hedged" in low and p["hedged"] is not True and "unhedged" not in low:
            findings.append(f"{t}: name says hedged but hedged={tristate_text(p['hedged'])}")
        if (p["role"] in ("core_intl", "cash", "defensive") and p["franking_pct"] > 15
                and p["structure"] != "hybrid_etf"):  # bank hybrids do pay franked distributions
            findings.append(f"{t}: franking {p['franking_pct']}% is implausible for role {p['role']}")
        if p["role"] in ("core_au", "income") and p["structure"] in ("etf", "lic") and p["franking_pct"] < 40:
            findings.append(f"{t}: franking {p['franking_pct']}% is low for an Australian equity {p['structure']}")
        if p["role"] == "cash" and p["mer_pct"] > 0.30:
            findings.append(f"{t}: cash product with MER {p['mer_pct']}% - check the figure")
        if p["mer_pct"] == 0:
            findings.append(f"{t}: MER is 0 - nothing listed is free; check the figure")
        if p["size_aud_m"] < 5:
            findings.append(f"{t}: size {p['size_aud_m']} AUD m - is that in millions?")
        if p["asset_class"] == "growth" and p["role"] in ("cash", "defensive"):
            findings.append(f"{t}: asset_class growth conflicts with role {p['role']}")
        if p["asset_class"] == "defensive" and p["role"] in ("core_au", "core_intl", "income"):
            findings.append(f"{t}: asset_class defensive conflicts with role {p['role']}")
        if p["role"] in ("cash", "defensive") and p["growth_pct"] > 0:
            findings.append(f"{t}: growth_pct {p['growth_pct']:.0f} on a {p['role']} product")
        if p["role"] in ("core_au", "core_intl", "income") and p["growth_pct"] < 100:
            findings.append(f"{t}: growth_pct {p['growth_pct']:.0f} on an equity product")
        if p["structure"] == "hybrid_etf" and p["role"] != "defensive":
            findings.append(f"{t}: hybrid_etf should carry role defensive, has {p['role']}")
        if (today - p["as_at"]).days > STATIC_STALE_DAYS:
            findings.append(f"{t}: static facts dated {p['as_at']} are more than {STATIC_STALE_DAYS} days old")
        if p["as_at"] > today:
            findings.append(f"{t}: as_at {p['as_at']} is in the future")
        if p["name"] in names:
            findings.append(f"{t}: same name as {names[p['name']]}")
        names[p["name"]] = t
    return findings


# ---------------------------------------------------------------------------
# Price and distribution history
# ---------------------------------------------------------------------------

def price_path(data_dir: str, ticker: str) -> str:
    return os.path.join(data_dir, f"{ticker}.csv")


def dividend_path(data_dir: str, ticker: str) -> str:
    return os.path.join(data_dir, f"{ticker}.dividends.csv")


def load_price_history(data_dir: str, ticker: str) -> list[dict] | None:
    """Rows of {date, close, volume} ascending by date; None if there is no
    file; [] if the file has no usable rows. volume is None when the file has
    no volume column or the cell is blank, so 'unknown' never becomes 'zero'."""
    path = price_path(data_dir, ticker)
    if not os.path.isfile(path):
        return None
    header, raw_rows = read_csv_rows(path)
    if not header:
        return []
    for col in ("date", "close"):
        if col not in header:
            raise ScreenerError(f"{path}: missing column {col!r} (a BOM or extra spaces in the header "
                                "are handled; check the spelling)")
    has_volume = "volume" in header
    rows: list[dict] = []
    for n, row in raw_rows:
        if is_blank(row.get("close")):
            continue  # Yahoo emits blank or 'null' rows on non-trading days
        d = parse_date(row.get("date"), f"{path} line {n}: date")
        close = parse_float(row.get("close"), f"{path} line {n}: close", 0.0, None)
        if close <= 0:
            continue
        volume = None
        if has_volume and not is_blank(row.get("volume")):
            volume = parse_float(row.get("volume"), f"{path} line {n}: volume", 0.0, None)
        rows.append({"date": d, "close": close, "volume": volume})
    # Keep the last row for a duplicated date (a re-fetch appended, not replaced).
    dedup: dict[date, dict] = {}
    for r in rows:
        dedup[r["date"]] = r
    return [dedup[d] for d in sorted(dedup)]


def load_distributions_report(data_dir: str, ticker: str) -> tuple[list[dict], int]:
    """Rows of {date, amount} ascending plus the number of exact duplicate
    rows (same date and amount) collapsed. Missing file means no distributions
    known; a duplicated row is the usual sign of a hand-merged file."""
    path = dividend_path(data_dir, ticker)
    if not os.path.isfile(path):
        return [], 0
    header, raw_rows = read_csv_rows(path)
    if not header:
        return [], 0
    for col in ("date", "amount"):
        if col not in header:
            raise ScreenerError(f"{path}: missing column {col!r}")
    seen: dict[tuple, dict] = {}
    duplicates = 0
    for n, row in raw_rows:
        if is_blank(row.get("amount")):
            continue
        d = parse_date(row.get("date"), f"{path} line {n}: date")
        amount = parse_float(row.get("amount"), f"{path} line {n}: amount", 0.0, None)
        if amount <= 0:
            continue
        key = (d, round(amount, 6))
        if key in seen:
            duplicates += 1
            continue
        seen[key] = {"date": d, "amount": amount}
    rows = sorted(seen.values(), key=lambda r: r["date"])
    return rows, duplicates


def load_distributions(data_dir: str, ticker: str) -> list[dict]:
    return load_distributions_report(data_dir, ticker)[0]


def compute_metrics(prices: list[dict], dists: list[dict], as_of: date, expected_per_year: int = 0) -> dict:
    """Derived numbers from history up to and including as_of.

    Everything is computed from rows dated <= as_of so that a fixed --as-of
    gives the same answer on any day, which is what makes the output testable.

    Volatility and drawdown use a distribution-adjusted series: each
    distribution is added back on the first trading day on or after its
    ex-date, so a cash ETF that pays out monthly is not scored as if it lost
    money twelve times a year. Price, yield and parcel arithmetic use the raw
    close, which is what you pay.
    """
    rows = [r for r in prices if r["date"] <= as_of]
    first_date = prices[0]["date"] if prices else None
    if not rows:
        return {"has_prices": False, "first_date": first_date}
    last = rows[-1]
    one_year_ago = as_of - timedelta(days=365)
    three_years_ago = as_of - timedelta(days=DRAWDOWN_WINDOW_DAYS)

    dist_sorted = sorted(dists, key=lambda d: d["date"])
    j = 0
    while j < len(dist_sorted) and dist_sorted[j]["date"] <= rows[0]["date"]:
        j += 1
    returns: list[tuple[date, float]] = []
    for a, b in zip(rows, rows[1:]):
        paid = 0.0
        while j < len(dist_sorted) and dist_sorted[j]["date"] <= b["date"]:
            paid += dist_sorted[j]["amount"]
            j += 1
        returns.append((b["date"], math.log((b["close"] + paid) / a["close"])))

    year_returns = [r for d, r in returns if d > one_year_ago]
    vol_pct = None
    if len(year_returns) >= 20:
        vol_pct = statistics.stdev(year_returns) * math.sqrt(TRADING_DAYS_PER_YEAR) * 100.0

    index = 1.0
    peak = 1.0
    mdd = 0.0
    window = [r for d, r in returns if d > three_years_ago]
    for r in window:
        index *= math.exp(r)
        peak = max(peak, index)
        mdd = max(mdd, 1.0 - index / peak)
    mdd_pct = mdd * 100.0 if window else None

    recent = [r for r in rows[-60:] if r["volume"] is not None]
    adv_aud = None
    if len(recent) >= 20:
        adv_aud = statistics.median(r["close"] * r["volume"] for r in recent)

    ttm = [d for d in dist_sorted if one_year_ago < d["date"] <= as_of]
    ttm_dist = sum(d["amount"] for d in ttm)
    cash_yield_pct = ttm_dist / last["close"] * 100.0
    scoring_dist = ttm_dist
    if expected_per_year and len(ttm) > expected_per_year:
        # Five quarterly payments in one window (drifting ex-dates, a special):
        # score on the most recent four, show the twelve-month figure.
        scoring_dist = sum(d["amount"] for d in ttm[-expected_per_year:])
    scoring_yield_pct = scoring_dist / last["close"] * 100.0

    base = None
    for r in rows:
        if r["date"] <= one_year_ago:
            base = r
        else:
            break
    total_return_1y_pct = None
    if base is not None and base["close"] > 0:
        total_return_1y_pct = ((last["close"] + ttm_dist) / base["close"] - 1.0) * 100.0

    return {
        "has_prices": True,
        "first_date": rows[0]["date"],
        "last_price": last["close"],
        "last_date": last["date"],
        "price_age_days": (as_of - last["date"]).days,
        "history_days": (last["date"] - rows[0]["date"]).days,
        "rows_1y": len([r for r in rows if r["date"] > one_year_ago]),
        "vol_pct": vol_pct,
        "mdd_pct": mdd_pct,
        "adv_aud": adv_aud,
        "ttm_dist_per_unit": ttm_dist,
        "ttm_dist_count": len(ttm),
        "expected_per_year": expected_per_year,
        "cash_yield_pct": cash_yield_pct,
        "scoring_yield_pct": scoring_yield_pct,
        "total_return_1y_pct": total_return_1y_pct,
    }


# ---------------------------------------------------------------------------
# Parcel arithmetic
# ---------------------------------------------------------------------------

def parcel_plan(price: float, parcel_aud: float, brokerage_aud: float = 0.0) -> dict:
    """What a parcel buys at this price after brokerage, in whole units."""
    if price <= 0:
        raise ScreenerError(f"price must be positive, got {price}")
    if parcel_aud <= 0 or brokerage_aud < 0:
        raise ScreenerError("parcel must be positive and brokerage non-negative")
    investable = parcel_aud - brokerage_aud
    # round() first: 9990.05 / 1.61 is 6204.999999999999 in binary floats.
    units = int(math.floor(round(investable / price, 9))) if investable > 0 else 0
    value = units * price
    return {
        "parcel_aud": parcel_aud,
        "brokerage_aud": brokerage_aud,
        "units": units,
        "value_aud": value,
        "total_cost_aud": value + brokerage_aud if units else 0.0,
        "leftover_aud": parcel_aud - (value + brokerage_aud) if units else parcel_aud,
        "marketable": value >= MIN_MARKETABLE_PARCEL_AUD,
        "brokerage_pct": (brokerage_aud / value * 100.0) if value else None,
    }


# ---------------------------------------------------------------------------
# Filters and scoring
# ---------------------------------------------------------------------------

def apply_filters(product: dict, metrics: dict, filters: dict, today: date) -> tuple[list[str], list[str]]:
    """Return (exclusion reasons, warnings). Empty exclusions means it survives."""
    rules = ROLE_RULES[product["role"]]
    excl: list[str] = []
    warn: list[str] = []

    if metrics.get("future_rows"):
        warn.append(f"{metrics['future_rows']} price rows dated after today were ignored")
    if metrics.get("duplicate_dists"):
        warn.append(f"{metrics['duplicate_dists']} duplicated distribution rows were collapsed: check the file")

    if not metrics.get("has_prices"):
        excl.append(metrics.get("reason") or "no price history in the data directory")
    else:
        age = metrics["price_age_days"]
        if age > filters["max_price_age_days"]:
            excl.append(f"last price is {age} days older than the as-of date (not trading?)")
        if metrics["adv_aud"] is None:
            warn.append("liquidity not assessed: fewer than 20 recent rows carry a volume")
        elif metrics["adv_aud"] < filters["min_adv_aud"]:
            text = (f"median daily value traded AUD {fmt_money(metrics['adv_aud'])} "
                    f"is below AUD {fmt_money(filters['min_adv_aud'])}")
            if product["structure"] in HARD_LIQUIDITY_STRUCTURES:
                excl.append(text + " and nothing quotes against an underlying basket for this structure")
            else:
                warn.append(text + ": thin on-screen volume; an ETF's real liquidity is the underlying "
                                   "market's, so use limit orders near iNAV and avoid the open and close")
        if metrics["vol_pct"] is None:
            warn.append("under 20 daily returns in the last year: volatility not assessed")
        if metrics["cash_yield_pct"] > YIELD_SANITY_CAP_PCT:
            warn.append(f"trailing yield {fmt_pct(metrics['cash_yield_pct'])} is unusually high: "
                        "check for capital returns, option premium or one-off distributions "
                        "(income scored neutral, not rewarded)")
        expected = FREQUENCIES[product["distribution_frequency"]]
        count = metrics["ttm_dist_count"]
        if expected and count < expected:
            warn.append(f"{count} distributions in the last year, {expected} expected: "
                        "dividend data may be incomplete")
        elif expected and count > expected:
            warn.append(f"{count} distributions in the last year, {expected} expected: a special payment "
                        f"or drifting ex-dates; income scored on the most recent {expected} "
                        f"({fmt_pct(metrics['scoring_yield_pct'])} cash)")
        if metrics["history_days"] < 365:
            warn.append("under one year of price history: drawdown and volatility are partial")
        elif metrics["history_days"] < DRAWDOWN_WINDOW_DAYS - 30:
            warn.append(f"only {metrics['history_days']} days of history: mdd% covers that span, not 3 years")

    if product["mer_pct"] > rules["mer_cap"]:
        excl.append(f"MER {product['mer_pct']:.2f}% is above the {product['role']} cap of {rules['mer_cap']:.2f}%")
    if product["size_aud_m"] < filters["min_size_aud_m"]:
        excl.append(f"fund size AUD {fmt_money(product['size_aud_m'])} m is below AUD "
                    f"{fmt_money(filters['min_size_aud_m'])} m")
    if product["structure"] == "hybrid_etf" and not filters["allow_hybrids"]:
        excl.append("bank hybrids: APRA is phasing out Additional Tier 1 capital instruments "
                    "(no new issues from 2027, existing ones expected to be replaced by 2032); "
                    "use --allow-hybrids to keep")
    if product["structure"] == "lic":
        warn.append("LIC: check the premium or discount to NTA before buying; not computed here")
    if product["structure"] == "active_etf":
        warn.append("active fund: results depend on the manager, not an index")
    if (today - product["as_at"]).days > filters["static_stale_days"]:
        warn.append(f"static facts dated {product['as_at']}: refresh MER, size and franking")
    return excl, warn


def score_product(product: dict, metrics: dict, tax_rate: float = COMPANY_TAX_RATE) -> dict:
    """0-100 within the product's role, with every component shown."""
    rules = ROLE_RULES[product["role"]]
    w = rules["weights"]
    notes: list[str] = []

    cost = clamp(100.0 * (1.0 - product["mer_pct"] / rules["mer_cap"]))

    adv = metrics.get("adv_aud")
    if adv is None or adv <= 0:
        liquidity = 0.0
        notes.append("liquidity unknown scored 0")
    else:
        liquidity = clamp(100.0 * math.log10(adv / 1e5) / 2.0)  # AUD 100k -> 0, AUD 10m -> 100

    size = clamp(100.0 * math.log10(max(product["size_aud_m"], 1e-9) / 100.0) / 2.0)  # 100m -> 0, 10bn -> 100

    cash_yield = metrics.get("cash_yield_pct", 0.0)
    scoring_yield = metrics.get("scoring_yield_pct", cash_yield)
    gross, credit = grossed_up_yield(cash_yield, product["franking_pct"], tax_rate)
    gross_for_score, _ = grossed_up_yield(scoring_yield, product["franking_pct"], tax_rate)
    if cash_yield > YIELD_SANITY_CAP_PCT:
        income = 50.0
        notes.append(f"yield above {YIELD_SANITY_CAP_PCT:.0f}% treated as unverified, income scored 50")
    else:
        income = clamp(100.0 * gross_for_score / rules["target_gross_yield"])
        if scoring_yield != cash_yield:
            notes.append(f"income scored on {scoring_yield:.2f}% (most recent {metrics['expected_per_year']} "
                         f"payments), not the {cash_yield:.2f}% twelve-month figure")

    vol = metrics.get("vol_pct")
    if vol is None:
        stability = 50.0
        notes.append("volatility unknown scored 50")
    else:
        stability = clamp(100.0 * (1.0 - vol / rules["vol_cap"]))

    mdd = metrics.get("mdd_pct")
    if mdd is None:
        drawdown = 50.0
        notes.append("drawdown unknown scored 50")
    else:
        drawdown = clamp(100.0 * (1.0 - mdd / rules["mdd_cap"]))

    components = {"cost": cost, "liquidity": liquidity, "size": size, "income": income,
                  "stability": stability, "drawdown": drawdown}
    total = sum(w[k] * components[k] for k in COMPONENTS) / 100.0
    return {
        "total": round(total, 1),
        "components": {k: round(v, 1) for k, v in components.items()},
        "weights": dict(w),
        "gross_yield_pct": gross,
        "franking_credit_yield_pct": credit,
        "tax_rate": tax_rate,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Screening
# ---------------------------------------------------------------------------

def _load_histories(products: list[dict], data_dir: str) -> dict:
    """ticker -> dict(prices, dists, duplicates, error). One bad file is one
    excluded product, never an aborted run."""
    out: dict[str, dict] = {}
    for p in products:
        t = p["ticker"]
        try:
            prices = load_price_history(data_dir, t)
            dists, dups = load_distributions_report(data_dir, t)
            out[t] = {"prices": prices, "dists": dists, "duplicates": dups, "error": None}
        except ScreenerError as exc:
            out[t] = {"prices": None, "dists": [], "duplicates": 0, "error": str(exc)}
    return out


def resolve_as_of(products: list[dict], data_dir: str, as_of: date | None, today: date | None = None) -> date | None:
    """The newest price date on or before today across the universe, unless the user fixed one."""
    if as_of is not None:
        return as_of
    today = today or date.today()
    newest = None
    for h in _load_histories(products, data_dir).values():
        for r in h["prices"] or []:
            if r["date"] <= today and (newest is None or r["date"] > newest):
                newest = r["date"]
    return newest


def screen(products: list[dict], data_dir: str, filters: dict, today: date,
           as_of: date | None = None, parcels=(10_000.0, 25_000.0), brokerage_aud: float = 0.0,
           tax_rate: float = COMPANY_TAX_RATE) -> dict:
    histories = _load_histories(products, data_dir)
    if as_of is None:
        for h in histories.values():
            for r in h["prices"] or []:
                if r["date"] <= today and (as_of is None or r["date"] > as_of):
                    as_of = r["date"]
    results: list[dict] = []
    for p in products:
        h = histories[p["ticker"]]
        prices = h["prices"]
        if h["error"]:
            metrics = {"has_prices": False, "reason": f"history file unreadable: {h['error']}"}
        elif prices is None:
            metrics = {"has_prices": False, "reason": "no price history in the data directory"}
        elif not prices:
            metrics = {"has_prices": False, "reason": "price file has no usable rows"}
        elif as_of is None:
            metrics = {"has_prices": False, "reason": "no price rows on or before today"}
        else:
            metrics = compute_metrics(prices, h["dists"], as_of, FREQUENCIES[p["distribution_frequency"]])
            if not metrics["has_prices"]:
                metrics["reason"] = (f"history starts {metrics['first_date']}, after the as-of date {as_of}")
            metrics["future_rows"] = sum(1 for r in prices if r["date"] > today)
            metrics["duplicate_dists"] = h["duplicates"]
        exclusions, warnings = apply_filters(p, metrics, filters, today)
        entry = {
            "product": p,
            "metrics": metrics,
            "exclusions": exclusions,
            "warnings": warnings,
            "score": None,
            "parcels": [],
        }
        if metrics.get("has_prices"):
            entry["score"] = score_product(p, metrics, tax_rate)
            entry["parcels"] = [parcel_plan(metrics["last_price"], amt, brokerage_aud) for amt in parcels]
            marketable = [pl for pl in entry["parcels"] if pl["marketable"]]
            if entry["parcels"] and not marketable:
                entry["exclusions"].append(
                    f"no parcel size given can buy a marketable AUD {MIN_MARKETABLE_PARCEL_AUD:.0f} holding "
                    f"at a unit price of AUD {metrics['last_price']:,.2f}")
            else:
                for plan in entry["parcels"]:
                    if not plan["marketable"]:
                        entry["warnings"].append(f"a AUD {fmt_money(plan['parcel_aud'])} parcel buys under the "
                                                 f"AUD {MIN_MARKETABLE_PARCEL_AUD:.0f} marketable minimum")
        results.append(entry)

    def sort_key(e):
        role_rank = ROLES.index(e["product"]["role"])
        survives = 0 if not e["exclusions"] else 1
        total = -(e["score"]["total"] if e["score"] else -1.0)
        return (role_rank, survives, total, e["product"]["ticker"])

    results.sort(key=sort_key)
    for e in results:
        peers = [x for x in results if x["product"]["role"] == e["product"]["role"] and not x["exclusions"]]
        e["rank_in_role"] = (peers.index(e) + 1) if e in peers else None
        e["role_survivors"] = len(peers)
    return {
        "as_of": as_of,
        "today": today,
        "filters": dict(filters),
        "parcels": list(parcels),
        "brokerage_aud": brokerage_aud,
        "tax_rate": tax_rate,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Illustrative structures
# ---------------------------------------------------------------------------

def allocate_parcels(mix: dict, n_parcels: int) -> dict:
    """Largest-remainder split of n whole parcels across the mix's roles."""
    if n_parcels < 1:
        raise ScreenerError("need at least one parcel")
    raw = {role: n_parcels * pct / 100.0 for role, pct in mix.items()}
    alloc = {role: int(math.floor(v)) for role, v in raw.items()}
    short = n_parcels - sum(alloc.values())
    for role, _ in sorted(raw.items(), key=lambda kv: (-(kv[1] - math.floor(kv[1])), -mix[kv[0]], kv[0])):
        if short <= 0:
            break
        alloc[role] += 1
        short -= 1
    return {role: n for role, n in alloc.items() if n > 0}


def illustrate(screened: dict, template: str, n_parcels: int, parcel_aud: float,
               brokerage_aud: float = 0.0, balance_aud: float | None = None, age: int = 60) -> dict:
    if template not in TEMPLATES:
        raise ScreenerError(f"template must be one of {tuple(TEMPLATES)}, got {template!r}")
    if balance_aud is not None and balance_aud <= 0:
        raise ScreenerError(f"--balance must be positive, got {balance_aud}")
    if not PRESERVATION_AGE <= age <= MAX_AGE:
        raise ScreenerError(f"--age must be between {PRESERVATION_AGE} (preservation age: nobody younger "
                            f"can hold a retirement-phase pension) and {MAX_AGE}, got {age}")
    spec = TEMPLATES[template]
    mix = spec["mix"]
    max_growth = spec["all_in_one_max_growth_pct"]
    alloc = allocate_parcels(mix, n_parcels)
    lines: list[dict] = []
    unfilled: list[str] = []
    skipped: list[str] = []
    outside_band: list[str] = []
    for role, count in alloc.items():
        survivors = [e for e in screened["results"] if e["product"]["role"] == role and not e["exclusions"]]
        if role == "all_in_one" and max_growth is not None:
            keep = [e for e in survivors if e["product"]["growth_pct"] <= max_growth]
            outside_band.extend(e["product"]["ticker"] for e in survivors if e not in keep)
            survivors = keep
        # A parcel that cannot buy a marketable holding (unit price too high for
        # the parcel) is skipped, not silently allocated zero units.
        buyable = []
        for e in survivors:
            if parcel_plan(e["metrics"]["last_price"], parcel_aud, brokerage_aud)["marketable"]:
                buyable.append(e)
            else:
                skipped.append(e["product"]["ticker"])
        if not buyable:
            unfilled.append(role)
            continue
        # Spread the role's parcels over its top-ranked survivors, one parcel
        # each, cycling back to the top if there are more parcels than products.
        for i in range(count):
            e = buyable[i % len(buyable)]
            plan = parcel_plan(e["metrics"]["last_price"], parcel_aud, brokerage_aud)
            lines.append({"role": role, "ticker": e["product"]["ticker"], "name": e["product"]["name"],
                          "parcel_aud": parcel_aud, "units": plan["units"], "value_aud": plan["value_aud"],
                          "score": e["score"]["total"], "gross_yield_pct": e["score"]["gross_yield_pct"],
                          "growth_pct": e["product"]["growth_pct"],
                          "yield_unverified": e["metrics"]["cash_yield_pct"] > YIELD_SANITY_CAP_PCT})
    deployed = sum(l["value_aud"] for l in lines)
    cash_value = sum(l["value_aud"] for l in lines if l["role"] == "cash")
    defensive_value = sum(l["value_aud"] * (100.0 - l["growth_pct"]) / 100.0 for l in lines)
    verified = [l for l in lines if not l["yield_unverified"]]
    verified_value = sum(l["value_aud"] for l in verified)
    weighted_gross = (sum(l["value_aud"] * l["gross_yield_pct"] for l in verified) / verified_value
                      if verified_value else 0.0)
    achieved = {}
    for role in alloc:
        achieved[role] = (sum(l["value_aud"] for l in lines if l["role"] == role) / deployed * 100.0) if deployed else 0.0
    out = {
        "template": template,
        "note": ILLUSTRATION_NOTE,
        "mix_pct": dict(mix),
        "parcels_by_role": alloc,
        "achieved_pct": achieved,
        "lines": lines,
        "unfilled_roles": unfilled,
        "skipped_not_marketable": skipped,
        "skipped_outside_growth_band": outside_band,
        "deployed_aud": deployed,
        "brokerage_total_aud": brokerage_aud * len(lines),
        "cash_share_pct": (cash_value / deployed * 100.0) if deployed else 0.0,
        "defensive_share_pct": (defensive_value / deployed * 100.0) if deployed else 0.0,
        "weighted_gross_yield_pct": weighted_gross,
        "unverified_yield_lines": len(lines) - len(verified),
        "drawdown_cover": None,
    }
    if balance_aud is not None:
        annual_min = minimum_annual_pension(balance_aud, age)
        out["drawdown_cover"] = {
            "age": age,
            "minimum_factor_pct": minimum_drawdown_factor(age),
            "annual_minimum_aud": annual_min,
            "years_covered_by_cash": (cash_value / annual_min) if annual_min else None,
            "years_covered_by_cash_and_defensive": (defensive_value / annual_min) if annual_min else None,
        }
    return out


# ---------------------------------------------------------------------------
# Live fetch: Yahoo Finance via the standard library (default), or yfinance
# ---------------------------------------------------------------------------

YAHOO_CHART_URL = ("https://query2.finance.yahoo.com/v8/finance/chart/{symbol}"
                   "?range={years}y&interval=1d&events=div&includeAdjustedClose=false")
USER_AGENT = f"Mozilla/5.0 (compatible; smsf_screener/{__version__})"
FETCH_BACKENDS = ("yahoo", "yfinance")


def _http_get_json(url: str, timeout: float = 20.0):
    """The one network choke point: tests replace it, and failures read well."""
    endpoint = url.split("?")[0]
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        hint = " (rate limited: wait a minute and retry)" if exc.code == 429 else ""
        raise ScreenerError(f"HTTP {exc.code} from {endpoint}{hint}")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        hint = ""
        if "CERTIFICATE_VERIFY_FAILED" in str(reason):
            hint = (" (a python.org install needs 'Install Certificates.command' run once from the "
                    "Python folder in Applications)")
        raise ScreenerError(f"could not reach {endpoint}: {reason}{hint}")
    except (ValueError, OSError, http.client.HTTPException) as exc:
        raise ScreenerError(f"bad response from {endpoint}: {type(exc).__name__}: {exc}")


def _finite(value) -> float | None:
    """A float for a number-like value, None for None/NaN/junk."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def parse_yahoo_chart(payload) -> tuple[list[dict], list[dict]]:
    """Turn Yahoo's chart JSON into (price rows, dividend rows). Raises ScreenerError."""
    try:
        chart = payload["chart"]
        if chart.get("error"):
            err = chart["error"]
            raise ScreenerError(f"Yahoo error: {err.get('description') or err}")
        result = chart["result"][0]
        offset = int((result.get("meta") or {}).get("gmtoffset", 0))
        stamps = result.get("timestamp") or []
        quote = result["indicators"]["quote"][0]
        closes = quote.get("close") or []
        volumes = quote.get("volume") or []
        if not all(isinstance(x, list) for x in (stamps, closes, volumes)):
            raise ScreenerError("Yahoo chart response has an unexpected shape "
                                "(timestamp, close or volume is not a list)")

        def local_date(ts) -> date:
            # Yahoo stamps each session in UTC; shifting by the exchange's offset
            # gives the Sydney trading date rather than the UTC date.
            return datetime.fromtimestamp(int(ts) + offset, tz=timezone.utc).date()

        rows: list[dict] = []
        for i, ts in enumerate(stamps):
            close = _finite(closes[i] if i < len(closes) else None)
            if ts is None or close is None or close <= 0:
                continue
            vol = _finite(volumes[i] if i < len(volumes) else None)
            rows.append({"date": local_date(ts), "close": close, "volume": vol if vol is not None else 0.0})
        dividends: list[dict] = []
        for item in (((result.get("events") or {}).get("dividends") or {}).values()):
            amount = _finite((item or {}).get("amount")) if isinstance(item, dict) else None
            ts = (item or {}).get("date") if isinstance(item, dict) else None
            if amount is None or amount <= 0 or ts is None:
                continue
            dividends.append({"date": local_date(ts), "amount": amount})
    except ScreenerError:
        raise
    except (KeyError, IndexError, TypeError, AttributeError, ValueError, OverflowError) as exc:
        raise ScreenerError(f"Yahoo chart response has an unexpected shape ({type(exc).__name__}: {exc})")
    rows.sort(key=lambda r: r["date"])
    dividends.sort(key=lambda r: r["date"])
    return rows, dividends


def _atomic_write_csv(path: str, header: list[str], rows) -> None:
    """Write to a temp file in the same directory and rename, so a failure
    mid-way never leaves a truncated file for the next run to trust."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".csv", dir=directory)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            for r in rows:
                w.writerow(r)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_history_csvs(data_dir: str, ticker: str, rows: list[dict], dividends: list[dict]) -> None:
    """Write the two CSV files the screener reads for one ticker."""
    os.makedirs(data_dir, exist_ok=True)
    _atomic_write_csv(price_path(data_dir, ticker), ["date", "close", "volume"],
                      ([r["date"].isoformat(), f"{r['close']:.6f}", int(round(_finite(r["volume"]) or 0.0))]
                       for r in rows))
    _atomic_write_csv(dividend_path(data_dir, ticker), ["date", "amount"],
                      ([d["date"].isoformat(), f"{d['amount']:.6f}"] for d in dividends))


def fetch_history_yahoo(tickers: list[str], data_dir: str, years: int = 3, suffix: str = ".AX",
                        progress=None, pause: float = 0.5) -> dict:
    """Standard-library download from Yahoo Finance's chart endpoint.

    No packages needed. Yahoo's ASX coverage is good for prices and volume and
    patchy for distributions, which is why the screener warns when it sees
    fewer distributions than the product's stated frequency implies. A short
    pause between requests keeps a 50-ticker run under Yahoo's rate limit.
    """
    fetched: list[str] = []
    empty: list[str] = []
    failed: dict[str, str] = {}
    for t in tickers:
        url = YAHOO_CHART_URL.format(symbol=f"{t}{suffix}", years=years)
        try:
            rows, dividends = parse_yahoo_chart(_http_get_json(url))
            if not rows:
                empty.append(t)
                continue
            write_history_csvs(data_dir, t, rows, dividends)
        except ScreenerError as exc:
            failed[t] = str(exc)
            continue
        except Exception as exc:  # anything else Yahoo or the disk throws: one ticker, not the run
            failed[t] = f"{type(exc).__name__}: {exc}"
            continue
        fetched.append(t)
        if progress:
            progress(t)
        if pause:
            time.sleep(pause)
    return {"fetched": fetched, "empty": empty, "failed": failed}


def fetch_history_yfinance(tickers: list[str], data_dir: str, years: int = 3, suffix: str = ".AX",
                           progress=None) -> dict:
    """Alternative backend using the third-party yfinance package."""
    try:
        import yfinance as yf  # type: ignore
    except ImportError:
        raise ScreenerError("yfinance is not installed; run: python3 -m pip install yfinance "
                            "(or use the default --fetch-backend yahoo, which needs nothing)")
    fetched: list[str] = []
    empty: list[str] = []
    failed: dict[str, str] = {}
    for t in tickers:
        try:
            hist = yf.Ticker(f"{t}{suffix}").history(period=f"{years}y", auto_adjust=False, actions=True)
            if hist is None or len(hist) == 0:
                empty.append(t)
                continue
            rows: list[dict] = []
            for idx, row in hist.iterrows():
                close = _finite(row.get("Close"))
                if close is None or close <= 0:
                    continue
                rows.append({"date": idx.date(), "close": close, "volume": _finite(row.get("Volume")) or 0.0})
            if not rows:
                empty.append(t)
                continue
            dividends: list[dict] = []
            if "Dividends" in hist.columns:
                for idx, amount in hist["Dividends"].items():
                    amt = _finite(amount)
                    if amt and amt > 0:
                        dividends.append({"date": idx.date(), "amount": amt})
            write_history_csvs(data_dir, t, rows, dividends)
        except Exception as exc:  # network, parsing, Yahoo changes, disk: report, keep going
            failed[t] = f"{type(exc).__name__}: {exc}"
            continue
        fetched.append(t)
        if progress:
            progress(t)
    return {"fetched": fetched, "empty": empty, "failed": failed}


def fetch_history(tickers: list[str], data_dir: str, years: int = 3, backend: str = "yahoo",
                  suffix: str = ".AX", progress=None) -> dict:
    """Download price and dividend history into the CSV layout this tool reads."""
    if backend == "yahoo":
        return fetch_history_yahoo(tickers, data_dir, years=years, suffix=suffix, progress=progress)
    if backend == "yfinance":
        return fetch_history_yfinance(tickers, data_dir, years=years, suffix=suffix, progress=progress)
    raise ScreenerError(f"fetch backend must be one of {FETCH_BACKENDS}, got {backend!r}")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _row(e: dict, n_parcels: int) -> dict:
    p, m, s = e["product"], e["metrics"], e["score"]
    units = [pl["units"] for pl in e["parcels"]]
    if len(units) < n_parcels:
        units = units + [None] * (n_parcels - len(units))
    return {
        "ticker": p["ticker"],
        "name": p["name"],
        "role": p["role"],
        "structure": p["structure"],
        "mer_pct": p["mer_pct"],
        "size_aud_m": p["size_aud_m"],
        "price": m.get("last_price"),
        "cash_yield_pct": m.get("cash_yield_pct"),
        "gross_yield_pct": s["gross_yield_pct"] if s else None,
        "franking_pct": p["franking_pct"],
        "vol_pct": m.get("vol_pct"),
        "mdd_pct": m.get("mdd_pct"),
        "adv_aud": m.get("adv_aud"),
        "score": s["total"] if s else None,
        "rank": e.get("rank_in_role"),
        "units": units,
    }


def _cells(r: dict) -> dict:
    """Formatted strings for the optional numbers, 'n/a' where unknown."""
    def f(value, spec):
        return "n/a" if value is None else format(value, spec)
    return {
        "price": f(r["price"], ",.2f"),
        "yld": f(r["cash_yield_pct"], ".2f"),
        "gross": f(r["gross_yield_pct"], ".2f"),
        "vol": f(r["vol_pct"], ".1f"),
        "mdd": f(r["mdd_pct"], ".1f"),
        "adv": "n/a" if r["adv_aud"] is None else format(r["adv_aud"] / 1000, ",.0f"),
        "score": f(r["score"], ".1f"),
        "units": ["n/a" if u is None else str(u) for u in r["units"]],
    }


def _footnote(screened: dict) -> str:
    brokerage = screened["brokerage_aud"]
    after = ("after AUD {:.2f} brokerage".format(brokerage) if brokerage
             else "with NO brokerage deducted (pass --brokerage for a real unit count)")
    return ("Columns: # = rank among products that passed every filter in this role, x = excluded (score kept "
            "for information only); MER% = annual fee; size$m = fund size, AUD millions; yld% = trailing "
            "12-month cash distributions / price; gross% = yld% plus the franking credit a 0% taxpayer gets "
            f"refunded (company tax rate {screened['tax_rate']:.0%}); frk% = typical franking (hand-curated); "
            "vol% = annualised 1-year volatility and mdd% = worst peak-to-trough fall over up to 3 years, both "
            "on a distribution-adjusted series; adv$k = median daily value traded (AUD thousands); score = "
            "0-100 fit to this role's rules (--rules), comparable only within a role and not a forecast; "
            f"u@Nk = whole units a parcel of AUD N thousand buys {after}.")


def render_text(screened: dict, show_excluded: bool = True) -> str:
    out: list[str] = [DISCLAIMER, ""]
    as_of = screened["as_of"]
    brokerage = screened["brokerage_aud"]
    out.append(f"smsf_screener {__version__}   as-of {as_of}   today {screened['today']}   "
               f"parcels AUD {' / '.join(fmt_money(x) for x in screened['parcels'])}   "
               f"brokerage AUD {brokerage:.2f} per trade" + ("" if brokerage else " (none assumed)"))
    if as_of and (screened["today"] - as_of).days > 7:
        out.append(f"WARNING: price data is {(screened['today'] - as_of).days} days old; re-run --fetch")
    f = screened["filters"]
    out.append(f"filters: size >= AUD {fmt_money(f['min_size_aud_m'])} m, median daily value >= AUD "
               f"{fmt_money(f['min_adv_aud'])} (hard for LICs and eTBs, a note for ETFs), price age <= "
               f"{f['max_price_age_days']} d, hybrids {'allowed' if f['allow_hybrids'] else 'excluded'}, "
               "role MER caps per --rules")
    out.append("")
    n_parcels = len(screened["parcels"])
    header = (f"{'#':>2} {'ticker':<7}{'name':<44}{'MER%':>6}{'size$m':>8}{'price':>11}{'yld%':>6}"
              f"{'gross%':>7}{'frk%':>5}{'vol%':>6}{'mdd%':>6}{'adv$k':>8}{'score':>6}"
              + "".join(f"{fmt_parcel_label(x):>9}" for x in screened["parcels"]))
    for role in ROLES:
        rows = [e for e in screened["results"] if e["product"]["role"] == role]
        if not rows:
            continue
        shown = rows if show_excluded else [e for e in rows if not e["exclusions"]]
        out.append(f"== {ROLE_LABELS[role]} ==")
        if not shown:
            out.append(f"   (all {len(rows)} products in this role were excluded; run without --hide-excluded "
                       "to see why)")
            out.append("")
            continue
        out.append(header)
        for e in shown:
            r = _row(e, n_parcels)
            mark = f"{r['rank']:>2}" if r["rank"] else " x"
            c = _cells(r)
            line = (f"{mark} {r['ticker']:<7}{shorten(r['name'], 43):<44}{r['mer_pct']:>6.2f}{r['size_aud_m']:>8,.0f}"
                    f"{c['price']:>11}{c['yld']:>6}{c['gross']:>7}{r['franking_pct']:>5.0f}{c['vol']:>6}"
                    f"{c['mdd']:>6}{c['adv']:>8}{c['score']:>6}"
                    + "".join(f"{u:>9}" for u in c["units"]))
            out.append(line)
            for reason in e["exclusions"]:
                out.append(f"      excluded: {reason}")
            for warning in e["warnings"]:
                out.append(f"      note: {warning}")
        out.append("")
    out.append(_footnote(screened))
    out.append("")
    out.append(DISCLAIMER.splitlines()[0])
    return "\n".join(out)


def render_explain(screened: dict, ticker: str) -> str:
    ticker = ticker.upper()
    for e in screened["results"]:
        if e["product"]["ticker"] != ticker:
            continue
        p, m, s = e["product"], e["metrics"], e["score"]
        tax = screened["tax_rate"]
        out = [f"{p['ticker']}  {p['name']}  ({p['issuer']}; {p['structure']}; role {p['role']})",
               f"  static facts as at {p['as_at']}: MER {p['mer_pct']:.2f}%, size AUD {fmt_money(p['size_aud_m'])} m, "
               f"franking {p['franking_pct']:.0f}%, distributions {p['distribution_frequency']}, "
               f"hedged {tristate_text(p['hedged'])}, growth share {p['growth_pct']:.0f}%"]
        if p["notes"]:
            out.append(f"  notes: {p['notes']}")
        if not m.get("has_prices"):
            out.append(f"  no usable price history: {m.get('reason', 'no price history')}")
        else:
            out.append(f"  last price AUD {m['last_price']:.2f} on {m['last_date']} "
                       f"({m['price_age_days']} days before as-of); {m['history_days']} days of history "
                       f"from {m['first_date']}")
            out.append(f"  TTM distributions AUD {m['ttm_dist_per_unit']:.4f}/unit over {m['ttm_dist_count']} "
                       f"payments = cash yield {fmt_pct(m['cash_yield_pct'])}")
            gross, credit = grossed_up_yield(m["cash_yield_pct"], p["franking_pct"], tax)
            out.append(f"  grossed-up yield = {m['cash_yield_pct']:.2f}% x (1 + {p['franking_pct']:.0f}% x "
                       f"{tax:.2f}/{1 - tax:.2f}) = {gross:.2f}% "
                       f"(franking credit refund worth {credit:.2f}%)")
            out.append(f"  volatility {fmt_pct(m['vol_pct'], 1)} and max drawdown {fmt_pct(m['mdd_pct'], 1)} "
                       f"(distribution-adjusted); median daily value AUD {fmt_money(m['adv_aud'])}; 1y total "
                       f"return {fmt_pct(m['total_return_1y_pct'], 1)}")
        for reason in e["exclusions"]:
            out.append(f"  EXCLUDED: {reason}")
        for warning in e["warnings"]:
            out.append(f"  note: {warning}")
        if s:
            rules = ROLE_RULES[p["role"]]
            out.append(f"  score {s['total']:.1f}/100 (rank {e['rank_in_role'] or '-'} of "
                       f"{e['role_survivors']} survivors in role; comparable only within the role)")
            out.append(f"    role caps: MER {rules['mer_cap']:.2f}%, vol {rules['vol_cap']:.0f}%, drawdown "
                       f"{rules['mdd_cap']:.0f}%, target gross yield {rules['target_gross_yield']:.1f}%")
            for k in COMPONENTS:
                v = s["components"][k]
                out.append(f"    {k:<10} {v:>6.1f} x weight {s['weights'][k]:>3} = {v * s['weights'][k] / 100:>6.1f}")
            for note in s["notes"]:
                out.append(f"    ({note})")
        for plan in e["parcels"]:
            if plan["units"] == 0:
                out.append(f"  AUD {fmt_money(plan['parcel_aud'])} parcel: cannot buy a single unit at AUD "
                           f"{m['last_price']:,.2f} after brokerage {plan['brokerage_aud']:.2f}")
                continue
            out.append(f"  AUD {fmt_money(plan['parcel_aud'])} parcel: {plan['units']} units = AUD "
                       f"{plan['value_aud']:,.2f} + brokerage {plan['brokerage_aud']:.2f}, leftover AUD "
                       f"{plan['leftover_aud']:,.2f}, brokerage {fmt_pct(plan['brokerage_pct'])} of value"
                       + ("" if plan["marketable"] else "  (BELOW MARKETABLE PARCEL)"))
        return "\n".join(out)
    raise ScreenerError(f"{ticker} is not in the universe")


def render_illustration(ill: dict) -> str:
    out = [f"Illustrative structure '{ill['template']}' - an example of shape, not a recommendation",
           "  target mix: " + ", ".join(f"{ROLE_LABELS[r]} {p}%" for r, p in ill["mix_pct"].items()),
           "  parcels: " + ", ".join(f"{r} x{n} ({ill['achieved_pct'].get(r, 0):.0f}% of deployed, target "
                                     f"{ill['mix_pct'][r]}%)" for r, n in ill["parcels_by_role"].items())]
    groups: dict[tuple, dict] = {}
    for l in ill["lines"]:
        g = groups.setdefault((l["role"], l["ticker"]), dict(l, parcels=0, units_total=0, value_total=0.0))
        g["parcels"] += 1
        g["units_total"] += l["units"]
        g["value_total"] += l["value_aud"]
    for g in groups.values():
        extra = ""
        if g["role"] == "all_in_one":
            extra += f"  ({g['growth_pct']:.0f}/{100 - g['growth_pct']:.0f} growth/defensive inside)"
        if g["yield_unverified"]:
            extra += "  (yield unverified: excluded from the weighted figure)"
        out.append(f"  {g['role']:<12}{g['ticker']:<7}{shorten(g['name'], 34):<35}{g['parcels']} x {g['units']} = "
                   f"{g['units_total']} units  AUD {g['value_total']:>10,.2f}  gross yield {g['gross_yield_pct']:.2f}%  "
                   f"score {g['score']:.1f}{extra}")
    for r in ill["unfilled_roles"]:
        out.append(f"  {r:<12}(no surviving product in the universe that this parcel size can buy)")
    if ill["skipped_not_marketable"]:
        out.append("  skipped because one parcel cannot buy a marketable holding: "
                   + ", ".join(ill["skipped_not_marketable"]))
    if ill["skipped_outside_growth_band"]:
        out.append("  skipped because their growth share is above this template's band: "
                   + ", ".join(ill["skipped_outside_growth_band"]))
    out.append(f"  deployed AUD {ill['deployed_aud']:,.2f} plus brokerage AUD {ill['brokerage_total_aud']:,.2f} over "
               f"{len(ill['lines'])} trades; cash {ill['cash_share_pct']:.1f}%, cash + defensive (counting what is "
               f"inside all-in-one funds) {ill['defensive_share_pct']:.1f}%; value-weighted gross yield "
               f"{ill['weighted_gross_yield_pct']:.2f}%"
               + (f" excluding {ill['unverified_yield_lines']} line(s) with unverified yields"
                  if ill["unverified_yield_lines"] else ""))
    dc = ill["drawdown_cover"]
    if dc:
        out.append(f"  at age {dc['age']} (on 1 July) the minimum drawdown is {dc['minimum_factor_pct']:.0f}% of "
                   f"balance = AUD {dc['annual_minimum_aud']:,.0f} a year (Schedule 7, rounded to AUD 10); cash "
                   f"covers {dc['years_covered_by_cash']:.1f} years of it, cash plus bonds/credit "
                   f"{dc['years_covered_by_cash_and_defensive']:.1f} years (bonds can fall; they are not cash)")
    out.append("  " + ILLUSTRATION_NOTE)
    return "\n".join(out)


def render_rules() -> str:
    out = ["Role rules (edit ROLE_RULES in the source to change them):"]
    for role, r in ROLE_RULES.items():
        out.append(f"  {role:<12} MER cap {r['mer_cap']:.2f}%  vol cap {r['vol_cap']:.0f}%  drawdown cap "
                   f"{r['mdd_cap']:.0f}%  target gross yield {r['target_gross_yield']:.1f}%  weights "
                   + " ".join(f"{k}={v}" for k, v in r["weights"].items()))
    out.append("Global filters (flags): " + ", ".join(f"{k}={v}" for k, v in DEFAULT_FILTERS.items()))
    out.append(f"Yield sanity cap {YIELD_SANITY_CAP_PCT:.0f}% (above it income scores neutral); company tax rate "
               f"for the gross-up {COMPANY_TAX_RATE:.0%} (--company-tax-rate; base-rate entities pay 25%)")
    out.append("Templates for --illustrate (percent of money deployed; the all-in-one sleeve is limited to "
               "products whose growth share fits the template):")
    for name, spec in TEMPLATES.items():
        band = spec["all_in_one_max_growth_pct"]
        out.append(f"  {name:<13}" + ", ".join(f"{r} {p}" for r, p in spec["mix"].items())
                   + (f"  (all_in_one growth share <= {band}%)" if band is not None else ""))
    out.append("Minimum drawdown factors by age at 1 July: " + ", ".join(f"{a}+ {f:.0f}%" for a, f in
                                                                         sorted(MINIMUM_DRAWDOWN_FACTORS)))
    return "\n".join(out)


def _json_default(o):
    if isinstance(o, (date, datetime)):
        return o.isoformat()
    raise TypeError(f"not serialisable: {type(o).__name__}")


def to_json(screened: dict, illustration: dict | None = None) -> str:
    payload = {
        "disclaimer": DISCLAIMER,
        "version": __version__,
        "as_of": screened["as_of"],
        "today": screened["today"],
        "filters": screened["filters"],
        "parcels": screened["parcels"],
        "brokerage_aud": screened["brokerage_aud"],
        "tax_rate": screened["tax_rate"],
        "results": [{
            "product": e["product"], "metrics": e["metrics"], "exclusions": e["exclusions"],
            "warnings": e["warnings"], "score": e["score"], "parcels": e["parcels"],
            "rank_in_role": e.get("rank_in_role"),
        } for e in screened["results"]],
        "illustration": illustration,
    }
    return json.dumps(payload, indent=2, default=_json_default, sort_keys=True)


def render_markdown(screened: dict, illustration: dict | None = None) -> str:
    out = ["# SMSF screener output", "", f"> {DISCLAIMER.replace(chr(10), ' ')}", "",
           f"As-of {screened['as_of']}, run {screened['today']}, parcels AUD "
           f"{' / '.join(fmt_money(x) for x in screened['parcels'])}, brokerage AUD "
           f"{screened['brokerage_aud']:.2f}.", ""]
    n_parcels = len(screened["parcels"])
    for role in ROLES:
        rows = [e for e in screened["results"] if e["product"]["role"] == role]
        if not rows:
            continue
        out.append(f"## {ROLE_LABELS[role]}")
        out.append("")
        out.append("| # | Ticker | Name | MER % | Size AUD m | Price | Cash yield % | Gross yield % | Franking % | "
                   "Vol % | Drawdown % | Daily value AUD k | Score | "
                   + " | ".join(f"Units @ {x / 1000:g}k" for x in screened["parcels"]) + " | Notes |")
        out.append("|" + "---|" * (14 + n_parcels))
        for e in rows:
            r = _row(e, n_parcels)
            c = _cells(r)
            notes = "; ".join(["EXCLUDED: " + x for x in e["exclusions"]] + e["warnings"])
            out.append(f"| {r['rank'] or 'x'} | {r['ticker']} | {r['name']} | {r['mer_pct']:.2f} | "
                       f"{r['size_aud_m']:,.0f} | {c['price']} | {c['yld']} | {c['gross']} | "
                       f"{r['franking_pct']:.0f} | {c['vol']} | {c['mdd']} | {c['adv']} | {c['score']} | "
                       + " | ".join(c["units"]) + f" | {notes} |")
        out.append("")
    out.append(_footnote(screened))
    out.append("")
    if illustration:
        out.append("## Illustrative structure")
        out.append("")
        out.append("```")
        out.append(render_illustration(illustration))
        out.append("```")
        out.append("")
    out.append(DISCLAIMER.splitlines()[0])
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        prog="smsf_screener.py",
        description="Rule-based screener for ASX-listed investments in a retirement-phase SMSF. "
                    "General information only; not personal advice.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 smsf_screener.py --fetch --brokerage 9.95         # download history into data/ beside the script, then screen\n"
               "  python3 smsf_screener.py --explain VAS                    # show the arithmetic for one code\n"
               "  python3 smsf_screener.py --illustrate balanced --n-parcels 6 --parcel 15000 --balance 500000\n"
               "  python3 smsf_screener.py --rules                          # print every policy number\n")
    ap.add_argument("--universe", default=os.path.join(here, "smsf_universe.csv"),
                    help="CSV of products and hand-curated static facts (default: smsf_universe.csv beside the script)")
    ap.add_argument("--data-dir", default=os.path.join(here, "data"),
                    help="directory of <TICKER>.csv and <TICKER>.dividends.csv (default: data/ beside the script)")
    ap.add_argument("--fetch", action="store_true", help="download history into --data-dir first, then screen")
    ap.add_argument("--fetch-only", action="store_true", help="download and stop")
    ap.add_argument("--fetch-backend", choices=FETCH_BACKENDS, default="yahoo",
                    help="yahoo = Yahoo Finance via the standard library (default, no packages); "
                         "yfinance = the third-party package")
    ap.add_argument("--years", type=int, default=3, help="years of history to fetch (default 3)")
    ap.add_argument("--as-of", type=str, default=None, help="freeze the as-of date (YYYY-MM-DD) for reproducible runs")
    ap.add_argument("--today", type=str, default=None, help="override today's date (YYYY-MM-DD), mainly for tests")
    ap.add_argument("--parcel", type=str, action="append", default=None,
                    help="parcel size in AUD; repeatable (default 10000 and 25000); --illustrate uses the first")
    ap.add_argument("--brokerage", type=str, default="0", help="brokerage per trade in AUD (default 0: none deducted)")
    ap.add_argument("--company-tax-rate", type=str, default=str(COMPANY_TAX_RATE),
                    help="rate used to gross up franking (default 0.30; base-rate entities frank at 0.25)")
    ap.add_argument("--min-size", type=str, default=str(DEFAULT_FILTERS["min_size_aud_m"]), help="minimum fund size, AUD m")
    ap.add_argument("--min-adv", type=str, default=str(DEFAULT_FILTERS["min_adv_aud"]),
                    help="minimum median daily value traded, AUD (hard for LICs/eTBs, a note for ETFs)")
    ap.add_argument("--max-price-age", type=int, default=DEFAULT_FILTERS["max_price_age_days"],
                    help="exclude if the last price is older than this many days before as-of")
    ap.add_argument("--allow-hybrids", action="store_true", help="keep bank hybrid funds in the shortlist")
    ap.add_argument("--only-role", choices=ROLES, action="append", default=None, help="restrict to a role; repeatable")
    ap.add_argument("--exclude", type=str, action="append", default=None, help="drop a ticker; repeatable")
    ap.add_argument("--hide-excluded", action="store_true", help="do not list products that failed a filter")
    ap.add_argument("--explain", type=str, default=None, metavar="TICKER", help="show the full arithmetic for one code")
    ap.add_argument("--illustrate", choices=tuple(TEMPLATES), default=None, help="lay out an example multi-parcel structure")
    ap.add_argument("--n-parcels", type=int, default=None, help="parcels in the illustration (default 6)")
    ap.add_argument("--balance", type=str, default=None,
                    help="pension account balance in AUD, to express cash cover in years of minimum drawdown")
    ap.add_argument("--age", type=int, default=None,
                    help=f"member's age at 1 July for the minimum drawdown factor (default 60; minimum {PRESERVATION_AGE})")
    ap.add_argument("--json", type=str, default=None, metavar="FILE", help="also write the full result as JSON")
    ap.add_argument("--markdown", type=str, default=None, metavar="FILE", help="also write a Markdown report")
    ap.add_argument("--audit-universe", action="store_true", help="cross-check the static CSV and stop")
    ap.add_argument("--rules", action="store_true", help="print every policy number and stop")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _check_output_path(path: str | None, what: str) -> None:
    if not path:
        return
    if os.path.isdir(path):
        raise ScreenerError(f"{what} {path} is a directory; give a file name")
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise ScreenerError(f"{what} {path}: folder {parent} does not exist")


def _write_text(path: str, text: str, what: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        raise ScreenerError(f"cannot write {what} {path}: {exc}")


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        if args.rules:
            print(render_rules())
            return 0
        today = parse_date(args.today, "--today") if args.today else date.today()
        as_of = parse_date(args.as_of, "--as-of") if args.as_of else None
        if as_of is not None and as_of > today:
            raise ScreenerError(f"--as-of {as_of} is after today {today}")
        brokerage = parse_float(args.brokerage, "--brokerage", 0.0, None)
        tax_rate = parse_float(args.company_tax_rate, "--company-tax-rate", 0.0, 0.99)
        min_size = parse_float(args.min_size, "--min-size", 0.0, None)
        min_adv = parse_float(args.min_adv, "--min-adv", 0.0, None)
        parcels = tuple(parse_float(x, "--parcel", 0.01, None) for x in args.parcel) if args.parcel else (10_000.0, 25_000.0)
        balance = parse_float(args.balance, "--balance", 0.01, None) if args.balance is not None else None
        if args.years < 1:
            raise ScreenerError("--years must be at least 1")
        _check_output_path(args.json, "--json")
        _check_output_path(args.markdown, "--markdown")
        if not args.illustrate:
            for flag, value in (("--balance", args.balance), ("--age", args.age), ("--n-parcels", args.n_parcels)):
                if value is not None:
                    print(f"note: {flag} only affects --illustrate, which was not requested", file=sys.stderr)
        age = args.age if args.age is not None else PRESERVATION_AGE
        n_parcels = args.n_parcels if args.n_parcels is not None else 6
        if args.illustrate:
            if not PRESERVATION_AGE <= age <= MAX_AGE:
                raise ScreenerError(f"--age must be between {PRESERVATION_AGE} (preservation age: nobody younger "
                                    f"can hold a retirement-phase pension) and {MAX_AGE}, got {age}")
            if n_parcels < 1:
                raise ScreenerError("--n-parcels must be at least 1")

        all_products = load_universe(args.universe)
        products = list(all_products)
        if args.only_role:
            products = [p for p in products if p["role"] in args.only_role]
        if args.exclude:
            drop = {t.upper() for t in args.exclude}
            known = {p["ticker"] for p in all_products}
            for t in sorted(drop - known):
                print(f"note: --exclude {t} matches nothing in the universe", file=sys.stderr)
            products = [p for p in products if p["ticker"] not in drop]
        if not products:
            raise ScreenerError("no products left after --only-role/--exclude")
        if args.explain:
            wanted = args.explain.upper()
            if wanted not in {p["ticker"] for p in products}:
                if wanted in {p["ticker"] for p in all_products}:
                    raise ScreenerError(f"{wanted} was removed by --exclude/--only-role")
                raise ScreenerError(f"{wanted} is not in the universe")

        anomalies = audit_universe(products, today)
        if args.audit_universe:
            print("\n".join(anomalies) if anomalies else "universe: no anomalies found")
            return 1 if anomalies else 0
        for a in anomalies:
            print(f"universe check: {a}", file=sys.stderr)

        if args.fetch or args.fetch_only:
            result = fetch_history([p["ticker"] for p in products], args.data_dir, years=args.years,
                                   backend=args.fetch_backend,
                                   progress=lambda t: print(f"fetched {t}", file=sys.stderr))
            print(f"fetched {len(result['fetched'])} of {len(products)}; no data for {result['empty'] or 'none'}",
                  file=sys.stderr)
            for t, why in result["failed"].items():
                print(f"failed {t}: {why}", file=sys.stderr)
            if not result["fetched"]:
                raise ScreenerError(f"nothing fetched: {len(result['failed'])} failed, {len(result['empty'])} "
                                    "returned no data")
            if args.fetch_only:
                return 1 if result["failed"] else 0

        if not os.path.isdir(args.data_dir):
            raise ScreenerError(f"data directory not found: {args.data_dir} (run with --fetch, or point "
                                f"--data-dir at CSV history)")
        filters = dict(DEFAULT_FILTERS, min_size_aud_m=min_size, min_adv_aud=min_adv,
                       max_price_age_days=args.max_price_age, allow_hybrids=args.allow_hybrids)
        screened = screen(products, args.data_dir, filters, today, as_of=as_of, parcels=parcels,
                          brokerage_aud=brokerage, tax_rate=tax_rate)
        if screened["as_of"] is None:
            raise ScreenerError(f"no price history found in {args.data_dir}; run with --fetch")

        if args.explain:
            print(DISCLAIMER)
            print()
            print(render_explain(screened, args.explain))
            return 0

        illustration = None
        if args.illustrate:
            illustration = illustrate(screened, args.illustrate, n_parcels, parcels[0],
                                      brokerage_aud=brokerage, balance_aud=balance, age=age)

        print(render_text(screened, show_excluded=not args.hide_excluded))
        if illustration:
            print()
            print(render_illustration(illustration))
        if args.json:
            _write_text(args.json, to_json(screened, illustration), "--json")
            print(f"wrote {args.json}", file=sys.stderr)
        if args.markdown:
            _write_text(args.markdown, render_markdown(screened, illustration), "--markdown")
            print(f"wrote {args.markdown}", file=sys.stderr)
        return 0
    except ScreenerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
