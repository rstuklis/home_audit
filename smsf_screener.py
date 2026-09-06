#!/usr/bin/env python3
"""
smsf_screener.py
================
A transparent, rule-based screener for ASX-listed investments, written for a
self-directed trustee of a Self-Managed Super Fund (SMSF) whose account is in
retirement phase and who deploys money in parcels of roughly AUD 10,000-25,000.

GENERAL INFORMATION ONLY. This program does not know your balance, your other
assets, your spouse, your health or your goals, so it cannot and does not
recommend anything. It ranks products against explicit, printed rules that you
can change. Under the Corporations Act 2001 (Cth) that is factual information
and, at most, general advice: it does not take your personal circumstances into
account. Decisions about your fund remain yours as trustee, and some of them
(transfer balance cap, commutations, estate planning, Division 296) are worth
a licensed adviser's or an SMSF specialist's time.

Runs on the Python standard library only, like its sibling home_net_audit.py.
The optional --fetch step needs the third-party `yfinance` package.

What it does
------------
1. Loads a hand-curated universe (smsf_universe.csv) of ASX-listed products
   with the static facts that free data sources do NOT provide reliably:
   management fee, fund size, typical franking level, structure and role.
   Every row carries an as-at date and the tool warns when it is stale.
2. Loads price and distribution history per ticker from CSV files:
       <data-dir>/<TICKER>.csv             date,close,volume
       <data-dir>/<TICKER>.dividends.csv   date,amount
   `--fetch` fills that directory from Yahoo Finance via yfinance.
3. Computes, per product: last price, 1-year volatility, 3-year maximum
   drawdown, median daily value traded, trailing 12-month cash yield, and the
   grossed-up yield a 0% taxpayer actually receives once franking credits are
   refunded.
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
  DRP   = Distribution (or Dividend) Reinvestment Plan
  CHESS = Clearing House Electronic Subregister System (ASX settlement)
  HIN   = Holder Identification Number (your CHESS-sponsored holding id)
  AUD   = Australian dollars
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import statistics
import sys
from datetime import date, datetime, timedelta

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DISCLAIMER = (
    "GENERAL INFORMATION ONLY - NOT PERSONAL FINANCIAL ADVICE.\n"
    "This screener applies fixed, printed rules to public data. It does not know\n"
    "your circumstances and does not recommend any product. Check every figure\n"
    "against the issuer's current documents before acting, and record your own\n"
    "reasoning in the fund's investment strategy as SIS Regulation 4.09 requires."
)

# Franking credits are refundable in full to a fund whose income is exempt
# current pension income. A dividend franked at the 30% company rate carries a
# credit of 30/70 of the cash amount.
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

# Minimum pension drawdown factors, SIS Regulations Schedule 7, by age at
# 1 July (or at commencement). Percent of the account balance.
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

# Per-role rules. Caps drive the hard filters AND the 0-100 component scores;
# weights (which must sum to 100) combine the components. Every number here is
# a policy choice, not a fact, and is printed by --rules so it can be argued
# with. Rationale in brief:
#   mer_cap            what the cheapest mainstream product in the role costs,
#                      times roughly three; anything dearer needs a reason.
#   vol_cap / mdd_cap  the annualised volatility and 3-year drawdown at which
#                      the stability/drawdown component reaches zero.
#   target_gross_yield the grossed-up yield that earns a full income score.
ROLE_RULES = {
    "cash": dict(mer_cap=0.30, vol_cap=2.0, mdd_cap=1.0, target_gross_yield=4.5,
                 weights=dict(cost=30, liquidity=20, size=10, income=25, stability=10, drawdown=5, franking=0)),
    "defensive": dict(mer_cap=0.35, vol_cap=8.0, mdd_cap=15.0, target_gross_yield=4.5,
                      weights=dict(cost=25, liquidity=15, size=10, income=15, stability=20, drawdown=15, franking=0)),
    "core_au": dict(mer_cap=0.25, vol_cap=25.0, mdd_cap=40.0, target_gross_yield=5.5,
                    weights=dict(cost=30, liquidity=15, size=15, income=15, stability=5, drawdown=5, franking=15)),
    "core_intl": dict(mer_cap=0.35, vol_cap=25.0, mdd_cap=40.0, target_gross_yield=2.5,
                      weights=dict(cost=35, liquidity=15, size=20, income=5, stability=15, drawdown=10, franking=0)),
    "income": dict(mer_cap=0.60, vol_cap=25.0, mdd_cap=40.0, target_gross_yield=7.0,
                   weights=dict(cost=20, liquidity=15, size=10, income=25, stability=10, drawdown=5, franking=15)),
    "diversifier": dict(mer_cap=0.60, vol_cap=30.0, mdd_cap=45.0, target_gross_yield=3.0,
                        weights=dict(cost=30, liquidity=20, size=15, income=5, stability=15, drawdown=15, franking=0)),
    "all_in_one": dict(mer_cap=0.35, vol_cap=20.0, mdd_cap=35.0, target_gross_yield=3.5,
                       weights=dict(cost=30, liquidity=15, size=15, income=10, stability=15, drawdown=15, franking=0)),
}

for _role, _rule in ROLE_RULES.items():
    assert _role in ROLES, _role
    assert sum(_rule["weights"].values()) == 100, (_role, sum(_rule["weights"].values()))

# Illustrative role mixes for --illustrate, in percent of the money deployed.
# These are EXAMPLES OF STRUCTURE drawn from the kinds of growth/defensive
# splits mainstream Australian sources describe for retirees; they are not a
# recommendation and the right split depends on facts this tool never sees.
TEMPLATES = {
    "conservative": {"cash": 20, "defensive": 40, "core_au": 15, "core_intl": 15, "diversifier": 10},
    "balanced": {"cash": 10, "defensive": 30, "core_au": 25, "core_intl": 25, "diversifier": 10},
    "growth": {"cash": 5, "defensive": 20, "core_au": 30, "core_intl": 35, "diversifier": 10},
    "income_tilt": {"cash": 10, "defensive": 30, "core_au": 15, "income": 15, "core_intl": 20, "diversifier": 10},
    "simple": {"cash": 10, "defensive": 20, "all_in_one": 70},
}
for _name, _mix in TEMPLATES.items():
    assert sum(_mix.values()) == 100, (_name, sum(_mix.values()))
    assert all(r in ROLES for r in _mix), _name

DEFAULT_FILTERS = dict(
    min_size_aud_m=100.0,       # below this, closure risk and wide spreads
    min_adv_aud=250_000.0,      # median daily value traded; parcel must be a small share of it
    max_price_age_days=10,      # last price older than this relative to as-of = not really trading
    allow_hybrids=False,
    static_stale_days=STATIC_STALE_DAYS,
)

UNIVERSE_COLUMNS = (
    "ticker", "name", "issuer", "structure", "role", "category", "asset_class",
    "mer_pct", "size_aud_m", "franking_pct", "distribution_frequency", "hedged",
    "notes", "as_at",
)

TICKER_RE = re.compile(r"^[A-Z0-9]{3,6}$")


class ScreenerError(Exception):
    """Any input problem the user has to fix (bad CSV, missing file, bad flag)."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def parse_date(text: str, what: str = "date") -> date:
    try:
        return date.fromisoformat(text.strip())
    except (ValueError, AttributeError):
        raise ScreenerError(f"{what}: expected YYYY-MM-DD, got {text!r}")


def parse_float(text, what: str, lo: float | None = None, hi: float | None = None,
                required: bool = True) -> float | None:
    if text is None or str(text).strip() == "":
        if required:
            raise ScreenerError(f"{what}: value is required")
        return None
    try:
        value = float(str(text).replace(",", "").strip())
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


def minimum_drawdown_factor(age: int) -> float:
    """Minimum annual pension payment, percent of balance, for the member's age."""
    if age < 0:
        raise ScreenerError(f"age must be non-negative, got {age}")
    for floor_age, factor in MINIMUM_DRAWDOWN_FACTORS:
        if age >= floor_age:
            return factor
    return MINIMUM_DRAWDOWN_FACTORS[-1][1]


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
# Universe (hand-curated static facts)
# ---------------------------------------------------------------------------

def load_universe(path: str) -> list[dict]:
    """Read and validate the product universe CSV. Raises ScreenerError."""
    if not os.path.isfile(path):
        raise ScreenerError(f"universe file not found: {path}")
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = [h.strip() for h in (reader.fieldnames or [])]
        missing = [c for c in UNIVERSE_COLUMNS if c not in header]
        if missing:
            raise ScreenerError(f"{path}: missing columns {missing}")
        rows = list(reader)

    products: list[dict] = []
    seen: set[str] = set()
    for n, raw in enumerate(rows, start=2):  # line 1 is the header
        where = f"{path} line {n}"
        row = {k: (v or "").strip() for k, v in raw.items() if k is not None}
        ticker = row["ticker"].upper()
        if not TICKER_RE.match(ticker):
            raise ScreenerError(f"{where}: ticker {row['ticker']!r} is not a 3-6 character ASX code")
        if ticker in seen:
            raise ScreenerError(f"{where}: duplicate ticker {ticker}")
        seen.add(ticker)
        if not row["name"]:
            raise ScreenerError(f"{where}: name is required")
        structure = row["structure"].lower()
        if structure not in STRUCTURES:
            raise ScreenerError(f"{where}: structure {row['structure']!r} not one of {STRUCTURES}")
        role = row["role"].lower()
        if role not in ROLES:
            raise ScreenerError(f"{where}: role {row['role']!r} not one of {ROLES}")
        asset_class = row["asset_class"].lower()
        if asset_class not in ASSET_CLASSES:
            raise ScreenerError(f"{where}: asset_class {row['asset_class']!r} not one of {ASSET_CLASSES}")
        freq = row["distribution_frequency"].lower()
        if freq not in FREQUENCIES:
            raise ScreenerError(f"{where}: distribution_frequency {row['distribution_frequency']!r} "
                                f"not one of {tuple(FREQUENCIES)}")
        products.append({
            "ticker": ticker,
            "name": row["name"],
            "issuer": row["issuer"],
            "structure": structure,
            "role": role,
            "category": row["category"],
            "asset_class": asset_class,
            "mer_pct": parse_float(row["mer_pct"], f"{where}: mer_pct", 0.0, 5.0),
            "size_aud_m": parse_float(row["size_aud_m"], f"{where}: size_aud_m", 0.0, None),
            "franking_pct": parse_float(row["franking_pct"], f"{where}: franking_pct", 0.0, 100.0),
            "distribution_frequency": freq,
            "hedged": parse_tristate(row["hedged"], f"{where}: hedged"),
            "notes": row["notes"],
            "as_at": parse_date(row["as_at"], f"{where}: as_at"),
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
            findings.append(f"{t}: name says hedged but hedged={p['hedged']!r}")
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
    """Rows of {date, close, volume} ascending by date, or None if no file."""
    path = price_path(data_dir, ticker)
    if not os.path.isfile(path):
        return None
    rows: list[dict] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = [h.strip().lower() for h in (reader.fieldnames or [])]
        for col in ("date", "close"):
            if col not in header:
                raise ScreenerError(f"{path}: missing column {col!r}")
        for n, raw in enumerate(reader, start=2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
            if not row.get("close"):
                continue  # Yahoo emits blank rows on non-trading days
            d = parse_date(row["date"], f"{path} line {n}: date")
            close = parse_float(row["close"], f"{path} line {n}: close", 0.0, None)
            if close <= 0:
                continue
            volume = parse_float(row.get("volume", ""), f"{path} line {n}: volume", 0.0, None, required=False) or 0.0
            rows.append({"date": d, "close": close, "volume": volume})
    rows.sort(key=lambda r: r["date"])
    # Keep the last row for a duplicated date (a re-fetch appended, not replaced).
    dedup: dict[date, dict] = {}
    for r in rows:
        dedup[r["date"]] = r
    return [dedup[d] for d in sorted(dedup)]


def load_distributions(data_dir: str, ticker: str) -> list[dict]:
    """Rows of {date, amount} ascending. Missing file means no distributions known."""
    path = dividend_path(data_dir, ticker)
    if not os.path.isfile(path):
        return []
    rows: list[dict] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = [h.strip().lower() for h in (reader.fieldnames or [])]
        for col in ("date", "amount"):
            if col not in header:
                raise ScreenerError(f"{path}: missing column {col!r}")
        for n, raw in enumerate(reader, start=2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
            if not row.get("amount"):
                continue
            d = parse_date(row["date"], f"{path} line {n}: date")
            amount = parse_float(row["amount"], f"{path} line {n}: amount", 0.0, None)
            if amount > 0:
                rows.append({"date": d, "amount": amount})
    rows.sort(key=lambda r: r["date"])
    return rows


def compute_metrics(prices: list[dict], dists: list[dict], as_of: date) -> dict:
    """Derived numbers from history up to and including as_of.

    Everything is computed from rows dated <= as_of so that a fixed --as-of
    gives the same answer on any day, which is what makes the output testable.
    """
    rows = [r for r in prices if r["date"] <= as_of]
    if not rows:
        return {"has_prices": False}
    last = rows[-1]
    one_year_ago = as_of - timedelta(days=365)
    three_years_ago = as_of - timedelta(days=3 * 365)

    year = [r for r in rows if r["date"] > one_year_ago]
    returns = [math.log(b["close"] / a["close"]) for a, b in zip(year, year[1:])]
    vol_pct = None
    if len(returns) >= 20:
        vol_pct = statistics.stdev(returns) * math.sqrt(TRADING_DAYS_PER_YEAR) * 100.0

    window = [r for r in rows if r["date"] > three_years_ago]
    peak = 0.0
    mdd = 0.0
    for r in window:
        peak = max(peak, r["close"])
        if peak > 0:
            mdd = max(mdd, 1.0 - r["close"] / peak)
    mdd_pct = mdd * 100.0 if len(window) >= 2 else None

    recent = rows[-60:]
    adv_aud = None
    if len(recent) >= 20:
        adv_aud = statistics.median(r["close"] * r["volume"] for r in recent)

    ttm = [d for d in dists if one_year_ago < d["date"] <= as_of]
    ttm_dist = sum(d["amount"] for d in ttm)
    cash_yield_pct = ttm_dist / last["close"] * 100.0

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
        "last_price": last["close"],
        "last_date": last["date"],
        "price_age_days": (as_of - last["date"]).days,
        "history_days": (last["date"] - rows[0]["date"]).days,
        "rows_1y": len(year),
        "vol_pct": vol_pct,
        "mdd_pct": mdd_pct,
        "adv_aud": adv_aud,
        "ttm_dist_per_unit": ttm_dist,
        "ttm_dist_count": len(ttm),
        "cash_yield_pct": cash_yield_pct,
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
    units = int(math.floor(investable / price)) if investable > 0 else 0
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

    if not metrics.get("has_prices"):
        excl.append("no price history in the data directory")
    else:
        age = metrics["price_age_days"]
        if age > filters["max_price_age_days"]:
            excl.append(f"last price is {age} days older than the as-of date (not trading?)")
        if metrics["adv_aud"] is None:
            warn.append("fewer than 20 recent price rows: liquidity not assessed")
        elif metrics["adv_aud"] < filters["min_adv_aud"]:
            excl.append(f"median daily value traded AUD {fmt_money(metrics['adv_aud'])} "
                        f"is below AUD {fmt_money(filters['min_adv_aud'])}")
        if metrics["vol_pct"] is None:
            warn.append("under 20 daily returns in the last year: volatility not assessed")
        if metrics["cash_yield_pct"] > YIELD_SANITY_CAP_PCT:
            warn.append(f"trailing yield {fmt_pct(metrics['cash_yield_pct'])} is unusually high: "
                        "check for capital returns, option premium or one-off distributions "
                        "(income scored neutral, not rewarded)")
        expected = FREQUENCIES[product["distribution_frequency"]]
        if expected and metrics["ttm_dist_count"] < expected:
            warn.append(f"{metrics['ttm_dist_count']} distributions in the last year, "
                        f"{expected} expected: dividend data may be incomplete")
        if metrics["history_days"] < 365:
            warn.append("under one year of price history: drawdown and volatility are partial")

    if product["mer_pct"] > rules["mer_cap"]:
        excl.append(f"MER {product['mer_pct']}% is above the {product['role']} cap of {rules['mer_cap']}%")
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


def score_product(product: dict, metrics: dict) -> dict:
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
    gross, credit = grossed_up_yield(cash_yield, product["franking_pct"])
    if cash_yield > YIELD_SANITY_CAP_PCT:
        income = 50.0
        notes.append(f"yield above {YIELD_SANITY_CAP_PCT:.0f}% treated as unverified, income scored 50")
    else:
        income = clamp(100.0 * gross / rules["target_gross_yield"])

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

    franking = clamp(product["franking_pct"])

    components = {
        "cost": cost, "liquidity": liquidity, "size": size, "income": income,
        "stability": stability, "drawdown": drawdown, "franking": franking,
    }
    total = sum(w[k] * components[k] for k in components) / 100.0
    return {
        "total": round(total, 1),
        "components": {k: round(v, 1) for k, v in components.items()},
        "weights": dict(w),
        "gross_yield_pct": gross,
        "franking_credit_yield_pct": credit,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Screening
# ---------------------------------------------------------------------------

def resolve_as_of(products: list[dict], data_dir: str, as_of: date | None) -> date | None:
    """The newest price date across the universe, unless the user fixed one."""
    if as_of is not None:
        return as_of
    newest = None
    for p in products:
        prices = load_price_history(data_dir, p["ticker"])
        if prices:
            newest = prices[-1]["date"] if newest is None else max(newest, prices[-1]["date"])
    return newest


def screen(products: list[dict], data_dir: str, filters: dict, today: date,
           as_of: date | None = None, parcels=(10_000.0, 25_000.0), brokerage_aud: float = 0.0) -> dict:
    as_of = resolve_as_of(products, data_dir, as_of)
    results: list[dict] = []
    for p in products:
        prices = load_price_history(data_dir, p["ticker"])
        dists = load_distributions(data_dir, p["ticker"])
        metrics = compute_metrics(prices or [], dists, as_of) if (prices and as_of) else {"has_prices": False}
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
            entry["score"] = score_product(p, metrics)
            entry["parcels"] = [parcel_plan(metrics["last_price"], amt, brokerage_aud) for amt in parcels]
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
    mix = TEMPLATES[template]
    alloc = allocate_parcels(mix, n_parcels)
    lines: list[dict] = []
    unfilled: list[str] = []
    skipped: list[str] = []
    for role, count in alloc.items():
        survivors = [e for e in screened["results"] if e["product"]["role"] == role and not e["exclusions"]]
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
                          "score": e["score"]["total"], "gross_yield_pct": e["score"]["gross_yield_pct"]})
    deployed = sum(l["value_aud"] for l in lines)
    defensive_value = sum(l["value_aud"] for l in lines if l["role"] in ("cash", "defensive"))
    weighted_gross = (sum(l["value_aud"] * l["gross_yield_pct"] for l in lines) / deployed) if deployed else 0.0
    out = {
        "template": template,
        "mix_pct": dict(mix),
        "parcels_by_role": alloc,
        "lines": lines,
        "unfilled_roles": unfilled,
        "skipped_not_marketable": skipped,
        "deployed_aud": deployed,
        "defensive_share_pct": (defensive_value / deployed * 100.0) if deployed else 0.0,
        "weighted_gross_yield_pct": weighted_gross,
        "drawdown_cover": None,
    }
    if balance_aud:
        factor = minimum_drawdown_factor(age)
        annual_min = balance_aud * factor / 100.0
        out["drawdown_cover"] = {
            "age": age,
            "minimum_factor_pct": factor,
            "annual_minimum_aud": annual_min,
            "years_covered_by_cash_and_defensive": (defensive_value / annual_min) if annual_min else None,
        }
    return out


# ---------------------------------------------------------------------------
# Optional live fetch (yfinance)
# ---------------------------------------------------------------------------

def fetch_history(tickers: list[str], data_dir: str, years: int = 3, suffix: str = ".AX",
                  progress=None) -> dict:
    """Download price and dividend history into the CSV layout this tool reads.

    Needs the third-party yfinance package (python3 -m pip install yfinance).
    Yahoo's ASX coverage is good for prices and volume and patchy for
    distributions, which is why the screener warns when it sees fewer
    distributions than the product's stated frequency implies.
    """
    try:
        import yfinance as yf  # type: ignore
    except ImportError:
        raise ScreenerError("yfinance is not installed; run: python3 -m pip install yfinance")
    os.makedirs(data_dir, exist_ok=True)
    fetched: list[str] = []
    empty: list[str] = []
    failed: dict[str, str] = {}
    for t in tickers:
        try:
            hist = yf.Ticker(f"{t}{suffix}").history(period=f"{years}y", auto_adjust=False, actions=True)
        except Exception as exc:  # network, parsing, Yahoo changes: report, keep going
            failed[t] = f"{type(exc).__name__}: {exc}"
            continue
        if hist is None or len(hist) == 0:
            empty.append(t)
            continue
        with open(price_path(data_dir, t), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["date", "close", "volume"])
            for idx, row in hist.iterrows():
                close = row.get("Close")
                if close is None or (isinstance(close, float) and math.isnan(close)):
                    continue
                vol = row.get("Volume", 0) or 0
                w.writerow([idx.date().isoformat(), f"{float(close):.6f}", int(vol)])
        with open(dividend_path(data_dir, t), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["date", "amount"])
            if "Dividends" in hist.columns:
                for idx, amount in hist["Dividends"].items():
                    if amount and float(amount) > 0:
                        w.writerow([idx.date().isoformat(), f"{float(amount):.6f}"])
        fetched.append(t)
        if progress:
            progress(t)
    return {"fetched": fetched, "empty": empty, "failed": failed}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _row(e: dict) -> dict:
    p, m, s = e["product"], e["metrics"], e["score"]
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
        "units": [pl["units"] for pl in e["parcels"]],
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
    }


def render_text(screened: dict, show_excluded: bool = True) -> str:
    out: list[str] = [DISCLAIMER, ""]
    as_of = screened["as_of"]
    out.append(f"smsf_screener {__version__}   as-of {as_of}   today {screened['today']}   "
               f"parcels AUD {' / '.join(fmt_money(x) for x in screened['parcels'])}   "
               f"brokerage AUD {screened['brokerage_aud']:.2f} per trade")
    if as_of and (screened["today"] - as_of).days > 7:
        out.append(f"WARNING: price data is {(screened['today'] - as_of).days} days old; re-run --fetch")
    f = screened["filters"]
    out.append(f"filters: size >= AUD {fmt_money(f['min_size_aud_m'])} m, median daily value >= AUD "
               f"{fmt_money(f['min_adv_aud'])}, price age <= {f['max_price_age_days']} d, "
               f"hybrids {'allowed' if f['allow_hybrids'] else 'excluded'}, role MER caps per --rules")
    out.append("")
    header = (f"{'#':>2} {'ticker':<7}{'name':<44}{'MER%':>6}{'size$m':>8}{'price':>11}{'yld%':>6}"
              f"{'gross%':>7}{'frk%':>5}{'vol%':>6}{'mdd%':>6}{'adv$k':>8}{'score':>6}"
              + "".join(f"{'u@' + str(int(x / 1000)) + 'k':>8}" for x in screened["parcels"]))
    for role in ROLES:
        rows = [e for e in screened["results"] if e["product"]["role"] == role]
        if not rows:
            continue
        out.append(f"== {ROLE_LABELS[role]} ==")
        out.append(header)
        for e in rows:
            r = _row(e)
            if e["exclusions"] and not show_excluded:
                continue
            mark = f"{r['rank']:>2}" if r["rank"] else " x"
            c = _cells(r)
            line = (f"{mark} {r['ticker']:<7}{r['name'][:43]:<44}{r['mer_pct']:>6.2f}{r['size_aud_m']:>8,.0f}"
                    f"{c['price']:>11}{c['yld']:>6}{c['gross']:>7}{r['franking_pct']:>5.0f}{c['vol']:>6}"
                    f"{c['mdd']:>6}{c['adv']:>8}{c['score']:>6}"
                    + "".join(f"{u:>8}" for u in r["units"]))
            out.append(line)
            for reason in e["exclusions"]:
                out.append(f"      excluded: {reason}")
            for warning in e["warnings"]:
                out.append(f"      note: {warning}")
        out.append("")
    out.append("Columns: yld% = trailing 12-month cash distributions / price; gross% = yld% plus the franking "
               "credit a 0% taxpayer gets refunded; frk% = typical franking (hand-curated); vol% = annualised "
               "1-year volatility; mdd% = worst 3-year peak-to-trough fall; adv$k = median daily value traded "
               "(AUD thousands); u@Nk = whole units a parcel of AUD N thousand buys after brokerage.")
    out.append("")
    out.append(DISCLAIMER.splitlines()[0])
    return "\n".join(out)


def render_explain(screened: dict, ticker: str) -> str:
    ticker = ticker.upper()
    for e in screened["results"]:
        if e["product"]["ticker"] != ticker:
            continue
        p, m, s = e["product"], e["metrics"], e["score"]
        out = [f"{p['ticker']}  {p['name']}  ({p['issuer']}; {p['structure']}; role {p['role']})",
               f"  static facts as at {p['as_at']}: MER {p['mer_pct']}%, size AUD {fmt_money(p['size_aud_m'])} m, "
               f"franking {p['franking_pct']:.0f}%, distributions {p['distribution_frequency']}, "
               f"hedged {p['hedged']}"]
        if p["notes"]:
            out.append(f"  notes: {p['notes']}")
        if not m.get("has_prices"):
            out.append("  no price history")
        else:
            out.append(f"  last price AUD {m['last_price']:.2f} on {m['last_date']} "
                       f"({m['price_age_days']} days before as-of); {m['history_days']} days of history")
            out.append(f"  TTM distributions AUD {m['ttm_dist_per_unit']:.4f}/unit over {m['ttm_dist_count']} "
                       f"payments = cash yield {fmt_pct(m['cash_yield_pct'])}")
            gross, credit = grossed_up_yield(m["cash_yield_pct"], p["franking_pct"])
            out.append(f"  grossed-up yield = {m['cash_yield_pct']:.2f}% x (1 + {p['franking_pct']:.0f}% x "
                       f"{COMPANY_TAX_RATE:.2f}/{1 - COMPANY_TAX_RATE:.2f}) = {gross:.2f}% "
                       f"(franking credit refund worth {credit:.2f}%)")
            out.append(f"  volatility {fmt_pct(m['vol_pct'], 1)}; max drawdown {fmt_pct(m['mdd_pct'], 1)}; "
                       f"median daily value AUD {fmt_money(m['adv_aud'])}; 1y total return "
                       f"{fmt_pct(m['total_return_1y_pct'], 1)}")
        for reason in e["exclusions"]:
            out.append(f"  EXCLUDED: {reason}")
        for warning in e["warnings"]:
            out.append(f"  note: {warning}")
        if s:
            rules = ROLE_RULES[p["role"]]
            out.append(f"  score {s['total']:.1f}/100 (rank {e['rank_in_role'] or '-'} of "
                       f"{e['role_survivors']} survivors in role)")
            out.append(f"    role caps: MER {rules['mer_cap']}%, vol {rules['vol_cap']}%, drawdown "
                       f"{rules['mdd_cap']}%, target gross yield {rules['target_gross_yield']}%")
            for k, v in s["components"].items():
                out.append(f"    {k:<10} {v:>6.1f} x weight {s['weights'][k]:>3} = {v * s['weights'][k] / 100:>6.1f}")
            for note in s["notes"]:
                out.append(f"    ({note})")
        for plan in e["parcels"]:
            out.append(f"  AUD {fmt_money(plan['parcel_aud'])} parcel: {plan['units']} units = AUD "
                       f"{plan['value_aud']:,.2f} + brokerage {plan['brokerage_aud']:.2f}, leftover AUD "
                       f"{plan['leftover_aud']:,.2f}, brokerage {fmt_pct(plan['brokerage_pct'])} of value"
                       + ("" if plan["marketable"] else "  (BELOW MARKETABLE PARCEL)"))
        return "\n".join(out)
    raise ScreenerError(f"{ticker} is not in the universe")


def render_illustration(ill: dict) -> str:
    out = [f"Illustrative structure '{ill['template']}' - an example of shape, not a recommendation",
           "  mix: " + ", ".join(f"{ROLE_LABELS[r]} {p}%" for r, p in ill["mix_pct"].items()),
           "  parcels: " + ", ".join(f"{r} x{n}" for r, n in ill["parcels_by_role"].items())]
    for l in ill["lines"]:
        out.append(f"  {l['role']:<12}{l['ticker']:<7}{l['name'][:40]:<41}{l['units']:>6} units  AUD "
                   f"{l['value_aud']:>10,.2f}  gross yield {l['gross_yield_pct']:.2f}%  score {l['score']:.1f}")
    for r in ill["unfilled_roles"]:
        out.append(f"  {r:<12}(no surviving product in the universe that this parcel size can buy)")
    if ill["skipped_not_marketable"]:
        out.append("  skipped because one parcel cannot buy a marketable holding: "
                   + ", ".join(ill["skipped_not_marketable"]))
    out.append(f"  deployed AUD {ill['deployed_aud']:,.2f}; cash + defensive share "
               f"{ill['defensive_share_pct']:.1f}%; value-weighted gross yield {ill['weighted_gross_yield_pct']:.2f}%")
    dc = ill["drawdown_cover"]
    if dc:
        yrs = dc["years_covered_by_cash_and_defensive"]
        out.append(f"  at age {dc['age']} the minimum drawdown is {dc['minimum_factor_pct']:.0f}% of balance = AUD "
                   f"{dc['annual_minimum_aud']:,.0f} a year; these cash + defensive parcels cover "
                   f"{yrs:.1f} years of it" if yrs is not None else "  drawdown cover not computed")
    return "\n".join(out)


def render_rules() -> str:
    out = ["Role rules (edit ROLE_RULES in the source to change them):"]
    for role, r in ROLE_RULES.items():
        out.append(f"  {role:<12} MER cap {r['mer_cap']:.2f}%  vol cap {r['vol_cap']:.0f}%  drawdown cap "
                   f"{r['mdd_cap']:.0f}%  target gross yield {r['target_gross_yield']:.1f}%  weights "
                   + " ".join(f"{k}={v}" for k, v in r["weights"].items()))
    out.append("Global filters (flags): " + ", ".join(f"{k}={v}" for k, v in DEFAULT_FILTERS.items()))
    out.append("Templates for --illustrate (percent of money deployed):")
    for name, mix in TEMPLATES.items():
        out.append(f"  {name:<13}" + ", ".join(f"{r} {p}" for r, p in mix.items()))
    out.append(f"Minimum drawdown factors by age: " + ", ".join(f"{a}+ {f:.0f}%" for a, f in
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
    for role in ROLES:
        rows = [e for e in screened["results"] if e["product"]["role"] == role]
        if not rows:
            continue
        out.append(f"## {ROLE_LABELS[role]}")
        out.append("")
        out.append("| # | Ticker | Name | MER % | Size AUD m | Price | Cash yield % | Gross yield % | Franking % | "
                   "Vol % | Drawdown % | Daily value AUD k | Score | "
                   + " | ".join(f"Units @ {int(x / 1000)}k" for x in screened["parcels"]) + " | Notes |")
        out.append("|" + "---|" * (14 + len(screened["parcels"])))
        for e in rows:
            r = _row(e)
            c = _cells(r)
            notes = "; ".join(["EXCLUDED: " + x for x in e["exclusions"]] + e["warnings"])
            out.append(f"| {r['rank'] or 'x'} | {r['ticker']} | {r['name']} | {r['mer_pct']:.2f} | "
                       f"{r['size_aud_m']:,.0f} | {c['price']} | {c['yld']} | {c['gross']} | "
                       f"{r['franking_pct']:.0f} | {c['vol']} | {c['mdd']} | {c['adv']} | {c['score']} | "
                       + " | ".join(str(u) for u in r["units"]) + f" | {notes} |")
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
               "  python3 smsf_screener.py --fetch --data-dir data          # download history, then screen\n"
               "  python3 smsf_screener.py --data-dir data --explain VAS     # show the arithmetic for one code\n"
               "  python3 smsf_screener.py --data-dir data --illustrate balanced --n-parcels 6 --parcel 15000\n"
               "  python3 smsf_screener.py --rules                           # print every policy number\n")
    ap.add_argument("--universe", default=os.path.join(here, "smsf_universe.csv"),
                    help="CSV of products and hand-curated static facts (default: smsf_universe.csv beside the script)")
    ap.add_argument("--data-dir", default=os.path.join(here, "data"),
                    help="directory of <TICKER>.csv and <TICKER>.dividends.csv (default: ./data)")
    ap.add_argument("--fetch", action="store_true", help="download history into --data-dir first (needs yfinance)")
    ap.add_argument("--fetch-only", action="store_true", help="download and stop")
    ap.add_argument("--years", type=int, default=3, help="years of history to fetch (default 3)")
    ap.add_argument("--as-of", type=str, default=None, help="freeze the as-of date (YYYY-MM-DD) for reproducible runs")
    ap.add_argument("--today", type=str, default=None, help="override today's date (YYYY-MM-DD), mainly for tests")
    ap.add_argument("--parcel", type=float, action="append", default=None,
                    help="parcel size in AUD; repeatable (default 10000 and 25000)")
    ap.add_argument("--brokerage", type=float, default=0.0, help="brokerage per trade in AUD (default 0)")
    ap.add_argument("--min-size", type=float, default=DEFAULT_FILTERS["min_size_aud_m"], help="minimum fund size, AUD m")
    ap.add_argument("--min-adv", type=float, default=DEFAULT_FILTERS["min_adv_aud"],
                    help="minimum median daily value traded, AUD")
    ap.add_argument("--max-price-age", type=int, default=DEFAULT_FILTERS["max_price_age_days"],
                    help="exclude if the last price is older than this many days before as-of")
    ap.add_argument("--allow-hybrids", action="store_true", help="keep bank hybrid funds in the shortlist")
    ap.add_argument("--only-role", choices=ROLES, action="append", default=None, help="restrict to a role; repeatable")
    ap.add_argument("--exclude", type=str, action="append", default=None, help="drop a ticker; repeatable")
    ap.add_argument("--hide-excluded", action="store_true", help="do not list products that failed a filter")
    ap.add_argument("--explain", type=str, default=None, metavar="TICKER", help="show the full arithmetic for one code")
    ap.add_argument("--illustrate", choices=tuple(TEMPLATES), default=None, help="lay out an example multi-parcel structure")
    ap.add_argument("--n-parcels", type=int, default=6, help="parcels in the illustration (default 6)")
    ap.add_argument("--balance", type=float, default=None,
                    help="pension account balance in AUD, to express cash cover in years of minimum drawdown")
    ap.add_argument("--age", type=int, default=60, help="member's age for the minimum drawdown factor (default 60)")
    ap.add_argument("--json", type=str, default=None, metavar="FILE", help="also write the full result as JSON")
    ap.add_argument("--markdown", type=str, default=None, metavar="FILE", help="also write a Markdown report")
    ap.add_argument("--audit-universe", action="store_true", help="cross-check the static CSV and stop")
    ap.add_argument("--rules", action="store_true", help="print every policy number and stop")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        if args.rules:
            print(render_rules())
            return 0
        today = parse_date(args.today, "--today") if args.today else date.today()
        as_of = parse_date(args.as_of, "--as-of") if args.as_of else None
        products = load_universe(args.universe)
        if args.only_role:
            products = [p for p in products if p["role"] in args.only_role]
        if args.exclude:
            drop = {t.upper() for t in args.exclude}
            products = [p for p in products if p["ticker"] not in drop]
        if not products:
            raise ScreenerError("no products left after --only-role/--exclude")

        anomalies = audit_universe(products, today)
        if args.audit_universe:
            print("\n".join(anomalies) if anomalies else "universe: no anomalies found")
            return 1 if anomalies else 0
        for a in anomalies:
            print(f"universe check: {a}", file=sys.stderr)

        if args.fetch or args.fetch_only:
            result = fetch_history([p["ticker"] for p in products], args.data_dir, years=args.years,
                                   progress=lambda t: print(f"fetched {t}", file=sys.stderr))
            print(f"fetched {len(result['fetched'])}, empty {result['empty']}, failed {result['failed']}",
                  file=sys.stderr)
            if args.fetch_only:
                return 0

        if not os.path.isdir(args.data_dir):
            raise ScreenerError(f"data directory not found: {args.data_dir} (run with --fetch, or point "
                                f"--data-dir at CSV history)")
        filters = dict(DEFAULT_FILTERS, min_size_aud_m=args.min_size, min_adv_aud=args.min_adv,
                       max_price_age_days=args.max_price_age, allow_hybrids=args.allow_hybrids)
        parcels = tuple(args.parcel) if args.parcel else (10_000.0, 25_000.0)
        for amt in parcels:
            if amt <= 0:
                raise ScreenerError(f"--parcel must be positive, got {amt}")
        screened = screen(products, args.data_dir, filters, today, as_of=as_of, parcels=parcels,
                          brokerage_aud=args.brokerage)
        if screened["as_of"] is None:
            raise ScreenerError(f"no price history found in {args.data_dir}; run with --fetch")

        if args.explain:
            print(DISCLAIMER)
            print()
            print(render_explain(screened, args.explain))
            return 0

        illustration = None
        if args.illustrate:
            illustration = illustrate(screened, args.illustrate, args.n_parcels, parcels[0],
                                      brokerage_aud=args.brokerage, balance_aud=args.balance, age=args.age)

        print(render_text(screened, show_excluded=not args.hide_excluded))
        if illustration:
            print()
            print(render_illustration(illustration))
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(to_json(screened, illustration))
            print(f"wrote {args.json}", file=sys.stderr)
        if args.markdown:
            with open(args.markdown, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(screened, illustration))
            print(f"wrote {args.markdown}", file=sys.stderr)
        return 0
    except ScreenerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
