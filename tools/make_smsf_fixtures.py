#!/usr/bin/env python3
"""Generate deterministic synthetic fixtures for tests/test_smsf_screener.py.

Synthetic on purpose. The tests must not assert anything about a real
product's price, yield or fee (all of which change), only that the arithmetic,
the filters and the ranking behave. Tickers are invented (CASHX, AUEQX, ...)
so that nobody mistakes the fixture universe for a shortlist.

    python3 tools/make_smsf_fixtures.py        # rewrites tests/fixtures/smsf/

Each series is a geometric random walk from a fixed seed, so re-running this
script reproduces the committed files byte for byte on any Python from 3.9 up.
"""

import csv
import math
import os
import random
from datetime import date, timedelta

START = date(2023, 9, 4)
END = date(2026, 9, 4)
FIXTURE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "tests", "fixtures", "smsf")

# ticker, start price, annual drift, annual volatility, mean daily volume,
# distributions per year, annual distribution yield (of start price),
# days to chop off the end of the price series (0 = trades to END)
SERIES = [
    ("CASHX", 50.0, 0.000, 0.003, 200_000, 12, 0.043, 0),
    ("CASHY", 100.0, 0.000, 0.004, 40_000, 12, 0.040, 0),
    ("BONDX", 45.0, 0.010, 0.060, 150_000, 4, 0.040, 0),
    ("HYBX", 10.0, 0.005, 0.030, 500_000, 12, 0.055, 0),
    ("AUEQX", 95.0, 0.060, 0.150, 250_000, 4, 0.038, 0),
    ("AUEQY", 130.0, 0.060, 0.150, 120_000, 4, 0.037, 0),
    ("PRICY", 30.0, 0.060, 0.160, 200_000, 2, 0.035, 0),
    ("INTLX", 120.0, 0.080, 0.140, 180_000, 4, 0.015, 0),
    ("OLDFCT", 60.0, 0.080, 0.140, 60_000, 4, 0.015, 0),
    ("HIYLD", 70.0, -0.020, 0.170, 100_000, 4, 0.140, 0),
    ("LICX", 7.5, 0.050, 0.140, 900_000, 2, 0.035, 0),
    ("TINYX", 20.0, 0.030, 0.200, 100_000, 0, 0.000, 0),
    ("GOLDX", 35.0, 0.100, 0.140, 300_000, 0, 0.000, 0),
    ("THINX", 20.0, 0.030, 0.180, 500, 0, 0.000, 0),
    ("RICHX", 30_000.0, 0.040, 0.120, 20, 0, 0.000, 0),
    ("STALE", 55.0, 0.050, 0.100, 100_000, 4, 0.030, 60),
    ("ALLX", 60.0, 0.050, 0.100, 150_000, 4, 0.030, 0),
]

# Static facts. NODATA has no price file on purpose.
UNIVERSE = [
    ("CASHX", "Fixture Cash ETF", "FixtureCo", "etf", "cash", "cash ETF", "defensive", 0.10, 2000, 0, "monthly", "na", "", "2026-06-30"),
    ("CASHY", "Fixture Dearer Cash ETF", "FixtureCo", "etf", "cash", "cash ETF", "defensive", 0.28, 300, 0, "monthly", "na", "", "2026-06-30"),
    ("BONDX", "Fixture Composite Bond ETF", "FixtureCo", "etf", "defensive", "bond ETF", "defensive", 0.10, 1500, 0, "quarterly", "na", "", "2026-06-30"),
    ("HYBX", "Fixture Bank Hybrid Fund", "FixtureCo", "hybrid_etf", "defensive", "hybrid fund", "defensive", 0.30, 2000, 45, "monthly", "na", "", "2026-06-30"),
    ("AUEQX", "Fixture Australian Shares ETF", "FixtureCo", "etf", "core_au", "Australian equities ETF", "growth", 0.07, 15000, 75, "quarterly", "na", "", "2026-06-30"),
    ("AUEQY", "Fixture Australia 200 ETF", "FixtureCo", "etf", "core_au", "Australian equities ETF", "growth", 0.05, 6000, 75, "quarterly", "na", "", "2026-06-30"),
    ("PRICY", "Fixture Equal Weight ETF", "FixtureCo", "etf", "core_au", "Australian equities ETF", "growth", 0.35, 2500, 70, "semi-annual", "na", "", "2026-06-30"),
    ("INTLX", "Fixture International Shares ETF", "FixtureCo", "etf", "core_intl", "international equities ETF", "growth", 0.18, 9000, 0, "quarterly", "no", "", "2026-06-30"),
    ("OLDFCT", "Fixture International Shares (Hedged) ETF", "FixtureCo", "etf", "core_intl", "international equities ETF", "growth", 0.20, 500, 0, "quarterly", "yes", "", "2025-01-01"),
    ("HIYLD", "Fixture Dividend Harvester Fund", "FixtureCo", "active_etf", "income", "dividend fund", "growth", 0.25, 4000, 80, "quarterly", "na", "", "2026-06-30"),
    ("LICX", "Fixture Investment Company", "FixtureCo", "lic", "income", "Australian equities LIC", "growth", 0.14, 10000, 100, "semi-annual", "na", "", "2026-06-30"),
    ("TINYX", "Fixture Tiny Infrastructure ETF", "FixtureCo", "etf", "diversifier", "infrastructure ETF", "growth", 0.40, 40, 0, "none", "no", "", "2026-06-30"),
    ("GOLDX", "Fixture Physical Gold", "FixtureCo", "etf", "diversifier", "gold ETF", "growth", 0.40, 3000, 0, "none", "no", "", "2026-06-30"),
    ("THINX", "Fixture Thinly Traded Property ETF", "FixtureCo", "etf", "diversifier", "property ETF", "growth", 0.20, 500, 0, "none", "na", "", "2026-06-30"),
    ("RICHX", "Fixture Very High Unit Price Fund", "FixtureCo", "etf", "diversifier", "gold ETF", "growth", 0.20, 1000, 0, "none", "no", "", "2026-06-30"),
    ("STALE", "Fixture Delisted Diversified ETF", "FixtureCo", "etf", "all_in_one", "diversified ETF", "mixed", 0.27, 1000, 20, "quarterly", "na", "", "2026-06-30"),
    ("ALLX", "Fixture Diversified Balanced ETF", "FixtureCo", "etf", "all_in_one", "diversified ETF", "mixed", 0.27, 3000, 20, "quarterly", "na", "", "2026-06-30"),
    ("NODATA", "Fixture Fund With No Price File", "FixtureCo", "etf", "all_in_one", "diversified ETF", "mixed", 0.27, 3000, 20, "quarterly", "na", "", "2026-06-30"),
]

UNIVERSE_COLUMNS = ("ticker", "name", "issuer", "structure", "role", "category", "asset_class",
                    "mer_pct", "size_aud_m", "franking_pct", "distribution_frequency", "hedged",
                    "notes", "as_at")


def trading_days(start, end):
    d = start
    while d <= end:
        if d.weekday() < 5:
            yield d
        d += timedelta(days=1)


def make_series(seed, start_price, drift, vol, mean_volume, end):
    rng = random.Random(seed)
    price = start_price
    rows = []
    for d in trading_days(START, end):
        rows.append((d, price, max(0, int(mean_volume * math.exp(rng.gauss(0, 0.4))))))
        price *= math.exp(drift / 252 + vol / math.sqrt(252) * rng.gauss(0, 1))
    return rows


def distribution_dates(per_year):
    if not per_year:
        return []
    step = 12 // per_year
    dates = []
    y, m = START.year, START.month
    while True:
        d = date(y, m, 1)
        if d > END:
            break
        if d >= START:
            dates.append(d)
        m += step
        while m > 12:
            m -= 12
            y += 1
    return dates


def main():
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    for i, (ticker, p0, drift, vol, volume, per_year, yld, chop) in enumerate(SERIES):
        end = END - timedelta(days=chop)
        rows = make_series(1000 + i, p0, drift, vol, volume, end)
        with open(os.path.join(FIXTURE_DIR, f"{ticker}.csv"), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["date", "close", "volume"])
            for d, close, vol_ in rows:
                w.writerow([d.isoformat(), f"{close:.4f}", vol_])
        with open(os.path.join(FIXTURE_DIR, f"{ticker}.dividends.csv"), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["date", "amount"])
            if per_year:
                amount = p0 * yld / per_year
                for d in distribution_dates(per_year):
                    if d <= end:
                        w.writerow([d.isoformat(), f"{amount:.4f}"])
    with open(os.path.join(FIXTURE_DIR, "universe.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(UNIVERSE_COLUMNS)
        for row in UNIVERSE:
            w.writerow(row)
    print(f"wrote {len(SERIES)} series and universe.csv to {FIXTURE_DIR}")


if __name__ == "__main__":
    main()
