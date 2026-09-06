# smsf_screener.py

A rule-based screener for ASX-listed investments, written for a self-directed
trustee of a Self-Managed Super Fund (SMSF) whose account is in retirement
phase and who deploys money in parcels of roughly AUD 10,000 to 25,000.

**General information only, not personal financial advice.** The program does
not know your balance, other assets, spouse, health or goals, so it cannot and
does not recommend anything. It applies fixed rules that it prints, to public
data that it names, and shows its arithmetic. Under the Corporations Act 2001
that is factual information and at most general advice. Decisions about the
fund remain the trustee's, and some of them (the transfer balance cap,
commutations, estate planning, the Division 296 tax on large balances) are
worth a licensed adviser's or SMSF specialist's time.

The companion research report, produced by a multi-agent pass with adversarial
fact-checking, is in `SMSF_INVESTMENT_OPTIONS.md`.

## Quick start (Terminal on a Mac)

Everything, including the download, uses only the Python standard library,
like `home_net_audit.py`. Nothing to `pip install`.

```sh
python3 --version                                     # 3.9 or newer; macOS offers to install
                                                      # the Command Line Tools if python3 is missing
cd ~/src/home_audit                                   # wherever you cloned the repository
python3 smsf_screener.py --fetch --brokerage 9.95     # download 3 years of history into ./data, then screen
python3 smsf_screener.py --brokerage 9.95             # screen again from the cached files
python3 smsf_screener.py --explain VAS                # every number behind one product
python3 smsf_screener.py --illustrate balanced --n-parcels 6 --parcel 15000 --balance 500000
python3 smsf_screener.py --rules                      # every policy number the tool uses
python3 smsf_screener.py --audit-universe             # cross-check the hand-curated CSV
```

The download takes about a minute for the 52 products (a short pause between
requests stays under Yahoo's rate limit) and prints a line per ticker. It
talks to Yahoo Finance's public chart endpoint; if that ever changes shape
the tool says so rather than writing bad files, and `--fetch-backend yfinance`
uses the third-party `yfinance` package instead (`python3 -m pip install
yfinance`). Use `--brokerage` with whatever your broker charges so the unit
counts and leftover cash are right. Add `--as-of YYYY-MM-DD` to freeze the
calculation date so two runs on different days agree. `--json out.json` and
`--markdown out.md` write the full result alongside the terminal table.

Two Mac-specific notes. A `CERTIFICATE_VERIFY_FAILED` error on `--fetch`
means a python.org Python without its certificates installed: run
`Install Certificates.command` from the Python folder in Applications once
(the Command Line Tools Python does not have this problem). And the terminal
table is about 150 characters wide, so widen the Terminal window or use
`--markdown out.md` and open that.

## What it computes

For each product in `smsf_universe.csv` with price history in the data
directory:

| Column | Meaning |
|---|---|
| price | last close on or before the as-of date |
| yld% | cash distributions in the trailing 12 months divided by price |
| gross% | yld% plus the franking credit a 0% taxpayer gets refunded: `yld x (1 + franking x 0.30/0.70)` |
| frk% | typical franking level, hand-curated in the CSV |
| vol% | annualised standard deviation of daily log returns over 1 year |
| mdd% | worst peak-to-trough fall over 3 years |
| adv$k | median daily value traded over the last 60 sessions, AUD thousands |
| score | 0-100 within the product's role, from the weighted components below |
| u@10k, u@25k | whole units a parcel buys after brokerage |

Hard filters, each printed with its reason when it excludes a product: a
role-specific fee cap, minimum fund size (AUD 100 m), minimum daily value
traded (AUD 250 k), a stale last price, and bank hybrids (excluded by default
because APRA is phasing out Additional Tier 1 instruments; `--allow-hybrids`
keeps them).

Score components, each 0-100: cost (fee versus the role cap), liquidity
(log-scaled daily value), size (log-scaled), income (grossed-up yield versus
the role's target), stability (volatility versus the role cap), drawdown, and
franking. Weights differ by role and sum to 100; `--rules` prints them and
`--explain TICKER` shows every multiplication. A trailing yield above 12% is
treated as unverified (capital returns, option premium and one-offs all
inflate it) and scores neutral rather than high.

The illustration (`--illustrate`) splits N parcels across roles using one of
five example mixes (conservative, balanced, growth, income_tilt, simple) with
largest-remainder rounding, fills each role from its top-ranked survivors, and
reports the cash-plus-defensive share, the value-weighted gross yield and, if
`--balance` is given, how many years of the age-based minimum drawdown those
defensive parcels would cover. It is an example of shape, not a recommendation.

## Data layout

```
data/VAS.csv                 date,close,volume        one row per trading day
data/VAS.dividends.csv       date,amount              one row per distribution
```

`--fetch` writes these from Yahoo Finance (`<TICKER>.AX`), converting Yahoo's
session timestamps to Sydney trading dates. Yahoo's coverage of ASX prices
and volume is good; its distribution history is patchy, which is why the tool
warns when it sees fewer distributions in a year than the product's stated
frequency implies. You can also fill the directory by hand from an issuer's
distribution history if a series looks wrong.

The `data/` directory is git-ignored: regenerate it rather than commit it.

## Maintaining smsf_universe.csv

The CSV is the part no free data source replaces. Columns:

`ticker, name, issuer, structure, role, category, asset_class, mer_pct,
size_aud_m, franking_pct, distribution_frequency, hedged, notes, as_at`

* `structure` is one of `etf`, `active_etf`, `lic`, `etb`, `hybrid_etf`.
* `role` is one of `cash`, `defensive`, `core_au`, `core_intl`, `income`,
  `diversifier`, `all_in_one` and decides which rule set applies.
* `mer_pct` is the management fee in percent (0.07 means 0.07% a year).
* `size_aud_m` is fund size in AUD millions.
* `franking_pct` is the typical franking level of distributions (0-100).
* `hedged` is `yes`, `no` or `na`.
* `as_at` is the date you last checked the row against the issuer's page.

`--audit-universe` cross-checks the rows (a name containing "Hedged" with
`hedged=no`, franking on a bond fund, a fee of zero, a size that looks like it
was typed in dollars, a row older than 400 days) and exits non-zero if it finds
anything. The test suite runs the same check on the committed file, so a
careless edit fails CI.

Refresh cadence that has worked: fees and sizes twice a year, franking after
each annual tax statement, and any time an issuer announces a change.

## Can this be automated in Python? What the tool shows

Feasible and done here:

* Prices, volume, volatility, drawdown, liquidity and trailing distributions
  from free data, for any ASX code.
* Franking-credit gross-up for a 0% taxpayer, parcel arithmetic including the
  AUD 500 marketable-parcel rule, and age-based minimum drawdown factors.
* Transparent, arguable ranking rules and example structures.

Needs a hand-maintained table (no stable free source):

* Management fees, fund sizes, typical franking, hedging, structure.
* Product-specific risks (hybrid phase-out, option overlays, US domicile).

Cannot be done reliably by a program:

* A Listed Investment Company's premium or discount to net tangible assets on
  the day you buy (the tool flags every LIC so you check).
* Bid-ask spreads and whether a quote is near indicative net asset value
  (use limit orders and avoid the first and last 15 minutes).
* Anything that depends on your circumstances: how much to hold in cash, the
  growth/defensive split, whether to hedge currency, estate and tax planning.

## Tests

```sh
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/test_smsf_screener.py -q
```

The network download could not be exercised from the environment this was
written in (its egress policy blocks Yahoo), so the Yahoo path is tested
against captured-shape JSON only. The first `--fetch` on your Mac is the real
test: if it reports failures for every ticker, the response shape has changed
and `parse_yahoo_chart` is the place to look.

The tests run offline against synthetic fixtures in `tests/fixtures/smsf/`
generated by `tools/make_smsf_fixtures.py` (deterministic seeds; invented
tickers such as CASHX and AUEQX so nobody mistakes the fixture universe for a
shortlist). No test asserts a fact about a real product; the committed
`smsf_universe.csv` is only checked for internal consistency and dates.
