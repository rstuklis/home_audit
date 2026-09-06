# smsf_screener.py

A rule-based screener for ASX-listed investments, written for a self-directed
trustee of a Self-Managed Super Fund (SMSF) whose account is in retirement
phase and who deploys money in parcels of roughly AUD 10,000 to 25,000.

**General information only, not personal financial advice.** The program does
not consider your objectives, financial situation or needs, so it cannot and
does not recommend anything. It applies fixed rules that it prints, to public
data that it names, and shows its arithmetic. Consider whether anything it
prints is appropriate for you and read each product's Product Disclosure
Statement (PDS) and target market determination before acting. Decisions
about the fund remain the trustee's, and some of them (the transfer balance
cap, commutations, estate planning, the Division 296 tax on large balances)
are worth a licensed adviser's or SMSF specialist's time.

The companion research report, produced by a multi-agent pass with adversarial
fact-checking, is in `SMSF_INVESTMENT_OPTIONS.md`.

## Quick start (Terminal on a Mac)

Everything, including the download, uses only the Python standard library,
like `home_net_audit.py`. Nothing to `pip install`.

```sh
python3 --version                                     # 3.9 or newer; macOS offers to install
                                                      # the Command Line Tools if python3 is missing
cd ~/src/home_audit                                   # wherever you cloned the repository
python3 smsf_screener.py --fetch --brokerage 9.95     # download 3 years of history into data/ beside
                                                      # the script, then screen
python3 smsf_screener.py --brokerage 9.95             # screen again from the cached files
python3 smsf_screener.py --explain VAS                # every number behind one product
python3 smsf_screener.py --illustrate balanced --n-parcels 6 --parcel 15000 --balance 500000
python3 smsf_screener.py --rules                      # every policy number the tool uses
python3 smsf_screener.py --audit-universe             # cross-check the hand-curated CSV
```

The download takes about a minute for the 53 products (a short pause between
requests stays under Yahoo's rate limit) and prints a line per ticker. It
talks to Yahoo Finance's public chart endpoint; if that ever changes shape the
tool says so per ticker rather than writing bad files, exits non-zero when
nothing could be fetched, and `--fetch-backend yfinance` uses the third-party
`yfinance` package instead (`python3 -m pip install yfinance`). Use
`--brokerage` with whatever your broker charges: with the default of 0 the unit
counts are one unit too generous for anyone who pays brokerage, and the
footnote says so. Add `--as-of YYYY-MM-DD` to freeze the calculation date so
two runs on different days agree. `--json out.json` and `--markdown out.md`
write the full result alongside the terminal table.

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
| # / x | rank among the products that passed every filter in the role; x = excluded (its score is kept for information only) |
| price | last close on or before the as-of date |
| yld% | cash distributions in the trailing 12 months divided by price |
| gross% | yld% plus the franking credit a 0% taxpayer gets refunded: `yld x (1 + franking x t/(1-t))` with t the company tax rate (default 0.30; `--company-tax-rate 0.25` for base-rate-entity payers) |
| frk% | typical franking level, hand-curated in the CSV |
| vol% | annualised standard deviation of daily log returns over 1 year, on a distribution-adjusted series |
| mdd% | worst peak-to-trough fall over up to 3 years on the same adjusted series (a note says when less than 3 years of history is available) |
| adv$k | median daily value traded over the last 60 sessions with a volume, AUD thousands |
| score | 0-100 within the product's role from the weighted components below; comparable only within a role, not a forecast |
| u@10k, u@25k | whole units a parcel buys after brokerage |

"Distribution-adjusted" matters for a retiree's screen: a cash ETF's unit
price drops by the payout every month, and on raw prices that looks like
twelve small losses a year. The screener adds each distribution back on its
ex-date before measuring volatility and drawdown, so a fund that never loses
money is not scored as if it did. Price, yield and parcel arithmetic use the
raw close, which is what you pay.

Hard filters, each printed with its reason when it excludes a product: a
role-specific fee cap, minimum fund size (AUD 100 m), a stale last price, bank
hybrids (excluded by default because APRA is phasing out Additional Tier 1
instruments; `--allow-hybrids` keeps them), and a product whose unit price is
too high for any parcel size given to buy a marketable AUD 500 holding. Thin
on-screen volume (below AUD 250 k a day) is a hard exclusion only for Listed
Investment Companies (LICs) and exchange-traded Treasury Bonds, where nothing
quotes against an underlying basket; for an ETF it is a note, because the
ETF's real liquidity is the underlying market's (use limit orders near the
indicative net asset value and avoid the open and close).

Score components, each 0-100: cost (fee versus the role cap), liquidity
(log-scaled daily value), size (log-scaled), income (grossed-up yield versus
the role's target), stability (volatility versus the role cap) and drawdown.
Franking is not a separate component: the income component already uses the
grossed-up yield, and a 0% taxpayer is indifferent between cash and credits.
Weights differ by role and sum to 100; `--rules` prints them and
`--explain TICKER` shows every multiplication. Two guards on the income
component: a trailing yield above 12% is treated as unverified (capital
returns, option premium and one-offs all inflate it) and scores neutral rather
than high; and when more distributions land in the twelve-month window than
the product's stated frequency implies (a special, or ex-dates drifting), the
income score uses the most recent expected number of payments and a note says
so, while the table still shows the twelve-month figure.

The illustration (`--illustrate`) splits N parcels across roles using one of
five example mixes (conservative, balanced, growth, income_tilt, simple) with
largest-remainder rounding, fills each role from its top-ranked survivors, and
prints the achieved split next to the target so the rounding is visible. It
reports the cash share, the cash-plus-defensive share counting what is inside
any all-in-one fund, the value-weighted gross yield with unverified yields
left out, and, if `--balance` is given, how many years of the age-based
minimum drawdown the cash alone and the cash plus bonds would cover (the
minimum is rounded to AUD 10 as Schedule 7 requires; `--age` is the member's
age at 1 July and must be at least 60, the preservation age). The `simple`
template limits its all-in-one sleeve to products whose own growth share is
at most 70%, so it cannot be filled with an all-growth fund. It is an example
of shape, not a recommendation, and says so on every output path.

## Data layout

```
data/VAS.csv                 date,close,volume        one row per trading day
data/VAS.dividends.csv       date,amount              one row per distribution
```

`--fetch` writes these from Yahoo Finance (`<TICKER>.AX`), converting Yahoo's
session timestamps to Sydney trading dates and writing each file atomically
so an interrupted download never leaves a truncated file. Yahoo's coverage of
ASX prices and volume is good; its distribution history is patchy, which is
why the tool warns when it sees fewer distributions in a year than the
product's stated frequency implies. You can also fill the directory by hand
from an issuer's distribution history if a series looks wrong: the readers
accept a UTF-8 byte-order mark, spaces around header names, `null` or blank
cells, a missing volume column (liquidity is then "not assessed" rather than
zero) and a stray trailing comma, collapse duplicated rows (and say so), and
a file that is genuinely unreadable excludes that one product with the reason
printed instead of stopping the run. Rows dated after today are ignored so a
mistyped year cannot move the as-of date for the whole universe.

The `data/` directory is git-ignored: regenerate it rather than commit it.

## Maintaining smsf_universe.csv

The CSV is the part no free data source replaces. Columns:

`ticker, name, issuer, structure, role, category, asset_class, growth_pct,
mer_pct, size_aud_m, franking_pct, distribution_frequency, hedged, notes,
as_at`

* `structure` is one of `etf`, `active_etf`, `lic`, `etb`, `hybrid_etf`.
* `role` is one of `cash`, `defensive`, `core_au`, `core_intl`, `income`,
  `diversifier`, `all_in_one` and decides which rule set applies.
* `growth_pct` is the product's own growth-asset share (0-100). Required for
  `all_in_one` rows (it is the whole point of those products); blank means 0
  for cash and defensive roles and 100 for the others.
* `mer_pct` is the management fee in percent (0.07 means 0.07% a year).
* `size_aud_m` is fund size in AUD millions.
* `franking_pct` is the typical franking level of distributions (0-100),
  franked at the 30% company rate unless you change `--company-tax-rate`.
* `hedged` is `yes`, `no` or `na`.
* `as_at` is the date you last checked the row against the issuer's page.

`--audit-universe` cross-checks the rows (a name containing "Hedged" with
`hedged=no`, franking on a bond fund, a growth share on a cash fund, a fee of
zero, a size that looks like it was typed in dollars, a row older than 400
days) and exits non-zero if it finds anything. The test suite runs the same
check on the committed file against the real calendar date, so a careless
edit or a file left to rot fails CI.

Refresh cadence that has worked: fees and sizes twice a year, franking after
each annual tax statement, and any time an issuer announces a change.

## Can this be automated in Python? What the tool shows

Feasible and done here:

* Prices, volume, volatility, drawdown, liquidity and trailing distributions
  from free data, for any ASX code, with no packages beyond the standard
  library.
* Franking-credit gross-up for a 0% taxpayer, parcel arithmetic including the
  AUD 500 marketable-parcel rule, and age-based minimum drawdown factors.
* Transparent, arguable ranking rules and example structures.

Needs a hand-maintained table (no stable free source):

* Management fees, fund sizes, typical franking, hedging, structure and the
  growth/defensive split inside diversified funds.
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

The tests run offline against synthetic fixtures in `tests/fixtures/smsf/`
generated by `tools/make_smsf_fixtures.py` (deterministic seeds; invented
tickers such as CASHX and AUEQX so nobody mistakes the fixture universe for a
shortlist; one test regenerates them and checks the bytes match). No test
asserts a fact about a real product; the committed `smsf_universe.csv` is only
checked for internal consistency and dates.

The network download could not be exercised from the environment this was
written in (its egress policy blocks Yahoo), so the Yahoo path is tested
against captured-shape JSON only. The first `--fetch` on your Mac is the real
test: if it reports failures for every ticker, the response shape has changed
and `parse_yahoo_chart` is the place to look.
