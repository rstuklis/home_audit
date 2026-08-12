#!/usr/bin/env python3
"""
seal_baseline.py
================
Seal the EXISTING home_net_audit baseline with a passphrase, in place, WITHOUT
re-scanning the network.

It loads the baseline snapshot already on disk, asks you for a passphrase
(typed at a hidden prompt — never echoed, never passed on the command line,
never written anywhere), and re-saves the same snapshot sealed. That turns the
baseline file tamper-evident: it gets a passphrase-keyed HMAC and keeps its
place in the integrity chain, so a later silent rewrite is detectable.

Run it yourself in a terminal, so the prompt can read your passphrase securely:

    python3 ~/src/home_audit/seal_baseline.py

Leave the passphrase blank to abort without changing anything.
"""

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import home_net_audit as h  # importing does not run the audit (main() is guarded)

state = h.load_baseline()
if state is None:
    sys.exit(f"No baseline found at {h.BASELINE_FILE} — run the audit first to create one.")

ts = state.get("timestamp", "unknown")
ndev = len(state.get("devices", []))
ports = state.get("router_open_ports")
print("About to seal the baseline already on disk (no new scan):")
print(f"  captured    : {ts}")
print(f"  devices     : {ndev}")
print(f"  router ports: {ports}")
print()

pw = getpass.getpass("Choose a baseline passphrase (blank to abort): ")
if not pw:
    sys.exit("Aborted — baseline left unchanged.")
if pw != getpass.getpass("Re-enter passphrase to confirm : "):
    sys.exit("Passphrases did not match — nothing changed.")

h.save_baseline(state, passphrase=pw)

result = h.verify_baseline(passphrase=pw)
print()
print(f"Sealed. Verification with the passphrase: {result.get('status')} "
      f"(keyed={result.get('keyed')})")
print(f"Baseline file: {h.BASELINE_FILE}")
print()
print("Keep this passphrase safe. Every future audit needs it to verify the")
print("baseline; there is no recovery if it is lost — you would just seal a new one.")
