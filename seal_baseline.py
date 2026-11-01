#!/usr/bin/env python3
"""
seal_baseline.py
================
Seal the EXISTING home_net_audit baseline with a passphrase, in place, WITHOUT
re-scanning the network — and verify it first.

It loads the baseline snapshot already on disk, checks its seal and its place
in the chain (and, when the receipt sink is configured, the off-host record of
it), asks you for a passphrase (typed at a hidden prompt — never echoed, never
passed on the command line, never written anywhere), and re-saves the same
snapshot sealed. That turns the baseline file tamper-evident: it gets a
passphrase-keyed HMAC and keeps its place in the integrity chain, so a later
silent rewrite is detectable.

The verification is the point. This script is the remedy every tamper warning
in the weekly report prescribes, and it used to seal whatever was on disk: a
baseline the report had just called "modified" became, after one run of this
script, a baseline that verified — with the modification inside it as the new
reference. So a record that reads modified, rolled back, missing, downgraded or
disputed by the off-host receipts is NOT sealed, and the script says why. If
you have reviewed the record yourself, every device and every port in it, run
it again with --force-reviewed: it then prints that full list once more and
asks you to confirm it before sealing.

The passphrase defaults to the one the chain already verifies with. The
scheduled job reads it from the Keychain, in ~/.home_net_audit/run_audit.sh:

    HOME_NET_AUDIT_PASSPHRASE="$(security find-generic-password \\
        -s "homenetaudit-baseline" -a "rgs_work" -w 2>/dev/null)"

Run this script with the same value in the environment and the baseline is
verified before anything is asked:

    HOME_NET_AUDIT_PASSPHRASE="$(security find-generic-password \\
        -s homenetaudit-baseline -a rgs_work -w)" python3 ~/src/home_audit/seal_baseline.py

Without it, a sealed chain is "unverifiable" and the script asks for the
existing passphrase before anything else. Typing a DIFFERENT passphrase than
the Keychain's re-keys the chain to it, and every scheduled run from then on
reports the baseline as modified and refuses to save — until the Keychain item
is updated to match. The script warns and asks twice before doing that.

Leave a passphrase prompt blank to abort without changing anything.
"""

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import home_net_audit as h  # importing does not run the audit (main() is guarded)

# What the local check can say about a record that must not be sealed as it
# stands. "unverifiable" is in the list on purpose: a keyed record that was not
# checked is not a record that passed.
REFUSED_INTEGRITY = ("modified", "rolled_back", "chain_missing", "record_missing",
                     "downgraded", "unverifiable")
# What the off-host receipts can say that contradicts the local record.
REFUSED_RECEIPTS = ("seal_mismatch", "seal_conflict", "keyed_downgrade", "history_truncated")

KEYCHAIN_LINE = ('security find-generic-password -s "homenetaudit-baseline" -a "rgs_work" -w')


def _stamp(value):
    return (str(value or "")[:16]).replace("T", " ")


def review_lines(state, labels):
    """Every line a person has to read before sealing a record they did not
    trust a minute ago: each device with its label, the device memory, and
    every port list. The attack this guards against puts one MAC or one port
    into the file; a count hides it, a list does not."""
    labels = labels or {}
    lines = ["  Devices in the record (the list the next audit will call known):"]
    devices = state.get("devices")
    if not isinstance(devices, list):
        lines.append("    (no device list in this record)")
    elif not devices:
        lines.append("    (none — the record says the sweep found nothing)")
    for d in devices if isinstance(devices, list) else []:
        if not isinstance(d, dict):
            continue
        mac = str(d.get("mac", "?")).lower()
        name = labels.get(mac)
        name = h._banner_text(name, 60) if isinstance(name, str) else ""
        vendor = h._banner_text(d.get("vendor"), 40)
        who = name or (f"unlabelled; {vendor}" if vendor else "unlabelled")
        lines.append(f"    {str(d.get('ip', '?')):<15} {mac}  [{who}]  {h._banner_text(d.get('subnet'), 24)}")
    memory = state.get("device_memory")
    if isinstance(memory, dict) and memory:
        lines.append("  Devices remembered on this network (a MAC here is never reported as NEW while remembered):")
        for mac in sorted(memory):
            entry = memory[mac] if isinstance(memory[mac], dict) else {}
            name = labels.get(str(mac).lower())
            name = f"  [{h._banner_text(name, 60)}]" if isinstance(name, str) and name else ""
            lines.append(f"    {str(mac).lower()}{name}  first seen {_stamp(entry.get('first_seen'))}, "
                         f"last seen {_stamp(entry.get('last_seen'))}")
    for key, what in (("router_open_ports", "Router open ports"),
                      ("upstream_open_ports", "Upstream modem open ports")):
        if key in state:
            lines.append(f"  {what}: {state.get(key)}")
    listening = state.get("listening")
    if isinstance(listening, list):
        ports = sorted({f"{s.get('proto')}/{s.get('port')}" for s in listening if isinstance(s, dict)})
        lines.append(f"  Listeners on this Mac: {', '.join(ports) if ports else '(none recorded)'}")
    upnp = (state.get("upnp") or {}).get("mappings") if isinstance(state.get("upnp"), dict) else None
    if isinstance(upnp, list):
        lines.append(f"  UPnP port mappings: {len(upnp)}")
        for m in upnp:
            if isinstance(m, dict):
                lines.append(f"    {h._banner_text(m.get('ext_port'), 8)} {h._banner_text(m.get('protocol'), 5)} -> "
                             f"{h._banner_text(m.get('int_ip'), 40)}:{h._banner_text(m.get('int_port'), 8)}  "
                             f"{h._banner_text(m.get('description'), 60)}")
    for key, what in (("gateway", "Gateway"), ("dns", "DNS servers")):
        if key in state:
            lines.append(f"  {what}: {state.get(key)}")
    return lines


def main(argv=None, ask=None, confirm=None):
    """Returns the exit status. `ask` reads a hidden line, `confirm` a visible one."""
    ask = ask or getpass.getpass
    confirm = confirm or input
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force-reviewed", action="store_true",
                    help="Seal a record the checks refuse — one that reads modified, rolled "
                         "back, unverifiable or disputed by the receipts — after reviewing "
                         "the full device and port lists it prints. Use only when you have "
                         "read every line and every one of them is yours.")
    args = ap.parse_args(argv)

    # Baselines are stored per network, so this has to pick the same one an
    # audit would before it reads or writes anything. Without it the script
    # seals whatever the module-level default points at — on a migrated setup,
    # a file no audit consults — and then reports success, leaving the baseline
    # actually in use unsealed while its owner believes it is tamper-evident.
    subnet, _ = h.use_current_network_baseline()
    net_line = h.describe_current_network(subnet)
    print("Checking the baseline already on disk before anything is sealed:")
    if net_line:
        print(net_line.rstrip())
    print(f"  file        : {os.path.basename(h.BASELINE_FILE)}")

    existing = os.environ.get(h.PASSPHRASE_ENV) or None
    report = h.verify_baseline(existing)
    if report.get("status") == "unverifiable":
        # Keyed, and no passphrase arrived in the environment. Ask for it now,
        # so the seal is checked rather than replaced: a check that was never
        # made is not a check that passed.
        typed = ask("Existing baseline passphrase (the Keychain's; blank if you do not have it): ")
        if typed:
            existing = typed
            report = h.verify_baseline(existing)
    print(h.describe_baseline_integrity(report))

    receipts = None
    sink = h.resolve_sink()
    if sink:
        receipts = h.compare_with_receipts(h.load_baseline_record(), h.read_receipts(sink), sink=sink)
        print(h.describe_receipt_status(receipts))
    else:
        print(f"  [INFO  ] Off-host receipts: {h.SINK_ENV} is not set, so the local record was not "
              "compared with the published one. The scheduled job sets it; run with the same "
              "value to compare.")

    state = h.load_baseline()
    if state is None:
        print(f"No baseline found at {h.BASELINE_FILE} — run the audit first to create one.")
        return 1

    refused = [s for s in (report.get("status"), (receipts or {}).get("status"))
               if s in REFUSED_INTEGRITY or s in REFUSED_RECEIPTS]
    if refused and not args.force_reviewed:
        print()
        print(f"NOT sealed: the record reads {' and '.join(refused)}. Sealing it as it stands would "
              "make it the reference,")
        print("and the next audit would report 'Seal verified' over whatever was put in it. Either:")
        if "unverifiable" in refused:
            print(f"  - supply the existing passphrase ({h.PASSPHRASE_ENV}, or at the prompt) so the "
                  "seal can be checked, or")
        print("  - review the record line by line — every device, every remembered device, every "
              "port — and if all of it is")
        print("    yours, run again with --force-reviewed, which prints that list and asks you to "
              "confirm it before sealing.")
        print("Nothing was changed.")
        return 1

    labels = h.load_labels()
    print()
    if refused:
        print(f"--force-reviewed: the record reads {' and '.join(refused)}. This is the record that "
              "will be sealed; read every line.")
    else:
        print("About to seal the baseline already on disk (no new scan):")
    print(f"  captured    : {state.get('timestamp', 'unknown')}")
    for line in review_lines(state, labels):
        print(line)
    print()
    if refused:
        answer = confirm("Every device and port above is yours, and this is the state you want as the "
                         "reference? Type SEAL to continue: ")
        if answer.strip() != "SEAL":
            print("Aborted — baseline left unchanged.")
            return 1

    # The passphrase. Default to the one the chain already verifies with: the
    # scheduled job reads the Keychain's, and a chain re-keyed to anything else
    # reads "modified" there every week until the Keychain is updated.
    if existing is not None:
        if not (report.get("status") == "ok" and report.get("keyed")):
            print(f"  The passphrase in {h.PASSPHRASE_ENV} did not verify this record. Sealing with it "
                  "keys the chain to it, which is")
            print("  what the scheduled job reads; a different one must also go into the Keychain.")
        pw = ask("Passphrase to seal with (Enter to keep the existing one): ")
        if not pw:
            pw = existing
        elif pw != existing:
            print(f"  Warning: that is not the passphrase this chain verified with. The scheduled job "
                  f"reads {h.PASSPHRASE_ENV} from the")
            print(f"  Keychain ({KEYCHAIN_LINE}); until that item is updated to the new passphrase, "
                  "every run will")
            print("  report the baseline as modified and refuse to save.")
            if pw != ask("Re-enter the NEW passphrase to confirm re-keying the chain: "):
                print("Passphrases did not match — nothing changed.")
                return 1
    else:
        pw = ask("Choose a baseline passphrase (blank to abort): ")
        if not pw:
            print("Aborted — baseline left unchanged.")
            return 1
        if pw != ask("Re-enter passphrase to confirm : "):
            print("Passphrases did not match — nothing changed.")
            return 1
        if existing is not None and pw != existing:
            print(f"  Warning: that differs from the passphrase in {h.PASSPHRASE_ENV}, which is what "
                  "the scheduled job will use.")
            print(f"  Update the Keychain item ({KEYCHAIN_LINE}) or every run will report the "
                  "baseline as modified.")
        elif existing is None and report.get("keyed"):
            print(f"  Warning: this chain was sealed with a passphrase this run was not given. "
                  "Sealing with a new one")
            print(f"  re-keys it; the scheduled job's {h.PASSPHRASE_ENV} must be changed to match.")

    record = h.save_baseline(state, passphrase=pw)
    published = h.describe_publish_result(record.get("_receipt"))
    if published:
        print(published)
    if not (record.get("_receipt") or {}).get("published"):
        print(f"  Note: no off-host receipt for this seal. Run with {h.SINK_ENV} set, as the\n"
              "  scheduled job does, or the next audit will say this run was never published.")

    result = h.verify_baseline(passphrase=pw)
    print()
    print(f"Sealed. Verification with the passphrase: {result.get('status')} "
          f"(keyed={result.get('keyed')})")
    print(f"Baseline file: {h.BASELINE_FILE}")
    print()
    print("Keep this passphrase safe. Every future audit needs it to verify the")
    print("baseline; there is no recovery if it is lost — you would just seal a new one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
