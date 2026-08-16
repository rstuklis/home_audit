# Running this as an observer

The audit is normally run by hand on the machine you care about. That is fine
for a spot check and it is not what this document is about.

This is about the other deployment: a **second device on the same network**,
watching continuously, writing its evidence somewhere the first machine cannot
reach. That arrangement exists for one reason — if the machine being audited is
compromised, everything it tells you about itself is suspect, including the
audit's own history.

Everything here works with the standard library on a Raspberry Pi.

---

## The one thing that actually carries the security

Skip everything else and get this right.

The audit seals its baseline and appends a receipt for every run to a sink you
configure. Sealing stops the record being **rewritten**. Receipts are what stop
it being **deleted**, because a wiped local history still leaves the off-host
log showing runs that the machine now denies.

**That only holds if the machine cannot rewrite the sink.** The script appends
and reports failure; it cannot enforce anything at the far end. If the observer
holds credentials that can also delete or overwrite remote history, an attacker
who takes the observer holds them too, and the receipts become decorative.

So the sink has to be append-only *from the client's point of view*:

| Sink | Gets you the property when |
|---|---|
| Object store (S3, R2, B2) | The credential grants `PutObject` only — no `DeleteObject`, no overwrite. Enable object-lock or versioning. |
| HTTPS collector | The token is write-only and the endpoint refuses `DELETE` and rejects re-writes of an existing key. |
| Syslog / log collector | The collector owns retention; the sender cannot recall a line. |
| Another host over SSH | The authorized key is `command="cat >> /var/log/audit-receipts.jsonl"` with `restrict`. |
| A mounted share | Only if mounted with append permission and no delete. **A plain read-write mount buys you almost nothing.** |

The last row is the trap: it looks identical in the config and in the code, and
gives you none of the guarantee.

```sh
export HOME_NET_AUDIT_SINK='https://collector.example/receipts'
export HOME_NET_AUDIT_SINK_TOKEN='write-only-token'
```

Receipts carry the run number, seal and chain link — **never** the audit state.
Your MAC addresses and topology do not leave the machine unless you explicitly
ask for `mode="full"`.

Two constraints on an HTTPS sink, both enforced rather than advisory:

* **Give it the final URL.** Redirects are refused, not followed. urllib's
  default handler turns a POST into a bodiless GET on a 301/302/303 and copies
  the `Authorization` header to the new host, so `http://…` redirecting to
  `https://…` silently dropped every receipt while reporting "accepted", and an
  on-path redirect would have handed over the token. A redirect is now a failed
  publish, and it says so.
* **A token requires `https://`.** Sending a bearer token over plain HTTP is
  refused outright.

**An HTTPS sink is write-only from this side.** The tool can publish to it but
cannot read it back, so the check that catches a wiped `~/.home_net_audit` —
local run number versus the highest receipted one — cannot run against a URL.
The audit reports that explicitly rather than showing "no receipts to compare
against", which was the same message it showed for a sink that really was
empty. To get the comparison, either point `HOME_NET_AUDIT_SINK` at an
append-only path the host can also read, or compare against the collector's own
copy out of band.

A failed publish is now printed. It always should have been: a receipt that did
not leave the machine is the same as never having sent one, and an unmounted
share or an expired token used to produce months of runs that published nothing
and said nothing.

---

## Sealing the baseline

Without a passphrase the baseline is still chained, but with a plain hash an
attacker can recompute. With one, they cannot.

```sh
export HOME_NET_AUDIT_PASSPHRASE='…'      # or use --seal-baseline to be prompted
```

The passphrase is never written to disk and never sent to the sink. A key stored
beside the thing it authenticates protects nothing, so the environment variable
is the compromise for unattended runs — it is readable by anything sharing that
process environment, which is worse than a prompt and much better than leaving
the baseline unauthenticated.

---

## Continuous monitoring

Two of the detections here can only see an attack that is **still happening**
when you look. A rogue Router Advertisement sent and withdrawn between scans
leaves no trace; so does a brief ARP poisoning window. Against someone who keeps
that window short, scanning on a schedule structurally cannot help.

`--monitor` polls only the cheap, high-signal checks — local command output, no
port scans, no probes — so it is safe to run every minute:

```sh
python3 home_net_audit.py --monitor --interval 60 \
    --alert-to https://alerts.example/hook
```

It watches the default gateway, **the gateway's MAC** (a change there with the
IP unchanged is what ARP poisoning looks like), the set of advertising IPv6
routers, the DNS resolvers, and arrivals in the neighbour table.

Alerts go to a **separate** destination from receipts, with a **separate**
credential. Routine bookkeeping and things a person must wake up for usually
belong on different channels — and an alert printed to a terminal on the host
under suspicion has been delivered to the adversary and nobody else.

```sh
export HOME_NET_AUDIT_ALERT='https://alerts.example/hook'
export HOME_NET_AUDIT_ALERT_TOKEN='alert-channel-token'   # sent as Bearer
```

`HOME_NET_AUDIT_ALERT_TOKEN` is optional — leave it unset for a destination
that authenticates in the URL, as most chat webhooks do. What it must never be
is your sink token.

The alert channel used to fall back to `HOME_NET_AUDIT_SINK_TOKEN` when no
alert token was set, which meant pointing `HOME_NET_AUDIT_ALERT` at a chat
webhook logged the append-only collector's credential at a third party on every
alert — the one credential whose whole purpose is that the audited host cannot
use it to rewrite what it has already published. It no longer falls back. **If
you were relying on that, alerts now go out unauthenticated until you set
`HOME_NET_AUDIT_ALERT_TOKEN` explicitly.**

The same two rules as the receipt sink apply to this URL, for the same reasons:
redirects are refused rather than followed, and a token requires `https://`.

**An alert that cannot be delivered is queued and retried** on every subsequent
poll, and named again at HIGH when the loop ends with any still undelivered.
The adversary an alert describes is in the path by definition and can drop the
POST while letting heartbeats through, so a single failed attempt used to mean
the finding existed only in stdout on the compromised host.

### Silence is not evidence

Every check in the loop catches someone who is in the path **while the loop is
running**. None of them are worth anything when the process is not running, and
stopping a process is far cheaper than defeating an ARP check. So the attack on
a monitor is not evasion, it is switching it off — and you do not need an
attacker for that. A reboot, a crash, an OOM kill or a `RestartSec` window does
it just as well.

Two things follow, and the monitor now handles both.

**Its reference point survives a restart.** The last snapshot is persisted to
`~/.home_net_audit/monitor_state-<chain>.json`, one file per network — carrying
a home reference on to café Wi-Fi used to raise three false HIGH findings on
arrival and three more on the way home, which is how a real one stops being
read. If that file cannot be written, the loop says so at HIGH rather than
silently re-baselining on every restart. It used to live in memory only, which
meant a restart re-baselined into whatever world it woke up in: poison the ARP
cache and the resolver while the monitor is down, and the restart adopted the
attacker's MAC and DNS as normal and never alerted on them — not just during the
gap, but ever. A restart now compares across the downtime and reports what
changed, flagged as observed across a window nobody was watching.

**It publishes a heartbeat**, on the receipt sink, saying observation was
happening at that moment. Without one, "no alerts this week" and "nothing was
watching this week" are the same output, and the reassuring reading is the one
people take. `--monitor` therefore wants `HOME_NET_AUDIT_SINK` set as much as a
full audit does; it says so at startup if it is missing. The next audit reads
those heartbeats back and names any window with no monitoring in it.

Gaps resolve to within one heartbeat interval (15 minutes), which the report
states rather than rounds away. A gap that is still open — no heartbeat between
the last one and now — is reported as HIGH rather than REVIEW, because that is
the one an attacker is inside at the moment you are reading.

What a heartbeat proves is narrow, and it is worth being exact about: **it says
the process was alive and could reach the sink. It does not say the checks were
meaningful.** An attacker who owns the host can keep heartbeats flowing while
feeding the monitor whatever they like. This detects a *stopped* monitor, not a
*subverted* one.

### systemd unit

```ini
# /etc/systemd/system/home-net-audit-monitor.service
[Unit]
Description=Home network monitor
After=network-online.target

[Service]
Type=simple
User=audit
Environment=HOME_NET_AUDIT_ALERT=https://alerts.example/hook
Environment=HOME_NET_AUDIT_SINK=https://collector.example/receipts
EnvironmentFile=/etc/home-net-audit/secrets     # tokens and passphrase, chmod 600
ExecStart=/usr/bin/python3 /opt/home_audit/home_net_audit.py --monitor --interval 60
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

The destinations sit in the unit because they are configuration; the three
credentials sit in `EnvironmentFile` because they are not:

```sh
# /etc/home-net-audit/secrets — chmod 600, owned by the audit user
HOME_NET_AUDIT_SINK_TOKEN=write-only-token
HOME_NET_AUDIT_ALERT_TOKEN=alert-channel-token
HOME_NET_AUDIT_PASSPHRASE=…
```

Keep the two tokens distinct. They authenticate to different endpoints and
protect different things — the sink token is what stops the audited host
rewriting its own published history, and it has no business travelling to
whatever service pages you.

Run it as a dedicated `audit` user. Its `~/.home_net_audit` should not be
writable by the account you use day to day.

### Scheduled full audits

The monitor is the tripwire; the full audit is the periodic deep pass.

```ini
# /etc/systemd/system/home-net-audit.timer  →  OnCalendar=daily
ExecStart=/usr/bin/python3 /opt/home_audit/home_net_audit.py \
    --no-speedtest --subnet 192.168.1.0/24
```

Skip `--speedtest` on a metered link; it moves ~15 MB. Do **not** add
`--probe-creds` to anything unattended — it sends real login attempts and can
lock you out of your own router.

---

## What the observer does and does not audit

The network readers speak both dialects, so a Linux observer sees the same
gateway, interfaces, neighbour table and resolvers as the Mac, in the same
format — which matters, because both diff against one shared baseline.

The **host-posture** checks (firewall, sharing services, Wi-Fi security) are
deliberately not ported. They describe whichever machine is running the audit,
and on an observer that is not the machine anyone cares about. Run those on the
Mac itself.

---

## Which program wrote the report

Sealing, receipts and heartbeats all authenticate **data**. None of them says
anything about the **program**, and the program runs on the machine being
assessed. Delete the check that would report a backdoor port and every one of
those defences keeps working perfectly, indefinitely, over a report that has
quietly stopped looking.

So every receipt and every heartbeat now carries a SHA-256 of the script that
wrote it, and the audit reports when that digest changes across the off-host
record.

**Read the limit before you rely on this.** The script hashes itself. A modified
script reports whatever digest it likes, including the original's, and nothing
here can tell — any check the script runs on itself is a check the attacker has
already edited. This is the same weakness the provenance section calls
*self-reported*, and it is in that class deliberately.

What it catches is a modification that did not anticipate being watched: an
unreviewed edit, a file swapped by someone who did not read it, drift between two
machines meant to run the same audit, a half-finished upgrade. Against an
adversary who knows the line exists it is worth nothing.

It covers this file only — not the interpreter, not the standard library, not
anything else on the host.

The digest is printed in the report so you can compare it against a trusted
source by hand, which is the one check that does not run on the suspect machine:

```sh
shasum -a 256 home_net_audit.py      # from a copy you trust, on a machine you trust
```

---

## Which findings survive a lying gateway

The report prints as one flat list of risk-tagged lines, and that format quietly
implies they are all equally well founded. They are not, and the report now says
so in an **Evidence provenance** section rather than leaving it to this document.

| Class | Means | Defeated by |
|---|---|---|
| Observed | Read from this machine's own OS — ARP cache, routing table, interfaces, firewall, its own listening sockets | A compromised **host** (which is why you run it from a second machine) |
| Measured | This tool did it and watched the result — TCP connect, TLS handshake, a DHCP offer arriving, a Router Advertisement on the link | Someone actively in the path, who has to act to interfere |
| Self-reported | The device under assessment said so — UPnP mappings, the router's admin pages, its answers to login attempts | The router simply omitting what it does not wish to mention |
| Via resolver | Answered through DNS, which on a home network the gateway usually serves | The gateway answering a question about itself |
| Third party | Fetched from an outside service — vendor names come from `api.macvendors.com` | Anyone on the path to that service; it also sends every discovered MAC off-network |

The distinction is not decoration. Two examples of what it changes:

**The router hostname check asks the suspect to confirm its own identity.** It
detects a rogue router by a reverse DNS lookup, and that lookup goes to whatever
resolver this machine is configured with — normally the router. A rogue one
answers with something unremarkable or with nothing at all, and *no PTR record*
is the most likely output on any real home network. It used to print `[OK]`. It
now prints `[INFO]` with the reason whenever the resolver is the gateway, and
keeps `[OK]` only when an independent resolver answered.

**A quiet UPnP dump is the router's account of its own forwarding table.** A
router that has punched a hole for an attacker omits it, and there is no second
source to check against. "No mappings" is now reported as what it is.

Read the class as a question about *what would have to be true for this to be
wrong*, not as a severity. A self-reported finding that **incriminates** is the
strongest evidence in the report — the router volunteered something against its
own interest. It is specifically the clean self-reported result that is weak, for
the same reason an unkeyed seal verifies without being forgery-proof: passing was
always available to an attacker.

---

## What none of this catches

Worth being blunt, because a monitoring setup invites more confidence than it
earns.

- **Passive interception upstream.** Anything at or beyond your ISP leaves no
  trace on the LAN. Assume it is possible and encrypt accordingly.
- **A compromised router.** UPnP mappings, DHCP offer contents and the admin page
  are all self-reported by the device you are trying to assess. The report now
  marks which findings those are rather than only saying so here, but marking
  them does not make them verifiable — nothing on the LAN can.
- **Endpoint implants.** Empirically the most likely route to a targeted
  individual, and a network monitor cannot see them. Lockdown Mode, prompt
  patching and Apple Threat Notifications matter far more here.
- **A subverted monitor.** Heartbeats catch a monitor that stopped. They do
  nothing about one that is still running and lying, because both the checks and
  the heartbeat come from the same host. Anyone who owns the observer gets both.
- **An edited audit script that knows it is attested.** The digest is computed by
  the same script it describes, so a deliberate edit can carry the original
  forward. Comparing the digest by hand against a trusted copy is the only check
  here that does not run on the machine under suspicion.
- **Wholesale destruction of the observer.** Receipts survive it; the observer
  does not.

The honest framing is that this produces **tamper-evidence** — a signed,
timestamped, off-host record that something changed on a given date — rather
than prevention. For someone who later needs to establish when they were
targeted, that is worth a great deal. It is not a shield.
