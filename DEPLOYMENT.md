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

### Re-sealing a baseline the report has called modified

`seal_baseline.py` seals the baseline already on disk, without a scan — and it
verifies it first. It is the remedy every tamper warning prescribes, and it
used to seal whatever it found: a record the report had just called
"modified" came out reading "Seal verified", with the modification inside as
the new reference. Run it with the passphrase the scheduled job uses, so the
check is made with the right key:

```sh
HOME_NET_AUDIT_PASSPHRASE="$(security find-generic-password -s homenetaudit-baseline -a rgs_work -w)" \
    python3 ~/src/home_audit/seal_baseline.py
```

It prints the integrity verdict and, with `HOME_NET_AUDIT_SINK` set, the
receipt comparison, then refuses to seal a record that reads modified, rolled
back, missing, downgraded or unverifiable, or that the off-host receipts
dispute. If you have reviewed the record yourself — every device, every
remembered device, every port — run it again with `--force-reviewed`: it
prints that list once more and asks you to type `SEAL`. Press Enter at the
passphrase prompt to keep the existing one; typing a different one re-keys
the chain, and the script warns twice, because the Keychain item the wrapper
reads then has to change to match or every run will report the baseline as
modified.

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

Two things soften or add to that, both at REVIEW:

- A gateway that moves onto the address of a device **you have labelled** with
  the locally-administered bit set (`38:…` labelled, `3a:…` seen) is how a
  router answers on a guest or IoT network of its own. It is reported at REVIEW
  and names the label. Any other change of the gateway's MAC stays HIGH.
- `--home-subnet 192.168.87.0/24` (or `HOME_NET_AUDIT_HOME_SUBNET`) names the
  network this machine normally lives on. The monitor follows the machine, so
  one left on another of your networks (one with a weekly baseline of its own)
  stops watching home: after three hours there it says so, and again each day.

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

### What the monitor remembers

The monitor keeps, in its state file, every device it has seen on that network
for the last 30 days, by MAC. A phone waking up, a printer coming back after a
quiet afternoon, a hub rebooting — none of them is a "new device" when it
reappears; a newcomer is named with your label for it, or marked as a private
address. An address that answers with different hardware between two polls is
HIGH: a DHCP lease moving to another device takes hours and passes through the
table empty, a swap inside one poll is what ARP spoofing of a host looks like.

### Several networks, one monitor

A Mac that audits several networks in turn still runs one monitor, on the
network it lives on — and it follows the Mac. The network is identified on
every poll, from the interfaces, this machine's address and the gateway the
poll read, the same way the audit identifies its own. When it changes, the
monitor switches to that network's own state file, chain, alert queue and
device memory, says so once (`[REVIEW] Network changed from X to Y; reference
switched`), and compares nothing until the next poll, which is then compared
against the reference it last left on that network, across the time since.
Nothing is saved or heartbeated under a chain that is not the network the
snapshot was taken on. It used to bind all of that once at start-up, so a roam
diffed the new network against the old one's reference — three false HIGHs
per move, one of them wording a changed address as "ARP poisoning" — and
heartbeated the wrong chain as continuous coverage.

The heartbeat log is keyed by network, and it cannot know which network the
monitor was meant for: when the Mac spent four days on the IoT network, the
monitor heartbeated under that network's chain, and every audit of it
afterwards read the silence since as "the monitor is not running now" at HIGH
— for ever, since nothing leaves an append-only log. Tell the audit which
networks have no monitor of their own:

```sh
python3 home_net_audit.py --compact --unmonitored      # a network without a monitor
```

Gaps found under that network's chain are then reported as information, with
the last heartbeat named, and never as a stopped monitor. The home network's
audit runs without the flag and keeps the HIGH.

### What the reference is, and what it is not

Three more things about the monitor's reference point, each learned from the
round-4 attack audit.

**A gap inside the process is a gap.** The restart case has been handled since
the state file existed; a Mac that sleeps for an hour does not restart the
process, it just stops polling, and that used to go unnoticed — whatever the
monitor saw on waking was alerted as if witnessed that minute. The gap test now
runs on every poll, against the previous poll's time, and the events of the
poll after a gap say they were observed across a window with no monitoring.

**A missing state file is not a first run.** The file is one `rm` away for
anything running as the user, and deleting it used to re-baseline the monitor
silently onto whatever the network looked like, heartbeats flowing on. The
monitor now reads the heartbeat record back at start-up: a reference missing
where heartbeats say a monitor was watching this chain is HIGH, and the first
poll is compared against a reference built from the weekly baseline — the
gateway and its MAC, the resolvers, the routers and what they hand out, the
swept devices and the device memory — across the window since the last
heartbeat. Only with no weekly baseline either is the poll adopted, and the
alert says so. A state file that describes another network, as the one a
roaming monitor used to write did, is discarded with a REVIEW and the baseline
stands in the same way.

**A baseline is bound to the gateway it was taken behind.** The subnet is not
an identity: the beach house, a friend's Google Wifi and this household's
pearl are all 192.168.86.0/24, and until now any of them would have been
audited into pearl's chain, sealed as its next run, and the modem password
sent to whatever answered at 192.168.1.1. Every baseline now records its
gateway's MAC, and a chain whose recorded MAC is not the one in the ARP table
is refused — `[REVIEW] The baseline for 192.168.86.0/24 was taken on a
different network` — by the audit, which then compares nothing and saves
nothing, and by the monitor, which neither compares, saves nor heartbeats
under it. A different gateway MAC is also what ARP poisoning on the home
network looks like, and refusing the chain there would silence the HIGH the
comparison exists to raise; so the chain is refused only when nothing else
ties the network to the baseline. A matching SSID, or a device the baseline
knows answering on the link, means the same network with a changed gateway
MAC, and the comparison says so. The monitor asks again on every poll, so an
ARP cache that held only the gateway when it joined decides nothing for long.
A lease with a wider mask than the network's own (a /23 on a /24 network)
starts a fresh baseline rather than adopting the one inside it, and says
which baseline it did not adopt; a narrower lease inside a known network
adopts that network's chain, and says so too.

### Devices whose silence matters

A device leaving is one "gone" line on the next run, and the baseline after
that no longer holds it. For a speaker that is right; for a camera hub or an
alarm panel the absence IS the finding for as long as it lasts. Mark them:

```sh
python3 home_net_audit.py --critical a4:11:62:2a:b9:0a      # saves the mark and exits
python3 home_net_audit.py --not-critical a4:11:62:2a:b9:0a
```

A critical device that stops answering is its own change line on the run it
leaves, a HIGH on every run after that while the device memory (30 days) still
knows it on that network, and — on the network the monitor watches — pinged
every poll and alerted HIGH after ten silent polls, with a REVIEW when it is
back. The marks live in `critical.json` beside `labels.json`.

### What a label means, and when to remove one

Only a label from you identifies a device. A vendor name is a lookup of a
prefix the device itself chose, fetched from a third party over the network
being audited, so it is shown as "vendor says …" and devices known only by
vendor are flagged and counted on their own line of the report and the
TL;DR. A label also settles the one question the audit cannot: an address
with the locally-administered bit set is a phone's rotating private address
unless you have labelled it, in which case it is a device — compared by
name, reported gone, remembered — whatever the bit says. Label the LinkTap
gateways, the IoT gateway and each Mac's own address for exactly that
reason.

A label outlives the device it named, and an address seen on the air for
months can be reused by anyone with the Wi-Fi key: a clone would print as
your own labelled device. So a remembered device coming back after a run
reported it gone is a change line, and labels no network has seen for 30
days are listed in the report. Nothing is removed by itself:

```sh
python3 home_net_audit.py --unlabel 70:89:76:78:6d:c6      # saves and exits
```

---

## What the observer does and does not audit

The network readers speak both dialects, so a Linux observer sees the same
gateway, interfaces, neighbour table and resolvers as the Mac, in the same
format — which matters, because both diff against one shared baseline.

The **host-posture** checks (firewall, sharing services, Wi-Fi security, the
trust store) are deliberately not ported. They describe whichever machine is
running the audit, and on an observer that is not the machine anyone cares
about. Run those on the Mac itself.

On the Mac, the trust store check reads both trust domains. The admin domain
(`security dump-trust-settings -d`) needs sudo to change and is empty on most
Macs; the user domain is where a Keychain Access "Always Trust", a
`security add-trusted-cert` into the login keychain or a mkcert install
lands, with no password, and Safari, Chrome and curl honour it. Any root
trusted in either domain is HIGH until you remove it (Keychain Access →
login → Certificates → Trust → "Use System Defaults"), and a setting arriving
is a change line. A modem scan in which no probe is answered — a firewall
dropping them, a modem rebooting, a guest network cut off from it — is
reported as filtered at REVIEW and the previous reading carried forward,
never as "no open ports".

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

---

## The weekly email

Both Macs send the same email: the city one. One message, readable on a
phone — the TL;DR block on top, a version check, then each network's report
— and nothing attached. The addresses each Mac sends from and to stay as they
are, and nothing new has to be set up or stored: `tools/audit_mail.py`
composes that email from the audit's output files and hands it to whatever
the Mac already sends with.

**The city Mac** sent this email through its own `send_report.py`, outside
the repository, and that script is retired. Its subject was a substring test
over the whole body — a device announcing itself as `CHANGES DETECTED` made
every Sunday say so, and an aborted audit said "no changes" — it tried the
mail server once and told nobody when that failed, and the TL;DR's memory had
already moved on when it tried, so the week after a lost email called that
week's new HIGHs "standing". The last line of `~/.home_net_audit/run_audit.sh`
becomes:

```sh
"$PY" "$REPO/tools/audit_mail.py" --smtp smtp.gmail.com:587 --keychain homenetaudit-smtp \
    --from robert.stuklis@gmail.com send --to robert.stuklis@gmail.com \
    --state "$DIR/digest_state.json" --body "$LAST"
```

Same Gmail account, same Keychain item, same text-and-HTML message with the
same 100 KB guard on the HTML part (`HOME_NET_AUDIT_PLAIN_EMAIL=1` still sends
the text alone). The `--state` is the file the digest step already names: the
send is what moves its memory on (below). What the subject says is decided by
the TL;DR's per-network lines, which carry nothing a device chose: `CHANGES
DETECTED` when any network changed, `AUDIT INCOMPLETE` when any network was
not audited — not joined, aborted, its report unreadable or without its
closing line — and both when both. The run number from the report goes in
too: `[Home Net Audit] 2026-11-08 — run 19 — no changes`. The numbers run on
by one a week, so a week whose email never came shows as a gap in the inbox
rather than as a quiet Sunday.

**When the email does not go.** The send is tried twice, ninety seconds
apart (`--retry-wait`), since a Mac that has just woken may not have its
network back. When it still fails, the message is kept in the outbox —
`~/.home_net_audit/outbox/` (`--outbox` for another) — under its own
subject and date, the log gets one line beginning `EMAIL NOT SENT:` that names
the file, and the step exits 1. Nothing else moves: `tools/report_digest.py`
writes its memory of the report as `digest_state.json.pending`, and only a
send that went moves it into place, so a lost week's items are still "new"
the week after. `resend` sends whatever the outbox holds, oldest first, each
with a fresh date under its old subject, and moves that week's memory into
place when it goes (unless a later email already moved the memory past it);
the first failure stops the pass and an empty outbox is silent, so it can run
from a schedule or by hand:

```sh
"$PY" "$REPO/tools/audit_mail.py" --smtp smtp.gmail.com:587 --keychain homenetaudit-smtp \
    --from robert.stuklis@gmail.com resend          # the beach Mac: --via mail-app --from robert@stuklis.net resend
```

**The monitor's alerts are in the TL;DR.** They went to a file nothing read:
four HIGHs — a changed gateway MAC among them — sat in `alerts.jsonl` for
eleven days without reaching any report, TL;DR or email. The digest now reads
the file `HOME_NET_AUDIT_ALERT` names, or `alerts.jsonl` beside the receipts
in the folder `HOME_NET_AUDIT_SINK` names, and `alerts-beach.jsonl` there
too when the other Mac writes one, and prints under the facts:

```
  MONITOR ALERTS SINCE THE PREVIOUS REPORT: 1 HIGH, 31 REVIEW
    alerts.jsonl: 32 alert(s), 2026-10-25 09:03 to 2026-11-01 08:59
      [HIGH] 2026-10-27 10:48  ipv6_router_appeared · New IPv6 router advertising: fe80::87e:f5b1:f821:c252%en0. …
      [REVIEW] neighbour_appeared ×29, observation_gap ×2
```

Every HIGH is listed with its time, kind and detail and is a flagged item in
its own right — new the week it is raised, standing if it is raised again,
dropped without being called cleared when it is not — and the REVIEWs are
counted by kind. The state file remembers the last alert time each file had
reported, so an alert is reported once. A file that cannot be read says so,
and clears nothing; no file configured says so too, rather than nothing.
Both wrappers export `HOME_NET_AUDIT_SINK` before the digest runs, so there
is nothing to set; a Mac that should read only its own monitor's file sets
`HOME_NET_AUDIT_ALERT` to it in its `run_audit.sh`. Claude's paragraph is
given the kinds and counts, never the details: an alert's detail is what the
monitor saw on the network, and it is withheld the way an announced name is.

**The beach Mac** has sent through Mail.app all along, from its own account
to the usual address, by an AppleScript in its wrapper, with the report
attached as a PDF. The same AppleScript now carries the report itself as the
body, and the PDF goes. In `~/.home_net_audit/run_audit.sh` the email step
becomes one line — the wrapper already captures the audit's output; hand that
file over as `NAME=FILE`:

```sh
"$PY" "$REPO/tools/audit_mail.py" --via mail-app --from robert@stuklis.net \
    send --to rstuklis@yahoo.com --site "beach house" \
    --state "$HOME/.home_net_audit/digest_state.json" --claude --repo "$REPO" \
    --save-body "$HOME/.home_net_audit/last_run.txt" \
    --save-html "$HOME/.home_net_audit/last_run.html" \
    "loveshack-h=$OUT"
```

What those do: `--via mail-app` sends through Mail.app, from the account
`--from` names, so no password is stored anywhere. `--state` is
`report_digest.py`'s memory of the previous report, which is what makes "new
since the previous report" mean something; it moves on only when the email
has gone. `--claude` adds the plain-English paragraph when the Claude CLI is
on the Mac, and goes without it when not. `--repo` prints the version check.
`--save-body` keeps the text that was sent, `--save-html` the same report as
the city Mac's HTML page, to open in a browser; both are written once the
email has gone, so they are of the email that was sent, and one that did not
go waits in the outbox instead. `--site` goes into the subject and the page
heading, so the two Macs' emails can be told apart: `[Home Net Audit]
2026-10-25 — beach house — run 12 — no changes`.

The step that printed the HTML report to PDF and the `osascript` that handed
it to Mail.app go; `--html-report` can stay for the copy on disk. The audit's
own output is what is sent, so the wrapper has to capture this run's output
to its own file (`$OUT` above), not only append it to the running log. Mail's
Automation permission is the one the wrapper already holds; it is granted to
the program that runs the wrapper (the launcher app on a scheduled run), and
a rebuild of that app asks for it again.

**One limit, worth knowing.** Mail.app's AppleScript takes the body as plain
text: it cannot be given HTML. So the beach email carries the report's text
and layout as the city email does, without the coloured cards and badges of
the city email's HTML. On a Mac, Mail > Settings > Fonts & Colors > "Use
fixed-width font for plain text messages" keeps the report's columns
aligned; the saved HTML page has the cards. Sending the HTML itself needs a
mail server and an app-specific password in the Keychain — the way below —
and that was declined, so it is not the default.

**When the audit itself fails** (exit 2, or the wrapper's own checks), the
wrapper sends a plain note the same way, with the tail of the log:

```sh
"$PY" "$REPO/tools/audit_mail.py" --via mail-app --from robert@stuklis.net \
    notify --to rstuklis@yahoo.com \
    --subject "[Home Net Audit] $(date +%F) — beach house — AUDIT DID NOT RUN" \
    --message "home_net_audit.py exited $rc" --text "$LOG" --tail 60
```

A test of the step without waiting for the schedule:

```sh
python3 tools/audit_mail.py --via mail-app --from robert@stuklis.net --to rstuklis@yahoo.com --test-email
```

**The other way, for the record: text and HTML through a mail server.** With
an app-specific password in the login keychain the tool sends the HTML page
itself, as the city Mac does. `--install` stores an iCloud address and
password under the service `home_net_audit-mail` (the arrangement the SMSF
screener's weekly email uses); `--test-email` sends one line. A password
another script already stored is used in place: `--smtp smtp.gmail.com:587
--keychain homenetaudit-smtp --from robert.stuklis@gmail.com` reads the city
Mac's Gmail item. Leave `--via` out, or say `--via smtp`, and the `send` and
`notify` lines above are otherwise the same.

---

## The city Mac's wrapper, by hand

`~/.home_net_audit/run_audit.sh` is not in this repository; the round-4 audit
found four things in it that only the owner can change, listed here so the
change is made once and the same way. None of them alters what the audit
measures.

**The version check's `git fetch` has no timeout.** Apple's git applies no
transfer timeout unless `http.lowSpeedLimit`/`http.lowSpeedTime` are set,
and the LaunchAgent sets no environment: a peer that accepts the connection
and then sends nothing holds the fetch for ever, between the audits and the
email — after the TL;DR has been written and before the report and the email
exist. The call in `version_check` becomes:

```sh
GIT_HTTP_LOW_SPEED_LIMIT=1 GIT_HTTP_LOW_SPEED_TIME=20 git -C "$REPO" fetch --quiet origin 2>/dev/null
```

(Below one byte a second for twenty seconds, the fetch fails and the check
says GitHub could not be reached, as it does for any other failure.) Moving
the check after the email step would do as well.

**The two Keychain reads at the top are equally unbounded.** A login
keychain that locks when the Mac sleeps answers a scheduled run with a
dialog nobody can see, and `security` waits on it. macOS has no `timeout`
command; `perl` is on every Mac and its alarm does the same:

```sh
HOME_NET_AUDIT_PASSPHRASE="$(perl -e 'alarm shift; exec @ARGV' 120 \
    security find-generic-password -s "homenetaudit-baseline" -a "rgs_work" -w 2>/dev/null)"
```

The audit then runs unsealed for the week and says so, which is the
degradation the wrapper already chose for a missing item.

**The sealing passphrase and the sink token are exported into every child.**
Including the external `claude` CLI the digest starts, which contacts the
network and has no use for either. The digest now starts Claude with every
`HOME_NET_AUDIT_*` variable and `TPLINK_PASSWORD` removed from its
environment; the wrapper keeps them out of the digest and the mailer
altogether by putting `env -u` in front of both steps:

```sh
env -u HOME_NET_AUDIT_PASSPHRASE -u TPLINK_PASSWORD -u HOME_NET_AUDIT_SINK_TOKEN \
    "$PY" "$DIGEST" "${CLAUDE_FLAG[@]}" --state "$DIR/digest_state.json" "${SKIPPED[@]}" "${PARTS[@]}"
env -u HOME_NET_AUDIT_PASSPHRASE -u TPLINK_PASSWORD -u HOME_NET_AUDIT_SINK_TOKEN \
    "$PY" "$REPO/tools/audit_mail.py" --smtp smtp.gmail.com:587 --keychain homenetaudit-smtp \
    --from robert.stuklis@gmail.com send --to robert.stuklis@gmail.com --state "$DIR/digest_state.json" --body "$LAST"
```

`HOME_NET_AUDIT_SINK` stays: the digest reads the monitor's alerts from the
folder it names.

**The modem password is read and exported every week for nothing.** The DSL
statistics need the modem on-link, and from every one of the three networks
here it is behind the router, so that section has been skipped on all 24
scheduled audits since August while the password sat in the environment of
each of them, of the version check, of the Wi-Fi helper, of Claude and of
the mailer. Delete the `TPLINK_PASSWORD` block (the `security` read, the
`export` and the note), and the Keychain item with it:

```sh
security delete-generic-password -s homenetaudit-tplink -a admin
```

If the statistics are ever wanted, the login has to be rebuilt first: the
firmware never accepted the legacy one the tool speaks, and that one sent the
password base64-encoded over plain HTTP.

