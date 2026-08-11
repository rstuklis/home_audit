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

Alerts go to a **separate** destination from receipts (`HOME_NET_AUDIT_ALERT`).
Routine bookkeeping and things a person must wake up for usually belong on
different channels — and an alert printed to a terminal on the host under
suspicion has been delivered to the adversary and nobody else.

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

## What none of this catches

Worth being blunt, because a monitoring setup invites more confidence than it
earns.

- **Passive interception upstream.** Anything at or beyond your ISP leaves no
  trace on the LAN. Assume it is possible and encrypt accordingly.
- **A compromised router.** UPnP mappings, DHCP responses and the admin page are
  all self-reported by the device you are trying to assess.
- **Endpoint implants.** Empirically the most likely route to a targeted
  individual, and a network monitor cannot see them. Lockdown Mode, prompt
  patching and Apple Threat Notifications matter far more here.
- **Wholesale destruction of the observer.** Receipts survive it; the observer
  does not.

The honest framing is that this produces **tamper-evidence** — a signed,
timestamped, off-host record that something changed on a given date — rather
than prevention. For someone who later needs to establish when they were
targeted, that is worth a great deal. It is not a shield.
