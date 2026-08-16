#!/usr/bin/env python3
"""
home_net_audit.py
=================
A defensive audit of YOUR OWN home network, designed to run in Terminal on
macOS using only the Python standard library (no pip installs).

Most checks are read-only. The one exception is the optional default-credentials
probe (menu option 14, or the --probe-creds flag), which actively sends login
attempts to your gateway. It is OFF by default, never runs as part of a normal
audit, and aborts automatically if the router signals a lockout.

Run with no arguments for an interactive menu. Classic command-line flags
still work if you prefer to script it.

IMPORTANT: Only run this against a network you own or administer. Scanning
networks you do not control may be illegal in your jurisdiction.

Acronyms used below:
  LAN   = Local Area Network (your home network)
  WAN   = Wide Area Network (the internet side of your router)
  DNS   = Domain Name System (turns names like example.com into IP addresses)
  ARP   = Address Resolution Protocol (maps IP addresses to hardware/MAC addrs)
  MAC   = Media Access Control address (a device's unique hardware identifier)
  OUI   = Organisationally Unique Identifier (first half of a MAC = the vendor)
  TLS   = Transport Layer Security (the encryption behind HTTPS)
  UPnP  = Universal Plug and Play (auto-config protocol; risky if WAN-exposed)
  SSDP  = Simple Service Discovery Protocol (UPnP discovery mechanism)
  SNMP  = Simple Network Management Protocol (device management; info leak risk)
  SMB   = Server Message Block (Windows file sharing; should not be on a router)
  CWMP  = CPE WAN Management Protocol, aka TR-069 (ISP remote mgmt; CVE-prone)
  DHCP  = Dynamic Host Configuration Protocol (assigns IP addresses on a LAN)
  WPA   = Wi-Fi Protected Access (wireless encryption standard)
  WEP   = Wired Equivalent Privacy (obsolete, broken Wi-Fi encryption)
"""

import argparse
import concurrent.futures as futures
import errno
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Everything this tool remembers lives under one directory, and one environment
# variable moves all of it: baselines, seal chains, labels, named networks and
# saved reports. It exists so a run can be pointed somewhere disposable without
# each caller having to know which files there are.
#
# That matters more than convenience. Ad-hoc verification — a python -c snippet
# that imports this module to check one function — writes to the real directory
# unless every path is redirected individually, and missing one is silent: the
# writes succeed, and the damage only surfaces later as a baseline full of
# invented devices, or a seal chain carrying entries no audit produced. Both
# have happened here. A single switch is something a careless one-liner can
# actually be bothered to set:
#
#     HOME_NET_AUDIT_DIR=$(mktemp -d) python3 -c '...'
#
# The default is unchanged, so nothing that does not set it behaves differently.
DIR_ENV = "HOME_NET_AUDIT_DIR"
BASELINE_DIR = os.path.expanduser(os.environ.get(DIR_ENV) or "~/.home_net_audit")
# Reassigned by select_network_baseline() once a run knows which network it is
# on. They stay module-level names rather than becoming functions because the
# test sandbox redirects every attribute ending in _FILE by name; a computed
# path would slip that net and let a test write to the real ~/.home_net_audit.
BASELINE_FILE = os.path.join(BASELINE_DIR, "baseline.json")
HISTORY_FILE  = os.path.join(BASELINE_DIR, "history.jsonl")
LABELS_FILE   = os.path.join(BASELINE_DIR, "labels.json")
NETWORKS_FILE = os.path.join(BASELINE_DIR, "networks.json")

# Read only when scutil is unavailable — i.e. when the audit is running from a
# Linux observer rather than the Mac. Named *_FILE so the test sandbox redirects
# it automatically and no test can read the real resolver configuration.
RESOLV_CONF_FILE = "/etc/resolv.conf"

# Baseline record format. 1 = the original bare state dict with no integrity
# data at all; 2 = the sealed, chained record written by save_baseline below.
# What lookup_vendor returns instead of a vendor for a randomised address.
# A constant because it is not a name: the display code has to be able to
# tell it apart from one, or a device the tool could not identify is
# presented as identified.
PRIVATE_MAC_VENDOR = "(randomized/private MAC)"

BASELINE_FORMAT = 2
KDF_ITERATIONS = 200_000
# Upper bound on the iteration count read back out of a baseline. The number in
# the file is whatever the file says, and PBKDF2 does exactly as much work as it
# is asked to: 10**12 iterations is not a malformed value that raises, it is a
# hang, in the one function whose job is to say the baseline was tampered with.
KDF_ITERATIONS_MAX = 10_000_000

# The largest subnet this tool will sweep. A /20 is 4096 addresses, which is
# already far past anything a home network uses and takes minutes; a /8 is 16.7
# million pings, one subprocess each.
MAX_SWEEP_ADDRESSES = 4096

# Bounds on the default-credential sweep's fan-out.
#
# It used to be 10 endpoints x 4 payloads x 16 credential pairs = 640 POSTs per
# port, 2560 across four open ports, against a menu prompt that said "Testing 16
# common credential pairs". Those are real login attempts on the user's own
# router, and a router that locks silently — no 429, no lockout phrase — is not
# caught by LockoutError at all, so the volume itself was the hazard.
#
# Endpoints carrying an actual password field are tried first; past the first
# few, an endpoint is being POSTed to on no evidence beyond "it returned 200".
MAX_LOGIN_ENDPOINTS = 3
MAX_LOGIN_SHAPES = 3

# Environment variable holding the baseline passphrase for unattended runs.
# Less safe than being prompted — it is readable by anything in the process's
# environment — but far better than leaving the baseline unauthenticated.
PASSPHRASE_ENV = "HOME_NET_AUDIT_PASSPHRASE"

# Where to copy each sealed baseline so the audited host cannot rewrite its own
# history. A path (local, mounted share, external disk) or an https:// URL.
SINK_ENV = "HOME_NET_AUDIT_SINK"
SINK_TOKEN_ENV = "HOME_NET_AUDIT_SINK_TOKEN"

# Where monitor-mode alerts go. Separate from the receipt sink on purpose: a
# receipt is routine bookkeeping, an alert is something a person needs to see,
# and they usually belong on different channels.
#
# Which is exactly why the alert channel needs its own credential. send_alert
# used to fall back to SINK_TOKEN_ENV, so pointing ALERT_ENV at a chat webhook
# logged the append-only collector's bearer token at a third party on every
# alert — the token whose whole purpose is that the audited host cannot use it
# to rewrite what it already published.
ALERT_ENV = "HOME_NET_AUDIT_ALERT"
ALERT_TOKEN_ENV = "HOME_NET_AUDIT_ALERT_TOKEN"
MONITOR_INTERVAL = 60

# Default named networks. Stored/overridden in ~/.home_net_audit/networks.json.
# Format: {"192.168.1.0/24": "loveshack", "192.168.87.0/24": "pearl"}
DEFAULT_NETWORKS = {
    "192.168.85.0/24": "loveshack-iot",
    "192.168.86.0/24": "pearl",
    "192.168.87.0/24": "loveshack",
}

PORTS_OF_INTEREST = {
    21:    ("FTP",            "HIGH",   "Unencrypted file transfer; should not be exposed."),
    23:    ("Telnet",         "HIGH",   "Unencrypted remote login; a classic router backdoor. Disable it."),
    22:    ("SSH",            "REVIEW", "Encrypted remote login. Fine if you set it up; suspicious if you didn't."),
    53:    ("DNS",            "INFO",   "Router DNS resolver. Normal on the LAN side."),
    80:    ("HTTP admin",     "MEDIUM", "Unencrypted web admin page. Prefer HTTPS for the admin UI."),
    443:   ("HTTPS admin",    "INFO",   "Encrypted web admin page. Expected."),
    139:   ("NetBIOS/SMB",    "HIGH",   "Windows file sharing should not run on a router."),
    445:   ("SMB",            "HIGH",   "Windows file sharing should not run on a router."),
    161:   ("SNMP",           "MEDIUM", "Management protocol; can leak device info if community strings are default."),
    1900:  ("UPnP/SSDP",      "REVIEW", "UPnP discovery. Convenient but can auto-open WAN ports; review."),
    5000:  ("UPnP/admin",     "REVIEW", "Often UPnP or an alternate admin port; confirm it's expected."),
    7547:  ("TR-069/CWMP",    "HIGH",   "ISP remote management. Historically very vulnerable; confirm it's WAN-only and patched."),
    8080:  ("HTTP alt-admin", "MEDIUM", "Alternate web admin port; unencrypted."),
    8443:  ("HTTPS alt-admin","INFO",   "Alternate encrypted admin port."),
    49152: ("UPnP",           "REVIEW", "UPnP control port; review."),
}

COMMON_PORTS = sorted(set(list(PORTS_OF_INTEREST.keys()) + [
    25, 110, 143, 3389, 5353, 5900, 8000, 8888, 9000, 1883
]))

KNOWN_DNS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "203.12.160.35": "Internode (ISP)", "203.12.160.36": "Internode (ISP)",
    # IPv6 counterparts, in the same normalised form get_dns_servers emits.
    # Without these, a dual-stack Mac reports its entirely ordinary resolvers
    # as unfamiliar on every run — the false alarm that trains a user to stop
    # reading this section, which is worse than not checking at all.
    "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
    "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
    "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
    "2620:119:35::35": "OpenDNS", "2620:119:53::53": "OpenDNS",
}

# Common default credentials to probe on router admin pages.
DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "1234"),
    ("admin",     "12345"),
    ("admin",     "123456"),
    ("admin",     ""),
    ("admin",     "Admin"),
    ("admin",     "administrator"),
    ("root",      "root"),
    ("root",      "admin"),
    ("root",      ""),
    ("user",      "user"),
    ("guest",     "guest"),
    ("support",   "support"),
    ("Admin",     "Admin"),
    ("supervisor","supervisor"),
]

# ---------------------------------------------------------------------------
# Helpers for talking to macOS
# ---------------------------------------------------------------------------

def run(cmd, timeout=10, merge_stderr=False):
    """Run a shell command, return stdout as text (empty string on failure).

    merge_stderr appends stderr, for the handful of tools that print their
    answer there — `security dump-trust-settings` prefixes its result with
    SecTrustSettingsCopyCertificates:, which is error-style, and reading only
    stdout would turn a clean trust store into "could not read".

    errors="replace" is load-bearing, not defensive dressing. Some of this
    output carries bytes a stranger chose: `arp -a` splices in resolver-derived
    hostnames, and mDNSResponder passes high bytes through unescaped. Strict
    UTF-8 would raise UnicodeDecodeError — a ValueError, so not caught below —
    out of the one function nearly every check funnels through, killing a
    monitor loop or aborting an audit before the later checks ever ran.
    """
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             errors="replace", timeout=timeout)
        if merge_stderr:
            return (out.stdout or "") + (out.stderr or "")
        return out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


# ---------------------------------------------------------------------------
# Platform dialects
#
# The audit is designed to run from a second device — a Linux box on the same
# LAN — so that a compromised Mac cannot hide local evidence from it. That means
# every network reader needs a Linux dialect alongside the macOS one.
#
# Rather than branch on sys.platform, each reader tries its known sources in
# order and takes the first that parses. run() returns "" for a command that
# does not exist, so on macOS the iproute2 attempts fall through to the BSD
# tools and on Linux the reverse — with no platform detection to get wrong, and
# correct behaviour on a host that happens to have both.
# ---------------------------------------------------------------------------

def parse_gateway_bsd(route_out, netstat_out=""):
    """`route -n get default`, falling back to the `netstat -rn` table."""
    m = re.search(r"gateway:\s*([\d.]+)", route_out)
    if m:
        return m.group(1)
    for line in netstat_out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if len(parts) >= 2 and re.match(r"[\d.]+$", parts[1]):
                return parts[1]
    return None


def parse_gateway_iproute(out):
    """`ip route show default` -> 'default via 192.168.1.1 dev eth0 ...'."""
    m = re.search(r"^default\s+via\s+(\S+)", out, re.MULTILINE)
    if not m:
        return None
    try:
        return str(ipaddress.ip_address(m.group(1)))
    except ValueError:
        return None


def get_default_gateway():
    # Each source is consulted only if the previous one came up empty. Passing
    # both run() calls as arguments would evaluate them eagerly and spawn
    # netstat on every single call, even when route already answered.
    gw = parse_gateway_bsd(run(["route", "-n", "get", "default"]))
    if gw:
        return gw
    gw = parse_gateway_bsd("", run(["netstat", "-rn"]))
    if gw:
        return gw
    return parse_gateway_iproute(run(["ip", "route", "show", "default"]))


def parse_interfaces_ifconfig(out):
    """macOS/BSD `ifconfig -a`."""
    results = []
    current_iface = None
    for line in out.splitlines():
        iface_m = re.match(r"^(\w+):", line)
        if iface_m:
            current_iface = iface_m.group(1)
        inet_m = re.search(r"inet ([\d.]+)\s+netmask (0x[0-9a-f]+|[\d.]+)", line)
        if inet_m and current_iface:
            ip = inet_m.group(1)
            mask_raw = inet_m.group(2)
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            try:
                if mask_raw.startswith("0x"):
                    mask_int = int(mask_raw, 16)
                    mask = socket.inet_ntoa(mask_int.to_bytes(4, "big"))
                else:
                    mask = mask_raw
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                results.append((current_iface, ip, net))
            except (ValueError, OverflowError):
                # OverflowError: a malformed netmask wider than 32 bits would
                # make mask_int.to_bytes(4, "big") raise.
                pass
    return results


def parse_interfaces_iproute(out):
    """`ip -o -4 addr show` -> '2: eth0    inet 192.168.1.50/24 brd ... '.

    The prefix length is already in the output, so there is no hex netmask to
    convert and no OverflowError to guard — an unparseable line is simply
    skipped, matching the BSD reader's contract.
    """
    results = []
    for line in out.splitlines():
        m = re.search(r"^\s*\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
        if not m:
            continue
        iface, ip, prefix = m.group(1), m.group(2), m.group(3)
        if ip.startswith("127.") or ip.startswith("169.254."):
            continue
        try:
            results.append((iface, ip,
                            ipaddress.ip_network(f"{ip}/{prefix}", strict=False)))
        except ValueError:
            pass
    return results


def get_all_interfaces():
    results = parse_interfaces_ifconfig(run(["ifconfig", "-a"]))
    if results:
        return results
    return parse_interfaces_iproute(run(["ip", "-o", "-4", "addr", "show"]))


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def guess_subnet(local_ip):
    if not local_ip:
        return None
    return ipaddress.ip_network(local_ip + "/24", strict=False)


def parse_resolv_conf(text):
    """/etc/resolv.conf — the Linux fallback when scutil is not present."""
    servers = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line.lower().startswith("nameserver"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        addr, sep, zone = parts[1].partition("%")
        try:
            ip = str(ipaddress.ip_address(addr)) + sep + zone
        except ValueError:
            continue
        if ip not in servers:
            servers.append(ip)
    return servers


def get_dns_servers():
    servers = _dns_from_scutil()
    if servers:
        return servers
    try:
        with open(RESOLV_CONF_FILE) as f:
            return parse_resolv_conf(f.read())
    except OSError:
        return []


def _dns_from_scutil():
    out = run(["scutil", "--dns"])
    servers = []
    # Capture the whole address rather than [\d.]+, which stopped at the first
    # colon: an IPv6 resolver like 2606:4700:4700::1111 was recorded as the
    # server "2606", and a link-local one like fe80::1%en0 matched nothing and
    # vanished. Both then read as an unrecognised resolver on every single run,
    # which is precisely the DNS-hijacking signal this check exists to raise.
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", out):
        addr, sep, zone = m.group(1).partition("%")
        try:
            # Normalise so one resolver written two ways is not a baseline
            # change. The zone is split off before parsing and re-attached
            # after, because scoped addresses only parse on Python 3.9+.
            ip = str(ipaddress.ip_address(addr)) + sep + zone
        except ValueError:
            continue
        if ip not in servers:
            servers.append(ip)
    return servers


def parse_neigh_iproute(out):
    """`ip neigh show` -> '192.168.1.1 dev eth0 lladdr aa:bb:.. REACHABLE'.

    FAILED and INCOMPLETE entries carry no usable address and are skipped, the
    same way `(incomplete)` is skipped in the BSD reader.
    """
    table = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{11,17})", line)
        if not m:
            continue
        if "FAILED" in line or "INCOMPLETE" in line:
            continue
        try:
            ip = str(ipaddress.ip_address(m.group(1)))
        except ValueError:
            continue
        raw = m.group(2).split(":")
        if len(raw) != 6:
            continue
        try:
            table[ip] = ":".join(f"{int(x, 16):02x}" for x in raw)
        except ValueError:
            continue
    return table


def read_arp_table():
    table = _read_arp_bsd()
    if table:
        return table
    return parse_neigh_iproute(run(["ip", "neigh", "show"]))


def _read_arp_bsd():
    # -n keeps arp(8) from resolving names, and the pattern below reads the MAC
    # only from the "at <mac>" column. Both halves matter: with resolution on,
    # the hostname is column one, and a search for a MAC-shaped token anywhere
    # in the line finds *it* first. Anyone able to publish a PTR or mDNS name
    # could therefore choose what this function reported as a neighbour's MAC —
    # naming themselves after the router's real MAC pins gateway_mac to the
    # pre-poison value forever, so the change is never detected. A forged name
    # containing "(a.b.c.d)" refiled the row under another IP as well.
    out = run(["arp", "-an"])
    table = {}
    for line in out.splitlines():
        row = re.search(r"\(([\d.]+)\)\s+at\s+"
                        r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
        if row:
            # Validate/normalise the IP so a malformed capture (e.g. leading
            # zeros) can't later crash sorted(..., key=ipaddress.ip_address).
            try:
                ip = str(ipaddress.ip_address(row.group(1)))
            except ValueError:
                continue
            raw = row.group(2).split(":")
            mac = ":".join(f"{int(x, 16):02x}" for x in raw)
            table[ip] = mac
    return table


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# IPv6 neighbours and router advertisements
#
# Rogue RA is among the easiest LAN takeovers there is. An attacker advertises
# itself as an IPv6 default router, SLAAC does the rest, and because macOS
# prefers IPv6 the traffic reroutes silently — while an IPv4-only audit reports
# a perfectly clean network. It is the one attack in this tool's scope that
# produced no signal at all.
#
# Detection is comparative, not absolute: one advertising router is normal, a
# second one appearing is the alarm, and a router that was not in the baseline
# is the stronger alarm. Both dialects are parsed into the same shape so the
# Mac and an observer agree on what they saw.
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"^[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}$")


def _normalise_v6(raw):
    """Return (canonical_address_with_zone, bare_address) or (None, None)."""
    addr, sep, zone = raw.partition("%")
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return None, None
    if parsed.version != 6:
        return None, None
    return str(parsed) + sep + zone, str(parsed)


def _normalise_mac(raw):
    if not _MAC_RE.match(raw or ""):
        return None
    try:
        return ":".join(f"{int(x, 16):02x}" for x in raw.split(":"))
    except ValueError:
        return None


def parse_ndp_neighbours(out):
    """macOS `ndp -an`. Captured from a real Mac; the columns are:

        Neighbor            Linklayer Address  Netif Expire    St Flgs Prbs
        fe80::1%en0         3c:22:fb:11:22:33  en0   23h59m58s R  R

    The R flag marks a router — that column is the whole point of reading this.

    The -n matters. Without it ndp reverse-resolves, and the Neighbor column
    comes back as a hostname rather than an address, so every single entry
    fails to parse and is dropped in silence. A capture from the macOS runner
    is what surfaced that; a hostname row is still skipped defensively here.
    """
    neighbours = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0].lower().startswith("neighbor"):
            continue
        addr, _ = _normalise_v6(parts[0])
        mac = _normalise_mac(parts[1])
        if not addr or not mac:
            continue          # (incomplete) entries carry no usable address
        # Columns are fixed: neighbor, lladdr, netif, expire, state, flags.
        # The state column uses R for REACHABLE and the flags column uses R for
        # router, so "is there an R after the netif" flags every reachable
        # neighbour as a router. Real ndp output from the macOS runner is what
        # exposed that; the flag has to be read from its own column.
        neighbours[addr] = {
            "mac": mac,
            "iface": parts[2],
            "router": len(parts) > 5 and "R" in parts[5],
        }
    return neighbours


def parse_ndp_routers(out):
    """macOS `ndp -rn` -> 'fe80::1%en0 if=en0, flags=O, pref=medium, ...'.

    The -n matters here for the same reason it matters for -a, and it was
    missed when -a was fixed: without it ndp reverse-resolves every router
    address it prints. On a Mac with six utun interfaces up, a real capture
    took over 30 seconds and never finished. run() gives this call 10, so the
    lookup does not merely slow the audit down — it returns "" every time, and
    the router check silently falls through to its last-resort source on any
    machine where the reverse lookups do not answer promptly.

    Entries whose interface identifier is all zeros are dropped. A Mac running
    a VPN has a default route on each tunnel, and ndp lists one line per
    tunnel with no router address to report:

        fe80::%utun0 if=utun0, flags=IST, pref=medium, expire=Never
        fe80::%utun1 if=utun1, flags=IST, pref=medium, expire=Never

    Those are not routers. RFC 4291 reserves the all-zeros interface
    identifier as the Subnet-Router anycast address, so no host ever holds it
    — the address is a placeholder meaning "a default route exists here", not
    a neighbour that sent a Router Advertisement. Kept, they read as four
    distinct routers (the zone makes each string unique), which is HIGH on a
    first run and, once the tunnels renumber across a VPN reconnect, a fresh
    "router not in the baseline" alarm on a network where nothing happened.
    A check that cries wolf at every VPN user is a check they stop reading.

    Captured from the macOS runner, which has four utun interfaces.
    """
    routers = []
    for line in out.splitlines():
        token = line.split()[0] if line.split() else ""
        addr, bare = _normalise_v6(token)
        if not addr:
            continue
        if ipaddress.ip_address(bare).packed[8:] == b"\x00" * 8:
            continue
        if addr not in routers:
            routers.append(addr)
    return routers


def parse_neigh6_iproute(out):
    """Linux `ip -6 neigh show`. The literal word `router` marks a router."""
    neighbours = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or "FAILED" in parts or "INCOMPLETE" in parts:
            continue
        addr, _ = _normalise_v6(parts[0])
        if not addr or "lladdr" not in parts:
            continue
        mac = _normalise_mac(parts[parts.index("lladdr") + 1])
        if not mac:
            continue
        neighbours[addr] = {
            "mac": mac,
            "iface": parts[parts.index("dev") + 1] if "dev" in parts else "",
            "router": "router" in parts,
        }
    return neighbours


def parse_routes6_iproute(out):
    """Linux `ip -6 route show default`.

        default via fe80::1 dev eth0 proto ra metric 1024 expires 1794sec

    `proto ra` means the route was learned from a Router Advertisement, which
    is exactly the mechanism being watched.
    """
    routers = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default" or "via" not in parts:
            continue
        addr, _ = _normalise_v6(parts[parts.index("via") + 1])
        if addr and addr not in routers:
            routers.append(addr)
    return routers


def get_ipv6_neighbours():
    neighbours = parse_ndp_neighbours(run(["ndp", "-an"]))
    if neighbours:
        return neighbours
    return parse_neigh6_iproute(run(["ip", "-6", "neigh", "show"]))


def get_ipv6_routers():
    """Every address currently advertising itself as an IPv6 default router."""
    routers = parse_ndp_routers(run(["ndp", "-rn"]))
    if routers:
        return routers
    routers = parse_routes6_iproute(run(["ip", "-6", "route", "show", "default"]))
    if routers:
        return routers
    # Last resort: the neighbour table's own router flag. Less authoritative
    # than the routing table but better than reporting none at all.
    return sorted(a for a, n in get_ipv6_neighbours().items() if n.get("router"))


def check_ipv6_routers(known=None):
    """Classify the advertising routers against the ones seen before.

    `known` is the baseline's list. Absolute counts alone are not enough: one
    router is normal, and on a network that legitimately has two the count
    would cry wolf forever. A router that was never in the baseline is the
    signal worth waking someone for.
    """
    routers = get_ipv6_routers()
    known = list(known or [])
    unexpected = [r for r in routers if r not in known] if known else []

    if not routers:
        return {"routers": [], "unexpected": [], "risk": "INFO",
                "note": "No IPv6 router is advertising on this link."}
    if unexpected:
        return {"routers": routers, "unexpected": unexpected, "risk": "HIGH",
                "note": f"IPv6 router(s) not in the baseline: {', '.join(unexpected)}. "
                        "A rogue Router Advertisement makes the sender your default "
                        "gateway for IPv6, and macOS prefers IPv6 — traffic would "
                        "reroute with nothing visible on the IPv4 side."}
    if len(routers) > 1 and not known:
        return {"routers": routers, "unexpected": [], "risk": "HIGH",
                "note": f"{len(routers)} IPv6 routers are advertising: "
                        f"{', '.join(routers)}. More than one is the classic sign of "
                        "a rogue Router Advertisement; confirm every one is yours, "
                        "then save a baseline so only new ones are flagged."}
    if len(routers) > 1:
        # Every one of them is in the baseline, so the operator has already
        # accepted this network's shape. Re-flagging it HIGH on every run would
        # train them to skip the section that shows a genuinely new router.
        return {"routers": routers, "unexpected": [], "risk": "OK",
                "note": f"{len(routers)} IPv6 routers advertising "
                        f"({', '.join(routers)}), all of them in the baseline."}
    return {"routers": routers, "unexpected": [], "risk": "OK",
            "note": f"One IPv6 router advertising ({routers[0]}), matching the baseline."
                    if known else
                    f"One IPv6 router advertising ({routers[0]}). No baseline to "
                    "compare against yet — save one so a second router would show up."}


def action_ipv6_routers(known=None):
    hr("IPv6 ROUTER ADVERTISEMENTS")
    result = check_ipv6_routers(known)
    neighbours = get_ipv6_neighbours()
    print(f"  IPv6 neighbours seen : {len(neighbours)}")
    for addr, n in sorted(neighbours.items()):
        flag = "  <-- advertising as a router" if n.get("router") else ""
        print(f"    {addr:<42} {n['mac']}{flag}")
    print(f"  [{result['risk']:6}] {result['note']}")
    return result


# Errors that mean "the probe never left this machine", as opposed to a port
# that answered with a refusal. connect_ex returns the errno rather than
# raising, and the numbers differ between macOS and Linux, so compare against
# the errno module rather than hard-coded integers.
UNREACHABLE_ERRNOS = frozenset((
    errno.EHOSTUNREACH,     # no route to host
    errno.ENETUNREACH,      # network unreachable
    errno.ENETDOWN,         # interface down
    errno.EHOSTDOWN,        # host down
))


def local_network_denied_note(what):
    """The note for a check the OS refused to let off this machine.

    Three checks reach the local subnet by different means — a TCP scan, a DHCP
    broadcast, an SSDP multicast — and macOS Local Network privacy denies all
    three to a background job with the same instant EHOSTUNREACH. Each used to
    describe that denial as a finding about the network: the scan said "no open
    ports", the DHCP check said "try sudo", the UPnP check said the router may
    have UPnP disabled. All three sent the reader somewhere useless, and the
    last two sent them somewhere actively wrong, since no amount of privilege
    or router configuration changes a permission the job cannot be granted.
    """
    return (f"{what} was refused by the OS, not answered by the network. On macOS "
            "this is Local Network privacy denying a background (launchd/cron) job "
            "access to its own subnet; the same audit run from a terminal works. "
            "It is not a privilege problem and sudo does not help — run the audit "
            "interactively for this check.")


def probe_port(host, port, timeout=0.6):
    """Probe one TCP port. True = open, False = closed, None = unreachable.

    The None case is the point of this function. macOS Local Network privacy
    denies a background/launchd process any connection to its own subnet, and
    the denial arrives instantly as EHOSTUNREACH — indistinguishable from a
    closed port if the result is collapsed to a boolean. That collapse is what
    let a blocked scheduled audit report "no open ports on your router" as
    fact, and write that empty list into the baseline as known-good. Keep the
    three states apart so a caller can tell "nothing is listening" from "I was
    never allowed to ask".
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((host, port))
        finally:
            s.close()
    except OSError as e:
        # socket() itself can raise (e.g. EMFILE "too many open files" under
        # high worker counts). Preserve the unreachable distinction here too.
        return None if e.errno in UNREACHABLE_ERRNOS else False
    if rc == 0:
        return True
    return None if rc in UNREACHABLE_ERRNOS else False


def check_port(host, port, timeout=0.6):
    """True only if the port is open. Unreachable counts as not-open.

    Kept boolean because every caller that asks about a single known port
    (is sshd listening on 127.0.0.1?) genuinely wants a yes/no. Callers that
    scan a host they may not be able to reach should use probe_port or
    scan_ports_detailed instead.
    """
    return probe_port(host, port, timeout) is True


def scan_ports_detailed(host, ports, workers=100):
    """Scan `ports` and report whether the host could be reached at all.

    Returns {"open": sorted list, "unreachable": int, "probed": int,
             "blocked": bool}. `blocked` is True only when every probe came
    back unreachable, which is the signature of a host that is off the network
    or a scan the OS refused outright — as opposed to a few probes failing
    while others got a real answer.
    """
    open_ports = []
    unreachable = 0
    probed = 0
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = {pool.submit(probe_port, host, p): p for p in ports}
        for fut in futures.as_completed(results):
            try:
                result = fut.result()
            except OSError:
                # A single failed probe should not abort the whole scan.
                continue
            probed += 1
            if result is True:
                open_ports.append(results[fut])
            elif result is None:
                unreachable += 1
    return {
        "open": sorted(open_ports),
        "unreachable": unreachable,
        "probed": probed,
        "blocked": probed > 0 and unreachable == probed,
    }


def scan_ports(host, ports, workers=100):
    """Open ports only. See scan_ports_detailed to tell blocked from closed."""
    return scan_ports_detailed(host, ports, workers)["open"]


def ping(ip):
    """Single ping (macOS syntax). Returns the ip if it replies, else None.

    A hard subprocess timeout guards against a ping that never exits (on Linux
    `-t` sets the TTL rather than a deadline, so without this a hung host would
    block its worker thread and stall the whole sweep).
    """
    # -t means a deadline on macOS but a TTL on Linux, where sending a probe
    # with TTL 1 would make every host beyond the first hop look dead. -W is the
    # Linux reply timeout and is not accepted on macOS. Pick the flag that
    # actually means "give up quickly" on the host we are on; the hard
    # subprocess timeout below stays as the backstop either way.
    limit = ["-t", "1"] if sys.platform == "darwin" else ["-W", "1"]
    try:
        out = subprocess.run(["ping", "-c", "1"] + limit + [str(ip)],
                             capture_output=True, text=True, timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return str(ip) if out.returncode == 0 else None


def is_real_host(ip, mac, subnet):
    """Exclude IPs outside the target subnet, pseudo-entries, multicast, and broadcast.

    The global ARP cache contains entries from all subnets on the machine.
    Without the subnet membership check, scanning 192.168.85.0/24 would pick
    up 192.168.87.x entries and tag them with the wrong network group.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Must belong to this subnet — prevents cross-subnet ARP bleed
    if addr not in subnet:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    if ip == str(subnet.network_address) or ip == str(subnet.broadcast_address):
        return False
    if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith(("01:00:5e", "33:33")):
        return False
    return True


def discover_devices(subnet, workers=50):
    hosts = list(subnet.hosts())
    alive = set()
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(ping, hosts):
            if res:
                alive.add(res)
    arp = read_arp_table()
    devices = []
    for ip in sorted(alive | set(arp.keys()), key=ipaddress.ip_address):
        mac = arp.get(ip, "unknown")
        if is_real_host(ip, mac, subnet):
            devices.append({"ip": ip, "mac": mac})
    return devices


OUI_HINTS = {
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi (Trading) Ltd",
    "e4:5f:01": "Raspberry Pi (Trading) Ltd",
    "3c:28:6d": "Google",
    "38:8b:59": "Google",
    "34:64:a9": "Hewlett Packard",
}


def is_randomized_mac(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def lookup_vendor(mac):
    if mac == "unknown":
        return ""
    if is_randomized_mac(mac):
        return PRIVATE_MAC_VENDOR
    prefix = ":".join(mac.split(":")[:3])
    try:
        req = urllib.request.Request("https://api.macvendors.com/" + mac,
                                     headers={"User-Agent": "home_net_audit"})
        with urllib.request.urlopen(req, timeout=4) as r:
            name = r.read().decode("utf-8", "ignore").strip()
            if name:
                return name
    except (urllib.error.URLError, OSError, ValueError):
        pass
    return OUI_HINTS.get(prefix, "")


def check_tls(host, port=443):
    """Fingerprint the certificate rather than just noting one exists.

    The DER bytes were already being fetched and thrown away — only their
    length was kept, which detects nothing. Hashing them turns this into
    interception detection for free: the router's admin certificate is
    self-signed and stable, so a changed fingerprint between runs means
    something re-issued it or something is answering in its place.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                if not der:
                    return {"present": True, "sha256": None, "cert_bytes": 0}
                return {"present": True,
                        "sha256": hashlib.sha256(der).hexdigest(),
                        "cert_bytes": len(der)}
    except Exception:
        return {"present": False, "sha256": None}


# ---------------------------------------------------------------------------
# Interception detection
# ---------------------------------------------------------------------------

def check_trust_store():
    """List admin-added trust settings on macOS.

    A clean Mac has none: `security dump-trust-settings -d` prints a "No Trust
    Settings" line and nothing else. Installing a root CA is how TLS
    interception is set up in practice, so anything here is worth reading —
    this is one of very few endpoint signals that is both cheap and unambiguous.

    Host-posture, so it is macOS-only by the same rule as the firewall and
    sharing checks: on an observer it would describe the wrong machine.
    """
    if sys.platform != "darwin":
        return {"supported": False, "entries": [], "risk": "INFO",
                "note": "Trust-store inspection is macOS-only; skipped here."}

    out = run(["security", "dump-trust-settings", "-d"], timeout=10,
              merge_stderr=True)
    if not out.strip():
        return {"supported": True, "entries": [], "risk": "REVIEW",
                "note": "Could not read the admin trust settings."}
    if "no trust settings" in out.lower():
        return {"supported": True, "entries": [], "risk": "OK",
                "note": "No admin-added trust settings — the expected state."}

    entries = [ln.strip() for ln in out.splitlines()
               if ln.strip().lower().startswith("cert ")]
    return {"supported": True, "entries": entries, "risk": "HIGH",
            "note": f"{len(entries) or 'Some'} admin-added trust setting(s) present. "
                    "A root certificate installed here lets whoever holds its key "
                    "read TLS traffic from this machine without a warning. Confirm "
                    "every one of these is yours."}


def build_dns_query(name="example.com", qid=0x4a4a):
    """A minimal DNS A query. Hand-built because the tool takes no dependencies."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def probe_dns_interception(target="192.0.2.1", timeout=2):
    """Ask a resolver that cannot exist and see whether anything answers.

    192.0.2.1 is TEST-NET-1 (RFC 5737) — reserved for documentation and routed
    nowhere. A DNS query sent there must time out. If something replies, a
    device on the path is transparently answering port 53 regardless of what
    the resolver configuration says, which is exactly the case reading
    `scutil --dns` cannot reveal.

    Three states, not two. A send that never left the machine is not evidence
    that nothing is intercepting — it is evidence of nothing at all, and used
    to be reported as the clean result. Every sibling probe here keeps that
    distinction (probe_port, check_rogue_dhcp, the SSDP sweep); this one now
    does too.

    The reply is checked before it is believed. connect() makes the kernel drop
    datagrams from anyone but the target, and the transaction id is random per
    call and must match: otherwise a stray or sprayed packet arriving on the
    ephemeral port raised a HIGH naming a responder of the sender's choosing.
    """
    qid = int.from_bytes(os.urandom(2), "big")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect((target, 53))
            sock.send(build_dns_query(qid=qid))
        except OSError as exc:
            return {"intercepted": None, "responder": None, "risk": "REVIEW",
                    "note": f"The query to {target} could not be sent ({exc.strerror or exc}), "
                            "so nothing was learned either way. This check has not run."}
        try:
            data, addr = sock.recvfrom(512)
        except (socket.timeout, OSError):
            return {"intercepted": False, "responder": None, "risk": "OK",
                    "note": f"No answer from {target}, which is the correct result — "
                            "port 53 is not being transparently redirected."}
    finally:
        sock.close()

    if len(data) < 12 or int.from_bytes(data[:2], "big") != qid:
        return {"intercepted": False, "responder": None, "risk": "OK",
                "note": f"No valid DNS answer from {target}, which is the correct "
                        "result — port 53 is not being transparently redirected."}

    return {"intercepted": True, "responder": addr[0], "risk": "HIGH",
            "note": f"{addr[0]} answered a DNS query addressed to {target}, an "
                    "address reserved for documentation that routes nowhere. "
                    "Something on the path is intercepting port 53, so the "
                    "configured resolvers are not the ones being used."}


def action_interception_checks():
    hr("INTERCEPTION CHECKS")
    trust = check_trust_store()
    print(f"  [{trust['risk']:6}] Trust store: {trust['note']}")
    for entry in trust["entries"]:
        print(f"           {entry}")

    dns = probe_dns_interception()
    print(f"  [{dns['risk']:6}] DNS path  : {dns['note']}")
    return {"trust_store": trust, "dns_interception": dns}


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def canonical_json(obj):
    """Deterministic serialisation, so a digest over the same state is stable.

    Sorted keys and fixed separators: without this, two runs producing an
    identical state could serialise differently and the seal would appear
    broken for no reason.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def derive_baseline_key(passphrase, salt, iterations=KDF_ITERATIONS):
    """Stretch a passphrase into a MAC key. PBKDF2 is in the standard library,
    which is the binding constraint here — the tool takes no dependencies."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)


def seal_payload(payload, key=None):
    """Return the hex digest that authenticates `payload`.

    With a key this is an HMAC and cannot be recomputed by someone who does not
    hold the passphrase. Without a key it is a bare SHA-256: enough to catch a
    truncated write, accidental corruption or a careless edit, but NOT a
    deliberate attacker, who can simply recompute it after changing the state.

    Those two cases are labelled differently everywhere they surface. An
    unkeyed baseline that silently claimed to be "verified" would be worse than
    no integrity checking at all, because it would be believed.
    """
    blob = canonical_json(payload)
    if key is None:
        return hashlib.sha256(blob).hexdigest()
    return hmac.new(key, blob, hashlib.sha256).hexdigest()


def _secure_dir():
    os.makedirs(BASELINE_DIR, exist_ok=True)
    try:
        # The baseline holds MAC addresses, topology and, if the probe was run,
        # which credentials were accepted. Other local accounts have no business
        # reading it.
        os.chmod(BASELINE_DIR, 0o700)
    except OSError:
        pass


def _write_json_atomic(path, obj, mode=0o600):
    """Write via a temp file and rename, so a crash cannot truncate the file.

    The previous implementation opened the real path with "w", which empties it
    before writing. A crash mid-write left an empty baseline — indistinguishable
    from never having had one.
    """
    _secure_dir()
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_history():
    """Return the append-only chain of past baseline seals, oldest first.

    Every consumer indexes into these entries as dicts, so anything else on a
    line is dropped here rather than at each call site. `json.loads` returns a
    perfectly valid `0` or `null` for a line reading "0" or "null", and that
    reached verify_baseline as an AttributeError and save_baseline as a
    TypeError — a one-byte edit anyone who can write this file could make, and
    the crash lands exactly where the tamper warning would have printed.
    """
    entries = []
    try:
        with open(HISTORY_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    entries.append(entry)
    except OSError:
        # Not just FileNotFoundError: an unreadable history is "no chain I can
        # see", the same as an absent one, and must not abort the audit.
        return []
    return entries


def _append_history(entry):
    _secure_dir()
    with open(HISTORY_FILE, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(HISTORY_FILE, 0o600)
    except OSError:
        pass


def resolve_passphrase(prompt=False):
    """Find the baseline passphrase, or None if the user has not set one up.

    Checked in order: the environment variable, then an interactive prompt when
    the caller asks for one. Never read from disk — a key stored beside the
    thing it authenticates protects nothing.
    """
    env = os.environ.get(PASSPHRASE_ENV)
    if env:
        return env
    if prompt and sys.stdin.isatty():
        import getpass
        entered = getpass.getpass(
            "Baseline passphrase (blank to leave the baseline unauthenticated): ")
        return entered or None
    return None


# Measurements that a run can fail to take without failing outright. A None
# here means "not measured this run", and must never overwrite a real reading.
# Measurements a run can fail to take, or decline to take, without failing
# outright. A missing key here means "not measured this run" and must never
# overwrite a real reading.
#
# "devices" and "scanned_subnets" are on this list because of a real incident,
# not a hypothetical: a --no-discovery run saves a state with no device list at
# all, and saving that wiped a baseline of ten known devices. The next audit
# would have reported every device in the house as newly arrived — the same
# corruption the port keys were added to prevent, in the one section where a
# false alarm is loudest. --no-discovery says "do not spend the time looking",
# never "there is nothing there".
#
# router_tls belongs here for the same reason and was missing. check_tls returns
# {"present": False, "sha256": None} when the handshake fails — a dict, so it
# passed the "is not None" test as a measurement and wrote itself over a real
# fingerprint. diff_baseline then skips the certificate comparison, because it
# correctly refuses to compare against an unknown, so a router certificate that
# changed during the outage was never reported: not on that run, and not after
# the next successful one re-established a baseline from the new cert.
CARRY_FORWARD_KEYS = ("router_open_ports", "upstream_open_ports",
                      "devices", "scanned_subnets", "router_tls")

# The two keys that record one measurement between them: what was found, and
# where it was possible to find anything. They are measured together or not at
# all, so they carry together — pairing a fresh device list with a stale
# coverage list would state that this run swept ground it never touched.
SWEEP_KEYS = ("devices", "scanned_subnets")


def tls_measured(state):
    """Whether `state` holds a real certificate reading.

    The presence of the key says nothing: a failed handshake produces a
    perfectly well-formed dict whose sha256 is None. The fingerprint is the
    measurement, so its absence is what "not measured" means here.
    """
    return (state.get("router_tls") or {}).get("sha256") is not None


def swept_anywhere(state):
    """Whether `state`'s device list is a measurement or an absence of looking.

    Key presence is not the question, and treating it as the question is what
    made "no devices" ambiguous in the first place. A sweep of a subnet this
    host has no interface in returns an empty list through the ordinary path:
    collect_devices resolves neighbours from the ARP cache and drops anything
    outside the swept subnet, so off-link ground answers exactly as empty ground
    does. onlink_coverage exists to tell those apart and records the verdict in
    scanned_subnets — an empty coverage list means no sighting was possible
    anywhere, which is not a finding about the network.

    So an empty device list is a measurement only where the run could have seen
    something. A non-empty one needs no corroboration: devices were found, which
    is proof the sweep reached somewhere, and demanding coverage as well would
    read every baseline saved before scanned_subnets existed as unmeasured.
    """
    devices = state.get("devices")
    if devices is None:
        return False
    if devices:
        return True
    return bool(state.get("scanned_subnets"))


def carry_forward_unmeasured(state, previous=None):
    """Return `state` with unmeasured values replaced by the last known-good ones.

    Writing None over a real reading does not just lose that reading — it
    destroys the reference point that change detection compares against, and
    because diff_baseline correctly refuses to compare against an unknown, the
    loss is permanent and silent: the next successful run has nothing to diff,
    reports no change, and then saves ITS reading as the new known-good. A port
    opened in between is never reported, on that run or any later one.

    This is reachable on exactly the deployment the unreachable-scan work was
    written for. The gateway is read from the routing table, which macOS Local
    Network privacy does not gate, so a blocked scheduled run resolves a
    gateway (passing main's existing incomplete-scan guard) while its port scan
    returns None. Keeping the previous value means the eventual successful run
    still has a real baseline to compare against.

    The substitution is recorded in `carried_forward` so the saved baseline
    never implies a measurement that was not taken, and `measured_at` records
    WHEN each value was last genuinely measured.

    That second record is what stops carrying quietly becoming lying. A carried
    value inherits the new run's timestamp along with the rest of the state, so
    without it a device list observed once in August would still present itself
    as measured today after months of runs that skipped the sweep — indefinitely
    and invisibly, because carrying has no natural end. Nothing here expires a
    value: refusing to carry is what destroyed a baseline in the first place.
    The age is recorded and surfaced instead, so a reader can weigh it.
    """
    if previous is None:
        previous = load_baseline() or {}
    stamp = state.get("timestamp") or datetime.now(timezone.utc).isoformat()
    previously_measured = previous.get("measured_at") or {}

    carried = []
    measured_at = {}
    for key in CARRY_FORWARD_KEYS:
        # An empty list is a real reading for the port keys — scanned, nothing
        # open — but not for the sweep pair, where it is also what a sweep of
        # unreachable ground returns. Asking only whether the key is present let
        # that second case through as a measurement and overwrite the baseline
        # with it: the ten-device incident above, reached by a laptop sweeping a
        # subnet it was not joined to rather than by --no-discovery. Silent, and
        # permanent, because the wiped list becomes the new reference point.
        if key in SWEEP_KEYS:
            measured = swept_anywhere(state)
        elif key == "router_tls":
            measured = tls_measured(state)
        else:
            measured = state.get(key) is not None
        if measured:
            if state.get(key) is not None:
                measured_at[key] = stamp
            # A run that swept but recorded no coverage list predates
            # scanned_subnets. Leaving the key absent is right: carrying the
            # previous run's coverage would attach it to this run's devices.
        elif (tls_measured(previous) if key == "router_tls"
              else previous.get(key) is not None):
            carried.append(key)
            # The origin of the reading, not the run that inherited it. Falling
            # back to the previous state's own timestamp covers a baseline saved
            # before measured_at existed.
            measured_at[key] = (previously_measured.get(key)
                                or previous.get("timestamp") or "")

    if not carried:
        # Nothing was inherited, so there is no age to track and no bookkeeping
        # to add: a run that measured everything saves exactly what it measured.
        # The next run that DOES carry recovers this run's time from the state's
        # own timestamp, which is when these values were read.
        return state
    merged = dict(state)
    for key in carried:
        merged[key] = previous[key]
    merged["carried_forward"] = sorted(carried)
    merged["measured_at"] = measured_at
    return merged


def save_baseline(state, passphrase=None):
    """Seal `state` into the baseline and extend the tamper-evidence chain.

    Returns the record that was written. Passing no passphrase still chains and
    seals, but with a bare hash rather than an HMAC — see seal_payload.
    """
    state = carry_forward_unmeasured(state)
    history = read_history()
    prev = history[-1]["seal"] if history else None
    seq = (history[-1]["seq"] + 1) if history else 1

    record = {
        "format": BASELINE_FORMAT,
        "seq": seq,
        "prev": prev,
        "keyed": passphrase is not None,
        # Which program wrote this. Inside the sealed payload so it cannot be
        # edited after the fact without breaking the seal — though that buys
        # less than it appears to, since the script computing the digest is the
        # one an attacker would have edited. See script_digest.
        "code": script_digest(),
        "state": state,
    }
    key = None
    if passphrase is not None:
        salt = os.urandom(16)
        record["kdf"] = {"salt": salt.hex(), "iterations": KDF_ITERATIONS}
        key = derive_baseline_key(passphrase, salt)

    record["seal"] = seal_payload({k: v for k, v in record.items() if k != "seal"}, key)
    # Anything added after this line is runtime status, not sealed content, and
    # must never be written to disk or it would break its own seal.

    _write_json_atomic(BASELINE_FILE, record)
    record["_receipt"] = publish_receipt(record)
    _append_history({
        "seq": seq,
        "seal": record["seal"],
        "keyed": record["keyed"],
        "ts": state.get("timestamp") or datetime.now(timezone.utc).isoformat(),
    })
    return record


def load_baseline_record():
    """Return the raw baseline record, whatever format it is in, or None.

    None means "nothing usable here", which is all most callers need.
    verify_baseline needs the distinction between never-written and
    unreadable, and gets it from baseline_file_exists() below.
    """
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def baseline_file_exists():
    """Whether a baseline file is present, regardless of whether it parses."""
    return os.path.exists(BASELINE_FILE)


def load_baseline(passphrase=None):
    """Return the saved audit state, or None.

    Kept returning the bare state dict so every existing caller is unaffected;
    integrity is reported separately by verify_baseline. A record that fails
    verification is still returned — refusing to diff would hand an attacker a
    denial of service, and the caller is expected to surface the warning.
    """
    record = load_baseline_record()
    if record is None:
        return None
    if isinstance(record, dict) and record.get("format") == BASELINE_FORMAT:
        return record.get("state")
    return record  # legacy format 1: the bare state dict


def verify_baseline(passphrase=None):
    """Check the baseline's seal and its position in the chain.

    Returns {status, keyed, detail}. Statuses:
      absent         no baseline saved yet, and no chain either
      legacy         pre-integrity baseline; nothing to verify
      record_missing the chain records runs but the baseline is gone or unreadable
      downgraded     the chain records sealed runs but this record carries no seal
      ok             seal recomputes and the chain agrees
      unverifiable   sealed with a passphrase that was not supplied
      modified       the seal does not match the contents
      rolled_back    valid record, but older than the chain has already recorded
      chain_missing  the record claims history that is not there

    The chain is read *first*, and that ordering is the point. Both cheap
    attacks on this file work by making the record stop looking like a sealed
    record at all — delete it, truncate it to "{", or drop the "format" key —
    and every one of those used to short-circuit to `absent` or `legacy` before
    the chain was ever consulted. Both statuses are benign-looking, both let
    the run continue, and the unconditional save that follows then wrote a
    fresh seal chained onto the attacker's record. The chain is the thing they
    cannot forge without the passphrase, so it decides what the record's shape
    means: with no chain, an unsealed baseline is history; with one, it is a
    downgrade.
    """
    history = read_history()
    record = load_baseline_record()

    if record is None:
        if history:
            last = history[-1]
            how = "cannot be read" if baseline_file_exists() else "is gone"
            return {"status": "record_missing", "keyed": False,
                    "detail": f"The seal chain records {len(history)} run(s), the most "
                              f"recent numbered {last.get('seq')}, but the baseline itself "
                              f"{how}. Removing or corrupting it is how a changed network "
                              "is made to look like a first run."}
        return {"status": "absent", "keyed": False,
                "detail": "No baseline saved yet."}

    if not isinstance(record, dict) or record.get("format") != BASELINE_FORMAT:
        if history:
            return {"status": "downgraded", "keyed": False,
                    "detail": f"The baseline carries no format-{BASELINE_FORMAT} seal, but "
                              f"the chain records {len(history)} sealed run(s). A genuine "
                              "legacy baseline predates the chain and cannot coexist with "
                              "one, so this record has been replaced with an unsealed one."}
        return {"status": "legacy", "keyed": False,
                "detail": "Baseline predates integrity checking and is unauthenticated. "
                          "Re-save it to start a verifiable chain."}

    keyed = bool(record.get("keyed"))
    if keyed and passphrase is None:
        return {"status": "unverifiable", "keyed": True,
                "detail": "Baseline is sealed with a passphrase; supply it to verify."}

    key = None
    if keyed:
        # Every one of these values is read back out of the file being checked,
        # so each is validated before it reaches PBKDF2. Unvalidated, a salt of
        # 123 or an iteration count of "200000" raised TypeError, 0 raised
        # ValueError, a kdf of [1,2] raised AttributeError, and 10**12 simply
        # hung — all of them uncaught, all of them out of the function whose
        # answer was about to be "this baseline has been altered".
        kdf = record.get("kdf")
        malformed = {"status": "modified", "keyed": True,
                     "detail": "Key derivation parameters are malformed, which is "
                               "itself a modification: they are covered by the seal."}
        if not isinstance(kdf, dict):
            return malformed
        salt_hex = kdf.get("salt", "")
        iterations = kdf.get("iterations", KDF_ITERATIONS)
        if not isinstance(salt_hex, str):
            return malformed
        if isinstance(iterations, bool) or not isinstance(iterations, int):
            return malformed
        if not 1 <= iterations <= KDF_ITERATIONS_MAX:
            return malformed
        try:
            salt = bytes.fromhex(salt_hex)
            key = derive_baseline_key(passphrase, salt, iterations)
        except (TypeError, ValueError, OverflowError):
            return malformed

    expected = seal_payload({k: v for k, v in record.items() if k != "seal"}, key)
    if not hmac.compare_digest(expected, str(record.get("seal", ""))):
        return {"status": "modified", "keyed": keyed,
                "detail": "The baseline's contents do not match its seal. It has been "
                          "altered since it was written."}

    history = read_history()
    if not history:
        if record.get("seq", 1) > 1:
            return {"status": "chain_missing", "keyed": keyed,
                    "detail": "The baseline references earlier runs but the history "
                              "file is gone. It may have been removed to hide a change."}
    else:
        last = history[-1]
        if record.get("seq") != last.get("seq") or record.get("seal") != last.get("seal"):
            return {"status": "rolled_back", "keyed": keyed,
                    "detail": f"The baseline is at run {record.get('seq')} but the chain "
                              f"has reached run {last.get('seq')}. An older baseline may "
                              "have been put back in place."}

    detail = ("Seal verified with your passphrase." if keyed else
              "Hash chain intact. Note this is unkeyed: it catches corruption and "
              "careless edits, not an attacker who can recompute it. Set a "
              "passphrase to make the baseline forgery-resistant.")
    return {"status": "ok", "keyed": keyed, "detail": detail}


# ---------------------------------------------------------------------------
# Off-host receipts
#
# Sealing stops the baseline being rewritten, but not deleted: an attacker who
# removes ~/.home_net_audit entirely leaves the next run looking like a first
# run, and nothing on the machine can tell those apart. The only fix is a copy
# somewhere the audited host cannot reach back into.
#
# What the script can do is send a receipt for every run and fail loudly if it
# cannot. What it CANNOT do is make the destination append-only — that is a
# property of how the sink is configured, and it is the property the whole
# scheme rests on. If the host holds credentials that can also delete or
# overwrite remote history, an attacker on that host holds them too.
# ---------------------------------------------------------------------------

def chain_id(baseline_path=None):
    """An opaque, stable identifier for the chain a baseline belongs to.

    Sequence numbers restart at 1 for every network once baselines are stored
    per network, so a shared receipt sink holds several chains whose seq values
    collide. compare_with_receipts reads the highest seq it can see and calls a
    lower local one "history_truncated" — the most severe thing this tool says,
    and the code's own words for it are "the strongest single indicator
    available that something removed the evidence". Auditing any network but the
    busiest would raise that, falsely, every time.

    Hashed rather than named on purpose. baseline_receipt exists to prove a run
    happened without shipping the network's shape off-host, and a subnet in
    clear would undo that for the users the restraint is for. A digest is enough
    to tell two chains apart, which is all the comparison needs.

    Derived from the selected baseline path, so it follows
    select_network_baseline automatically and needs no global of its own — one
    that the test sandbox does not redirect would leak between tests.
    """
    name = os.path.basename(baseline_path or BASELINE_FILE)
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]


def script_digest(path=None):
    """SHA-256 of the audit script on disk, or None if it cannot be read.

    Everything else in this module authenticates DATA. The baseline is sealed so
    it cannot be rewritten, receipts survive it being deleted, heartbeats show
    observation was happening. Not one of them says anything about the program
    that produced any of it — and the program lives on the machine being
    assessed. Delete the check that would report a backdoor port and every one
    of those defences keeps working perfectly, indefinitely, over a report that
    has simply stopped looking. Recording the digest is what makes that edit
    visible in the off-host record rather than invisible forever.

    The limit is severe, and stating it is most of the point: THE SCRIPT HASHES
    ITSELF. A modified script reports whatever digest it likes, including the
    original's, and nothing here can tell. This is exactly the weakness the
    provenance section calls self-reported — a witness testifying about itself —
    and it belongs in that class rather than being dressed up as an integrity
    guarantee. It is the same shape as the router hostname check asking the
    gateway to confirm its own identity, and it is not fixable from in here: any
    check the script runs on itself is a check the attacker has already edited.

    What it does catch is a modification that did not anticipate being watched —
    an unreviewed edit, a file swapped by someone who did not read it, drift
    between two machines meant to run the same audit, a half-finished upgrade.
    Against an adversary who knows this line exists it is worth nothing.

    It also covers only this file. The interpreter, the standard library and
    anything else on the host are outside it.
    """
    try:
        with open(path or os.path.abspath(__file__), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def baseline_receipt(record):
    """The minimum that proves a run happened, and nothing more.

    Deliberately excludes the audit state. A receipt is enough to detect a
    rollback or a wiped history later, and shipping MAC addresses, network
    topology and any accepted credentials to a remote endpoint would create a
    fresh disclosure risk for exactly the users this is meant to protect.
    Publishing the full record is available but has to be asked for.

    `chain` says WHICH sequence this seq belongs to, without saying which
    network it is.
    """
    return {
        "seq": record.get("seq"),
        "seal": record.get("seal"),
        "prev": record.get("prev"),
        "keyed": record.get("keyed"),
        "chain": chain_id(),
        # Copied from the record rather than recomputed, so the receipt attests
        # to the program that actually wrote that baseline, not to whatever is
        # on disk by the time the receipt is published.
        "code": record.get("code"),
    }


def resolve_sink(explicit=None):
    return explicit or os.environ.get(SINK_ENV) or None


def publish_receipt(record, destination=None, mode="digest", token=None):
    """Copy a receipt (or the whole record) to the off-host sink.

    Returns {published, detail, mode}. Never raises: a failed publish must be
    reported, not fatal, or an unreachable sink would stop the audit running at
    all. The caller is expected to surface `published` — a receipt that silently
    failed to leave the machine is the same as never having sent one.
    """
    destination = resolve_sink(destination)
    if not destination:
        return {"published": False, "mode": mode,
                "detail": "No off-host sink configured. The baseline exists only on "
                          "this machine, so deleting it wholesale would leave no trace."}

    payload = record if mode == "full" else baseline_receipt(record)
    payload = dict(payload, published_at=datetime.now(timezone.utc).isoformat())

    try:
        if destination.startswith(("http://", "https://")):
            return _publish_https(payload, destination,
                                  token or os.environ.get(SINK_TOKEN_ENV), mode)
        return _publish_path(payload, destination, mode)
    except Exception as e:                      # noqa: BLE001 - reported, not raised
        return {"published": False, "mode": mode,
                "detail": f"Could not publish the receipt to {destination}: {e}"}


def _publish_path(payload, destination, mode):
    """Append to a file the host can add to but should not be able to rewrite.

    A mounted share, an external disk, or a directory owned by another account.
    Append mode is the client half of the contract; the sink has to enforce the
    other half.
    """
    if os.path.isdir(destination):
        destination = os.path.join(destination, "receipts.jsonl")
    parent = os.path.dirname(destination)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(destination, "a") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return {"published": True, "mode": mode,
            "detail": f"Receipt appended to {destination}."}


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect instead of quietly following it.

    urllib's default handler turns a POST into a bodiless GET on 301, 302 and
    303, and copies every header except content-length and content-type to the
    new host. Two things followed from that, both silent:

    * `http://collector/receipts` redirecting to https — which is close to
      universal — dropped the receipt body on every publish while this function
      returned "Receipt accepted (HTTP 200)". The sink stayed empty, so the one
      check that survives a wiped ~/.home_net_audit was never armed.
    * An on-path attacker redirecting to their own host collected the sink
      token, which is the credential for the append-only log itself.

    A redirect is not something this transport should paper over: the
    destination the user configured is the destination, or the publish failed.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            f"{msg}: refusing to follow a redirect to {newurl}. Point the sink "
            "at its final URL — following it would send the body, and the "
            "token, somewhere the configuration did not name.",
            headers, fp)


def _publish_https(payload, url, token, mode):
    if token and not url.startswith("https://"):
        # A bearer token over plain http is readable by anyone on the path,
        # starting with the LAN this tool is auditing.
        #
        # Named by mode rather than "the sink token": this function is the
        # transport for receipts, heartbeats and alerts, and the alert channel
        # carries a different credential to a different endpoint. Telling an
        # alert user their sink token was refused points them at the wrong
        # setting.
        which = "alert token" if mode == "alert" else "sink token"
        return {"published": False, "mode": mode,
                "detail": f"Refusing to send the {which} to {url}: it is not https. "
                          f"Use an https destination, or clear the {which}."}
    headers = {"Content-Type": "application/json", "User-Agent": "home_net_audit"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=canonical_json(payload), headers=headers)
    opener = urllib.request.build_opener(_NoRedirects)
    with opener.open(req, timeout=10) as r:
        code = r.getcode()
        final = r.geturl()
    if final != url:
        return {"published": False, "mode": mode,
                "detail": f"The receipt ended up at {final}, not the configured {url}. "
                          "Treating that as unpublished."}
    return {"published": True, "mode": mode,
            "detail": f"Receipt accepted by {url} (HTTP {code})."}


def receipt_sink_is_readable(source):
    """Whether receipts can be read back from `source` at all.

    An https sink is write-only from here: publishing branches on the scheme
    but reading does not, so read_receipts falls through to open() and gets
    FileNotFoundError. Returning [] for that is indistinguishable from "the
    sink is empty", which is the difference between "nothing has been
    published" and "I cannot see what was published" — and the second must
    never be reported as the first, because the whole point of the sink is to
    contradict a local baseline that claims to be a first run.
    """
    return not str(source).startswith(("http://", "https://"))


def read_receipts(source):
    """Read back a receipt log to compare against. Returns [] if unreadable.

    Non-dict lines are dropped here rather than at each call site: every
    consumer indexes into these entries as objects, and a single line reading
    `null` in a shared sink used to reach compare_with_receipts as an
    AttributeError — no verdict, no diff, no baseline saved, no report, on
    every run. read_heartbeats and code_attestations already guarded; this is
    the same guard, moved to where the entries are produced.
    """
    if not receipt_sink_is_readable(source):
        return []
    if os.path.isdir(source):
        source = os.path.join(source, "receipts.jsonl")
    entries = []
    try:
        with open(source) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    entries.append(entry)
    except OSError:
        return []
    return entries


def compare_with_receipts(record, receipts, sink=None):
    """Check the local baseline against the off-host record of what ran.

    This is what catches the attack local sealing cannot: wiping
    ~/.home_net_audit and letting the next run start clean. Locally that is
    indistinguishable from a genuine first run — but the receipt log still shows
    run 7, and a local baseline claiming run 1 gives it away.

    Returns {status, detail}. Statuses: ok, no_receipts, sink_unreadable,
    chain_unknown, unpublished_runs, history_truncated, seal_mismatch,
    seal_conflict, keyed_downgrade.

    `sink` is optional and used only to tell "nothing was published" apart from
    "I cannot read what was published from here".
    """
    # Only this chain's receipts, plus every receipt that predates chains.
    #
    # A sink is shared across networks while sequence numbers restart at 1 for
    # each, so comparing against all of them reads another network's longer
    # history as this one's evidence being deleted. Filtering on the chain id
    # fixes that for anything published since.
    #
    # A receipt with no chain id was published when one shared baseline served
    # everything, and cannot be attributed to a network now. An earlier attempt
    # pinned those to a "legacy" id derived from the old filename, which read
    # well and was wrong: migration renames the baseline, so the id moved and
    # every pre-upgrade receipt stopped matching anything. That silently
    # disabled the one check that catches a wiped ~/.home_net_audit — the local
    # copy and its history go together, and only the off-host record survives to
    # contradict a run claiming to be the first.
    #
    # So they are accepted for every chain. The cost is that a second network
    # may report history_truncated off another network's older runs: a false
    # alarm, loud and investigable. The alternative was a missed one. Between
    # those this module chooses loud every time.
    # A receipt written before chains existed carries no id and belongs to the
    # single shared baseline that was the only one then. Treating it as that
    # chain keeps tamper detection working for anyone who has not migrated;
    # dropping it would quietly disable the check for them, which is worse than
    # the collision being fixed.
    mine = chain_id()
    # Heartbeats share this sink but say nothing about baselines. Counting them
    # would let a log holding only monitor liveness report that the baseline
    # "agrees with 40 off-host receipt(s)" when not one of them is about a run.
    baseline_receipts = [r for r in (receipts or []) if r.get("kind") != "heartbeat"]
    receipts = [r for r in baseline_receipts if r.get("chain") in (None, mine)]

    if not receipts:
        if sink is not None and not receipt_sink_is_readable(sink):
            return {"status": "sink_unreadable",
                    "detail": f"Receipts are published to {sink}, which this tool can "
                              "write to but not read back. The truncation check cannot "
                              "run, so a wiped local baseline would not be contradicted "
                              "here. Compare against the collector's own copy."}
        if baseline_receipts:
            # Every receipt in the log belongs to some other chain. The chain id
            # is derived from the baseline filename, which is derived from the
            # subnet — so a renumbering rogue DHCP server moves it, drops every
            # receipt this machine ever published, and used to leave a REVIEW
            # saying there was nothing to compare against while a fresh chain
            # was sealed at seq 1 under the attacker's numbering.
            chains = {r.get("chain") for r in baseline_receipts}
            return {"status": "chain_unknown",
                    "detail": f"The sink holds {len(baseline_receipts)} receipt(s), but "
                              f"none for this baseline's chain ({mine}); they belong to "
                              f"{len(chains)} other chain(s). Either this is a network "
                              "the tool has not audited before, or the subnet changed "
                              "underneath it — which is something a rogue DHCP server "
                              "can do deliberately to orphan the evidence."}
        return {"status": "no_receipts",
                "detail": "No off-host receipts to compare against."}

    # Keyed-ness is sticky, and this is the only place that can hold it to that.
    #
    # An unkeyed seal is one a compromised host can recompute at will, so the
    # cheapest forgery available to an attacker without the passphrase is not to
    # break the key but to strip it: replace the baseline with an unkeyed record
    # carrying whatever state they like, and extend the chain one step as unkeyed.
    # verify_baseline cannot catch this — the same attacker rewrites the local
    # history to agree that the run was unkeyed, and an unkeyed seal that matches
    # its own contents verifies. The receipts are the one record they cannot
    # overwrite, and they still say the chain was keyed. If any receipt here was
    # keyed while the local baseline now is not, the key has been removed, and
    # everything the current baseline claims is attacker-controlled.
    if any(r.get("keyed") for r in receipts) and not (record or {}).get("keyed"):
        return {"status": "keyed_downgrade",
                "detail": "The off-host receipts record this chain as sealed with a "
                          "passphrase, but the local baseline is now unkeyed. An "
                          "unkeyed seal is one a compromised host can forge, so the "
                          "key was stripped to rewrite the baseline undetected. Treat "
                          "the current baseline as attacker-controlled and re-seal "
                          "from a trusted state."}

    highest = max((r.get("seq") or 0) for r in receipts)
    local_seq = (record or {}).get("seq") or 0

    if local_seq < highest:
        return {"status": "history_truncated",
                "detail": f"Off-host receipts record {highest} runs but this machine's "
                          f"baseline is at run {local_seq}. Local history has been "
                          "truncated or deleted — the strongest single indicator "
                          "available that something removed the evidence."}

    if local_seq > highest:
        # The local record claims runs the sink never saw. Either publishing has
        # been failing silently, or the baseline was fabricated locally — and a
        # seq ahead of every receipt is the strongest signal available for the
        # second. This used to fall straight through to "ok", asserting
        # agreement about runs the receipts had no knowledge of.
        return {"status": "unpublished_runs",
                "detail": f"This machine's baseline is at run {local_seq} but the "
                          f"off-host receipts stop at run {highest}. "
                          f"{local_seq - highest} run(s) were never published — check "
                          "whether the sink is reachable, because until it is, nothing "
                          "off this machine can contradict the local record."}

    match = [r for r in receipts if r.get("seq") == local_seq]
    if match:
        seals = {r.get("seal") for r in match}
        if len(seals) > 1:
            # An append-only sink lets the host add lines but not remove them,
            # so two different seals for one run means one of them was written
            # to bury the other. Reading match[-1] — the newest, i.e. the one an
            # attacker can append — made that forgery the reference.
            return {"status": "seal_conflict",
                    "detail": f"Run {local_seq} appears in the receipt log more than "
                              "once with different seals. An append-only sink cannot "
                              "lose a line, so a second one was added to cover the "
                              "first. Treat the local baseline as untrusted."}
        # match[0], not match[-1]: the first receipt for a seq is the one
        # published when the run happened.
        if record and match[0].get("seal") != record.get("seal"):
            return {"status": "seal_mismatch",
                    "detail": f"Run {local_seq} was recorded off-host with a different "
                              "seal than the copy on this machine. The local baseline "
                              "has been replaced since it was published."}

    return {"status": "ok",
            "detail": f"Local baseline agrees with {len(receipts)} off-host receipt(s)."}


# ---------------------------------------------------------------------------
# Monitor mode
#
# Two of the detections in this tool can only see an attack that is still
# happening when you look. A rogue Router Advertisement sent and withdrawn
# between scans leaves no trace; so does a brief ARP poisoning window. Against
# an adversary who keeps that window short, point-in-time scanning structurally
# cannot help — which makes continuous observation a security requirement here
# rather than a convenience.
#
# The full audit is far too heavy to loop: port scans, vendor lookups and a
# speed test take a minute and move real traffic. What runs continuously is the
# cheap, high-signal subset below — all of it local command output, no probes,
# no network round trips — so it is safe to poll every minute on a Pi.
# ---------------------------------------------------------------------------

def monitor_snapshot():
    """The cheap half of the audit: what an attacker has to change to redirect you.

    The gateway is pinged first, as check_arp_spoofing does. Without it an entry
    that has aged out of the ARP cache reads as gateway_mac=None, and a None in
    the reference is worse than useless — see carry_forward_gateway_mac.
    """
    gateway = get_default_gateway()
    if gateway:
        ping(gateway)
    arp = read_arp_table()
    return {
        "gateway": gateway,
        "gateway_mac": arp.get(gateway) if gateway else None,
        "ipv6_routers": get_ipv6_routers(),
        "dns": get_dns_servers(),
        "neighbours": sorted(arp),
    }


def carry_forward_gateway_mac(snapshot, previous):
    """Keep the last MAC actually observed, rather than storing a blank.

    diff_snapshots correctly declines to compare when either side is None. That
    is the right call per-poll and the wrong thing to then persist: the sequence
    good → None → attacker skips both comparisons and quietly installs the
    attacker's MAC as the new reference, so the HIGH gateway_mac_changed never
    fires — not for that transition, and not afterwards. An attacker can force
    the blank poll by flooding until `arp -an` exceeds run()'s timeout.

    Returns (snapshot, note). The note is a REVIEW event when the MAC could not
    be read at all, because "I could not see the gateway" is itself worth
    saying out loud rather than papering over.
    """
    if snapshot.get("gateway_mac") or not previous:
        return snapshot, None
    carried = previous.get("gateway_mac")
    if not carried:
        return snapshot, None
    snapshot = dict(snapshot, gateway_mac=carried)
    return snapshot, {
        "severity": "REVIEW", "kind": "gateway_mac_unreadable",
        "detail": f"The gateway's MAC could not be read this poll; keeping the last "
                  f"observed value ({carried}) as the reference. A blank reading is "
                  "not evidence that nothing changed, and storing it would have "
                  "hidden the next change."}


def diff_snapshots(old, new):
    """Compare two snapshots into a list of {severity, kind, detail}.

    Ordered by how directly the change redirects traffic. A changed gateway MAC
    and a new IPv6 router are the two that mean someone is already in the path.
    """
    events = []
    if not old:
        return events

    if old.get("gateway") != new.get("gateway"):
        events.append({
            "severity": "HIGH", "kind": "gateway_changed",
            "detail": f"Default gateway changed from {old.get('gateway')} to "
                      f"{new.get('gateway')}."})

    old_mac, new_mac = old.get("gateway_mac"), new.get("gateway_mac")
    if old_mac and new_mac and old_mac != new_mac:
        events.append({
            "severity": "HIGH", "kind": "gateway_mac_changed",
            "detail": f"The gateway's MAC changed from {old_mac} to {new_mac} while "
                      "its IP stayed the same. That is what ARP poisoning looks "
                      "like — someone may now be between this machine and the router."})

    appeared = [r for r in new.get("ipv6_routers", []) if r not in old.get("ipv6_routers", [])]
    if appeared:
        events.append({
            "severity": "HIGH", "kind": "ipv6_router_appeared",
            "detail": f"New IPv6 router advertising: {', '.join(appeared)}. A rogue "
                      "Router Advertisement reroutes traffic with no IPv4 sign."})

    if set(old.get("dns", [])) != set(new.get("dns", [])):
        events.append({
            "severity": "HIGH", "kind": "dns_changed",
            "detail": f"DNS resolvers changed from {old.get('dns')} to {new.get('dns')}."})

    new_neighbours = [n for n in new.get("neighbours", []) if n not in old.get("neighbours", [])]
    if new_neighbours:
        events.append({
            "severity": "REVIEW", "kind": "neighbour_appeared",
            "detail": f"New device(s) on the LAN: {', '.join(new_neighbours)}."})

    return events


# ---------------------------------------------------------------------------
# Observation windows
#
# Everything above detects a change by comparing two polls. That is worth
# exactly as much as the monitor's own continuity, and nothing was recording it.
#
# Two consequences, both demonstrated rather than theorised. The loop kept its
# reference snapshot in memory only, so stopping the process and starting it
# again re-baselined into whatever world it woke up in: poison the ARP cache and
# the resolver while it is down, and the restart adopts the attacker's MAC and
# DNS as normal and never alerts on them again — not during the gap, but ever.
# And because nothing recorded when the monitor was up, "no alerts this week"
# was indistinguishable from "nothing was watching this week".
#
# That second one is the same shape as the problem receipts were added for. A
# missing local baseline could not be told apart from a genuine first run, so
# the fix was an off-host record of what had happened. A missing observation
# cannot be told apart from a quiet network, so the fix is an off-host record of
# when observation was happening. Neither prevents anything; both make the
# absence legible afterwards.
#
# What a heartbeat proves is narrow, and overstating it would defeat the point:
# it says the process was alive and could reach the sink at that moment. It does
# NOT say the checks were meaningful. An attacker who owns the host can keep
# heartbeats flowing while feeding the monitor whatever it likes. This detects a
# STOPPED monitor, not a SUBVERTED one.
# ---------------------------------------------------------------------------

# The last snapshot, persisted so a restart resumes its comparison instead of
# starting a new one. Named *_FILE so the test sandbox redirects it by name.
#
# This is the pre-per-network path, kept because a deployment that has been
# running has state here; monitor_state_file() returns the per-network one that
# is actually used, and falls back to this when it is the only thing present.
MONITOR_STATE_FILE = os.path.join(BASELINE_DIR, "monitor_state.json")

# How often liveness is published. Every poll would mean 1440 sink writes a day
# to say nothing; this bounds it. The cost is that a gap is only resolvable to
# within one heartbeat interval, which observation_gaps reports rather than
# rounds away.
HEARTBEAT_INTERVAL = 900

# How far ahead of now a heartbeat may be stamped before it is discarded as
# unusable. The sink is append-only by design, so an entry dated 2099 can never
# be removed — and one was enough to disable the check permanently: it sorted
# last, made the trailing window negative, and turned the HIGH "the monitor is
# not running now" into a past-tense REVIEW for good. A wrong clock (a resumed
# VM, an RTC-less Pi before NTP) produces the same thing with no attacker.
HEARTBEAT_SKEW = 300


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_stamp(value):
    """Parse an ISO timestamp to an aware datetime, or None if unusable.

    Anything unreadable is None rather than an exception: these stamps come from
    a log an attacker may have appended to, and a crash on a malformed line
    would turn the evidence trail into a denial of service.
    """
    try:
        stamp = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp


def _format_duration(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    hours, minutes = divmod(seconds // 60, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h" if hours else f"{days}d"


def monitor_state_file():
    """The state path for the currently selected network.

    One global file was wrong in both directions. Carrying a home reference on
    to café Wi-Fi produced a HIGH gateway_changed, a HIGH gateway_mac_changed
    whose text says "while its IP stayed the same … ARP poisoning" — factually
    false, the IP changed in the same batch — and a HIGH dns_changed, then the
    mirror image on the way home. Three false HIGHs per move is how a real one
    stops being read. And in the other direction, a reference from a different
    network is not a reference at all, so a genuine change on this one had
    nothing meaningful to be compared against.

    Keyed off the same chain id the receipts use, so the two agree about which
    network they are describing.

    Falls back to the pre-per-network path only when that is the only state
    present, so an already-running monitor keeps its reference across the
    upgrade instead of re-baselining — which is the very thing this module
    treats as an attack when it happens by accident.
    """
    per_network = os.path.join(BASELINE_DIR, f"monitor_state-{chain_id()}.json")
    if not os.path.exists(per_network) and os.path.exists(MONITOR_STATE_FILE):
        return MONITOR_STATE_FILE
    return per_network


def load_monitor_state():
    """Return (snapshot, observed_at) from the last poll, or (None, None).

    (None, None) means no monitor has ever run here, which is a genuine start
    and not a gap. A restart that finds state resumes against it, so the window
    while the process was down is compared rather than silently adopted.
    """
    try:
        with open(monitor_state_file()) as f:
            saved = json.load(f)
    except FileNotFoundError:
        return None, None
    except (json.JSONDecodeError, OSError):
        # Present but unusable is not the same as absent, and the caller needs
        # to be able to say so rather than silently re-baselining.
        return None, None
    if not isinstance(saved, dict):
        return None, None
    return saved.get("snapshot"), _parse_stamp(saved.get("observed_at"))


def save_monitor_state(snapshot, at=None):
    """Persist the reference snapshot so the next start has something to diff.

    Returns True on success. A monitor that cannot persist its reference still
    watches correctly within this process; it just cannot survive a restart, and
    every restart then re-baselines into whatever world it wakes up in. That is
    worth continuing through and not worth doing silently, which is why this
    reports rather than either raising or swallowing.
    """
    try:
        _write_json_atomic(monitor_state_file(), {
            "snapshot": snapshot,
            "observed_at": (at or _utcnow()).isoformat(),
        })
        return True
    except OSError:
        return False


def monitor_heartbeat(destination=None, token=None, interval=None, at=None):
    """Publish one proof that observation was happening at this moment.

    Deliberately the same shape and the same channel as a baseline receipt: it
    is routine bookkeeping, not something a person is meant to read, and it
    needs exactly the append-only property receipts need. It carries no
    snapshot — liveness is the whole claim, and shipping the neighbour table
    every quarter hour would leak the network's shape to the sink.
    """
    payload = {
        "kind": "heartbeat",
        "chain": chain_id(),
        "interval": interval if interval is not None else MONITOR_INTERVAL,
        "at": (at or _utcnow()).isoformat(),
        # A long-running monitor is the deployment where an edited script has
        # the most time to go unnoticed, so liveness carries the same attestation
        # a baseline does.
        "code": script_digest(),
    }
    destination = resolve_sink(destination)
    if not destination:
        return {"published": False, "mode": "heartbeat",
                "detail": "No off-host sink configured, so nothing records that the "
                          "monitor was running. A silent week and a stopped monitor "
                          "will look the same."}
    try:
        if destination.startswith(("http://", "https://")):
            return _publish_https(payload, destination,
                                  token or os.environ.get(SINK_TOKEN_ENV), "heartbeat")
        return _publish_path(payload, destination, "heartbeat")
    except Exception as e:                      # noqa: BLE001 - reported, not raised
        return {"published": False, "mode": "heartbeat",
                "detail": f"Could not publish the heartbeat to {destination}: {e}"}


def read_heartbeats(source):
    """Heartbeats from a receipt log, oldest first. Baseline receipts are skipped."""
    return [r for r in read_receipts(source)
            if isinstance(r, dict) and r.get("kind") == "heartbeat"
            and r.get("chain") in (None, chain_id())]


def observation_gaps(heartbeats, interval=None, now=None):
    """Windows during which nothing was watching. Returns [{start, end, seconds}].

    A gap is a gap whether the monitor was killed, crashed, or the machine was
    simply off. Distinguishing those is not something this log can do, and
    guessing would put a reassuring explanation on the one record that exists to
    stop reassuring explanations.

    The trailing window — between the last heartbeat and now — counts. It is the
    one an attacker is inside right now, and reporting only closed gaps would
    hide exactly the case that matters most.

    `interval` defaults to what the heartbeats themselves recorded, not to the
    module constant. Both readers called this without an argument, so the
    threshold was pinned to 900s while real spacing is max(--interval, 900) —
    and a monitor running at --interval 3600 had every one of its healthy
    hourly beats reported as a window with no monitoring, plus a HIGH claiming
    it was not running. The payload has carried its own interval all along.
    """
    heartbeats = [h for h in (heartbeats or []) if isinstance(h, dict)]
    now = now or _utcnow()
    stamps = sorted(s for s in (_parse_stamp(h.get("at")) for h in heartbeats)
                    if s is not None and s <= now + timedelta(seconds=HEARTBEAT_SKEW))
    if not stamps:
        return []
    if interval is None:
        recorded = [h.get("interval") for h in heartbeats
                    if isinstance(h.get("interval"), (int, float))
                    and not isinstance(h.get("interval"), bool)
                    and h.get("interval") > 0]
        # The largest recorded cadence, so a monitor that was restarted with a
        # longer interval is not judged against its old one.
        interval = max(recorded) if recorded else HEARTBEAT_INTERVAL
    # One missed heartbeat is a slow disk or a busy Pi; the allowance is what
    # keeps this from crying wolf on every hiccup.
    threshold = max(interval * 2, interval + 60)
    gaps = []
    for earlier, later in zip(stamps, stamps[1:]):
        elapsed = (later - earlier).total_seconds()
        if elapsed > threshold:
            gaps.append({"start": earlier.isoformat(), "end": later.isoformat(),
                         "seconds": elapsed})
    trailing = (now - stamps[-1]).total_seconds()
    if trailing > threshold:
        gaps.append({"start": stamps[-1].isoformat(), "end": None,
                     "seconds": trailing})
    return gaps


def describe_clock_anomalies(heartbeats, now=None):
    """Report heartbeats stamped in the future, or None if there are none.

    observation_gaps discards them so one bad entry cannot disable the coverage
    check, but discarding quietly would hide the reason the log is wrong. Either
    the clock on the monitoring host is wrong, or someone appended an entry to a
    log that by design cannot have entries removed.
    """
    now = now or _utcnow()
    ahead = [s for s in (_parse_stamp(h.get("at")) for h in (heartbeats or [])
                         if isinstance(h, dict))
             if s is not None and s > now + timedelta(seconds=HEARTBEAT_SKEW)]
    if not ahead:
        return None
    return (f"  [REVIEW] Heartbeat clock: {len(ahead)} heartbeat(s) are stamped in the "
            f"future, the furthest at {max(ahead).isoformat()}. They are excluded from "
            "the coverage check. Either this host's clock is wrong, or entries were "
            "added to a log that cannot have entries removed.")


def describe_observation_gaps(gaps):
    """A risk-tagged line naming when nobody was watching, or None if nobody was.

    Silent when observation was continuous, so a healthy monitor adds no noise —
    the same bargain describe_comparison_coverage makes.
    """
    if not gaps:
        return None
    open_gap = [g for g in gaps if g.get("end") is None]
    longest = max(g["seconds"] for g in gaps)
    risk = "HIGH" if open_gap else "REVIEW"
    if open_gap:
        tail = (f"including one still open ({_format_duration(open_gap[0]['seconds'])} "
                "with no heartbeat) — the monitor is not running now")
    else:
        tail = f"the longest {_format_duration(longest)}"
    return (f"  [{risk:6}] Observation coverage: {len(gaps)} window(s) with no "
            f"monitoring, {tail}. Changes made and reverted inside those windows "
            "left no trace. Nothing is reported about them, which is not the same "
            "as nothing having happened.")


def resolve_alert_sink(explicit=None):
    return explicit or os.environ.get(ALERT_ENV) or None


def send_alert(event, destination=None, token=None):
    """Deliver one event off the machine.

    Printing to a terminal on the host under suspicion delivers the alert
    straight to the adversary and nowhere else, so monitor mode is only worth
    running with somewhere for these to go. Returns the same {published, detail}
    shape as publish_receipt and likewise never raises.
    """
    destination = resolve_alert_sink(destination)
    if not destination:
        return {"published": False,
                "detail": "No alert destination configured; the event stayed on "
                          "this machine."}
    payload = dict(event, at=datetime.now(timezone.utc).isoformat())
    try:
        if destination.startswith(("http://", "https://")):
            # ALERT_TOKEN_ENV, never SINK_TOKEN_ENV: the alert destination is a
            # different endpoint by design, and the receipt sink's credential
            # has no business travelling there.
            return _publish_https(payload, destination,
                                  token or os.environ.get(ALERT_TOKEN_ENV), "alert")
        return _publish_path(payload, destination, "alert")
    except Exception as e:                      # noqa: BLE001 - reported, not raised
        return {"published": False,
                "detail": f"Could not deliver the alert to {destination}: {e}"}


def run_monitor(interval=MONITOR_INTERVAL, iterations=None, alert_to=None,
                sleeper=time.sleep, printer=print,
                heartbeat_interval=HEARTBEAT_INTERVAL, clock=None):
    """Poll the cheap checks and alert on change.

    `iterations=None` runs until interrupted; a number bounds it, which is what
    makes this testable without waiting. Returns every event raised.

    The reference snapshot is loaded from disk and written back every poll, so
    stopping and restarting the process resumes the comparison rather than
    beginning a new one. Keeping it in memory alone meant a restart adopted
    whatever it woke up to — poison the ARP cache and the resolver while the
    monitor is down and the restart silently made the attacker the new normal,
    permanently. A restart across a real gap now compares over it and says so.
    """
    # A callable, not an instant: the loop reads it once per poll. The
    # pure-function siblings (observation_gaps, describe_baseline_freshness)
    # take a datetime under the name `now`, so this one is named for what it is.
    clock = clock or _utcnow
    # Select the baseline for the network this monitor is actually watching,
    # before anything reads chain_id(). Without this the monitor published every
    # heartbeat under sha256("baseline.json") while the audit read them back
    # under sha256("baseline-<key>.json"), so read_heartbeats returned nothing,
    # observation_gaps returned nothing, and describe_observation_gaps returned
    # None — the same value it returns for "observation was continuous". A
    # monitor dead for a fortnight printed absolutely nothing. The feature was
    # inert in every per-network deployment, which is all of them since
    # per-network baselines landed.
    use_current_network_baseline()
    raised = []
    count = 0
    printer(f"Monitoring every {interval}s. Watching the gateway, its MAC, IPv6 "
            "routers, DNS and the neighbour table.")
    if not resolve_alert_sink(alert_to):
        printer("  Note: no alert destination set. Findings will print here only — "
                f"set {ALERT_ENV} so they leave this machine.")
    if not resolve_sink():
        printer("  Note: no receipt sink set, so nothing off-host will record that "
                f"this monitor ran. Set {SINK_ENV} — otherwise a week with no "
                "alerts and a monitor that was never running look identical.")

    # Undelivered alerts are queued and retried, not dropped after one attempt.
    #
    # The loop used to print "(not delivered: ...)" to stdout — on the host
    # under suspicion, which is the one place an alert is worth nothing — and
    # then adopt the change as the new normal anyway. The adversary an alert
    # describes is in-path by definition and can drop the alert POST while
    # letting heartbeats through, so nothing else reported the loss either.
    undelivered = []
    state_warned = False
    heartbeat_warned = False

    def _deliver(event):
        result = send_alert(event, alert_to)
        if not result["published"]:
            undelivered.append(event)
            printer(f"           (not delivered, queued: {result['detail']})")
        return result

    def _retry_undelivered():
        if not undelivered:
            return
        still = []
        for event in undelivered:
            if not send_alert(event, alert_to)["published"]:
                still.append(event)
        delivered = len(undelivered) - len(still)
        if delivered:
            printer(f"           ({delivered} queued alert(s) delivered)")
        undelivered[:] = still

    previous, observed_at = load_monitor_state()
    started = clock()
    # A gap is measured against the promise the monitor makes: it said it would
    # look every `interval` seconds. One missed poll is a slow machine; beyond
    # that, nobody was watching.
    gap_after = interval * 2 + 60
    resumed_gap = None
    if previous is not None and observed_at is not None:
        down = (started - observed_at).total_seconds()
        if down > gap_after:
            resumed_gap = down
            event = {
                "severity": "REVIEW", "kind": "observation_gap",
                "detail": f"Monitoring resumed after {_format_duration(down)} with "
                          f"nothing watching (last poll {observed_at.isoformat()}). "
                          "A change made and undone inside that window left no trace, "
                          "so the comparison below is across the gap, not of it."}
            raised.append(event)
            printer(f"  [{event['severity']:6}] {event['detail']}")
            _deliver(event)

    last_heartbeat = None
    try:
        while iterations is None or count < iterations:
            polled_at = clock()
            snapshot = monitor_snapshot()
            snapshot, carried = carry_forward_gateway_mac(snapshot, previous)
            if carried:
                raised.append(carried)
                printer(f"  [{carried['severity']:6}] {carried['detail']}")
                _deliver(carried)
            for event in diff_snapshots(previous, snapshot):
                if resumed_gap is not None:
                    # The finding is real, but it was not witnessed happening,
                    # and the reader is entitled to know which of those they have.
                    event = dict(event, across_gap=True)
                    event["detail"] += (" Observed across a "
                                        f"{_format_duration(resumed_gap)} window with "
                                        "no monitoring, so when it happened is unknown.")
                raised.append(event)
                printer(f"  [{event['severity']:6}] {event['detail']}")
                _deliver(event)

            previous = snapshot
            resumed_gap = None          # only the first comparison spans the gap
            _retry_undelivered()
            if not save_monitor_state(snapshot, polled_at) and not state_warned:
                state_warned = True
                printer("  [HIGH  ] The reference snapshot could not be written to "
                        f"{monitor_state_file()}. This process still compares poll to "
                        "poll, but every restart will re-baseline against whatever it "
                        "wakes up to — including an attacker already in place.")
            if (last_heartbeat is None
                    or (polled_at - last_heartbeat).total_seconds() >= heartbeat_interval):
                # last_heartbeat only advances on a delivered beat. Advancing it
                # regardless meant an unreachable sink produced no heartbeat and
                # no retry until the next interval, so the coverage record —
                # the thing that says the monitor was running — silently thinned
                # out while the monitor was in fact running perfectly well.
                beat = monitor_heartbeat(interval=interval, at=polled_at)
                if beat.get("published"):
                    last_heartbeat = polled_at
                elif not heartbeat_warned:
                    heartbeat_warned = True
                    printer(f"  [REVIEW] Heartbeat not published: {beat.get('detail', '')}")

            count += 1
            if iterations is None or count < iterations:
                sleeper(interval)
    except KeyboardInterrupt:
        printer("\nStopped.")
    if undelivered:
        printer(f"  [HIGH  ] {len(undelivered)} alert(s) never left this machine. "
                "They are listed above and nowhere else — if this host is the one "
                "under suspicion, treat them as unreported.")
    return raised


def code_attestations(receipts):
    """(digest, when) for every receipt that recorded one, oldest first.

    Both channels are read: a baseline receipt stamps `published_at`, a
    heartbeat stamps `at`. Monitor deployments may publish nothing but
    heartbeats for weeks, and those are exactly the runs where an edited script
    has the longest to go unnoticed.
    """
    found = []
    for r in receipts or ():
        if not isinstance(r, dict):
            continue
        digest = r.get("code")
        if not digest:
            continue                 # predates attestation; not a change
        found.append((digest, r.get("published_at") or r.get("at") or ""))
    return sorted(found, key=lambda pair: pair[1])


def code_changes(receipts):
    """Points in the off-host record where the attesting script changed."""
    seen = code_attestations(receipts)
    changes = []
    for (before, _), (after, when) in zip(seen, seen[1:]):
        if before != after:
            changes.append({"from": before, "to": after, "at": when})
    return changes


def describe_code_attestation(receipts):
    """A line on whether the audit program itself has changed, or None.

    Silent when nothing off-host has attested anything, so a deployment without
    a sink gains no line about a record it is not keeping.
    """
    seen = code_attestations(receipts)
    if not seen:
        return None
    changes = code_changes(receipts)
    caveat = ("Self-reported: the script hashes itself, so this catches an edit "
              "that did not expect to be watched, not one that did.")
    if not changes:
        return (f"  [INFO  ] Audit code: sha256 {seen[-1][0][:12]}… unchanged across "
                f"{len(seen)} off-host record(s). {caveat}")
    last = changes[-1]
    return (f"  [REVIEW] Audit code: the script's digest changed at "
            f"{last['at'] or 'an unrecorded time'} ({last['from'][:12]}… → "
            f"{last['to'][:12]}…), {len(changes)} time(s) on record. If you did not "
            f"update the tool, something edited it. {caveat}")


def describe_publish_result(receipt):
    """One line for the terminal when a receipt could not leave the machine.

    Returns None when it did, so callers can `if line: print(line)`.

    publish_receipt's docstring has always said the caller must surface this —
    "a receipt that silently failed to leave the machine is the same as never
    having sent one" — and no caller did. An unmounted sink or an expired token
    produced months of runs that published nothing and said nothing, while the
    comparison against those absent receipts reported everything in order.
    """
    if not receipt or receipt.get("published"):
        return None
    return f"  [REVIEW] Receipt not published: {receipt.get('detail', '')}"


def describe_receipt_status(report):
    risk = {
        "ok": "OK",
        "no_receipts": "REVIEW",
        "sink_unreadable": "REVIEW",
        "chain_unknown": "REVIEW",
        "unpublished_runs": "REVIEW",
        "history_truncated": "HIGH",
        "seal_mismatch": "HIGH",
        "seal_conflict": "HIGH",
        "keyed_downgrade": "HIGH",
    }.get(report.get("status"), "REVIEW")
    return f"  [{risk:6}] Off-host receipts: {report.get('detail', '')}"


def describe_baseline_integrity(report):
    """One risk-tagged line for the terminal, matching the audit's own style."""
    risk = {
        "ok": "OK" if report.get("keyed") else "REVIEW",
        "absent": "INFO",
        "legacy": "REVIEW",
        "unverifiable": "REVIEW",
        "modified": "HIGH",
        "rolled_back": "HIGH",
        "chain_missing": "HIGH",
        # Both are the same claim as chain_missing seen from the other side —
        # the chain and the record disagree about whether this machine has ever
        # sealed a baseline — so they carry the same weight.
        "record_missing": "HIGH",
        "downgraded": "HIGH",
    }.get(report.get("status"), "REVIEW")
    return f"  [{risk:6}] Baseline integrity: {report.get('detail', '')}"


_CARRIED_LABELS = {
    "devices": "device list",
    "scanned_subnets": "scan coverage",
    "router_open_ports": "router ports",
    "upstream_open_ports": "upstream modem ports",
}


def describe_baseline_freshness(state, now=None):
    """A caveat line when the baseline holds values it did not measure, or None.

    "No changes since baseline" reads as an all-clear over the whole network.
    It is a weaker statement than that whenever part of the baseline was carried
    forward: those values were compared against a reading taken some time ago,
    not against what the baseline run saw. Carrying is still right — the
    alternative destroyed a baseline of ten devices — but the reader is entitled
    to know which parts of the comparison rest on old ground, and how old.

    Silent when everything was measured, so the ordinary run gains no noise.
    """
    carried = (state or {}).get("carried_forward") or []
    if not carried:
        return None
    measured_at = state.get("measured_at") or {}
    now = now or datetime.now(timezone.utc)
    parts = []
    oldest_days = 0
    for key in sorted(carried):
        label = _CARRIED_LABELS.get(key, key)
        when = measured_at.get(key)
        try:
            stamp = datetime.fromisoformat(when)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            days = max(0, (now - stamp).days)
            oldest_days = max(oldest_days, days)
            parts.append(f"{label} ({days}d)" if days else f"{label} (today)")
        except (TypeError, ValueError):
            parts.append(f"{label} (age unknown)")
            oldest_days = max(oldest_days, 1)
    risk = "REVIEW" if oldest_days >= 7 else "INFO"
    return (f"  [{risk:6}] Baseline freshness: carried forward, not measured when "
            f"the baseline was saved — {', '.join(parts)}.")


def describe_comparison_coverage(old, new):
    """A caveat line naming what the device comparison could not cover, or None.

    The sibling of describe_baseline_freshness, for the run rather than the
    baseline. That one says the baseline holds values it did not measure; this
    one says the comparison just made was narrower than it looks.

    Both exist because "No changes since baseline." is printed by measuring
    nothing at all just as readily as by measuring everything and finding it
    unchanged. diff_baseline is right to withhold a device comparison it cannot
    support — an unswept run reporting every device as gone is the alarm that
    started this — but withholding it silently substitutes one wrong answer for
    another, and the second is worse for being reassuring. A --no-discovery run
    printed a clean bill of health over a device list nobody had looked at.

    Two narrower comparisons are worth naming, and neither is a finding:

    The device list was not compared at all, because one side never swept. The
    mirror case is the dangerous one — a first baseline saved from a run that
    skipped discovery means the next full audit has nothing to compare its
    arrivals against, so a genuine intruder that WAS seen goes unreported.

    Or both sides swept, but not the same ground, so a departure from the ground
    this run missed is not something the report would have said.

    Silent when the comparison was whole, so an ordinary run gains no noise.
    """
    old, new = old or {}, new or {}
    old_swept, new_swept = swept_anywhere(old), swept_anywhere(new)
    if not (old_swept and new_swept):
        if not old_swept and not new_swept:
            why = "neither this run nor the baseline swept for devices"
        elif not new_swept:
            # Covers both --no-discovery and a sweep of ground this host is not
            # on, which are the same thing seen from the report: no sighting was
            # possible, so nothing about the devices was learned.
            why = "this run did not sweep for devices"
        else:
            why = "the baseline holds no swept device list"
        return (f"  [INFO  ] Comparison coverage: device list not compared — {why}. "
                "Arrivals and departures are unknown here, not absent.")

    new_cov = {s for s in (new.get("scanned_subnets") or ()) if isinstance(s, str)}
    if not new_cov:
        # No coverage recorded means a baseline predating scanned_subnets, and
        # diff_baseline falls back to a plain set diff there. Nothing was
        # narrowed, so there is nothing to caveat.
        return None
    unswept = sorted({d.get("subnet") for d in (old.get("devices") or [])
                      if isinstance(d, dict) and isinstance(d.get("subnet"), str)
                      and d.get("subnet") and d.get("subnet") not in new_cov})
    if not unswept:
        return None
    return (f"  [INFO  ] Comparison coverage: the baseline lists devices on "
            f"{', '.join(unswept)}, which this run did not sweep, so nothing "
            "there is reported as gone.")


# ---------------------------------------------------------------------------
# Evidence provenance
#
# Every finding in this report rests on something, and what it rests on is not
# always independent of what it describes. The report prints as one flat list,
# which quietly implies the lines are equally well founded. They are not, and
# the gap is not academic: a clean result obtained by asking the device under
# suspicion is not a clean result. It is that device's answer.
#
# Four classes, ordered by how much a compromised gateway can do about them:
#
#   OBSERVED       this machine's own kernel and OS state — the ARP cache, the
#                  routing table, its interfaces, its firewall, its own
#                  listening sockets. A gateway cannot edit any of it. A
#                  compromised HOST can, which is the entire reason DEPLOYMENT
#                  .md argues for running this from a second machine.
#   MEASURED       something this tool did over the network and watched the
#                  result of: a TCP connect, a TLS handshake, a DHCP offer
#                  arriving, a Router Advertisement on the link. Someone in the
#                  path can interfere, but they have to act, and acting is what
#                  most of the rest of this tool is looking for.
#   SELF_REPORTED  the device being assessed said so. UPnP mappings are the
#                  router's own list of the holes it has punched; DSL stats and
#                  admin banners come off its own pages. A compromised router
#                  omits whatever it likes.
#   RESOLVER_DEPENDENT
#                  answered through DNS. On a home network the resolver usually
#                  IS the gateway, so a question about the router gets answered
#                  by the router.
#
# This is deliberately NOT a severity axis, and reading it as one gets it
# backwards. A self-reported finding of an open port or an active mapping is
# excellent evidence — the router volunteered something against its own
# interest. What carries no weight is specifically the CLEAN self-reported
# result, for the same reason an unkeyed seal verifies without being
# forgery-proof: the check passed, and passing was always available to an
# attacker. Absence of evidence, from a witness with a motive, is not evidence
# of absence.
# ---------------------------------------------------------------------------

OBSERVED = "observed"
MEASURED = "measured"
SELF_REPORTED = "self_reported"
RESOLVER_DEPENDENT = "resolver_dependent"
THIRD_PARTY = "third_party"

# state key -> (class, what the finding actually rests on, human label)
#
# Two entries do not correspond to a state key of their own, because one
# measurement can rest on two different grounds at once. The device list is a
# read of this machine's own ARP cache; the vendor names attached to it came
# from an HTTP call to a service on the internet, over the network being
# audited. Same key, same printed table, two answers to "what if this is
# wrong", so they are listed apart rather than averaged into one.
EVIDENCE = {
    "gateway":             (OBSERVED, "this machine's routing table", "Default gateway"),
    "dns":                 (OBSERVED, "this machine's resolver configuration", "DNS settings"),
    "devices":             (OBSERVED, "this machine's ARP and neighbour caches", "Connected devices"),
    "arp_spoof":           (OBSERVED, "repeated reads of this machine's ARP cache", "ARP spoofing check"),
    "firewall":            (OBSERVED, "this machine's firewall configuration", "Firewall status"),
    "sharing":             (OBSERVED, "this machine's sharing service configuration", "Sharing services"),
    "listening":           (OBSERVED, "this machine's own listening sockets", "Listening services"),
    "wifi":                (OBSERVED, "this machine's Wi-Fi association", "Wi-Fi security"),

    "router_open_ports":   (MEASURED, "TCP connections this tool opened to the gateway", "Router port scan"),
    "upstream_open_ports": (MEASURED, "TCP connections this tool opened to the modem", "Upstream port scan"),
    "router_tls":          (MEASURED, "the certificate the gateway presented", "Router TLS"),
    "ipv6":                (MEASURED, "Router Advertisements seen on the link", "IPv6 routers"),
    "evil_twin":           (MEASURED, "beacons seen on the air", "Evil twin check"),
    # How many servers answered is a fact about the wire. What they offered is
    # not: the gateway, DNS and static routes in an offer are values the server
    # chose to send, and a rogue that answers alone still reads as the only one.
    "dhcp":                (MEASURED, "which servers answered a DHCP request on the wire", "Rogue DHCP check"),
    "interception":        (MEASURED, "how a crafted query came back", "Interception checks"),

    "upnp":                (SELF_REPORTED, "the gateway's own list of its port mappings", "UPnP port mappings"),
    "dsl":                 (SELF_REPORTED, "the router's own admin page", "DSL line stats"),
    "default_creds":       (SELF_REPORTED, "the router's own responses to login attempts", "Default credentials"),
    "dhcp_offer_contents": (SELF_REPORTED, "the values the answering DHCP server chose to send", "DHCP offer contents"),

    "router_hostname":     (RESOLVER_DEPENDENT, "a reverse DNS answer about the gateway", "Router hostname"),

    "device_vendors":      (THIRD_PARTY, "an HTTP lookup to api.macvendors.com, over this network", "Device vendor names"),
}

_EVIDENCE_TAG = {
    SELF_REPORTED: "self-reported",
    RESOLVER_DEPENDENT: "via resolver",
    THIRD_PARTY: "third party",
}

# Findings that share a state key with something of a different provenance, and
# the test for whether this run actually produced them.
_DERIVED_EVIDENCE = {
    "device_vendors": lambda state: any(
        isinstance(d, dict) and d.get("vendor")
        for d in (state.get("devices") or ())),
    "dhcp_offer_contents": lambda state: bool(
        isinstance(state.get("dhcp"), dict) and state["dhcp"].get("responders")),
}


def evidence_for(key):
    """(class, basis, label) for a state key, or None if it is not a finding."""
    return EVIDENCE.get(key)


def findings_by_evidence(state):
    """Group the findings actually present in `state` by evidence class."""
    state = state or {}
    grouped = {}
    for key in state:
        entry = EVIDENCE.get(key)
        if entry and state.get(key) is not None:
            grouped.setdefault(entry[0], []).append(key)
    for key, was_produced in _DERIVED_EVIDENCE.items():
        try:
            produced = was_produced(state)
        except (AttributeError, TypeError):
            # A malformed state should cost the caller its provenance section,
            # not the audit it is describing.
            continue
        if produced:
            grouped.setdefault(EVIDENCE[key][0], []).append(key)
    return {cls: sorted(keys) for cls, keys in grouped.items()}


def describe_evidence_basis(state):
    """The report block naming which findings came from the thing they describe.

    Silent when this run produced none of them, so a report with nothing to
    qualify gains no paragraph telling the reader that nothing needs qualifying.
    """
    grouped = findings_by_evidence(state)
    dependent = [(cls, key)
                 for cls in (SELF_REPORTED, RESOLVER_DEPENDENT, THIRD_PARTY)
                 for key in grouped.get(cls, ())]
    if not dependent:
        return None

    independent = len(grouped.get(OBSERVED, ())) + len(grouped.get(MEASURED, ()))
    width = max(len(EVIDENCE[key][2]) for _cls, key in dependent)
    lines = ["  Not every finding above rests on the same ground. These came from "
             "the device",
             "  they describe, through it, or from someone else entirely:"]
    for cls, key in dependent:
        _cls, basis, label = EVIDENCE[key]
        lines.append(f"    [{_EVIDENCE_TAG[cls]:13}] {label:{width}}  — {basis}")
    lines.append("")
    lines.append("  Take seriously anything they admit to: a router listing a port "
                 "mapping has")
    lines.append("  volunteered something against its own interest. A CLEAN result "
                 "from them is")
    lines.append("  worth much less — it says nothing was volunteered, which is not "
                 "the same as")
    lines.append("  there being nothing to find.")
    if independent:
        lines.append(f"  The other {independent} finding(s) rest on this machine's own "
                     "state or on measurements")
        lines.append("  this tool made itself, which a gateway cannot edit. A "
                     "compromised HOST can —")
        lines.append("  that is what running this from a second machine is for.")
    return "\n".join(lines)


def load_labels():
    try:
        with open(LABELS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_labels(labels):
    os.makedirs(BASELINE_DIR, exist_ok=True)
    with open(LABELS_FILE, "w") as f:
        json.dump(labels, f, indent=2)


def load_networks():
    """Return {subnet_str: network_name} — merges defaults with saved overrides."""
    try:
        with open(NETWORKS_FILE) as f:
            saved = json.load(f)
        merged = dict(DEFAULT_NETWORKS)
        merged.update(saved)
        return merged
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(DEFAULT_NETWORKS)


def save_networks(networks):
    os.makedirs(BASELINE_DIR, exist_ok=True)
    with open(NETWORKS_FILE, "w") as f:
        json.dump(networks, f, indent=2)


def identify_network(interfaces, local_ip, gateway=None):
    """Which network this run is ON, as a subnet string, or None.

    Not the set of subnets swept — that is coverage, and a run may sweep ground
    it is not attached to. This is the one network whose baseline the run should
    be compared against: the subnet holding the default gateway, falling back to
    the one holding this machine's own address.
    """
    nets = [net for _, _, net in (interfaces or [])]
    if gateway:
        try:
            gw = ipaddress.ip_address(gateway)
            for net in nets:
                if gw in net:
                    return str(net)
        except ValueError:
            pass
    if local_ip:
        try:
            me = ipaddress.ip_address(local_ip)
            for net in nets:
                if me in net:
                    return str(net)
        except ValueError:
            pass
    fallback = guess_subnet(local_ip) if local_ip else None
    return str(fallback) if fallback else None


def baseline_key(subnet_str):
    """A filename-safe key for a subnet, or None.

    Keyed on the subnet rather than the friendly name because the subnet is the
    stable identity: renaming "pearl" in networks.json is a labelling change and
    must not orphan that network's baseline and seal chain.
    """
    if not subnet_str:
        return None
    return re.sub(r"[^0-9A-Za-z]+", "-", str(subnet_str)).strip("-") or None


def existing_key_for_same_network(directory, subnet_str):
    """A baseline already on disk for this network under a different prefix.

    The key carries the prefix length, so 192.168.87.0/24 and 192.168.87.0/23
    are different files. A router handing out a changed netmask — after a
    firmware update, or a lease from a different DHCP scope — would therefore
    look like a network nobody has ever audited: "no baseline saved yet", a
    fresh chain from seq 1, and the real baseline left on disk unread.

    Re-keying on the network address alone would fix that and orphan every
    baseline already written, so instead the exact key is tried first and this
    is the fallback. Nothing is renamed or migrated; an existing chain is simply
    found and carried on with.

    Only an unambiguous match is adopted. If two prefixes are already on disk
    for one network there is no way to tell which is the live one, and guessing
    would attach a run to the wrong chain — worse than starting a clean one.

    The limit worth knowing: this matches on the NETWORK ADDRESS, so it covers a
    prefix change that leaves that address alone (/24 to /25 on 192.168.87.0)
    and not one that moves it (192.168.87.0/24 to a /23, whose network address
    is 192.168.86.0 — a /23 spans both). The wider case still starts a fresh
    baseline, and says so rather than silently comparing against the wrong
    chain. Matching on overlap instead would cover it, at the cost of letting
    two genuinely different networks adopt each other's history; that trade is
    not worth making for a case with no observed instance.

    Returns the key, or None.
    """
    try:
        net = ipaddress.ip_network(str(subnet_str), strict=False)
    except (ValueError, TypeError):
        return None
    wanted = str(net.network_address).replace(".", "-")
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    matches = []
    for name in names:
        m = re.fullmatch(r"baseline-(.+)\.json", name)
        if not m:
            continue
        key = m.group(1)
        head, _, tail = key.rpartition("-")
        if head == wanted and tail.isdigit():
            matches.append(key)
    return matches[0] if len(matches) == 1 else None


def select_network_baseline(subnet_str):
    """Point BASELINE_FILE and HISTORY_FILE at this network's own files.

    One baseline per network, because comparing a network against another one's
    baseline is not a comparison at all: every device on the new network reads
    as an arrival, every device on the old one as a departure, and the two
    routers' ports are diffed against each other. Worse, the run then saves
    over the baseline, so switching back produces the mirror image and neither
    network ever accumulates a usable history. Three known Wi-Fi networks made
    that the normal case rather than an edge one.

    The seal chain follows the baseline, since a chain only means anything
    relative to the thing it is chaining.

    Returns the key used, or None if the network could not be identified — in
    which case the shared default files stay selected, which is what every
    release before this one used.
    """
    global BASELINE_FILE, HISTORY_FILE
    key = baseline_key(subnet_str)
    if not key:
        return None
    # Siblings of the baseline CURRENTLY selected, not of BASELINE_DIR. Those
    # are two names that can disagree, and anything repointing BASELINE_FILE
    # without also repointing BASELINE_DIR -- the test sandbox among them --
    # would otherwise have selection jump back to whatever BASELINE_DIR says and
    # write outside the redirection entirely. Deriving from the file leaves one
    # source of truth: selection follows wherever the baseline was pointed.
    directory = os.path.dirname(BASELINE_FILE) or BASELINE_DIR
    # The exact key wins whenever it names a baseline that exists. Only when it
    # does not is a differently-masked one for the same network considered, so
    # this can adopt a chain but never divert away from one.
    if not os.path.exists(os.path.join(directory, f"baseline-{key}.json")):
        sibling = existing_key_for_same_network(directory, subnet_str)
        if sibling:
            key = sibling
    BASELINE_FILE = os.path.join(directory, f"baseline-{key}.json")
    HISTORY_FILE = os.path.join(directory, f"history-{key}.jsonl")
    return key


def migrate_legacy_baseline(announce=None):
    """Move a pre-per-network baseline to the network it was actually taken on.

    The old layout had one baseline.json for every network. Which network it
    described is not a guess: the record says so, in scanned_subnets or in the
    subnet its devices were found on. Migrating on that evidence keeps the
    existing seal chain intact and attached to the right network, where leaving
    it would strand a verified history the moment per-network files took over.

    A legacy baseline with nothing to identify it is left exactly where it is
    rather than filed under a guess. Returns the key it was migrated to, or None.
    """
    # dirname(BASELINE_FILE), not BASELINE_DIR: the two can disagree, and
    # selection already derives from the file. Using different roots here would
    # let migration look for a legacy baseline in one place while selection
    # points somewhere else.
    root = os.path.dirname(BASELINE_FILE) or BASELINE_DIR
    legacy_baseline = os.path.join(root, "baseline.json")
    legacy_history = os.path.join(root, "history.jsonl")
    if not os.path.exists(legacy_baseline):
        return None
    try:
        with open(legacy_baseline) as f:
            record = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    state = record.get("state", record) if isinstance(record, dict) else {}
    subnet = None
    swept = state.get("scanned_subnets") or []
    if swept and isinstance(swept[0], str):
        subnet = swept[0]
    if not subnet:
        for d in state.get("devices") or []:
            if isinstance(d, dict) and isinstance(d.get("subnet"), str):
                subnet = d["subnet"]
                break
    if not subnet:
        # A --no-discovery run saves neither coverage nor devices, so those two
        # say nothing — but such a baseline still records the gateway it audited,
        # and the network is the gateway's own. Without this a scheduled-only
        # user's entire sealed chain is unidentifiable, and the caller below
        # would leave it on disk unread for ever.
        gw = state.get("gateway")
        if isinstance(gw, str):
            guessed = guess_subnet(gw)
            if guessed:
                subnet = str(guessed)

    key = baseline_key(subnet)
    if not key:
        return None

    target_baseline = os.path.join(BASELINE_DIR, f"baseline-{key}.json")
    target_history = os.path.join(BASELINE_DIR, f"history-{key}.jsonl")
    if os.path.exists(target_baseline):
        return None                      # already migrated; never overwrite
    try:
        os.replace(legacy_baseline, target_baseline)
        if os.path.exists(legacy_history) and not os.path.exists(target_history):
            os.replace(legacy_history, target_history)
    except OSError:
        return None
    if announce:
        announce(f"  Baseline migrated to per-network storage: {subnet} "
                 f"-> {os.path.basename(target_baseline)}")
    return key


def use_current_network_baseline(interfaces=None, local_ip=None, gateway=None,
                                 announce=print):
    """Select this network's baseline, migrating a legacy one first.

    Called before anything reads or writes a baseline. Migration runs first so
    a pre-per-network baseline is filed under its own network rather than
    stranded beside the new files.

    Returns (subnet, key); either may be None when the network cannot be
    identified, in which case the shared default files remain selected.
    """
    migrate_legacy_baseline(announce=announce)

    # If a legacy baseline is still here, migration could not work out which
    # network it describes. Selecting a per-network file now would abandon it:
    # it stays on disk, sealed and verified, while every later run reads an
    # empty path, reports "no baseline saved yet" for a network that has one,
    # and starts a fresh chain at seq 1. Losing change detection AND the chain
    # is worse than sharing one baseline was. Keep reading it, and say so.
    root = os.path.dirname(BASELINE_FILE) or BASELINE_DIR
    if os.path.exists(os.path.join(root, "baseline.json")):
        if announce:
            announce("  Baseline predates per-network storage and does not record "
                     "which network it describes, so it is still shared. Save a "
                     "baseline from a full audit to give this network its own.")
        return None, None

    if interfaces is None:
        interfaces = get_all_interfaces()
    if local_ip is None:
        local_ip = get_local_ip()
    if gateway is None:
        gateway = get_default_gateway()
    subnet = identify_network(interfaces, local_ip, gateway)
    return subnet, select_network_baseline(subnet)


def describe_current_network(subnet, networks=None):
    """One line naming the network a comparison is against, or None.

    Worth stating plainly once baselines are per-network: "No changes since
    baseline" means nothing until the reader knows which baseline, and on a
    machine that moves between three known Wi-Fi networks the answer is not
    obvious from anything else on screen.
    """
    if not subnet:
        return None
    name = network_name_for_subnet(subnet, networks or load_networks())
    label = f"{name} ({subnet})" if name != subnet else subnet
    return f"  Network: {label}"


def network_name_for_subnet(subnet_str, networks):
    """Return the friendly name for a subnet string, or the subnet itself."""
    # Normalise to network address form for lookup
    try:
        net = ipaddress.ip_network(subnet_str, strict=False)
        key = str(net)
    except ValueError:
        key = subnet_str
    return networks.get(key, networks.get(subnet_str, subnet_str))


def diff_baseline(old, new):
    notes = []
    # Randomised addresses are compared as a population, not as identities.
    #
    # iOS and macOS rotate their private Wi-Fi address, so the same phone is a
    # different MAC on Tuesday than it was on Monday. Compared as a set, every
    # rotation reads as a device arriving and another leaving, and a household
    # of phones produces that alarm on every single run — for ever, and with
    # nothing wrong. An alarm that is always firing is one nobody reads, and it
    # buries the two lines here that mean something.
    #
    # Dropping them entirely is not the answer either: most new devices on a
    # home network are phones, and they all arrive with a private address. So
    # the population is still watched, just by count rather than by name — the
    # only claim a rotating identifier supports. Six becoming twelve is worth
    # saying; naming which six is not, because the names are already stale.
    def _split(entry):
        """Read the device list defensively and index it by MAC.

        Returns (stable_macs, private_macs, subnets_by_mac).

        Two kinds of damage are tolerated here, because a baseline is
        hand-editable JSON on disk and this is the code that has to survive it:

        A device dict with no usable "mac" is skipped rather than indexed. It
        used to be read as d["mac"], so a single truncated entry raised
        KeyError, and since that happened before any comparison, the healthy
        devices beside it were never compared at all — a real intruder sitting
        next to one corrupt record was silently never reported.

        MACs are lowercased. read_arp_table already normalises, so both sides
        agreed only by coincidence; a baseline that had been hand-edited or
        pasted from a vendor page (uppercase is the usual rendering) made every
        unmoved device read as one arriving AND one leaving, on every run, for
        ever.
        """
        macs = set()
        subnets = {}
        for d in entry.get("devices", []) or []:
            if not isinstance(d, dict):
                continue
            mac = d.get("mac")
            if not isinstance(mac, str) or mac == "unknown":
                continue
            mac = mac.lower()
            macs.add(mac)
            subnet = d.get("subnet")
            if isinstance(subnet, str) and subnet:
                subnets.setdefault(mac, set()).add(subnet)
        stable = {m for m in macs if not is_randomized_mac(m)}
        return stable, macs - stable, subnets

    # A run that did not sweep has no "devices" key at all, and that is not the
    # same as a sweep that found nothing. Read as an empty set, every device in
    # the baseline reads as gone — which is what --no-discovery produced: nine
    # devices reported missing from a network where nothing had moved. The same
    # discipline the port lists already follow: an unmeasured side is compared
    # against nothing, in either direction. An empty LIST still diffs, because a
    # sweep that genuinely found nothing is a real and alarming finding.
    devices_measured = swept_anywhere(old) and swept_anywhere(new)

    old_macs, old_private, old_subnets = _split(old)
    new_macs, new_private, new_subnets = _split(new)
    new_cov = {s for s in (new.get("scanned_subnets") or ()) if isinstance(s, str)}
    old_cov = {s for s in (old.get("scanned_subnets") or ()) if isinstance(s, str)}
    appeared = (new_macs - old_macs) if devices_measured else set()
    vanished = (old_macs - new_macs) if devices_measured else set()
    # Both sides having swept somewhere does not mean they swept the same ground,
    # and a departure is a claim about ground: this run looked where the device
    # used to answer and it was not there. The subnet-move check below has always
    # carried that test; departures never did, so a baseline from a full audit
    # compared against the menu's single-subnet sweep reported every device on
    # every other subnet as gone — the loudest line in the report, describing
    # nothing but the two runs covering different ground.
    #
    # Arrivals need no such test and must not be given one. A device that is
    # present was seen, directly, by this run; that the baseline never covered
    # where it is now makes it more worth reporting, not less. Suppressing an
    # unknown device because the old run had not looked there is the blindness
    # named below, in the section where it would cost the most.
    if new_cov:
        # No recorded subnet means a baseline written before devices carried one.
        # Where it used to answer is unknown, so there is nothing to check it
        # against, and reporting is what the empty set already yields here.
        vanished = {m for m in vanished if old_subnets.get(m, set()) <= new_cov}
    if appeared:
        notes.append(f"NEW device(s) since baseline: {', '.join(sorted(appeared))}")
    if vanished:
        notes.append(f"Device(s) gone since baseline: {', '.join(sorted(vanished))}")
    # A device that changes subnet leaves the MAC set completely unchanged, so
    # the two comparisons above are structurally blind to it — collect_devices
    # records a "subnet" per device precisely so this can be seen. It matters
    # in both directions: something that was on the guest network appearing on
    # the trusted one is a boundary being crossed, and a device that moved the
    # other way may have been re-homed by someone else. Only stable MACs are
    # considered; a rotating private address is a different identity each run,
    # so "the same device moved" is a claim it cannot support.
    # One test carries the claim: this run swept every subnet the device used to
    # be on and did not find it there, so "it left" is a measurement rather than
    # an absence of looking. Without it, two runs covering different ground
    # report a move for every device answering on both (a gateway, or a VLAN
    # subinterface sharing the parent MAC) — the menu's device scan sweeps one
    # subnet chosen from DEFAULT_NETWORKS while a full audit sweeps what the
    # interfaces suggest, so "not seen there" and "never looked there" have to be
    # told apart, and only a recorded sweep list can do it.
    #
    # Requiring the BASELINE to have covered the destination too was a mistake
    # worth naming, because it read as caution and behaved as blindness. That
    # test asks only whether the destination is novel, and on an unknown answer
    # it discarded the half of the finding that HAD been measured. A baseline
    # saved from the menu covers the single subnet it swept, so the veto silenced
    # a move onto any other network — including a device crossing from the IoT
    # subnet to the trusted one, the exact boundary crossing this check exists to
    # catch. Novelty of the destination is worth saying, never worth suppressing
    # the note for.
    moved = []
    for mac in (sorted(old_subnets.keys() & new_subnets.keys() & old_macs & new_macs)
                if devices_measured else []):
        was, now = old_subnets[mac], new_subnets[mac]
        if new_cov and was.isdisjoint(now) and was <= new_cov:
            entry = f"{mac} ({', '.join(sorted(was))} -> {', '.join(sorted(now))})"
            if old_cov and not now <= old_cov:
                entry += " [the baseline never covered that destination]"
            moved.append(entry)
    if moved:
        # This note is reported whatever else fired, and it claims nothing about
        # anything else. It used to end "The MAC set is unchanged, so nothing
        # else about the network looks different" — a statement about the WHOLE
        # report, made from inside one check, before the router-port, evil-twin,
        # DHCP and certificate comparisons below have even run. It printed
        # directly above a new-open-port and an evil-twin finding and told the
        # reader to stand down about them. Gating the whole note on there being
        # no arrivals was no better: it deleted a boundary crossing precisely
        # when the run was at its most eventful.
        notes.append(
            f"Device(s) moved to a different subnet: {'; '.join(moved)}. A device "
            "that changes subnet keeps its MAC, so it is not reported as an "
            "arrival or a departure above.")
    # Only on a rise, and deliberately so. A falling count is the most ordinary
    # thing on a home network — phones sleep and drop off the table — and
    # reporting it would fire on most runs while saying nothing.
    #
    # The known blind spot this leaves: one household phone leaving as an
    # intruder joins nets to no change in the count, and nothing is said. That
    # is not fixable by reporting falls, because with a rotating identifier
    # there is no signal to recover — an address seen this run and not last is
    # equally consistent with a new device and with the same device having
    # re-randomised. The count is the only claim these addresses support.
    if devices_measured and len(new_private) > len(old_private):
        notes.append(
            f"{len(new_private)} device(s) using rotating private addresses, up "
            f"from {len(old_private)}. These cannot be identified across runs, so "
            "they are counted rather than named; a rise can be new devices or the "
            "same ones having re-randomised.")
    # None means the scan could not reach the router, not that it found nothing.
    # Diffing an unknown against a known would invent a change in whichever
    # direction the blocked run happened to fall: a blocked new run reads as
    # "all ports closed", and the recovery run after it as "all ports opened".
    #
    # Both scanned hosts are compared, not just the router. upstream_open_ports
    # has been collected and saved into the baseline all along but never diffed,
    # so Telnet appearing on the modem was completely silent — on the one device
    # in the house that faces the internet directly, where an open port is worth
    # more than it is on the LAN side of the router behind it.
    for key, host in (("router_open_ports", "router"),
                      ("upstream_open_ports", "upstream modem")):
        old_ports = old.get(key)
        new_ports = new.get(key)
        if old_ports is None or new_ports is None:
            continue
        old_ports = set(old_ports)
        new_ports = set(new_ports)
        if new_ports - old_ports:
            note = f"NEW open port(s) on {host}: {sorted(new_ports - old_ports)}"
            if key == "upstream_open_ports":
                note += (". This device faces the internet, so a port opening here "
                         "is exposed more widely than one on the router behind it.")
            notes.append(note)
        if old_ports - new_ports:
            notes.append(f"Port(s) now closed on {host}: {sorted(old_ports - new_ports)}")
    old_bssids = set(old.get("wifi_bssids", []))
    new_bssids = set(new.get("wifi_bssids", []))
    if new_bssids - old_bssids:
        notes.append(
            f"NEW access point advertising your SSID: {sorted(new_bssids - old_bssids)}. "
            "A second AP broadcasting your network name is an evil twin.")

    old_offer = (old.get("dhcp") or {}).get("responders") or []
    new_offer = (new.get("dhcp") or {}).get("responders") or []
    if old_offer and new_offer:
        notes.extend(diff_dhcp_offer(old_offer[0], new_offer[0]))

    old_cert = (old.get("router_tls") or {}).get("sha256")
    new_cert = (new.get("router_tls") or {}).get("sha256")
    if old_cert and new_cert and old_cert != new_cert:
        notes.append(
            "Router TLS certificate CHANGED: "
            f"{old_cert[:16]}… -> {new_cert[:16]}…. The admin certificate is "
            "self-signed and stable, so this means it was re-issued or something "
            "is answering in the router's place.")

    old_ra = set(old.get("ipv6_routers", []))
    new_ra = set(new.get("ipv6_routers", []))
    if new_ra - old_ra:
        notes.append(
            "NEW IPv6 router advertising on the LAN: "
            f"{sorted(new_ra - old_ra)} — a rogue Router Advertisement would "
            "look exactly like this, and reroutes traffic with no IPv4 sign.")
    if old_ra - new_ra:
        notes.append(f"IPv6 router(s) no longer advertising: {sorted(old_ra - new_ra)}")
    if set(old.get("dns", [])) != set(new.get("dns", [])):
        notes.append(f"DNS servers CHANGED: was {old.get('dns')}, now {new.get('dns')}")

    # The gateway and its MAC are sealed into every baseline and were never
    # compared, which left the audit blind to the one change it most needs to
    # see. check_arp_spoofing's verdict is len(macs_seen) > 1 over five polls in
    # about six seconds, so a poisoner who is simply *there* — already in place,
    # steady state — yields one MAC and prints "[OK] MAC address stable". The
    # monitor has this comparison; the audit did not, so a full audit run
    # against an actively poisoned network reported "no changes since baseline".
    old_gw, new_gw = old.get("gateway"), new.get("gateway")
    if old_gw and new_gw and old_gw != new_gw:
        notes.append(
            f"Default gateway CHANGED: was {old_gw}, now {new_gw}. Everything this "
            "machine sends off-link now goes somewhere else.")

    old_macs = set((old.get("arp_spoof") or {}).get("macs_seen") or [])
    new_macs = set((new.get("arp_spoof") or {}).get("macs_seen") or [])
    if old_macs and new_macs and old_macs != new_macs:
        notes.append(
            f"Gateway MAC CHANGED: was {sorted(old_macs)}, now {sorted(new_macs)}. "
            "A stable MAC that is stable at a DIFFERENT value than the baseline is "
            "what an ARP poisoner who was already in place before this run looks "
            "like — the per-run 'stable across all polls' check cannot see it.")
    return notes


# ---------------------------------------------------------------------------
# Speed test & DSL stats
# ---------------------------------------------------------------------------

def speed_test(duration=6):
    """Measure download and upload speed via Cloudflare's speed-test endpoints.
    Download and upload run concurrently to roughly halve total elapsed time.
    Returns (download_mbps, upload_mbps); either may be None on failure.
    """
    def _download():
        try:
            req = urllib.request.Request(
                "https://speed.cloudflare.com/__down?bytes=10000000",
                headers={"User-Agent": "home_net_audit"})
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=15) as r:
                total = 0
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if time.time() - t0 > duration:
                        break
            elapsed = time.time() - t0
            if elapsed > 0 and total > 0:
                return (total * 8) / elapsed / 1_000_000
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        return None

    def _upload():
        try:
            data = os.urandom(5_000_000)
            req = urllib.request.Request(
                "https://speed.cloudflare.com/__up", data=data,
                headers={"User-Agent": "home_net_audit",
                         "Content-Type": "application/octet-stream"})
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=15):
                pass
            elapsed = time.time() - t0
            if elapsed > 0:
                return (len(data) * 8) / elapsed / 1_000_000
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        return None

    with futures.ThreadPoolExecutor(max_workers=2) as pool:
        dl_fut = pool.submit(_download)
        ul_fut = pool.submit(_upload)
        return dl_fut.result(), ul_fut.result()


# DSL stat regexes, pre-compiled once at import (the scrape loop runs them
# against every candidate page).
# The gaps around each keyword exclude DIGITS, and that single change fixes two
# separate ways these patterns produced a plausible wrong number rather than no
# number — which is why neither was ever noticed.
#
# It stops the quantifier before the capture group eating into the value.
# `[^<]{0,20}` was greedy: it swallowed as much of "SNR: 6.5 dB" as it could,
# then gave back only what `([\d.]+)` needed, which is the single character
# after the decimal point. Every SNR and attenuation figure came out as its own
# last digit — 6.5 read as 5, 24.8 as 8, 13.1 as 1 — printed beside this tool's
# own "healthy >6 dB" note, so a perfectly good line reported itself as failing.
# A quantifier that cannot cross a digit cannot reach into the number at all.
#
# It also stops a label reaching a different field's value. In a row holding
# more than one measurement — "Upstream Rate 1024 Kbps Downstream SNR 6.5" —
# the upstream pattern would otherwise step over the rate and capture the
# DOWNSTREAM figure. A number in the gap means another field has already been
# passed, so the label and the keyword do not belong to each other.
#
# The trailing `?` on those quantifiers is deliberate but, given the digit
# exclusion, currently unobservable: no input can distinguish lazy from greedy
# while a digit cannot be crossed. It is kept because it states the intent —
# take the shortest gap — and would carry the load again if the character class
# were ever loosened. Do not read it as tested; the digit exclusion is what the
# tests in test_dsl_stats.py actually pin.
# Excluding digits is necessary and not sufficient, because the thing that most
# often sits between a direction word and somebody else's number carries no
# digit at all: the link state. A status row reads
#
#     DSL Status | Up | Downstream SNR Margin | 6.5
#
# and once _dsl_rows has merged those cells, an unanchored [Uu]p matches the
# bare state word, walks a digit-free gap through "Downstream SNR Margin", and
# reports 6.5 as the UPSTREAM figure — a number the modem never gave for that
# direction. Before rows existed the "<" between cells blocked it and nothing
# was reported, so adding row support turned "no value" into "wrong value",
# which this module's own docstrings call the worse outcome. Two things fix it:
#
#   the direction must be spelled out. "Downstream" and "Upstream" are what an
#   xDSL status page calls the two directions; bare "Up" and "Down" are what it
#   calls the LINK STATE, and abbreviations when they appear are "DS"/"US". So
#   the short form was contributing almost nothing and mistaking a state for a
#   direction constantly. Requiring the full word also disposes of "Setup",
#   "Group", "Backup" and "Startup" in one move. Firmware that really does label
#   a field "Down Rate" now yields no reading rather than a misattributed one,
#   which is the trade this module makes everywhere else.
#
#   a gap that refuses to cross the OPPOSITE direction word, so a pattern
#   cannot start at one direction and finish inside the other's field. This is
#   the invariant the digit exclusion was reaching for and could not express:
#   what disqualifies a match is another direction having been passed, whether
#   or not it brought a number with it.
_DSL_GAP_D = r"(?:(?!\b[Uu]pstream\b)[^<\d])"    # may not reach past "Upstream"
_DSL_GAP_U = r"(?:(?!\b[Dd]ownstream\b)[^<\d])"  # may not reach past "Downstream"

_DSL_PATTERNS = {
    "downstream_kbps":   [re.compile(r"\b[Dd]ownstream" + _DSL_GAP_D + r"{0,40}?(\d{3,6})\s*[Kk]bps")],
    "upstream_kbps":     [re.compile(r"\b[Uu]pstream" + _DSL_GAP_U + r"{0,40}?(\d{3,6})\s*[Kk]bps")],
    "downstream_snr_db": [re.compile(r"\b[Dd]ownstream" + _DSL_GAP_D + r"{0,40}?SNR" + _DSL_GAP_D + r"{0,20}?([\d.]+)")],
    "upstream_snr_db":   [re.compile(r"\b[Uu]pstream" + _DSL_GAP_U + r"{0,40}?SNR" + _DSL_GAP_U + r"{0,20}?([\d.]+)")],
    "downstream_attn_db":[re.compile(r"\b[Dd]ownstream" + _DSL_GAP_D + r"{0,40}?[Aa]ttenuation" + _DSL_GAP_D + r"{0,20}?([\d.]+)")],
    "upstream_attn_db":  [re.compile(r"\b[Uu]pstream" + _DSL_GAP_U + r"{0,40}?[Aa]ttenuation" + _DSL_GAP_U + r"{0,20}?([\d.]+)")],
}


_TPLINK_ENCRYPTED_LOGIN_MARKERS = ("tpencrypt", "cryptojs", "gdprproxy", "/cgi_gdpr")


def _tplink_uses_encrypted_login(login_page_html):
    """True if this firmware encrypts credentials in the browser before login.

    Newer TP-Link builds derive a session key with RSA, encrypt the payload
    with AES and POST it to /cgi_gdpr; the legacy scheme this module speaks
    puts a base64'd password straight in a GET query string. Telling them apart
    matters because the failures look identical from the outside — no page is
    retrieved either way — while the remedies are not remotely alike, and the
    old message ("auth failed or unknown page paths") pointed at the two
    remedies that cannot help.

    Detected from the scripts the login page loads rather than by attempting a
    login, so it costs nothing and cannot contribute to locking anyone out of
    their own modem.
    """
    page = (login_page_html or "").lower()
    return any(marker in page for marker in _TPLINK_ENCRYPTED_LOGIN_MARKERS)


def _dsl_rows(raw):
    """Split a router status page into rows, each flattened to plain text.

    Two things have to be true at once, and getting one without the other
    produces a wrong number rather than no number:

    A label and its value must be able to reach each other. A router serves a
    table — `<td>Downstream SNR</td><td>6.5</td>` — so the patterns, which
    cannot cross a `<`, failed on precisely the pages this function is aimed
    at, and every run reported "format unrecognised" whatever the modem said.

    A label must NOT be able to reach a different measurement's value. Simply
    deleting the tags allows that: flattened to one string, "Upstream Rate 1024
    Kbps Downstream SNR 6.5" lets the upstream-SNR pattern start at "Upstream",
    run past the rate, and capture the DOWNSTREAM figure. Upstream then reports
    downstream's number, which is worse than reporting nothing.

    Rows are the structure that separates measurements, so rows are what this
    preserves. Tags within a row become spaces rather than vanishing, so cells
    cannot be glued into a word that never appeared.
    """
    parts = re.split(r"(?i)</tr>|</p>|<br\s*/?>|[\r\n]+", raw)
    rows = []
    for part in parts:
        text = re.sub(r"<[^>]+>", " ", part)
        text = text.replace("&nbsp;", " ").replace("&#160;", " ")
        text = re.sub(r"[ \t]+", " ", text).strip()
        if text:
            rows.append(text)
    return rows


def tplink_dsl_stats(ip, password):
    import base64, http.cookiejar, http.client
    base = f"http://{ip}"
    stats = {
        "downstream_kbps": None, "upstream_kbps": None,
        "downstream_snr_db": None, "upstream_snr_db": None,
        "downstream_attn_db": None, "upstream_attn_db": None,
    }
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    hdrs = {"User-Agent": "home_net_audit", "Referer": base + "/"}

    def fetch(url, post=False):
        try:
            req = urllib.request.Request(url, data=(b"" if post else None), headers=hdrs)
            with opener.open(req, timeout=6) as r:
                return r.read().decode("utf-8", "ignore")
        except http.client.IncompleteRead as e:
            return e.partial.decode("utf-8", "ignore")
        except Exception:
            return ""

    b64pwd = base64.b64encode(password.encode()).decode()
    login_url = (f"{base}/cgi/login?UserName=admin"
                 f"&Passwd={urllib.parse.quote(b64pwd)}"
                 f"&Action=1&LoginStatus=0")
    login_resp = fetch(login_url, post=True)
    # Use the public CookieJar iterator rather than the private _cookies dict,
    # which is a CPython implementation detail not guaranteed on every runtime.
    if not list(jar) and "success" not in login_resp.lower():
        import hashlib
        md5pwd = hashlib.md5(password.encode()).hexdigest().upper()
        fetch(f"{base}/cgi/login?UserName=admin&Passwd={md5pwd}&Action=1&LoginStatus=0", post=True)

    dsl_paths = [
        "/html/status/xdslStatus.html", "/html/advance/xdsl.html",
        "/html/status/dslStatus.html",  "/cgi/getAdsl",
        "/cgi/getDsl",                  "/cgi/getXdsl",
        "/cgi/getStatus?resource=dsl",  "/userRpm/StatusRpm.htm",
    ]
    raw = ""
    for path in dsl_paths:
        raw = fetch(base + path)
        if raw and any(kw in raw.lower() for kw in
                       ["snr", "attenuation", "downstream", "upstream", "sync rate"]):
            break
        raw = ""
    if not raw:
        # "auth failed or unknown page paths" covers two very different
        # situations and sends the reader after the wrong one. The common cause
        # is neither: the login above is TP-Link's LEGACY scheme, a plain GET
        # with the password base64'd in the query string, and current firmware
        # does not accept it. Those builds encrypt the credentials in the
        # browser (RSA for the session key, AES for the payload, POSTed to a
        # /cgi_gdpr endpoint), which is a different protocol rather than a
        # different path — no password and no page list can bridge it.
        #
        # The login page names the difference: it pulls tpEncrypt.js, cryptoJS
        # and gdprProxy.js, none of which exist on the older builds this code
        # was written against. Checking for them costs one unauthenticated GET
        # and turns a misleading message into an actionable one.
        if _tplink_uses_encrypted_login(fetch(base + "/")):
            return stats, ("This modem's firmware uses TP-Link's encrypted login "
                           "(RSA/AES via /cgi_gdpr), which this tool does not "
                           "implement — the password is not the problem. DSL "
                           "stats are unavailable until that login is supported.")
        return stats, "Could not retrieve DSL stats — auth failed or unknown page paths"

    rows = _dsl_rows(raw)
    for key, pats in _DSL_PATTERNS.items():
        matched = False
        for pat in pats:
            for row in rows:
                m = pat.search(row)
                if m:
                    try:
                        stats[key] = float(m.group(1))
                    except ValueError:
                        pass
                    matched = True
                    break
            if matched:
                break
    note = "" if any(v is not None for v in stats.values()) else \
        "Connected but no DSL values parsed — format unrecognised"
    return stats, note


# ---------------------------------------------------------------------------
# NEW FEATURE 1: Wi-Fi security mode
# ---------------------------------------------------------------------------

def _parse_connected_wifi_block(text):
    """Return (ssid, block_body) for the CONNECTED Wi-Fi network from
    `system_profiler SPAirPortDataType` output.

    Anchors to the first 'Current Network Information:' whose next deeper-indented
    line is a bare 'name:' key (the en0 block — the awdl0/AirDrop block has none),
    and bounds the body before 'Other Local Wi-Fi Networks:' so a neighbour's
    Security value can never be read by mistake.
    """
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.strip() != "Current Network Information:":
            continue
        cur_indent = len(ln) - len(ln.lstrip())
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j >= len(lines):
            continue
        key_indent = len(lines[j]) - len(lines[j].lstrip())
        name = lines[j].strip()
        # Must be a deeper-indented 'name:' key, not a 'Field: value' child.
        if key_indent > cur_indent and name.endswith(":") and ":" not in name[:-1]:
            body = []
            for k in range(j + 1, len(lines)):
                s = lines[k]
                if not s.strip():
                    continue
                ind = len(s) - len(s.lstrip())
                if s.strip().startswith("Other Local Wi-Fi Networks:") or ind <= key_indent:
                    break
                body.append(s)
            return name[:-1].strip(), "\n".join(body)
    return None, ""


# Section titles in `system_profiler SPAirPortDataType` output — structure,
# not network names. Matched exactly, and interface names by shape.
#
# The previous suffix test ("...Networks", "...Information") was wrong twice
# over. It rejected any real SSID ending in the same word — a neighbour called
# "AAA Guest Networks" — and, worse, the reject branch left `ssid` pointing at
# the *previous* network, so the rejected network's BSSIDs were filed under it.
# Listed first under "Other Local Wi-Fi Networks", such a neighbour handed its
# BSSID to the connected SSID and raised a false evil-twin HIGH, which was then
# written into the baseline. The mirror case — the user's own SSID ending in
# "Networks" — filed every BSSID under "en0" instead, so check_evil_twin found
# nothing for the real SSID and blamed Location Services for a parser bug.
WIFI_SECTION_HEADERS = frozenset({
    "Wi-Fi",
    "Software Versions",
    "Interfaces",
    "Current Network Information",
    "Other Local Wi-Fi Networks",
})


def parse_wifi_networks(text):
    """Return {ssid: [bssid, ...]} across every network system_profiler lists.

    Covers the connected block and the 'Other Local Wi-Fi Networks' section
    together, because an evil twin is precisely a second BSSID advertising the
    SSID you are connected to.
    """
    networks = {}
    ssid = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            candidate = stripped[:-1].strip()
            if (not candidate or candidate in WIFI_SECTION_HEADERS
                    or re.fullmatch(r"en\d+", candidate)):
                # A section header ends the previous network. Leaving `ssid` set
                # is what misattributed the next BSSIDs.
                ssid = None
            else:
                ssid = candidate
                networks.setdefault(ssid, [])
            continue
        m = re.match(r"BSSID:\s*(\S+)", stripped)
        if m and ssid:
            bssid = m.group(1).strip()
            if bssid.lower() in ("<redacted>", "redacted"):
                continue
            raw = bssid.split(":")
            if len(raw) == 6:
                try:
                    bssid = ":".join(f"{int(x, 16):02x}" for x in raw)
                except ValueError:
                    continue
                if bssid not in networks[ssid]:
                    networks[ssid].append(bssid)
    return {k: v for k, v in networks.items() if v}


def check_evil_twin(ssid=None, known=None):
    """Flag a BSSID advertising your SSID that was not in the baseline.

    Comparative for the same reason as rogue-RA detection: a mesh or a pair of
    access points legitimately puts several BSSIDs behind one SSID, so a count
    would alarm forever. What matters is a new one appearing.
    """
    out = run(["system_profiler", "SPAirPortDataType"], timeout=15) or ""
    networks = parse_wifi_networks(out)
    if ssid is None:
        ssid, _ = _parse_connected_wifi_block(out)

    if not ssid or ssid == "<redacted>":
        return {"ssid": None, "bssids": [], "unexpected": [], "risk": "REVIEW",
                "note": "Could not read the connected SSID. macOS withholds it "
                        "from a process without Location Services access — grant "
                        "it to this terminal in System Settings > Privacy & "
                        "Security > Location Services. Running with sudo does "
                        "not help; the gate is the permission, not the user."}

    bssids = networks.get(ssid, [])
    if not bssids:
        return {"ssid": ssid, "bssids": [], "unexpected": [], "risk": "REVIEW",
                "note": f"No BSSID visible for {ssid}. BSSIDs are withheld from a "
                        "process without Location Services access — grant it in "
                        "System Settings > Privacy & Security > Location Services. "
                        "sudo does not reveal them."}

    known = list(known or [])
    unexpected = [b for b in bssids if b not in known] if known else []
    if unexpected:
        return {"ssid": ssid, "bssids": bssids, "unexpected": unexpected, "risk": "HIGH",
                "note": f"{ssid} is being advertised by {', '.join(unexpected)}, which "
                        "was not in the baseline. A second access point broadcasting "
                        "your network name is an evil twin — clients may associate "
                        "with it instead of yours."}
    return {"ssid": ssid, "bssids": bssids, "unexpected": [], "risk": "OK",
            "note": f"{ssid} advertised by {len(bssids)} known BSSID(s)." if known
                    else f"{ssid} advertised by {', '.join(bssids)}. No baseline yet — "
                         "save one so a new access point would stand out."}


def action_evil_twin(known=None):
    hr("EVIL TWIN CHECK")
    result = check_evil_twin(known=known)
    print(f"  SSID   : {result['ssid'] or 'unknown'}")
    for b in result["bssids"]:
        flag = "  <-- not in baseline" if b in result["unexpected"] else ""
        print(f"    {b}{flag}")
    print(f"  [{result['risk']:6}] {result['note']}")
    return result


def check_wifi_security():
    """
    Report the connected Wi-Fi network's security mode from system_profiler.
    (The legacy `airport` utility was removed on current macOS.) WEP is broken;
    open networks have no encryption at all.

    Returns a dict: ssid, auth, cipher, risk, note. ssid is None when macOS
    withholds it, which it does from any process without Location Services
    access — the default for a terminal, and unaffected by sudo. An SSID and a
    BSSID can be looked up in a wardriving database to place a house on a map,
    so those two fields sit behind that permission while everything else in the
    same report — firmware, channel, country code, the security mode this
    function actually needs — comes back either way.
    """
    out = run(["system_profiler", "SPAirPortDataType"], timeout=15) or ""
    result = {"ssid": None, "auth": None, "cipher": None, "risk": "UNKNOWN", "note": ""}

    ssid_raw, block = _parse_connected_wifi_block(out)
    if ssid_raw and ssid_raw != "<redacted>":
        result["ssid"] = ssid_raw

    # Security is scoped to the connected block only — never a neighbour's value.
    m = re.search(r"^\s*Security:\s*(.+?)\s*$", block, re.MULTILINE)
    if m:
        result["auth"] = m.group(1).strip()

    a = (result["auth"] or "").lower()
    if a in ("none", "open"):
        # Only the literal macOS 'None' string means a truly open network.
        result["risk"] = "HIGH"
        result["note"] = "OPEN network — all traffic is unencrypted. Use WPA2 or WPA3."
    elif not a:
        # No Security value parsed — a failure to read, NOT a confirmed open net.
        result["risk"] = "REVIEW"
        # Deliberately not "try sudo". The Security field comes back to an
        # unprivileged process — only the SSID and BSSID are withheld, and by
        # Location Services rather than by privilege. Suggesting root here
        # sends someone to run a network audit as root for no benefit.
        result["note"] = ("Could not read the Wi-Fi security mode. Are you on "
                          "Wi-Fi? This field does not need elevated privileges, "
                          "so an empty one means the report had no network block "
                          "to read, not that permission was missing.")
    elif "wep" in a:
        result["risk"] = "HIGH"
        result["note"] = "WEP is cryptographically broken. Upgrade to WPA2 or WPA3 immediately."
    elif "wpa3" in a:
        if "wpa2" in a:
            result["risk"] = "OK"
            result["note"] = "WPA2/WPA3 transitional — good, but a WPA2 fallback is still allowed."
        else:
            result["risk"] = "GOOD"
            result["note"] = "WPA3 — current best practice."
    elif "wpa2" in a:
        if "wpa/" in a:
            result["risk"] = "MEDIUM"
            result["note"] = "WPA/WPA2 mixed — the legacy WPA fallback weakens security. Set WPA2/WPA3 only."
        else:
            result["risk"] = "OK"
            result["note"] = "WPA2 — acceptable. WPA3 preferred if your router supports it."
    elif "wpa" in a:
        result["risk"] = "MEDIUM"
        result["note"] = "WPA (original) has known weaknesses. Upgrade to WPA2 or WPA3."
    else:
        result["risk"] = "REVIEW"
        result["note"] = f"Unrecognised auth type '{result['auth']}'. Investigate."

    return result


def action_wifi_security():
    hr("WI-FI SECURITY MODE")
    r = check_wifi_security()
    print(f"  SSID (network name) : "
          f"{r['ssid'] or 'unknown (needs Location Services access)'}")
    print(f"  Auth / encryption   : {r['auth'] or 'unknown'}")
    if r["cipher"]:
        print(f"  Cipher              : {r['cipher']}")
    print(f"  Risk                : [{r['risk']}]")
    print(f"  Note                : {r['note']}")
    return r


# ---------------------------------------------------------------------------
# NEW FEATURE 2: Rogue DHCP detector
# ---------------------------------------------------------------------------

def parse_dhcp_options(data):
    """Split the option TLVs out of a DHCP packet into {code: bytes}.

    Counting responders was never the whole story. A single, perfectly ordinary
    DHCP server can hand out a poisoned gateway, resolver or static route, and
    the count stays at one the entire time.

    RFC 2131 fixes the magic cookie at byte 236, and that is where it is read
    from. Searching for it instead handed the sender control of where parsing
    began: `sname` (44) and `file` (108) are free-form bytes they fill in, so a
    decoy cookie there followed by an 0xff terminator ended the option walk
    before it reached offset 236. The audit then reported the benign gateway
    from the decoy while the client applied the poisoned one that follows.
    """
    if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
        return {}
    options = {}
    i = 240
    while i < len(data):
        code = data[i]
        if code == 255:                 # end
            break
        if code == 0:                   # pad
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        if len(value) < length:
            break                       # truncated packet
        options[code] = value
        i += 2 + length
    return options


def _addresses(value):
    return [socket.inet_ntoa(value[i:i + 4]) for i in range(0, len(value) - 3, 4)]


def decode_classless_routes(value):
    """RFC 3442 option 121 — the quiet traffic-redirect vector.

    A static route pushed here reroutes a subnet without the attacker having to
    win a DHCP race or touch the default gateway, so the network keeps looking
    entirely normal. Encoding is a prefix width, that many significant octets
    of destination, then a 4-byte gateway.
    """
    routes = []
    i = 0
    while i < len(value):
        width = value[i]
        i += 1
        if width > 32:
            break
        octets = (width + 7) // 8
        dest = value[i:i + octets]
        i += octets
        gateway = value[i:i + 4]
        i += 4
        if len(dest) < octets or len(gateway) < 4:
            break
        dest = dest + b"\x00" * (4 - octets)
        routes.append(f"{socket.inet_ntoa(dest)}/{width} via {socket.inet_ntoa(gateway)}")
    return routes


def describe_dhcp_offer(data):
    """The parts of an OFFER that decide where this machine's traffic goes."""
    options = parse_dhcp_options(data)
    described = {
        "router": _addresses(options.get(3, b"")),
        "dns": _addresses(options.get(6, b"")),
        "static_routes": [],
    }
    for code in (121, 249):             # 249 is Microsoft's original of the same
        if code in options:
            described["static_routes"] = decode_classless_routes(options[code])
            break
    return described


def diff_dhcp_offer(old, new):
    """Compare two OFFERs. Any change here redirects traffic."""
    notes = []
    if not old:
        return notes
    for key, label in (("router", "gateway"), ("dns", "DNS servers")):
        if old.get(key) and new.get(key) and old[key] != new[key]:
            notes.append(f"DHCP is now handing out a different {label}: "
                         f"{old[key]} -> {new[key]}.")
    old_routes = set(old.get("static_routes", []))
    new_routes = set(new.get("static_routes", []))
    if new_routes - old_routes:
        notes.append(
            f"NEW DHCP static route(s): {sorted(new_routes - old_routes)}. A route "
            "pushed this way redirects a subnet without changing the default "
            "gateway, so nothing else about the network looks different.")
    return notes


def check_rogue_dhcp(timeout=4):
    """
    Send a DHCP (Dynamic Host Configuration Protocol) DISCOVER broadcast and
    collect all OFFER responses. More than one responder means a rogue DHCP
    server is present — a serious network security risk.
    Returns list of dicts: [{ip, mac, offered_ip}]
    """
    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68

    # Build a minimal DHCP DISCOVER packet. The source MAC only fills the chaddr
    # field (it doesn't affect responder counting), so extract one from ifconfig
    # defensively and fall back to a placeholder if it can't be parsed.
    xid = os.urandom(4)
    ether_m = re.search(r"ether\s+([0-9a-fA-F:]{17})", run(["ifconfig"]))
    try:
        mac_bytes = bytes.fromhex(ether_m.group(1).replace(":", "")) if ether_m \
            else b"\xaa\xbb\xcc\xdd\xee\xff"
    except ValueError:
        mac_bytes = b"\xaa\xbb\xcc\xdd\xee\xff"
    mac_bytes = mac_bytes[:6].ljust(6, b"\x00")

    packet = struct.pack(
        "!BBBBLHH4s4s4s4s16s64s128s",
        1,            # op: BOOTREQUEST
        1,            # htype: Ethernet
        6,            # hlen: MAC length
        0,            # hops
        struct.unpack("!L", xid)[0],  # xid
        0,            # secs
        0x8000,       # flags: broadcast
        b"\x00" * 4,  # ciaddr
        b"\x00" * 4,  # yiaddr
        b"\x00" * 4,  # siaddr
        b"\x00" * 4,  # giaddr
        mac_bytes + b"\x00" * 10,  # chaddr (padded to 16)
        b"\x00" * 64,  # sname
        b"\x00" * 128, # file
    )
    # DHCP magic cookie + options: DHCP Discover, end
    options = b"\x63\x82\x53\x63"  # magic cookie
    options += b"\x35\x01\x01"     # option 53: DHCP Discover
    options += b"\xff"             # end

    packet += options

    responders = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind(("", DHCP_CLIENT_PORT))
        sock.sendto(packet, ("255.255.255.255", DHCP_SERVER_PORT))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                # 4096, not 1024: a large OFFER was truncated mid-options, so
                # anything past the first kilobyte was invisible to the
                # poisoning check below while the OS client still applied it.
                data, addr = sock.recvfrom(4096)
                server_ip = addr[0]
                # Parse offered IP from yiaddr (bytes 16-20 of response)
                if len(data) >= 20:
                    offered_ip = socket.inet_ntoa(data[16:20])
                else:
                    offered_ip = "unknown"
                # Avoid duplicates
                if not any(r["ip"] == server_ip for r in responders):
                    responders.append({"ip": server_ip, "offered_ip": offered_ip,
                                       **describe_dhcp_offer(data)})
            except socket.timeout:
                break
            except OSError:
                break
    except OSError as e:
        # "try sudo" was wrong for the commonest cause. EHOSTUNREACH here is the
        # Local Network denial, not a permission this user can escalate to.
        if e.errno in UNREACHABLE_ERRNOS:
            return [], local_network_denied_note("The DHCP DISCOVER broadcast")
        if e.errno in (errno.EACCES, errno.EPERM):
            return [], (f"Could not bind to port 68, which needs privilege: {e}. "
                        "Re-run with sudo to include this check.")
        return [], f"Could not bind to port 68: {e}"
    finally:
        sock.close()

    return responders, None


def action_rogue_dhcp():
    hr("ROGUE DHCP DETECTOR")
    print("  Sending DHCP DISCOVER broadcast (waiting 4s for responses)...")
    responders, err = check_rogue_dhcp()
    if err:
        print(f"  [SKIP] {err}")
        return {"responders": [], "error": err}

    if not responders:
        print("  No DHCP responses received (normal if your router uses unicast).")
        return {"responders": []}

    print(f"  {len(responders)} DHCP server(s) responded:")
    for r in responders:
        print(f"    {r['ip']}  →  offered IP: {r['offered_ip']}")

    if len(responders) > 1:
        print("  [HIGH] Multiple DHCP servers detected! One may be a rogue server.")
        print("         A rogue DHCP server can redirect all your traffic. Investigate immediately.")
    else:
        print("  [OK] Only one DHCP server responded.")

    return {"responders": responders}


# ---------------------------------------------------------------------------
# NEW FEATURE 3: UPnP port mapping dump
# ---------------------------------------------------------------------------

def _upnp_url_points_at(url, gateway):
    """True if `url` is an http(s) URL whose host is exactly `gateway`.

    Both URLs this function guards are read out of a document a device on the
    LAN wrote. Unchecked, LOCATION could name any scheme urllib's default
    opener understands — file: and ftp: among them — and an absolute
    <controlURL> could aim a hundred SOAP POSTs at any host on the internet.
    Neither is a UPnP feature; both were reachable by answering one broadcast.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and parts.hostname == gateway


def get_upnp_port_mappings(gateway):
    """
    Discover the UPnP (Universal Plug and Play) control URL via SSDP
    (Simple Service Discovery Protocol), then query all port mappings.
    Returns (mappings_list, error_string).
    Each mapping: {ext_port, protocol, int_ip, int_port, description, enabled}
    """
    # Step 1: SSDP M-SEARCH to find the UPnP root device
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"
        "\r\n"
    )
    location = None
    ssdp_refused = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(msearch.encode(), (SSDP_ADDR, SSDP_PORT))
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                # The sender's address is the whole point of reading it. SSDP is
                # a broadcast question and anyone on the link may answer; taking
                # the first reply meant an attacker beat the router by design,
                # since MX: 2 tells a conforming device to wait before
                # responding. They then served a description document naming
                # themselves, and the audit reported *their* (empty) mapping
                # list as "the gateway's own list" while the real router quietly
                # forwarded a port. Only the gateway's answer counts.
                data, addr = sock.recvfrom(4096)
                if addr[0] != gateway:
                    continue
                text = data.decode("utf-8", "ignore")
                loc_m = re.search(r"(?i)LOCATION:\s*(\S+)", text)
                if loc_m:
                    location = loc_m.group(1).strip()
                    break
            except socket.timeout:
                break
    except OSError as e:
        # Whether SSDP left the machine at all decides which of two very
        # different things the silence means.
        ssdp_refused = e.errno in UNREACHABLE_ERRNOS
    finally:
        sock.close()

    if not location:
        if ssdp_refused:
            return [], local_network_denied_note("SSDP discovery")
        return [], "No UPnP device found via SSDP (router may have UPnP disabled)"

    if not _upnp_url_points_at(location, gateway):
        return [], (f"The UPnP reply from {gateway} pointed at {location}, which is "
                    "not an http(s) address on the gateway itself. Not followed, so "
                    "port mappings were not read.")

    # Step 2: Fetch the device description XML to find the control URL
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "home_net_audit"})
        with urllib.request.urlopen(req, timeout=5) as r:
            xml = r.read().decode("utf-8", "ignore")
    except Exception as e:
        return [], f"Could not fetch UPnP device description: {e}"

    # Extract base URL and control URL
    base_url_m = re.match(r"(https?://[^/]+)", location)
    base_url = base_url_m.group(1) if base_url_m else f"http://{gateway}"

    ctrl_m = re.search(r"<serviceType>urn:schemas-upnp-org:service:WANIPConnection[^<]*</serviceType>.*?<controlURL>([^<]+)</controlURL>", xml, re.DOTALL)
    if not ctrl_m:
        ctrl_m = re.search(r"<controlURL>([^<]+)</controlURL>", xml)
    if not ctrl_m:
        return [], "Could not find WANIPConnection control URL in UPnP description"

    ctrl_path = ctrl_m.group(1).strip()
    ctrl_url = ctrl_path if ctrl_path.startswith("http") else base_url + ctrl_path
    if not _upnp_url_points_at(ctrl_url, gateway):
        return [], (f"The UPnP description named a control URL at {ctrl_url}, which is "
                    "not on the gateway. Not followed, so port mappings were not read.")

    # Step 3: GetGenericPortMappingEntry in a loop
    mappings = []
    soap_tpl = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewPortMappingIndex>{index}</NewPortMappingIndex>
    </u:GetGenericPortMappingEntry>
  </s:Body>
</s:Envelope>"""

    for i in range(100):  # cap at 100 mappings
        body = soap_tpl.format(index=i).encode()
        req = urllib.request.Request(
            ctrl_url, data=body,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"',
                "User-Agent": "home_net_audit",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                resp = r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            if e.code in (500, 501):
                break  # no more entries
            break
        except Exception:
            break

        if "SpecifiedArrayIndexInvalid" in resp or "InvalidIndex" in resp:
            break

        def xtag(tag, text):
            m = re.search(fr"<[^>]*{tag}[^>]*>([^<]*)<", text, re.IGNORECASE)
            return m.group(1).strip() if m else ""

        mappings.append({
            "ext_port":    xtag("NewExternalPort", resp),
            "protocol":    xtag("NewProtocol", resp),
            "int_ip":      xtag("NewInternalClient", resp),
            "int_port":    xtag("NewInternalPort", resp),
            "description": xtag("NewPortMappingDescription", resp),
            "enabled":     xtag("NewEnabled", resp),
        })

    return mappings, None


def action_upnp_dump():
    hr("UPnP PORT MAPPING DUMP")
    gateway = get_default_gateway()
    if not gateway:
        print("  Could not determine gateway. Skipping UPnP check.")
        # "note", like every other early return here. This alone said "error",
        # which the report does not read, so a run that never sent an SSDP
        # packet rendered as "No UPnP port mappings found." — plus a provenance
        # row crediting the gateway for an answer it was never asked for.
        return {"mappings": [],
                "note": "UPnP was not queried: the gateway could not be determined."}

    print(f"  Querying UPnP on gateway {gateway} via SSDP...")
    mappings, err = get_upnp_port_mappings(gateway)

    if err:
        print(f"  [INFO] {err}")
        return {"mappings": [], "note": err}

    if not mappings:
        # "None found" and "none disclosed" are the same output here, and the
        # difference is the whole question. Every mapping in this list is one
        # the gateway chose to enumerate about itself; one that has forwarded a
        # port for an attacker simply leaves it out of the answer, and the tool
        # has no second source to check that against.
        print("  The gateway reported no active UPnP port mappings.")
        print("  That is its own account of its own forwarding table, so it is weak "
              "evidence:")
        print("  a router hiding a mapping omits it here and this check cannot tell. "
              "Ports")
        print("  reachable from outside are worth confirming from outside.")
        return {"mappings": []}

    print(f"  {len(mappings)} active UPnP port mapping(s):")
    print(f"  {'Ext.Port':<10} {'Proto':<6} {'→ Internal':<22} {'Description'}")
    print(f"  {'-'*8:<10} {'-'*5:<6} {'-'*20:<22} {'-'*20}")
    for m in mappings:
        internal = f"{m['int_ip']}:{m['int_port']}"
        enabled = "" if m["enabled"] in ("1", "true", "True") else " [DISABLED]"
        print(f"  {m['ext_port']:<10} {m['protocol']:<6} {internal:<22} {m['description']}{enabled}")

    print("\n  Note: Each mapping above is a hole punched through your router to an")
    print("  internal device. Review any you don't recognise — malware can add these.")
    return {"mappings": mappings}


# ---------------------------------------------------------------------------
# NEW FEATURE 4: ARP spoofing detector
# ---------------------------------------------------------------------------

def check_arp_spoofing(gateway, polls=5, interval=1.5):
    """
    Poll the ARP (Address Resolution Protocol) cache multiple times and check
    whether the gateway's MAC address changes between polls. A changing MAC is
    the classic sign of an ARP poisoning / man-in-the-middle attack.
    Returns dict: {gateway, macs_seen, spoofing_suspected}
    """
    macs_seen = set()
    print(f"  Polling ARP cache for gateway {gateway} ({polls}× every {interval}s)...")
    for i in range(polls):
        # Force a fresh ARP entry by pinging the gateway.
        #
        # Through ping(), not a bare subprocess.run. This was the only call site
        # in the file with neither a timeout nor a try/except, so on a Linux
        # observer with iproute2 but no iputils it raised FileNotFoundError
        # straight out of action_full_audit — taking roughly nine later checks,
        # the baseline save and the report with it. ping() also picks the
        # deadline flag that means "give up quickly" on the platform it is on;
        # -t is a TTL on Linux, so this loop was sending TTL-1 probes there.
        ping(gateway)
        arp = read_arp_table()
        mac = arp.get(gateway)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            macs_seen.add(mac)
        if i < polls - 1:
            time.sleep(interval)

    return {
        "gateway": gateway,
        "macs_seen": sorted(macs_seen),
        "spoofing_suspected": len(macs_seen) > 1,
    }


def action_arp_spoof_check():
    hr("ARP SPOOFING DETECTOR")
    gateway = get_default_gateway()
    if not gateway:
        print("  Could not determine gateway. Skipping.")
        return {}

    result = check_arp_spoofing(gateway)
    macs = result["macs_seen"]

    if not macs:
        print(f"  Could not resolve a MAC for gateway {gateway}.")
        print("  (This is normal if the gateway is not on the local subnet.)")
        return result

    print(f"  Gateway {gateway} MAC address(es) seen: {', '.join(macs)}")

    if result["spoofing_suspected"]:
        print("  [HIGH] Multiple MACs observed for the gateway!")
        print("         This strongly suggests an ARP poisoning / man-in-the-middle attack.")
        print("         Disconnect from the network and investigate immediately.")
    else:
        print(f"  [OK] MAC address stable across all polls: {macs[0]}")

    return result


# ---------------------------------------------------------------------------
# NEW FEATURE 5: Default credentials probe
# ---------------------------------------------------------------------------

class LockoutError(Exception):
    """Raised when the router signals rate-limiting / account lockout, so the
    credential probe can abort before locking the owner out of their own admin UI."""


# Response signals that the router is rate-limiting or has locked the account.
LOCKOUT_INDICATORS = [
    "too many", "try again later", "temporarily locked", "account locked",
    "locked out", "exceeded", "maximum number of", "login attempts",
    "rate limit", "please wait",
]


def probe_default_credentials(gateway):
    """
    Try common default username/password combinations against the router's
    HTTP admin page.

    Two mechanisms are tried per port:

    1. Basic Auth — only applicable if the server issues a 401 with a
       WWW-Authenticate: Basic challenge on an unauthenticated request.
       A credential pair is accepted only when:
         a) the authenticated response is NOT 401/403, AND
         b) the response body does NOT contain a login form (no <form>
            with a password field, no "login" / "sign in" heading).

    2. Form POST — POST common credential payloads to likely login endpoints.
       A login is considered successful only when ALL of:
         a) the response body contains at least one admin-session indicator
            (logout link, dashboard heading, known management keyword), AND
         b) the response body does NOT contain a login form indicator
            (input[type=password], "incorrect password", "invalid credentials",
            "login failed").

    Returns (successes, lockout_note, coverage), where successes is a list of
    (username, password, port, method) tuples.

    `coverage` records what the sweep actually managed to do, and exists because
    an empty `successes` had four different meanings collapsed into one. The
    router refused every guess; or no admin port answered; or ports answered but
    never presented a Basic Auth challenge or a login form, so nothing was ever
    submitted; or the OS refused to let this process reach the subnet at all.
    Only the first is a finding about the router's password. The other three are
    an absence of testing, and reporting them as a pass says the probe checked
    something it never touched.
    """
    import base64
    successes = []
    ports_to_try = [80, 8080, 8443, 443]
    # `attempts` counts credential submissions, not requests: a GET that finds
    # no login form is reconnaissance, and counting it would restore exactly the
    # ambiguity this dict exists to remove.
    #
    # `unanswered` counts requests that got no response at all, and `aborted`
    # holds the lockout note if the sweep stopped early. Both exist because
    # "attempts" alone let two different truncated sweeps render as the clean
    # verdict: one where the router started dropping connections (each drop was
    # counted as an attempt that was refused), and one where LockoutError ended
    # the sweep entirely (the note never crossed the function boundary, so the
    # HTML report called credential_coverage_verdict on a coverage dict with no
    # record that anything had gone wrong).
    coverage = {"attempts": 0, "open": [], "blocked": [], "closed": [],
                "unanswered": 0, "aborted": None}

    # Keywords that reliably indicate an authenticated admin session.
    AUTHED_INDICATORS = [
        "logout", "log out", "sign out", "signout",
        "dashboard", "overview",
        "firmware", "reboot", "factory reset",
        "wireless settings", "wifi settings", "wlan",
        "port forwarding", "nat", "upnp",
        "dhcp server", "lan settings",
        "administration", "system log",
        "connected devices", "attached devices",
    ]

    # Keywords that indicate we are still looking at a login page / error.
    LOGIN_INDICATORS = [
        'type="password"', "type='password'",
        'input.*password',       # will be used as regex below
        "incorrect password", "wrong password",
        "invalid password", "invalid credentials",
        "login failed", "authentication failed",
        "please log in", "please sign in",
        "enter your password", "enter password",
        "<form", "login form",
    ]

    def _body_is_authed(body):
        """Return True if body looks like a post-login admin page."""
        b = body.lower()
        has_admin_content = any(kw in b for kw in AUTHED_INDICATORS)
        # Check for login-form indicators (including regex for input[type=password])
        import re as _re
        has_login_form = (
            any(kw in b for kw in LOGIN_INDICATORS if "*" not in kw)
            or bool(_re.search(r'type\s*=\s*["\']?password', b))
        )
        return has_admin_content and not has_login_form

    def _fetch(url, headers=None, data=None, timeout=4):
        """Return (status_code, body_str) or (None, '') on error.

        Raises LockoutError if the server signals rate-limiting / account lock,
        so the caller can abort before locking the owner out of their router.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener = urllib.request.build_opener(handler)
            with opener.open(req, timeout=timeout) as r:
                code, body = r.getcode(), r.read(8192).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            try:
                code, body = e.code, e.read(8192).decode("utf-8", "ignore")
            except Exception:
                code, body = e.code, ""
        except Exception:
            # No response at all. The caller must not count this as a credential
            # that was submitted and refused — a router that silently drops
            # connections after N failures produces exactly this, and counting
            # it turned a defended router into "every one was refused".
            coverage["unanswered"] += 1
            return None, ""
        if code == 429 or any(k in body.lower() for k in LOCKOUT_INDICATORS):
            raise LockoutError(f"router signalled lockout/rate-limit (HTTP {code})")
        return code, body

    def try_basic_auth(base_url, user, pwd):
        """
        Only flag success if the server actually challenges with 401 first,
        then accepts the credentials AND the response body looks authenticated.
        """
        # Step 1: unauthenticated probe — does this endpoint use Basic Auth?
        code, _ = _fetch(base_url + "/")
        if code != 401:
            # Not a Basic Auth endpoint; skip (avoid false positives on open pages)
            return False

        # Step 2: send credentials
        creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        auth_code, body = _fetch(base_url + "/", headers={
            "Authorization": f"Basic {creds}",
            "User-Agent": "home_net_audit",
        })
        if auth_code is None:
            # Counted as unanswered by _fetch, not as a refusal.
            return False
        coverage["attempts"] += 1

        if auth_code in (401, 403):
            return False  # rejected

        # Step 3: verify the response body is an admin page, not a login form
        return _body_is_authed(body)

    # The (endpoint, payload) shapes that this router actually responds to,
    # learned once per base URL and reused for every later credential pair.
    #
    # Without it the sweep was 10 endpoints × 4 payloads × 16 credential pairs =
    # 640 POSTs per port, 2560 across four open ports, while the menu announced
    # "Testing 16 common credential pairs" — the number the user consented to.
    # The 0.05s sleeps paced only the outer loop, so 40 POSTs per pair went
    # back to back. A router that locks silently, with no 429 and no lockout
    # phrase in the body, is not caught by LockoutError at all, so the volume
    # itself was the hazard.
    login_shapes = {}

    def try_form_login(base_url, user, pwd):
        """
        POST credentials to common login endpoints and check the response
        body for authenticated-session indicators.
        """
        endpoints = [
            "/",
            "/login",
            "/login.html",
            "/login.asp",
            "/login.cgi",
            "/admin",
            "/admin/login",
            "/cgi-bin/luci",
            "/index.asp",
            "/userRpm/LoginRpm.htm",
        ]
        payloads = [
            f"username={urllib.parse.quote(user)}&password={urllib.parse.quote(pwd)}",
            f"user={urllib.parse.quote(user)}&pass={urllib.parse.quote(pwd)}",
            f"UserName={urllib.parse.quote(user)}&Passwd={urllib.parse.quote(pwd)}&Action=1",
            f"uname={urllib.parse.quote(user)}&upasswd={urllib.parse.quote(pwd)}",
        ]
        def _post(ep, pl):
            post_code, body = _fetch(
                base_url + ep,
                data=pl.encode(),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "home_net_audit",
                    "Referer": base_url + ep,
                },
            )
            if post_code is None:
                return None
            coverage["attempts"] += 1
            # Inside the payload loop, not only around the outer one. The old
            # placement let forty POSTs per credential pair go back to back.
            time.sleep(0.05)
            return _body_is_authed(body)

        known = login_shapes.get(base_url)
        if known is not None:
            for ep, pl_index in known:
                if pl_index < len(payloads) and _post(ep, payloads[pl_index]):
                    return True
            return False

        # First credential pair only: find which endpoints look like a login and
        # which payload shapes this router answers, then remember a handful.
        candidates = []
        for ep in endpoints:
            get_code, get_body = _fetch(base_url + ep)
            if get_code is None:
                continue
            get_lower = get_body.lower()
            import re as _re
            has_form = ("<form" in get_lower and
                        bool(_re.search(r'type\s*=\s*["\']?password', get_lower)))
            # Only POST to pages that actually have a login form (avoids noise)
            if not has_form and get_code not in (200,):
                continue
            candidates.append((0 if has_form else 1, ep))

        # A router that answers 200 for unknown paths makes every endpoint a
        # candidate, which is where the fan-out came from. Endpoints carrying an
        # actual password field are tried first, and the list is capped: past
        # the first few, an endpoint is being POSTed on no evidence at all, and
        # the cost of that is real login attempts against the user's router.
        candidates.sort()
        candidates = [ep for _rank, ep in candidates[:MAX_LOGIN_ENDPOINTS]]

        discovered = []
        for ep in candidates:
            for index, pl in enumerate(payloads):
                answered = _post(ep, pl)
                if answered is None:
                    continue
                # The server processed this shape, so it is worth repeating for
                # the remaining credential pairs. Anything else is not.
                discovered.append((ep, index))
                if answered:
                    login_shapes[base_url] = discovered[:MAX_LOGIN_SHAPES]
                    return True
        login_shapes[base_url] = discovered[:MAX_LOGIN_SHAPES]
        return False

    lockout_note = None
    try:
        for port in ports_to_try:
            scheme = "https" if port in (443, 8443) else "http"
            base = f"{scheme}://{gateway}:{port}"
            # probe_port rather than check_port: the boolean collapses "the OS
            # refused to let me ask" into "nothing is listening", which is the
            # exact collapse that let a blocked scheduled run report a clean
            # bill of health for ports it never reached. Same mistake, same
            # cost, one function along.
            reachable = probe_port(gateway, port, timeout=1.0)
            if reachable is None:
                coverage["blocked"].append(port)
                continue
            if reachable is False:
                coverage["closed"].append(port)
                continue
            coverage["open"].append(port)

            found = False
            for user, pwd in DEFAULT_CREDS:
                if try_basic_auth(base, user, pwd):
                    successes.append((user, pwd, port, "Basic Auth"))
                    found = True
                    break
                time.sleep(0.05)

            if not found:
                for user, pwd in DEFAULT_CREDS:
                    if try_form_login(base, user, pwd):
                        successes.append((user, pwd, port, "Form POST"))
                        break
                    time.sleep(0.05)
    except LockoutError as e:
        lockout_note = str(e)
        # Recorded inside `coverage`, not only returned alongside it.
        #
        # action_default_creds returns {gateway, successes, coverage} and drops
        # lockout_note on the floor, so the HTML report — which calls
        # credential_coverage_verdict(dc["coverage"]) unconditionally — had no
        # way to know the sweep had stopped early. Its first live branch is
        # `if attempts:`, so a router that started rate-limiting after eight
        # guesses rendered a green "8 credential pair(s) submitted … and every
        # one was refused", and the sealed baseline kept saying it.
        coverage["aborted"] = lockout_note

    return successes, lockout_note, coverage


def credential_coverage_verdict(coverage):
    """(risk, message) for a sweep that accepted nothing.

    "No default credentials accepted (or admin page not reachable)." was one
    line for four outcomes, and the parenthetical is the tell: it names the
    ambiguity and then badges the result OK anyway. Three of the four are an
    absence of testing, and the reader of a security report is entitled to know
    the probe never reached the thing it is reassuring them about.

    Only a sweep that actually submitted credentials and had them refused is a
    finding about the router's password, and only that one is OK.

    One decision, returned rather than printed, because the terminal and the
    HTML export both render it. The HTML copy had drifted further than the
    terminal — it dropped even the parenthetical and stated a flat "No default
    credentials accepted", in the artefact most likely to be read by someone who
    did not run the probe.
    """
    if not coverage:
        # A record written before coverage was tracked. What the sweep reached
        # is genuinely unknown, and substituting any of the four verdicts below
        # would invent a detail — including the "nothing answered" one, which
        # reads as a fact about the router.
        return "INFO", ("No default credentials were accepted, but this record does "
                        "not say what the probe managed to reach, so whether any "
                        "credential was actually submitted is unknown. Re-run the "
                        "probe for a verdict that distinguishes the two.")

    attempts = coverage.get("attempts") or 0
    open_ports = coverage.get("open") or []
    blocked = coverage.get("blocked") or []
    aborted = coverage.get("aborted")
    unanswered = coverage.get("unanswered") or 0

    # Checked before `attempts`, because a truncated sweep is not a verdict
    # about the password: most of DEFAULT_CREDS was never tried, and the
    # account may now be locked. This is the branch the terminal reached via
    # `elif not lockout_note` and the HTML report never reached at all.
    if aborted:
        return "REVIEW", (f"The sweep stopped early: {aborted}. "
                          f"{attempts} credential pair(s) had been submitted and "
                          "refused before that, but the rest were never tried, so "
                          "this says nothing about whether the router's password is "
                          "a default. Check whether the admin account is now locked.")

    if unanswered and not attempts:
        return "REVIEW", (f"{unanswered} request(s) to the admin port(s) got no "
                          "response at all, and no credential was ever submitted. A "
                          "router that drops connections after repeated failures "
                          "looks exactly like this, so nothing here is a finding "
                          "about the password.")

    if attempts:
        where = ", ".join(str(p) for p in open_ports) or "the admin ports"
        return "OK", (f"{attempts} credential pair(s) submitted on port(s) {where} "
                      "and every one was refused.")

    if blocked:
        return "REVIEW", ("No credentials were tested. "
                          + local_network_denied_note("The default-credentials probe"))

    if open_ports:
        where = ", ".join(str(p) for p in open_ports)
        return "INFO", (f"Port(s) {where} answered but never presented a Basic Auth "
                        "challenge or a login form, so no credentials were submitted. "
                        "This is not a finding that the password is strong — nothing "
                        "was guessed at. The admin UI may use a login this probe "
                        "cannot drive.")

    return "INFO", ("No admin service answered on ports 80, 8080, 8443 or 443, so no "
                    "credentials were tested. Nothing here says the router's password "
                    "is good; it says the probe found nothing to try it against. An "
                    "admin UI on another port would be missed entirely.")


def describe_credential_coverage(coverage):
    """The terminal line for credential_coverage_verdict."""
    risk, message = credential_coverage_verdict(coverage)
    return f"  [{risk:6}] {message}"


def action_default_creds():
    hr("DEFAULT CREDENTIALS PROBE")
    gateway = get_default_gateway()
    if not gateway:
        print("  Could not determine gateway. Skipping.")
        return {}

    print(f"  Testing {len(DEFAULT_CREDS)} common credential pairs on {gateway}...")
    print("  NOTE: this sends real login attempts to your router — it is NOT")
    print("  read-only and can trip lockout/rate-limit protection. It aborts")
    print("  automatically if the router signals a lockout.")
    # Say what the sweep can actually cost, not just how many pairs it holds.
    # A form login is tried across several endpoint and payload shapes, so the
    # first credential pair explores; the rest reuse whatever answered.
    print("  Each pair may take several requests while the login shape is being")
    print("  found; after the first pair only the shape that answered is reused.")
    successes, lockout_note, coverage = probe_default_credentials(gateway)

    if lockout_note:
        print(f"\n  [STOPPED] {lockout_note}")
        print("            Aborted early to avoid locking you out of your router.")

    if successes:
        print(f"\n  [HIGH] Default credentials ACCEPTED on gateway {gateway}:")
        for user, pwd, port, method in successes:
            display_pwd = pwd if pwd else "(empty)"
            print(f"    Port {port} ({method}): {user} / {display_pwd}")
        print("\n  Change your router admin password immediately!")
    else:
        # Printed even after a lockout. The verdict now knows about the abort —
        # coverage["aborted"] carries it — so this is the line that says the
        # sweep was truncated rather than clean, which is exactly what the
        # reader needs and what `elif not lockout_note` used to withhold.
        print(describe_credential_coverage(coverage))

    return {"gateway": gateway, "successes": successes, "coverage": coverage}


# ---------------------------------------------------------------------------
# NEW FEATURE 6: Router hostname check
# ---------------------------------------------------------------------------

def check_router_hostname(gateway, resolvers=None):
    """
    Perform a reverse DNS lookup on the gateway IP.
    An unexpected or suspicious hostname may indicate a rogue router.
    Returns dict: {gateway, hostname, suspicious, self_attested}

    The lookup goes through whatever resolver this machine is configured to
    use, and on a home network that is normally the gateway itself — which is
    the device this check exists to be suspicious of. When that is the case the
    answer is the router's statement about its own identity, and a rogue one
    answers it exactly as an honest one would: with something unremarkable, or
    with nothing at all. The nothing-at-all path is the most likely output on a
    real home network, and it used to print as a passed check.

    So `self_attested` records who answered. It does not make the finding
    wrong — a cloud-provider PTR is still worth seeing — but it decides whether
    a clean result may be reported as OK, in the same way and for the same
    reason that an unkeyed seal verifies without being called forgery-proof.

    `resolvers` is passed in rather than read here so this stays a pure
    function of what it is given; callers that do not supply it get
    self_attested None, meaning "not established" rather than "no".
    """
    try:
        hostname = socket.gethostbyaddr(gateway)[0]
    except socket.herror:
        hostname = None
    except Exception:
        hostname = None

    self_attested = None if resolvers is None else (gateway in resolvers)
    suspicious = False
    note = ""
    if not hostname:
        note = "No reverse DNS entry. Normal for most home routers."
    else:
        # Flag if the hostname looks like a public/cloud service or unusual TLD
        suspicious_patterns = [
            r"amazonaws\.com", r"googleusercontent\.com", r"azure\.com",
            r"cloudflare\.com", r"digitalocean\.com", r"linode\.com",
            r"vultr\.com", r"ovh\.com", r"hetzner\.com",
        ]
        for pat in suspicious_patterns:
            if re.search(pat, hostname, re.IGNORECASE):
                suspicious = True
                note = f"Hostname matches a cloud provider ({pat}). Investigate — this may not be your router."
                break
        if not suspicious:
            note = "Hostname looks normal for a home router."

    return {"gateway": gateway, "hostname": hostname, "suspicious": suspicious,
            "note": note, "self_attested": self_attested}


def action_router_hostname():
    hr("ROUTER HOSTNAME CHECK")
    gateway = get_default_gateway()
    if not gateway:
        print("  Could not determine gateway.")
        return {}

    resolvers = get_dns_servers()
    result = check_router_hostname(gateway, resolvers)
    print(f"  Gateway IP : {result['gateway']}")
    print(f"  Hostname   : {result['hostname'] or '(none)'}")

    if result["suspicious"]:
        # Still worth reporting at full volume. A router that names a cloud
        # provider has said something against its own interest, and evidence
        # from a witness with a motive to lie is strongest when it incriminates.
        print(f"  [HIGH] {result['note']}")
    elif result["self_attested"]:
        # Not OK. The gateway resolved the question about the gateway, so a
        # rogue one produces this exact output, and printing OK would certify a
        # check that cannot fail closed.
        print(f"  [INFO] {result['note']}")
        print("         This answer came from the gateway itself — it is one of this "
              "machine's")
        print("         resolvers, so it was asked to vouch for its own identity. A "
              "rogue router")
        print("         answers this the same way yours just did. Not a passed check.")
    else:
        print(f"  [OK] {result['note']}")
    return result


# ---------------------------------------------------------------------------
# NEW FEATURE 7: Listening services audit
# ---------------------------------------------------------------------------

def check_listening_services():
    """
    Use netstat to find all processes on this Mac that are accepting inbound
    TCP/UDP connections. Helps spot unexpected listeners (malware, forgotten
    servers, etc.).
    Returns list of dicts: {proto, local_addr, port, pid, process}
    """
    listeners = {}

    def _add_from_lsof(lsof_out, proto):
        # lsof's NAME column puts ':' before the port for the *:p, ipv4:p AND
        # bracketed [ipv6]:p forms, so a trailing ':<port>' match covers all
        # three (the old IPv4-only regex silently dropped IPv6 listeners).
        for line in lsof_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            addr_field = parts[8]
            if "->" in addr_field:
                continue  # established connection, not a listener
            m = re.search(r":(\d+)$", addr_field)
            if not m:
                continue
            key = (proto, int(m.group(1)))
            if key not in listeners:
                listeners[key] = {"proto": proto, "port": int(m.group(1)),
                                  "pid": parts[1], "process": parts[0]}

    # lsof gives process names for TCP listeners AND UDP-bound sockets
    # (netstat alone can't supply process names on macOS).
    _add_from_lsof(run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=10), "TCP")
    _add_from_lsof(run(["lsof", "-nP", "-iUDP"], timeout=10), "UDP")

    # netstat fills any (proto, port) lsof missed; process stays unknown there.
    out = run(["netstat", "-anp", "tcp"], timeout=10) + run(["netstat", "-anp", "udp"], timeout=10)
    for line in out.splitlines():
        if "LISTEN" in line or line.startswith("udp"):
            parts = line.split()
            if len(parts) < 4:
                continue
            # TCP rows are already filtered by the LISTEN state above. UDP has
            # no state column, so a socket this Mac dialled OUT on looks exactly
            # like one waiting for callers unless the foreign address is read:
            # a listener has the wildcard "*.*", a connected socket names its
            # peer. _add_from_lsof has always made this distinction ("->" in the
            # address); netstat spells the same thing differently, and skipping
            # it here re-added the ephemeral source port of an ordinary outbound
            # request as an unrecognised listener with pid and process "?" —
            # noise that pushes a real finding off the end of the list.
            #
            # Only a positively identified peer suppresses the row. A short or
            # unexpected line keeps its entry: failing towards reporting is the
            # right direction for a listener audit.
            if line.startswith("udp") and len(parts) >= 5 and parts[4] not in ("*.*", "*:*"):
                continue
            proto = parts[0].upper().replace("6", "").replace("4", "")
            # macOS netstat uses a DOT before the port (e.g. "*.59882").
            m = re.search(r"[.:](\d+)$", parts[3])
            if m:
                key = (proto, int(m.group(1)))
                if key not in listeners:
                    listeners[key] = {"proto": proto, "port": int(m.group(1)),
                                      "pid": "?", "process": "?"}

    return sorted(listeners.values(), key=lambda x: x["port"])


UNNAMED_PROCESS = "?"


def classify_listeners(services, system_ports):
    """Split listeners into the three groups a reader must treat differently.

    Returns {"system", "named", "unattributed"}.

    A listener on a well-known system port is background. Of the rest, one with
    a process name is something the reader can actually recognise or not. One
    without a name is not a finding yet: lsof reports only processes owned by
    the invoking user, so anything belonging to root or another account arrives
    from netstat with nothing attached. On this machine that is most of them —
    four rows named against twenty-one netstat sees.

    Keeping them apart matters because the two groups need opposite advice.
    "Verify you recognise them" is impossible for a bare port number, and
    printing it under twenty unnameable rows buries the two entries that could
    genuinely have been checked. Unlike the Local Network denials elsewhere in
    this tool, sudo really does fix this one, so it is worth saying.
    """
    system, named, unattributed = [], [], []
    for s in services:
        port = s.get("port")
        if not isinstance(port, int) or port < 1024 or port in system_ports:
            system.append(s)
        elif str(s.get("process") or "").strip() in ("", UNNAMED_PROCESS):
            unattributed.append(s)
        else:
            named.append(s)
    return {"system": system, "named": named, "unattributed": unattributed}


def action_listening_services():
    hr("LISTENING SERVICES AUDIT")
    print("  Checking what processes on this Mac accept inbound connections...")
    services = check_listening_services()

    # Well-known safe system ports to de-noise the output
    SYSTEM_PORTS = {
        53: "mDNS/DNS", 137: "NetBIOS", 138: "NetBIOS",
        5353: "mDNS", 5354: "mDNS proxy", 631: "CUPS printing",
    }

    if not services:
        print("  Could not enumerate listening services (try running with sudo).")
        return []

    groups = classify_listeners(services, SYSTEM_PORTS)
    unattributed = groups["unattributed"]
    named = groups["named"]

    print(f"\n  {'Port':<7} {'Proto':<6} {'Process':<22} Note")
    print(f"  {'-'*5:<7} {'-'*5:<6} {'-'*20:<22} {'-'*30}")
    for s in services:
        port = s["port"]
        note = SYSTEM_PORTS.get(port, "")
        marker = "* " if s in named or s in unattributed else "  "
        print(f"{marker} {port:<7} {s['proto']:<6} {s['process']:<22} {note}")

    if named:
        print(f"\n  * {len(named)} non-system listener(s) named above. "
              "Verify you recognise them.")
    if unattributed:
        # Deliberately not lumped in with the line above. A port number on its
        # own is not something anyone can recognise, and the remedy here is real
        # — unlike the Local Network denials elsewhere in this tool, sudo does
        # supply these names.
        ports = ", ".join(str(s["port"]) for s in unattributed[:8])
        more = f" (+{len(unattributed) - 8} more)" if len(unattributed) > 8 else ""
        print(f"\n  * {len(unattributed)} listener(s) could not be attributed to a "
              "process: lsof reports only\n    processes owned by you, so these belong "
              "to root or another account. Re-run\n    with sudo to name them before "
              "judging whether they belong here.")
        print(f"    Ports: {ports}{more}")
    if not named and not unattributed:
        print("\n  No unexpected listeners found.")

    return services


# ---------------------------------------------------------------------------
# NEW FEATURE 8: Sharing services check
# ---------------------------------------------------------------------------

def _launchd_running(label):
    """Return True if the launchd label is loaded AND running, False if it is
    absent (not loaded into the system domain), or None on error.

    Uses `launchctl print system/<label>` (works unprivileged on current macOS,
    unlike `launchctl list <label>` which fails for system-domain daemons). The
    value after 'state =' is compared exactly so 'state = not running' is never
    misread as running.
    """
    try:
        p = subprocess.run(["launchctl", "print", "system/" + label],
                           capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if p.returncode != 0:
        return False  # label not loaded → service off
    for line in p.stdout.splitlines():
        s = line.strip()
        if s.startswith("state ="):
            return s.split("=", 1)[1].strip() == "running"
    return False


def check_sharing_services():
    """
    Query macOS for enabled sharing services — each is an inbound attack
    surface. Returns a list of dicts: name, enabled (True/False/None=unknown),
    risk, note.

    `systemsetup -get*` needs admin and otherwise prints an admin-access message
    with exit 0; we string-match it and report UNKNOWN rather than a false OFF.
    smbd is launch-on-demand, so its authoritative on/off comes from
    `launchctl print-disabled system`, corroborated by a live listener probe.
    """
    services = []

    # Remote Login (SSH): launchd state OR a live listener on 22.
    ssh_on = bool(_launchd_running("com.openssh.sshd")) or check_port("127.0.0.1", 22, timeout=0.4)
    services.append({
        "name": "Remote Login (SSH)",
        "enabled": ssh_on,
        "risk": "REVIEW" if ssh_on else "OK",
        "note": "SSH enabled — fine if intentional; disable if not needed." if ssh_on else "Disabled.",
    })

    # Screen Sharing / VNC: launchd state OR a live listener on 5900.
    ss_on = bool(_launchd_running("com.apple.screensharing")) or check_port("127.0.0.1", 5900, timeout=0.4)
    services.append({
        "name": "Screen Sharing / VNC",
        "enabled": ss_on,
        "risk": "HIGH" if ss_on else "OK",
        "note": "Screen visible to anyone with credentials; use only if needed." if ss_on else "Disabled.",
    })

    # File Sharing (SMB): authoritative config flag, OR live state/listener.
    smb_cfg = None
    try:
        p = subprocess.run(["launchctl", "print-disabled", "system"],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r'"com\.apple\.smbd"\s*=>\s*(\w+)', p.stdout)
        if m:
            # This is the dict of DISABLED services, so the value answers "is it
            # disabled?", not "is it on?". Two dialects appear across macOS
            # versions and only an explicit map reads both:
            #
            #   "=> true"      listed as disabled      -> SMB off
            #   "=> disabled"  listed as disabled      -> SMB off
            #   "=> enabled"   listed as NOT disabled  -> SMB on
            #   "=> false"     listed as NOT disabled  -> SMB on
            #
            # `== "enabled"` got three of the four right and read "=> false" —
            # the one token that means sharing is ON — as off. That is the
            # dangerous direction to be wrong in: smbd is launch-on-demand, so a
            # Mac that is genuinely sharing files sits with "state = not
            # running" and port 445 closed, and neither live probe can see it.
            # The config flag is the only signal that can tell the truth, and it
            # printed a confident "Disabled." over a real exposure.
            #
            # Anything outside these four tokens leaves smb_cfg as None so the
            # live probes decide, rather than a guess dressed as a measurement.
            token = m.group(1).lower()
            if token in ("enabled", "false"):
                smb_cfg = True
            elif token in ("disabled", "true"):
                smb_cfg = False
    except (subprocess.TimeoutExpired, OSError):
        pass
    smb_on = bool(smb_cfg) or (_launchd_running("com.apple.smbd") is True) \
        or check_port("127.0.0.1", 445, timeout=0.4)
    services.append({
        "name": "File Sharing (SMB)",
        "enabled": smb_on,
        "risk": "REVIEW" if smb_on else "OK",
        "note": "File shares visible on the network." if smb_on else "Disabled.",
    })

    # Remote Apple Events: only determinable with root. Report UNKNOWN (never a
    # false OFF) when the admin-access message comes back (note: exit code is 0).
    rae_out = (run(["systemsetup", "-getremoteappleevents"], timeout=5) or "").lower()
    if "you need administrator access" in rae_out or not rae_out.strip():
        services.append({
            "name": "Remote Apple Events",
            "enabled": None,
            "risk": "UNKNOWN",
            "note": "Unknown — re-run this audit with sudo to determine its state.",
        })
    elif "remote apple events: on" in rae_out:
        services.append({
            "name": "Remote Apple Events",
            "enabled": True,
            "risk": "REVIEW",
            "note": "Allows remote AppleScript control.",
        })
    else:
        services.append({
            "name": "Remote Apple Events",
            "enabled": False,
            "risk": "OK",
            "note": "Disabled.",
        })

    # mDNS / Bonjour: always on; informational.
    services.append({
        "name": "mDNS / Bonjour",
        "enabled": True,
        "risk": "INFO",
        "note": "Always on; advertises this Mac's services to the local network.",
    })

    return services


def action_sharing_services():
    hr("SHARING SERVICES CHECK")
    print("  Checking macOS sharing services (run with sudo for full detail)...")
    services = check_sharing_services()

    for s in services:
        state = "?  " if s["enabled"] is None else ("ON " if s["enabled"] else "OFF")
        print(f"  [{s['risk']:7}] {state}  {s['name']:<22} {s['note']}")

    enabled = [s for s in services if s["enabled"] and s["risk"] not in ("INFO", "OK")]
    if enabled:
        print(f"\n  {len(enabled)} sharing service(s) active. Disable any you don't need.")

    return services


# ---------------------------------------------------------------------------
# NEW FEATURE 9: Firewall status
# ---------------------------------------------------------------------------

def check_firewall():
    """
    Check the macOS application firewall state using socketfilterfw.
    Returns dict: {enabled, stealth_mode, block_all, note}
    """
    fw_cmd = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    result = {"enabled": None, "stealth_mode": None, "block_all": None, "note": ""}

    global_out = run([fw_cmd, "--getglobalstate"], timeout=5)
    stealth_out = run([fw_cmd, "--getstealthmode"], timeout=5)
    blockall_out = run([fw_cmd, "--getblockall"], timeout=5)

    # Global state: parse the documented "(State = N)" integer. 1 = on (allow
    # signed apps), 2 = on (block-all); 0 = off. The old "enabled" substring
    # rule was brittle; the integer is the stable signal. None = unknown.
    m = re.search(r"State\s*=\s*(\d+)", global_out)
    result["enabled"] = (int(m.group(1)) >= 1) if m else None

    # Stealth mode reports "...stealth mode is on/off" — note there is NO
    # "enabled" token, which is why the old `"enabled" in out` rule always
    # reported stealth OFF even when it was on.
    sl = stealth_out.lower()
    if "is on" in sl or "enabled" in sl:
        result["stealth_mode"] = True
    elif "is off" in sl or "disabled" in sl:
        result["stealth_mode"] = False
    else:
        result["stealth_mode"] = None

    # Block-all reports "...block all state set to enabled/disabled." Test for
    # "disabled" FIRST so a loose "enabled" match can't misfire.
    bl = blockall_out.lower()
    if "disabled" in bl:
        result["block_all"] = False
    elif "enabled" in bl or "block all is on" in bl:
        result["block_all"] = True
    else:
        result["block_all"] = None

    if result["enabled"] is None:
        result["note"] = "Could not determine firewall state (unexpected command output)."
    elif not result["enabled"]:
        result["note"] = "Firewall is OFF. Enable it in System Settings → Network → Firewall."
    elif result["block_all"] is True:
        result["note"] = "Block all mode — maximum restriction. Verify legitimate apps still work."
    elif result["stealth_mode"] is True:
        result["note"] = "Enabled with stealth mode — good configuration."
    elif result["stealth_mode"] is False:
        result["note"] = "Enabled (stealth mode off). Consider enabling stealth mode for extra protection."
    else:
        # stealth_mode is None: --getstealthmode output was unparseable. Saying
        # "stealth mode off" here would state an unmeasured value as fact, and
        # this note is not terminal-only — generate_html_report copies it
        # verbatim into the shareable report.
        result["note"] = ("Enabled. Stealth mode state could not be determined "
                          "(unexpected --getstealthmode output).")

    return result


def action_firewall_check():
    hr("FIREWALL STATUS")
    fw = check_firewall()

    def onoff(v):
        return "UNKNOWN" if v is None else ("ON" if v else "OFF")

    risk = "REVIEW" if fw["enabled"] is None else ("OK" if fw["enabled"] else "HIGH")
    print(f"  [{risk:6}] Application Firewall : {onoff(fw['enabled'])}")
    print(f"            Stealth Mode         : {onoff(fw['stealth_mode'])}")
    print(f"            Block All            : {onoff(fw['block_all'])}")
    print(f"            Note                 : {fw['note']}")
    return fw


# ---------------------------------------------------------------------------
# NEW FEATURE 10: HTML report export
# ---------------------------------------------------------------------------

# Every state key generate_html_report knows how to render. Keys carrying a risk
# rating that are absent from this set are reported as missing rather than
# dropped — see the end of generate_html_report.
RENDERED_STATE_KEYS = frozenset({
    "timestamp", "gateway", "router_open_ports", "upstream_open_ports", "dns",
    "devices", "scanned_subnets", "wifi", "wifi_bssids", "arp_spoof", "firewall",
    "sharing", "default_creds", "speed_download_mbps", "speed_upload_mbps",
    "upnp", "dhcp", "listening", "router_hostname", "evil_twin", "ipv6",
    "ipv6_routers", "interception", "router_tls", "dsl",
    # Bookkeeping written by carry_forward_unmeasured, not findings.
    "carried_forward", "measured_at",
})


def _carries_risk(value):
    """Whether a state value is (or contains) something with a risk rating."""
    if isinstance(value, dict):
        return "risk" in value or any(_carries_risk(v) for v in value.values())
    if isinstance(value, list):
        return any(_carries_risk(v) for v in value)
    return False


class _SafeHTML(str):
    """A string already known to be safe HTML — _esc() passes it through unchanged."""


def _esc(value):
    """HTML-escape any value for safe interpolation; _SafeHTML passes through.

    Untrusted strings reach the report from third parties (macvendors.com vendor
    names, a broadcast Wi-Fi SSID, reverse-DNS hostnames, UPnP descriptions). Any
    of these could contain '<', '>' or quotes and inject markup into the report,
    which runs when the file is opened in a browser. Escape everything here.
    """
    if isinstance(value, _SafeHTML):
        return value
    return html.escape(str(value), quote=True)


def generate_html_report(state, output_path=None):
    """
    Generate a self-contained, colour-coded HTML report from the audit state.
    Returns the path of the saved file.
    """
    if output_path is None:
        # Write reports OUTSIDE the git repo (into the gitignored data dir) so a
        # report containing MACs, topology and accepted credentials can't be
        # accidentally committed.
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(BASELINE_DIR, "reports", f"audit_report_{ts}.html")

    RISK_COLOUR = {
        "HIGH":   "#e74c3c",
        "MEDIUM": "#e67e22",
        "REVIEW": "#f39c12",
        "INFO":   "#3498db",
        "OK":     "#27ae60",
        "GOOD":   "#27ae60",
        "UNKNOWN":"#95a5a6",
    }

    def onoff(value):
        """Render a tri-state as the terminal does: None is UNKNOWN, not OFF.

        check_firewall and check_sharing_services both return None for a state
        they could not determine — an unparseable socketfilterfw reply, or
        Remote Apple Events without sudo. Collapsing that to "OFF" tells the
        reader a service is definitely disabled when the audit never found out,
        and this report is the artefact most likely to be forwarded to someone
        else. action_firewall_check and action_sharing_services have always got
        this right; this keeps the written report agreeing with the terminal.
        """
        return "UNKNOWN" if value is None else ("ON" if value else "OFF")

    def risk_badge(risk):
        colour = RISK_COLOUR.get(str(risk).upper(), "#95a5a6")
        return _SafeHTML(
            f'<span style="background:{colour};color:white;padding:2px 8px;'
            f'border-radius:3px;font-size:0.85em;font-weight:bold">'
            f'{html.escape(str(risk))}</span>')

    def section(title, body_html):
        return f"""
        <div class="section">
          <h2>{title}</h2>
          {body_html}
        </div>"""

    def table(headers, rows, row_colours=None):
        th = "".join(f"<th>{_esc(h)}</th>" for h in headers)
        tbody = ""
        for i, row in enumerate(rows):
            colour = (row_colours[i] if row_colours and i < len(row_colours) else "")
            bg = f' style="background:{colour}22"' if colour else ""
            td = "".join(f"<td>{_esc(cell)}</td>" for cell in row)
            tbody += f"<tr{bg}>{td}</tr>"
        return f"<table><thead><tr>{th}</tr></thead><tbody>{tbody}</tbody></table>"

    sections_html = ""
    ts_str = state.get("timestamp", datetime.now(timezone.utc).isoformat())

    # Gateway
    if "gateway" in state:
        sections_html += section("Gateway", f"<p>Default gateway: <strong>{_esc(state['gateway'])}</strong></p>")

    # Open ports
    if "router_open_ports" in state:
        ports = state["router_open_ports"]
        if ports:
            rows = []
            colours = []
            for p in ports:
                svc, risk, note = PORTS_OF_INTEREST.get(p, ("unknown", "REVIEW", "Investigate."))
                rows.append([str(p), svc, risk_badge(risk), note])
                colours.append(RISK_COLOUR.get(risk, ""))
            body = table(["Port", "Service", "Risk", "Note"], rows, colours)
        elif ports is None:
            # Distinct from the empty list below: the scan never reached the
            # host, so reporting "no open ports found" would be a false all-clear
            # in the one artefact most likely to be read by someone else.
            body = ("<p>{} Could not reach the router to scan it, so its open "
                    "ports are <strong>unknown</strong> for this run — this is "
                    "not a finding of &quot;no open ports&quot;.</p>").format(
                        risk_badge("REVIEW"))
        else:
            body = "<p>No open ports found.</p>"
        sections_html += section("Router Open Ports", body)

    # DNS
    if "dns" in state:
        dns_rows = []
        for d in state["dns"]:
            label = KNOWN_DNS.get(d, "")
            dns_rows.append([d, label or "—"])
        sections_html += section("DNS Settings", table(["Server", "Known Provider"], dns_rows))

    # Devices
    if "devices" in state:
        dev_rows = [[d["ip"], d["mac"], d.get("vendor", ""), d.get("subnet", "")]
                    for d in state["devices"]]
        sections_html += section("Connected Devices",
            table(["IP", "MAC", "Vendor", "Subnet"], dev_rows))

    # Wi-Fi
    if "wifi" in state:
        w = state["wifi"]
        colour = RISK_COLOUR.get(w.get("risk", ""), "")
        # `or`, not a dict default: check_wifi_security always sets both keys, so
        # the '?' fallback was dead and an unreadable mode rendered as
        # "Auth: None" — which is the literal string macOS prints for an OPEN
        # network, and which this module's own parser treats as exactly that.
        body = f"""<table><tbody>
          <tr><td><strong>SSID</strong></td><td>{_esc(w.get('ssid') or 'unknown')}</td></tr>
          <tr><td><strong>Auth</strong></td><td>{_esc(w.get('auth') or 'unknown (could not be read)')}</td></tr>
          <tr><td><strong>Risk</strong></td><td>{risk_badge(w.get('risk','?'))}</td></tr>
          <tr><td><strong>Note</strong></td><td>{_esc(w.get('note',''))}</td></tr>
        </tbody></table>"""
        sections_html += section("Wi-Fi Security", body)

    # ARP spoofing
    if "arp_spoof" in state:
        a = state["arp_spoof"]
        macs = a.get("macs_seen") or []
        # Three states, not two. spoofing_suspected is len(macs_seen) > 1, which
        # is False for "stable" and equally False for "never observed" — and
        # action_arp_spoof_check returns a bare {} when the gateway cannot be
        # determined at all, which callers still store. So a green OK used to
        # render beside "Gateway: ?" on a check that never ran. The terminal has
        # always got this right by returning early before its [OK] line.
        if a.get("spoofing_suspected"):
            risk = "HIGH"
        elif macs:
            risk = "OK"
        else:
            risk = "REVIEW"
        body = f"""<p>{risk_badge(risk)} Gateway: {_esc(a.get('gateway') or '?')}</p>
                   <p>MACs seen: {_esc(', '.join(macs) or 'none')}</p>"""
        if a.get("spoofing_suspected"):
            body += "<p style='color:red'><strong>⚠ Multiple MACs detected — possible ARP poisoning!</strong></p>"
        elif not macs:
            body += ("<p>No MAC was resolved for the gateway, so nothing was "
                     "compared. This is not evidence that the gateway is stable.</p>")
        sections_html += section("ARP Spoofing Check", body)

    # Firewall
    if "firewall" in state:
        fw = state["firewall"]
        enabled = fw.get("enabled")
        # REVIEW, not HIGH, for an undetermined firewall: a red HIGH badge
        # asserts the firewall is off. Mirrors action_firewall_check's
        # `"REVIEW" if fw["enabled"] is None else ...`.
        risk = "REVIEW" if enabled is None else ("OK" if enabled else "HIGH")
        body = f"""<p>{risk_badge(risk)} Firewall: {onoff(enabled)}</p>
                   <p>Stealth mode: {onoff(fw.get('stealth_mode'))}</p>
                   <p>{_esc(fw.get('note',''))}</p>"""
        sections_html += section("Firewall Status", body)

    # Sharing services
    if "sharing" in state:
        rows = []
        colours = []
        for s in state["sharing"]:
            # onoff, not a truthiness test: enabled=None means the audit could
            # not inspect the service (Remote Apple Events without sudo), and a
            # reader must be able to tell that from one that is genuinely off.
            # The row tint stays keyed on a service being definitely on, so an
            # unknown is never painted with its worst-case risk colour.
            rows.append([s["name"], onoff(s["enabled"]),
                         risk_badge(s["risk"]), s["note"]])
            colours.append(RISK_COLOUR.get(s["risk"], "") if s["enabled"] else "")
        sections_html += section("Sharing Services", table(["Service", "State", "Risk", "Note"], rows, colours))

    # Default creds
    if "default_creds" in state:
        dc = state["default_creds"]
        if dc.get("successes"):
            # Never write the accepted password into a shareable report file.
            rows = [[u, "(accepted — shown in terminal only)", str(port), m]
                    for u, p, port, m in dc["successes"]]
            body = f"<p>{risk_badge('HIGH')} Default credentials accepted!</p>" + \
                   table(["Username", "Password", "Port", "Method"], rows)
        else:
            # Same verdict as the terminal, from the same function. This branch
            # used to badge OK unconditionally, which read as "the router
            # refused every guess" even when the probe never found a login page
            # to guess at.
            _risk, _message = credential_coverage_verdict(dc.get("coverage"))
            body = f"<p>{risk_badge(_risk)} {_esc(_message)}</p>"
        sections_html += section("Default Credentials Probe", body)

    # Speed
    if "speed_download_mbps" in state:
        dl = state.get("speed_download_mbps")
        ul = state.get("speed_upload_mbps")
        body = f"""<p>Download: <strong>{f'{dl:.1f} Mbps' if dl else 'n/a'}</strong></p>
                   <p>Upload:   <strong>{f'{ul:.1f} Mbps' if ul else 'n/a'}</strong></p>"""
        sections_html += section("Speed Test", body)

    # UPnP mappings
    if "upnp" in state:
        mappings = state["upnp"].get("mappings", [])
        if mappings:
            rows = [[m["ext_port"], m["protocol"], m["int_ip"], m["int_port"], m["description"]]
                    for m in mappings]
            body = table(["Ext Port", "Proto", "Int IP", "Int Port", "Description"], rows)
        else:
            # _esc, like every sibling interpolation in this function. The note
            # is not ours: get_upnp_port_mappings builds it from the SOAP fault
            # or error text the router returned, so its content is chosen by the
            # device being audited. Interpolated raw it was markup injection
            # into a report the owner is likely to forward to someone else, from
            # the one participant in the exchange with a reason to shape it.
            note = state["upnp"].get("note", "No UPnP port mappings found.")
            body = f"<p>{_esc(note)}</p>"
        sections_html += section("UPnP Port Mappings", body)

    # DHCP
    if "dhcp" in state:
        responders = state["dhcp"].get("responders", [])
        # The error is read first, and it has to be: binding port 68 needs root,
        # so on a normal non-sudo run action_rogue_dhcp returns
        # {"responders": [], "error": ...} and no packet ever left the machine.
        # Reading only `responders` rendered that as "No DHCP responses
        # captured." — a statement about the network, made by a check that did
        # not run. The key had two producers and no consumer anywhere.
        error = state["dhcp"].get("error")
        if error:
            body = (f"<p>{risk_badge('REVIEW')} {_esc(error)}</p>"
                    "<p>No DHCP request was sent, so nothing is known about which "
                    "servers would have answered.</p>")
        elif len(responders) > 1:
            rows = [[r["ip"], r["offered_ip"]] for r in responders]
            body = f"<p>{risk_badge('HIGH')} Multiple DHCP servers detected!</p>" + \
                   table(["Server IP", "Offered IP"], rows)
        elif responders:
            body = f"<p>{risk_badge('OK')} One DHCP server: {_esc(responders[0]['ip'])}</p>"
        else:
            body = f"<p>{risk_badge('OK')} No DHCP responses captured.</p>"
        sections_html += section("Rogue DHCP Check", body)

    # Listening services
    if "listening" in state:
        svcs = state["listening"]
        if svcs:
            rows = [[str(s["port"]), s["proto"], s["process"]] for s in svcs]
            sections_html += section("Listening Services", table(["Port", "Proto", "Process"], rows))

    # Router hostname
    if "router_hostname" in state:
        rh = state["router_hostname"]
        if rh.get("suspicious"):
            risk = "HIGH"
        elif rh.get("self_attested"):
            # The gateway answered the question about the gateway. A rogue one
            # answers it identically, so this cannot be badged as a pass.
            risk = "INFO"
        else:
            risk = "OK"
        body = f"""<p>{risk_badge(risk)} Gateway: {_esc(rh.get('gateway','?'))}</p>
                   <p>Hostname: {_esc(rh.get('hostname') or '(none)')}</p>
                   <p>{_esc(rh.get('note',''))}</p>"""
        if rh.get("self_attested"):
            body += ("<p>This answer was served by the gateway itself, which is one "
                     "of this machine's resolvers — it was asked to vouch for its own "
                     "identity. A rogue router answers exactly as this one did, so "
                     "this is <strong>not a passed check</strong>.</p>")
        sections_html += section("Router Hostname Check", body)

    # Evil twin
    if "evil_twin" in state:
        t = state["evil_twin"]
        rows = [[b, "not in baseline" if b in (t.get("unexpected") or []) else ""]
                for b in (t.get("bssids") or [])]
        body = (f"<p>{risk_badge(t.get('risk', 'REVIEW'))} SSID: "
                f"{_esc(t.get('ssid') or 'unknown')}</p>"
                f"<p>{_esc(t.get('note', ''))}</p>")
        if rows:
            body += table(["BSSID", "Status"], rows)
        sections_html += section("Evil Twin Check", body)

    # IPv6 router advertisements
    if "ipv6" in state:
        ra = state["ipv6"]
        body = (f"<p>{risk_badge(ra.get('risk', 'REVIEW'))} {_esc(ra.get('note', ''))}</p>")
        routers = ra.get("routers") or []
        if routers:
            body += table(["Advertising router"], [[r] for r in routers])
        sections_html += section("IPv6 Router Advertisements", body)

    # Interception: trust store and the DNS path
    if "interception" in state:
        inter = state["interception"]
        body = ""
        trust = inter.get("trust_store")
        if trust:
            body += (f"<p>{risk_badge(trust.get('risk', 'REVIEW'))} Trust store: "
                     f"{_esc(trust.get('note', ''))}</p>")
            entries = trust.get("entries") or []
            if entries:
                body += table(["Added root certificate"], [[e] for e in entries])
        dns_probe = inter.get("dns_interception")
        if dns_probe:
            body += (f"<p>{risk_badge(dns_probe.get('risk', 'REVIEW'))} DNS path: "
                     f"{_esc(dns_probe.get('note', ''))}</p>")
        if body:
            sections_html += section("Interception Checks", body)

    # Router certificate
    if "router_tls" in state:
        tls = state["router_tls"]
        digest = tls.get("sha256")
        if digest:
            body = (f"<p>{risk_badge('INFO')} Certificate fingerprint: "
                    f"<code>{_esc(digest)}</code></p>"
                    "<p>Recorded so a change between runs is visible. The router's "
                    "admin certificate is self-signed and stable, so a different "
                    "fingerprint means it was re-issued or something is answering "
                    "in the router's place.</p>")
        else:
            body = (f"<p>{risk_badge('REVIEW')} No certificate was read from the "
                    "gateway, so there is nothing to compare against next run.</p>")
        sections_html += section("Router Certificate", body)

    # Upstream modem ports
    if "upstream_open_ports" in state:
        ports = state["upstream_open_ports"]
        if ports is None:
            body = (f"<p>{risk_badge('REVIEW')} The upstream modem could not be "
                    "scanned, so nothing is known about which ports it exposes.</p>")
        elif ports:
            body = (f"<p>{risk_badge('HIGH')} Open port(s) on the upstream modem: "
                    f"{_esc(', '.join(str(p) for p in ports))}</p>"
                    "<p>This device faces the internet directly, so a port open here "
                    "is exposed more widely than one on the router behind it.</p>")
        else:
            body = f"<p>{risk_badge('OK')} No open ports found on the upstream modem.</p>"
        sections_html += section("Upstream Modem Ports", body)

    # DSL line stats
    if "dsl" in state:
        d = state["dsl"]
        def _val(v, unit):
            return f"{v}{unit}" if v is not None else "not read"
        rows = [
            ["Downstream sync", _val(d.get("downstream_kbps"), " Kbps")],
            ["Upstream sync", _val(d.get("upstream_kbps"), " Kbps")],
            ["Downstream SNR", _val(d.get("downstream_snr_db"), " dB")],
            ["Upstream SNR", _val(d.get("upstream_snr_db"), " dB")],
        ]
        sections_html += section("DSL Line", table(["Measurement", "Value"], rows))

    # Nothing that carries a risk may be silently absent from this file.
    #
    # The report used to render fifteen hand-written sections while the audit
    # populated twenty-one keys, and six of those — the evil-twin check, IPv6
    # router advertisements, DNS interception, the trust store, the router
    # certificate and the upstream modem's ports — appeared nowhere in it. Four
    # of them can return HIGH. So a run that printed two HIGH findings in the
    # terminal produced a file containing no trace of either, while the
    # provenance footer below still counted them among the findings resting on
    # "measurements this tool made itself". The file is the artefact people
    # forward; it was the one that lied.
    #
    # A missing section is now a visible finding in the report rather than an
    # absence, so the next check added cannot go unrendered quietly.
    _unrendered = sorted(k for k in state
                         if k not in RENDERED_STATE_KEYS and _carries_risk(state[k]))
    if _unrendered:
        sections_html += section("Not Included In This Report", (
            f"<p>{risk_badge('REVIEW')} This report has no section for "
            f"{_esc(', '.join(_unrendered))}, and {'they' if len(_unrendered) > 1 else 'it'} "
            "carried a risk rating in this run. Read the terminal output for "
            f"{'those' if len(_unrendered) > 1 else 'that'} finding(s) — this file is "
            "incomplete.</p>"))

    # Evidence provenance.
    #
    # The terminal report prints this too, but it matters more here: an exported
    # file is the artefact most likely to be read by someone who did not run the
    # audit and cannot see which lines the gateway was trusted for.
    _grouped = findings_by_evidence(state)
    _basis_rows = [[EVIDENCE[key][2], _EVIDENCE_TAG[cls], EVIDENCE[key][1]]
                   for cls in (SELF_REPORTED, RESOLVER_DEPENDENT, THIRD_PARTY)
                   for key in _grouped.get(cls, ())]
    if _basis_rows:
        _independent = len(_grouped.get(OBSERVED, ())) + len(_grouped.get(MEASURED, ()))
        body = table(["Finding", "Came from", "Specifically"], _basis_rows)
        body += ("<p>The findings above did not come from an independent source. Take "
                 "seriously anything they admit to — a router listing a port mapping "
                 "has volunteered something against its own interest. A <em>clean</em> "
                 "result from them is worth much less: it says nothing was "
                 "volunteered, which is not the same as there being nothing to "
                 "find.</p>")
        if _independent:
            body += (f"<p>The other {_independent} finding(s) rest on this machine's "
                     "own state or on measurements this tool made itself, which a "
                     "gateway cannot edit. A compromised <strong>host</strong> can, "
                     "which is what running this from a second machine is for.</p>")
        sections_html += section("Evidence Provenance", body)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Home Network Audit Report — {ts_str[:10]}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          max-width: 960px; margin: 40px auto; padding: 0 20px;
          background: #f5f5f7; color: #1d1d1f; }}
  h1   {{ color: #1d1d1f; border-bottom: 3px solid #0071e3; padding-bottom: 10px; }}
  h2   {{ color: #0071e3; margin-top: 0; }}
  .section {{ background: white; border-radius: 12px; padding: 24px;
              margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  table {{ border-collapse: collapse; width: 100%; }}
  th    {{ background: #f5f5f7; text-align: left; padding: 8px 12px;
           border-bottom: 2px solid #d2d2d7; }}
  td    {{ padding: 8px 12px; border-bottom: 1px solid #e8e8ed; }}
  tr:last-child td {{ border-bottom: none; }}
  .footer {{ text-align: center; color: #86868b; font-size: 0.85em; margin-top: 40px; }}
</style>
</head>
<body>
<h1>🏠 Home Network Audit Report</h1>
<p>Generated: {ts_str} &nbsp;|&nbsp; Tool: home_net_audit.py</p>
{sections_html}
<div class="footer">
  This is a point-in-time snapshot, not a guarantee of security.
  For deeper analysis, consider nmap and your router vendor's advisories.
</div>
</body>
</html>"""

    # The same protection the baseline gets, for the same content. This file
    # holds MACs, topology, hostnames, the SSID and which credential/port/method
    # combinations the router accepted, and it was written 0644 into a 0755
    # directory — readable by every account on the machine. _secure_dir was
    # reachable only from a baseline or history write, so `--html-report
    # --no-save-baseline` never called it at all.
    _secure_dir()
    report_dir = os.path.dirname(output_path)
    os.makedirs(report_dir, exist_ok=True)
    try:
        os.chmod(report_dir, 0o700)
    except OSError:
        pass
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(html_doc)
    try:
        # O_CREAT leaves an existing file's mode alone, so set it explicitly.
        os.chmod(output_path, 0o600)
    except OSError:
        pass

    return output_path


def action_html_report(state):
    hr("HTML REPORT EXPORT")
    if not state:
        print("  No audit data in this session. Run some checks first.")
        return None
    path = generate_html_report(state)
    print(f"  Report saved to: {path}")
    print("  Open it in any browser to view the colour-coded results.")
    return path


# ---------------------------------------------------------------------------
# Shared output helpers
# ---------------------------------------------------------------------------

def hr(title=""):
    print("\n" + "=" * 64)
    if title:
        print(title)
        print("=" * 64)


def print_network_info():
    interfaces = get_all_interfaces()
    local_ip = get_local_ip()
    gateway = get_default_gateway()
    print(f"Your Mac's primary IP : {local_ip}")
    print(f"Default gateway       : {gateway}")
    if interfaces:
        print("Active interfaces:")
        for iface, ip, net in interfaces:
            print(f"  {iface:<8} {ip:<16} subnet: {net}")
    return interfaces, local_ip, gateway


# ---------------------------------------------------------------------------
# Individual audit actions (original)
# ---------------------------------------------------------------------------

def audit_host(label, host, full_scan=False):
    """Port-scan one host, print a risk-annotated summary, and return open ports.

    Shared by action_port_scan and action_full_audit (previously duplicated).
    """
    port_set = range(1, 65536) if full_scan else COMMON_PORTS
    n = "all 65535" if full_scan else str(len(COMMON_PORTS))
    print(f"\nScanning {n} ports on {label} ({host})...")
    t0 = time.time()
    scan = scan_ports_detailed(host, port_set)
    open_ports = scan["open"]
    if scan["blocked"]:
        # Every probe returned "unreachable", so this is not a host with
        # nothing listening — it is a host we were never able to ask. Saying
        # "none found" here would be a fabrication, and saving it as [] would
        # tell the next run that the ports had closed.
        print(f"Done in {time.time()-t0:.1f}s. UNKNOWN — could not reach {host}.")
        print(f"  [REVIEW] All {scan['probed']} probes returned 'unreachable' "
              f"before any timeout, so the result is not 'no open ports'.")
        if sys.platform == "darwin":
            print("           On macOS this is what Local Network privacy looks like "
                  "when it denies a\n           background job: a scheduled "
                  "(launchd/cron) run cannot reach its own subnet,\n           while the "
                  "same audit run from a terminal can. Routed hosts on other subnets\n"
                  "           still answer, which is why an upstream modem can scan "
                  "cleanly in the\n           same run. Run the audit interactively to "
                  "scan this host.")
        return None
    print(f"Done in {time.time()-t0:.1f}s. Open ports: {open_ports or 'none found'}")
    for p in open_ports:
        svc, risk, note = PORTS_OF_INTEREST.get(
            p, ("unknown", "REVIEW", "Unrecognised service; investigate."))
        print(f"  [{risk:6}] {p:>5}  {svc:<14} {note}")
    tls = check_tls(host)
    if tls.get("sha256"):
        print(f"  HTTPS (TLS) certificate: present, sha256 {tls['sha256'][:16]}…")
    else:
        print(f"  HTTPS (TLS) certificate present: {tls.get('present')}")
    if open_ports and 80 in open_ports and 443 not in open_ports:
        print("  Note: port 80 open without 443. App-managed mesh systems")
        print("  (Google Nest, eero) use 80/5000 locally — not a web admin panel.")
    return open_ports


def action_port_scan(full_scan=False, upstream_ip=None):
    hr("PORT SCAN")
    _, _, gateway = print_network_info()

    open_ports = []
    if gateway:
        open_ports = audit_host("default gateway", gateway, full_scan)
    else:
        print("Could not determine default gateway.")

    if upstream_ip:
        hr("UPSTREAM MODEM")
        audit_host("upstream modem", upstream_ip, full_scan)

    return gateway, open_ports


def _print_devices_grouped(all_devices, labels, networks, scanned_subnets=None):
    """Print devices grouped by subnet, with a named network header for each group.

    scanned_subnets — list of IPv4Network objects that were swept. When provided,
    a header is shown for every scanned subnet even if no devices were found,
    so the user can see that empty subnets were actually scanned.
    """
    from collections import defaultdict
    by_subnet = defaultdict(list)
    for d in all_devices:
        by_subnet[d.get("subnet", "unknown")].append(d)

    # Build the ordered set of subnet keys to display: all scanned subnets first
    # (preserving scan order), then any extra keys from by_subnet not already covered.
    display_order = []
    if scanned_subnets:
        for net in scanned_subnets:
            display_order.append(str(net))
    for key in sorted(by_subnet.keys()):
        if key not in display_order:
            display_order.append(key)

    unlabelled = []
    total = 0
    for subnet_str in display_order:
        group = by_subnet.get(subnet_str, [])
        net_name = network_name_for_subnet(subnet_str, networks)
        header = f"  Network: {net_name}  ({subnet_str})"
        print(f"\n{header}")
        print(f"  {'-' * (len(header) - 2)}")
        if not group:
            print(f"    (no devices found)")
        for d in group:
            mac = d["mac"]
            name = labels.get(mac.lower(), "")
            vend = d.get("vendor", "")
            # "(randomized/private MAC)" is what lookup_vendor returns when it
            # declines to look one up. It reads as a vendor here and suppressed
            # the "unlabelled" flag, so a device the tool explicitly could not
            # identify was presented as identified — and left out of the count
            # that tells the reader how many they still have to account for.
            identified = name or (vend if vend != PRIVATE_MAC_VENDOR else "")
            display_name = name or vend
            tag = f"  {display_name}" if display_name else ""
            flag = "" if identified else "  <-- unlabelled"
            print(f"    {d['ip']:<15} {mac}{tag}{flag}")
            if not identified:
                unlabelled.append(mac)
            total += 1

    print(f"\n  Total: {total} device(s) across {len(display_order)} subnet(s) scanned.")
    if unlabelled:
        print(f"  {len(unlabelled)} unidentified device(s). Tag them with:")
        print(f"    python3 home_net_audit.py --label MAC='Device Name' ...")


def onlink_coverage(subnets_to_sweep, interfaces):
    """Which swept subnets this host could actually have seen a device on.

    A sweep is evidence of absence only where a sighting was possible. Device
    discovery resolves neighbours through the ARP cache, which holds ON-LINK
    entries only, so sweeping a subnet this machine has no interface in returns
    nothing whatever is actually there. Recording that as "scanned" converts
    "could not reach" into "measured absence" — the single inference the rest of
    this module refuses to make (probe_port keeps unreachable as a third state;
    audit_host will not print a blocked scan as "no open ports"; diff_baseline
    will not compare a router-port list against an unknown).

    It matters because the sweep list is often fixed while the vantage point is
    not: menu option 3's "All networks" sweeps all of DEFAULT_NETWORKS, and a
    --subnet job sweeps whatever it was given, regardless of which network this
    Mac happens to be joined to today. Without this filter, a laptop moving
    between household SSIDs makes the router — one MAC answering on whichever
    subnet is currently on-link — look like it crossed a network boundary, when
    only the observer moved.
    """
    onlink = [net for _, _, net in (interfaces or [])]
    return [str(s) for s in subnets_to_sweep
            if any(s.overlaps(net) for net in onlink)]


def is_onlink(address, interfaces):
    """Whether `address` sits in a subnet this machine has an interface in.

    Used before anything is sent that must not leave the LAN. Off-link is not a
    connectivity question here — the packet would very likely be delivered, via
    the default route, to a device belonging to someone else.

    With no interface list at all the answer is False: unknown must not read as
    permission, since the whole point of the check is the case where nobody
    checked.
    """
    try:
        addr = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    return any(addr in net for _, _, net in (interfaces or []))


def resolve_subnets(subnet_overrides, extra_subnets, interfaces, local_ip):
    """Build the ordered list of subnets to sweep: CLI overrides (validated) or
    auto-detected interfaces, plus any explicit extras. Invalid CIDRs are
    skipped with a warning rather than crashing."""
    if subnet_overrides:
        subnets = []
        for s in subnet_overrides:
            try:
                subnets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                print(f"  Skipping invalid subnet {s!r} "
                      "(expected CIDR like 192.168.1.0/24).")
    elif interfaces:
        # A plain list, not a set: the de-duplication below already removes
        # repeats and preserves order, so a set here only discarded the order
        # interfaces were detected in — leaving the primary link (en0) liable to
        # be swept and reported after a secondary one.
        subnets = [net for _, _, net in interfaces]
    else:
        fb = guess_subnet(local_ip)
        subnets = [fb] if fb else []

    for s in (extra_subnets or []):
        try:
            subnets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            print(f"  Skipping invalid extra subnet {s!r}.")

    # De-duplicate while preserving scan order (avoids sweeping a subnet twice
    # if it appears in both the overrides and the extras, or is repeated).
    seen, ordered = set(), []
    for net in subnets:
        if net not in seen:
            seen.add(net)
            ordered.append(net)

    # Refuse a sweep too large to finish. discover_devices materialises
    # list(subnet.hosts()) and hands every address to a 50-worker pool running
    # one ping subprocess each, so --subnet 10.0.0.0/8 means 16.7 million
    # processes. It is self-inflicted and interruptible, but it is also
    # pointless: discovery resolves neighbours through the ARP cache, which
    # holds on-link entries only, so nothing beyond the local prefix could be
    # seen however long it ran.
    kept = []
    for net in ordered:
        if net.num_addresses > MAX_SWEEP_ADDRESSES:
            print(f"  Skipping {net}: {net.num_addresses:,} addresses is past the "
                  f"{MAX_SWEEP_ADDRESSES:,} this sweep will attempt. ARP discovery "
                  "cannot see past the on-link prefix anyway — pass the specific "
                  "subnet you mean.")
            continue
        kept.append(net)
    return kept


def collect_devices(subnets_to_sweep, labels, networks, no_vendors=False, sweep_note=""):
    """Ping-sweep each subnet (de-duplicating by IP), then resolve vendors.

    Vendor lookups skip labelled / unknown / randomized MACs entirely and sleep
    only BETWEEN real API calls. Shared by action_discover_devices and
    action_full_audit (previously duplicated). Returns the device list.
    """
    all_devices = []
    seen_ips = set()
    for subnet in subnets_to_sweep:
        net_name = network_name_for_subnet(str(subnet), networks)
        print(f"  Sweeping {subnet}  [{net_name}]{sweep_note}...")
        for d in discover_devices(subnet):
            if d["ip"] not in seen_ips:
                seen_ips.add(d["ip"])
                all_devices.append({**d, "subnet": str(subnet)})

    if not no_vendors and all_devices:
        needs_lookup = [d for d in all_devices
                        if not labels.get(d["mac"].lower())
                        and d["mac"] != "unknown"
                        and not is_randomized_mac(d["mac"])]
        if needs_lookup:
            print(f"  Looking up vendors for {len(needs_lookup)} unlabelled device(s)...")
        for d in all_devices:
            mac = d["mac"]
            if is_randomized_mac(mac) and not labels.get(mac.lower()):
                d["vendor"] = PRIVATE_MAC_VENDOR
            else:
                d["vendor"] = ""
        for i, d in enumerate(needs_lookup):
            if i > 0:
                time.sleep(1.1)  # rate-limit between real API calls only
            d["vendor"] = lookup_vendor(d["mac"])
    return all_devices


def action_discover_devices(no_vendors=False, subnet_overrides=None, extra_subnets=None):
    """
    Discover devices on one or more subnets.

    subnet_overrides  — replace auto-detected subnets entirely (CLI --subnet flag)
    extra_subnets     — append to auto-detected subnets (menu option 3b / Pearl network)

    Returns (devices, scanned_subnets). The second element is which subnets were
    actually swept, as strings. A caller that saves a baseline must record it:
    without it a later comparison cannot tell a device that left a subnet from a
    subnet that was never scanned, and this entry point is exactly where the two
    diverge — it sweeps whatever single subnet the menu offered, while a full
    audit sweeps what the interfaces suggest.
    """
    hr("CONNECTED DEVICES")
    interfaces = get_all_interfaces()
    local_ip = get_local_ip()
    labels = load_labels()
    networks = load_networks()

    subnets_to_sweep = resolve_subnets(subnet_overrides, extra_subnets, interfaces, local_ip)
    if not subnets_to_sweep:
        print("  Could not determine any subnet. Pass one with --subnet 192.168.1.0/24")
        return [], []

    all_devices = collect_devices(subnets_to_sweep, labels, networks,
                                  no_vendors=no_vendors, sweep_note="  (this takes ~10-30s)")
    _print_devices_grouped(all_devices, labels, networks, scanned_subnets=subnets_to_sweep)
    # Only the on-link subnets count as coverage. This entry point is where the
    # sweep list and the vantage point diverge most: "All networks" sweeps every
    # DEFAULT_NETWORKS entry whether or not this Mac is joined to any of them.
    return all_devices, onlink_coverage(subnets_to_sweep, interfaces)


def action_check_dns():
    hr("DNS SETTINGS")
    gateway = get_default_gateway()
    dns = get_dns_servers()
    if not dns:
        print("Could not read DNS settings.")
        return []
    for d in dns:
        label = KNOWN_DNS.get(d)
        if label:
            print(f"  {d}  (recognised public resolver: {label})")
        elif gateway and d == gateway:
            print(f"  {d}  (your router — normal; it forwards to your ISP)")
        else:
            print(f"  {d}  <-- unfamiliar. Confirm this is your ISP/router. "
                  f"Unexpected DNS can indicate hijacking.")
    return dns


def action_save_baseline(state):
    hr("SAVE BASELINE")
    if not state:
        print("No data collected in this session yet.")
        print("Run a Full Audit or individual checks first, then save.")
        return
    # Save against the network this session actually measured, not whichever
    # file happens to be selected.
    _subnet, _ = use_current_network_baseline()
    _net_line = describe_current_network(_subnet)
    if _net_line:
        print(_net_line)
    passphrase = resolve_passphrase(prompt=True)
    _record = save_baseline(state, passphrase=passphrase)
    print(f"Baseline saved to {BASELINE_FILE}")
    _pub = describe_publish_result(_record.get("_receipt"))
    if _pub:
        print(_pub)
    if passphrase is None:
        print("  Note: saved unsealed. Set a passphrase (or "
              f"{PASSPHRASE_ENV}) so the baseline cannot be silently rewritten.")
    print(f"Timestamp: {state.get('timestamp', '?')}")
    keys = [k for k in state if k != "timestamp"]
    print(f"Saved sections: {', '.join(keys)}")


def action_compare_baseline(state):
    hr("CHANGE DETECTION (vs saved baseline)")
    _subnet, _ = use_current_network_baseline()
    _net_line = describe_current_network(_subnet)
    if _net_line:
        print(_net_line)
    print(describe_baseline_integrity(verify_baseline(resolve_passphrase())))
    _sink = resolve_sink()
    if _sink:
        print(describe_receipt_status(compare_with_receipts(
            load_baseline_record(), read_receipts(_sink), sink=_sink)))
        # Silent unless a monitor has actually run, so an audit-only user gains
        # no noise from a feature they are not using.
        _beats = read_heartbeats(_sink)
        _gaps = describe_observation_gaps(observation_gaps(_beats))
        if _gaps:
            print(_gaps)
        # Future-stamped heartbeats are excluded from the coverage check above,
        # and saying so matters: the sink is append-only, so an entry that
        # cannot be removed was either mis-stamped by a wrong clock or added.
        _clock = describe_clock_anomalies(_beats)
        if _clock:
            print(_clock)
        # Reads both channels: a monitor-only deployment publishes heartbeats
        # for weeks without a single baseline receipt, and that is exactly where
        # an edited script has the longest to go unnoticed.
        _code = describe_code_attestation(read_receipts(_sink))
        if _code:
            print(_code)
    old = load_baseline()
    _freshness = describe_baseline_freshness(old)
    if _freshness:
        print(_freshness)
    if not old:
        print("No baseline saved yet.")
        print("Run option 5 (Save baseline) after a full audit to enable this.")
        return
    if not state:
        print("No data collected in this session to compare.")
        print("Run a Full Audit or individual checks first.")
        return
    changes = diff_baseline(old, state)
    print(f"Baseline from: {old.get('timestamp', '?')}")
    # Above the verdict, because it qualifies the verdict: it is as true of a
    # short list of changes as it is of "No changes since baseline."
    _coverage = describe_comparison_coverage(old, state)
    if _coverage:
        print(_coverage)
    if changes:
        print("CHANGES DETECTED:")
        for c in changes:
            print("  ! " + c)
    else:
        print("No changes since baseline.")


# ---------------------------------------------------------------------------
# Full audit
# ---------------------------------------------------------------------------

def action_full_audit(full_scan=False, no_vendors=False, no_speedtest=False,
                      upstream_ip=None, tplink_password=None, subnet_overrides=None,
                      extra_subnets=None, probe_creds=False, no_discovery=False):
    state = {"timestamp": datetime.now(timezone.utc).isoformat()}

    hr("NETWORK INTERFACES")
    interfaces, local_ip, gateway = print_network_info()
    state["gateway"] = gateway
    # Choose the baseline before anything is compared or saved: this machine
    # roams between known networks, and each keeps its own.
    _subnet, _ = use_current_network_baseline(interfaces, local_ip, gateway)
    _net_line = describe_current_network(_subnet)
    if _net_line:
        print(_net_line)

    # Port scan
    hr("ROUTER / GATEWAY PORT SCAN")
    if gateway:
        state["router_open_ports"] = audit_host("default gateway", gateway, full_scan)
        state["router_tls"] = check_tls(gateway)
    if upstream_ip:
        hr("UPSTREAM MODEM")
        state["upstream_open_ports"] = audit_host("upstream modem", upstream_ip, full_scan)

    # DSL stats
    if tplink_password:
        hr("DSL LINE STATS (TP-Link VX420-G2h)")
        # The gateway, not a hardcoded 192.168.1.1.
        #
        # tplink_dsl_stats puts the modem password in the query string of a
        # plain http:// GET — base64 first, then MD5 on retry, both replayable.
        # Defaulting the destination to a literal address meant that on a LAN
        # numbered anything else, the request left via the default route: over
        # a split-tunnel VPN, or through a router that forwards RFC1918, it
        # reaches a stranger's device and lands in their access log. The only
        # feedback was "Could not retrieve DSL stats — auth failed."
        tplink_ip = upstream_ip or gateway
        if not tplink_ip:
            print("  Skipped: no upstream modem address and no gateway, so there is "
                  "nowhere on this network to send the request.")
        elif not is_onlink(tplink_ip, interfaces):
            print(f"  Skipped: {tplink_ip} is not on any network this machine is "
                  "joined to, and the modem password would have left the LAN in "
                  "the clear to get there. Pass --upstream with an on-link address.")
        else:
            print(f"  Requesting DSL stats from {tplink_ip} ...")
            dsl, note = tplink_dsl_stats(tplink_ip, tplink_password)
            if note:
                print(f"  Note: {note}")
            fmt = lambda v, u: f"{v}{u}" if v is not None else "n/a"
            print(f"  Downstream sync : {fmt(dsl['downstream_kbps'], ' Kbps')}")
            print(f"  Upstream sync   : {fmt(dsl['upstream_kbps'], ' Kbps')}")
            print(f"  Downstream SNR  : {fmt(dsl['downstream_snr_db'], ' dB')}  (healthy >6 dB)")
            print(f"  Upstream SNR    : {fmt(dsl['upstream_snr_db'], ' dB')}")
            state["dsl"] = dsl

    # DNS
    hr("DNS SETTINGS")
    dns = get_dns_servers()
    state["dns"] = dns
    for d in dns:
        label = KNOWN_DNS.get(d)
        if label:
            print(f"  {d}  ({label})")
        elif gateway and d == gateway:
            print(f"  {d}  (your router)")
        else:
            print(f"  {d}  <-- unfamiliar")

    # Devices
    if not no_discovery:
        hr("CONNECTED DEVICES")
        labels = load_labels()
        networks = load_networks()
        subnets_to_sweep = resolve_subnets(subnet_overrides, extra_subnets, interfaces, local_ip)
        if subnets_to_sweep:
            all_devices = collect_devices(subnets_to_sweep, labels, networks, no_vendors=no_vendors)
            state["devices"] = all_devices
            # Record where we looked AND could have seen something — not merely
            # what was on the sweep list. Without this a later comparison cannot
            # tell "the device is no longer on that subnet" from "that subnet
            # was never scanned this run"; with the unfiltered list it cannot
            # tell it from "that subnet was unreachable from here".
            state["scanned_subnets"] = onlink_coverage(subnets_to_sweep, interfaces)
            _print_devices_grouped(all_devices, labels, networks, scanned_subnets=subnets_to_sweep)

    # Speed test
    if not no_speedtest:
        hr("SPEED TEST")
        print("Testing speed via Cloudflare (~15 MB of traffic; use --no-speedtest to skip)...")
        dl, ul = speed_test()
        if dl:
            rating = "good" if dl >= 20 else "slow" if dl >= 5 else "very slow"
            print(f"Download : {dl:.1f} Mbps  ({rating})")
        else:
            print("Download : could not measure")
        if ul:
            print(f"Upload   : {ul:.1f} Mbps")
        else:
            print("Upload   : could not measure")
        state["speed_download_mbps"] = dl
        state["speed_upload_mbps"] = ul

    # ---- NEW FEATURES in full audit ----

    wifi = action_wifi_security()
    state["wifi"] = wifi

    arp = action_arp_spoof_check()
    state["arp_spoof"] = arp

    state["interception"] = action_interception_checks()

    twin = action_evil_twin((load_baseline() or {}).get("wifi_bssids"))
    state["evil_twin"] = twin
    state["wifi_bssids"] = twin["bssids"]

    ra = action_ipv6_routers((load_baseline() or {}).get("ipv6_routers"))
    state["ipv6"] = ra
    state["ipv6_routers"] = ra["routers"]

    fw = action_firewall_check()
    state["firewall"] = fw

    sharing = action_sharing_services()
    state["sharing"] = [{"name": s["name"], "enabled": s["enabled"],
                          "risk": s["risk"], "note": s["note"]} for s in sharing]

    listening = action_listening_services()
    state["listening"] = listening

    rh = action_router_hostname()
    state["router_hostname"] = rh

    # The credential probe is NOT read-only and can lock you out of your router,
    # so it only runs when explicitly requested (--probe-creds / menu option 14).
    if probe_creds:
        dc = action_default_creds()
        state["default_creds"] = dc

    upnp = action_upnp_dump()
    state["upnp"] = upnp

    dhcp = action_rogue_dhcp()
    state["dhcp"] = dhcp

    # Baseline comparison
    hr("CHANGE DETECTION (vs saved baseline)")
    print(describe_baseline_integrity(verify_baseline(resolve_passphrase())))
    _sink = resolve_sink()
    if _sink:
        print(describe_receipt_status(compare_with_receipts(
            load_baseline_record(), read_receipts(_sink), sink=_sink)))
        # Silent unless a monitor has actually run, so an audit-only user gains
        # no noise from a feature they are not using.
        _beats = read_heartbeats(_sink)
        _gaps = describe_observation_gaps(observation_gaps(_beats))
        if _gaps:
            print(_gaps)
        # Future-stamped heartbeats are excluded from the coverage check above,
        # and saying so matters: the sink is append-only, so an entry that
        # cannot be removed was either mis-stamped by a wrong clock or added.
        _clock = describe_clock_anomalies(_beats)
        if _clock:
            print(_clock)
        # Reads both channels: a monitor-only deployment publishes heartbeats
        # for weeks without a single baseline receipt, and that is exactly where
        # an edited script has the longest to go unnoticed.
        _code = describe_code_attestation(read_receipts(_sink))
        if _code:
            print(_code)
    old = load_baseline()
    _freshness = describe_baseline_freshness(old)
    if _freshness:
        print(_freshness)
    if old:
        changes = diff_baseline(old, state)
        print(f"Baseline from: {old.get('timestamp', '?')}")
        _coverage = describe_comparison_coverage(old, state)
        if _coverage:
            print(_coverage)
        if changes:
            print("CHANGES DETECTED:")
            for c in changes:
                print("  ! " + c)
        else:
            print("No changes since baseline.")
    else:
        print("No baseline saved yet. Use option 5 after reviewing results.")

    _basis = describe_evidence_basis(state)
    if _basis:
        hr("EVIDENCE PROVENANCE")
        print(_basis)

    hr()
    print("Full audit complete. This is a snapshot, not a guarantee.")

    return state


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

MENU = """
================================================================
  Home Network Audit
================================================================
  --- Core checks ---
  1.  Full audit  (all read-only checks in one run)
  2.  Port scan only
  3.  Discover devices  (choose networks via sub-menu)
  4.  Check DNS settings
  5.  Save baseline
  6.  Compare against saved baseline
  7.  Speed test

  --- Security checks ---
  8.  Wi-Fi security mode  (WPA2/WPA3 vs WEP/open)
  9.  ARP spoofing detector
  10. Firewall status
  11. Sharing services check
  12. Listening services audit
  13. Router hostname check
  14. Default credentials probe
  15. UPnP port mapping dump
  16. Rogue DHCP detector

  --- Reporting ---
  17. Export HTML report  (save colour-coded report to file)

  0.  Exit
================================================================"""


def interactive_menu():
    if sys.platform != "darwin":
        print("Note: written for macOS. Some system commands may differ.\n")

    session_state = {}

    while True:
        print(MENU)
        try:
            choice = input("  Enter choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        def ts():
            session_state.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

        if choice == "0":
            print("\nGoodbye.")
            break

        elif choice == "1":
            state = action_full_audit()
            session_state.update(state)

        elif choice == "2":
            full = input("  Full scan (all 65535 ports)? Much slower. [y/N]: ").strip().lower() == "y"
            gateway, open_ports = action_port_scan(full_scan=full)
            if gateway:
                ts(); session_state["gateway"] = gateway
                session_state["router_open_ports"] = open_ports

        elif choice == "3":
            networks = load_networks()
            # Build ordered list from DEFAULT_NETWORKS so order is predictable
            ordered = [(cidr, name) for cidr, name in DEFAULT_NETWORKS.items()]
            # Merge in any user-saved networks not already present
            saved = load_networks()
            for cidr, name in saved.items():
                if not any(c == cidr for c, _ in ordered):
                    ordered.append((cidr, name))

            print("\n  Which networks to scan?")
            for i, (cidr, name) in enumerate(ordered, 1):
                print(f"    {i}. {name:<20} ({cidr})")
            print(f"    {len(ordered)+1}. All networks")
            sub = input(f"    Enter choice (default: 1): ").strip() or "1"

            try:
                sub_i = int(sub)
            except ValueError:
                sub_i = 1

            if sub_i == len(ordered) + 1:
                subnet_overrides = [cidr for cidr, _ in ordered]
            elif 1 <= sub_i <= len(ordered):
                subnet_overrides = [ordered[sub_i - 1][0]]
            else:
                print(f"  Invalid choice, defaulting to {ordered[0][1]}.")
                subnet_overrides = [ordered[0][0]]

            no_v = input("  Skip vendor lookups (faster)? [y/N]: ").strip().lower() == "y"
            devices, swept = action_discover_devices(no_vendors=no_v,
                                                     subnet_overrides=subnet_overrides)
            ts(); session_state["devices"] = devices
            # This path sweeps ONE subnet chosen from the menu, which is
            # routinely not the ground a full audit covers. Recording it is what
            # stops a later comparison calling that difference a device move.
            session_state["scanned_subnets"] = swept

        elif choice == "4":
            dns = action_check_dns()
            ts(); session_state["dns"] = dns

        elif choice == "5":
            action_save_baseline(session_state)

        elif choice == "6":
            action_compare_baseline(session_state)

        elif choice == "7":
            hr("SPEED TEST")
            print("Testing speed via Cloudflare (~15s, ~15 MB of traffic)...")
            dl, ul = speed_test()
            rating = ("good" if dl >= 20 else "slow" if dl >= 5 else "very slow") if dl else ""
            print(f"Download : {f'{dl:.1f} Mbps  ({rating})' if dl else 'could not measure'}")
            print(f"Upload   : {f'{ul:.1f} Mbps' if ul else 'could not measure'}")
            ts()
            session_state["speed_download_mbps"] = dl
            session_state["speed_upload_mbps"] = ul

        elif choice == "8":
            r = action_wifi_security()
            ts(); session_state["wifi"] = r

        elif choice == "9":
            r = action_arp_spoof_check()
            ts(); session_state["arp_spoof"] = r

        elif choice == "10":
            fw = action_firewall_check()
            ts(); session_state["firewall"] = fw

        elif choice == "11":
            sharing = action_sharing_services()
            ts(); session_state["sharing"] = sharing

        elif choice == "12":
            listening = action_listening_services()
            ts(); session_state["listening"] = listening

        elif choice == "13":
            rh = action_router_hostname()
            ts(); session_state["router_hostname"] = rh

        elif choice == "14":
            print("\n  WARNING: this sends real login attempts to your router and is")
            print("  NOT read-only. On some routers repeated attempts can lock you out")
            print("  (the probe aborts automatically if it detects a lockout signal).")
            if input("  Proceed? [y/N]: ").strip().lower() == "y":
                dc = action_default_creds()
                ts(); session_state["default_creds"] = dc
            else:
                print("  Skipped.")

        elif choice == "15":
            upnp = action_upnp_dump()
            ts(); session_state["upnp"] = upnp

        elif choice == "16":
            dhcp = action_rogue_dhcp()
            ts(); session_state["dhcp"] = dhcp

        elif choice == "17":
            action_html_report(session_state)

        else:
            print(f"  Unknown choice '{choice}'. Please enter 0-17.")

        input("\n  Press Enter to return to menu...")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Defensive audit of your own home network. "
                    "Run with no arguments for an interactive menu.",
        epilog=(
            "Environment:\n"
            f"  {DIR_ENV:<28} where baselines, seal chains, labels and reports\n"
            f"  {'':<28} are kept (default ~/.home_net_audit). Point it at a\n"
            f"  {'':<28} temporary directory to try something without touching\n"
            f"  {'':<28} the real one.\n"
            f"  {PASSPHRASE_ENV:<28} seals the baseline so it cannot be rewritten unnoticed.\n"
            f"  {SINK_ENV:<28} off-host receipt destination; {SINK_TOKEN_ENV} its bearer token.\n"
            f"  {ALERT_ENV:<28} where --monitor sends alerts.\n"
            "  TPLINK_PASSWORD              modem admin password, for DSL line stats."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subnet", nargs="+",
                    help="Override auto-detected subnets entirely, e.g. 192.168.1.0/24")
    ap.add_argument("--extra-subnet", nargs="+", metavar="SUBNET",
                    help="Append extra subnets to scan in addition to auto-detected ones, e.g. 192.168.87.0/24")
    ap.add_argument("--upstream",
                    help="IP of an upstream modem to scan separately")
    ap.add_argument("--full", action="store_true",
                    help="Full router port scan (1-65535, slower)")
    ap.add_argument("--no-vendors", action="store_true",
                    help="Skip online vendor lookups (faster)")
    ap.add_argument("--no-save-baseline", action="store_true",
                    help="Skip saving this run as the comparison baseline")
    ap.add_argument("--label", nargs="+", metavar="MAC=NAME",
                    help="Tag a device MAC with a friendly name")
    ap.add_argument("--no-discovery", action="store_true",
                    help="Skip the LAN device sweep")
    ap.add_argument("--no-speedtest", action="store_true",
                    help="Skip the speed test")
    ap.add_argument("--tplink-password", metavar="PASSWORD",
                    help="TP-Link admin password to fetch DSL line stats. "
                         "WARNING: visible to other users via `ps`; prefer the "
                         "TPLINK_PASSWORD env var or --tplink-password-prompt.")
    ap.add_argument("--tplink-password-prompt", action="store_true",
                    help="Securely prompt for the TP-Link password instead of "
                         "passing it on the command line.")
    ap.add_argument("--probe-creds", action="store_true",
                    help="Actively test default admin credentials against the gateway. "
                         "NOT read-only and can trigger router lockout; off by default.")
    ap.add_argument("--html-report", action="store_true",
                    help="Save an HTML report after the audit")
    ap.add_argument("--monitor", action="store_true",
                    help="Run continuously, polling the cheap high-signal checks and "
                         "alerting on change. This is the only mode that can catch a "
                         "rogue RA or ARP poisoning that is withdrawn between scans.")
    ap.add_argument("--interval", type=int, default=MONITOR_INTERVAL, metavar="SECONDS",
                    help=f"Seconds between monitor polls (default {MONITOR_INTERVAL}).")
    ap.add_argument("--alert-to", metavar="DEST",
                    help="Where monitor alerts go — a path or https:// URL off this "
                         f"machine. Or set {ALERT_ENV}.")
    ap.add_argument("--publish-to", metavar="DEST",
                    help="Append a receipt for each run to a path or https:// URL the "
                         "audited host cannot rewrite, so a wiped local history is "
                         f"still detectable. Or set {SINK_ENV}.")
    ap.add_argument("--seal-baseline", action="store_true",
                    help="Prompt for a passphrase and seal the baseline with it, so "
                         f"it cannot be rewritten unnoticed. Or set {PASSPHRASE_ENV}.")
    ap.add_argument("--menu", action="store_true",
                    help="Force interactive menu")
    args = ap.parse_args()

    cli_args_given = any([
        args.subnet, getattr(args, "extra_subnet", None), args.upstream,
        args.full, args.no_vendors, args.no_save_baseline, args.label,
        args.no_discovery, args.no_speedtest, args.tplink_password,
        args.tplink_password_prompt, args.probe_creds, args.html_report,
        args.seal_baseline, args.publish_to, args.monitor,
    ])

    if args.monitor:
        run_monitor(interval=args.interval, alert_to=args.alert_to)
        return

    if not cli_args_given or args.menu:
        interactive_menu()
        return

    # Resolve the TP-Link password from the safest available source.
    tplink_password = None
    if args.tplink_password_prompt:
        import getpass
        tplink_password = getpass.getpass("TP-Link admin password: ")
    elif args.tplink_password:
        tplink_password = args.tplink_password
        print("Warning: passing --tplink-password on the command line exposes it "
              "in the process list. Prefer the TPLINK_PASSWORD env var or "
              "--tplink-password-prompt.\n")
    else:
        tplink_password = os.environ.get("TPLINK_PASSWORD")

    if sys.platform != "darwin":
        print("Note: written for macOS. Some system commands may differ.\n")

    labels = load_labels()
    if args.label:
        for entry in args.label:
            if "=" in entry:
                mac, name = entry.split("=", 1)
                labels[mac.strip().lower()] = name.strip()
        save_labels(labels)
        print(f"Labels saved ({len(labels)} total).\n")

    state = action_full_audit(
        full_scan=args.full,
        no_vendors=args.no_vendors,
        no_speedtest=args.no_speedtest,
        upstream_ip=args.upstream,
        tplink_password=tplink_password,
        subnet_overrides=args.subnet,
        extra_subnets=getattr(args, "extra_subnet", None),
        probe_creds=args.probe_creds,
        no_discovery=args.no_discovery,
    )

    if args.no_save_baseline:
        pass
    elif state.get("gateway") is None:
        # Saving a gateway-less run would drop router_open_ports from the
        # baseline and trigger false "NEW open port" alarms on the next run.
        print("\nSkipping baseline save: gateway could not be determined, so this "
              "scan is incomplete and would corrupt change detection.")
    else:
        if args.publish_to:
            os.environ[SINK_ENV] = args.publish_to
        passphrase = resolve_passphrase(prompt=args.seal_baseline)
        _record = save_baseline(state, passphrase=passphrase)
        print(f"\nBaseline saved to {BASELINE_FILE}")
        _pub = describe_publish_result(_record.get("_receipt"))
        if _pub:
            print(_pub)
        if passphrase is None:
            print(f"Note: saved unsealed. Use --seal-baseline or set "
                  f"{PASSPHRASE_ENV} to make it tamper-evident.")

    if args.html_report:
        path = generate_html_report(state)
        print(f"HTML report saved to {path}")


if __name__ == "__main__":
    main()
