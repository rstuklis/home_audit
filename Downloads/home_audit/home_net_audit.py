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
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASELINE_DIR = os.path.expanduser("~/.home_net_audit")
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
BASELINE_FORMAT = 2
KDF_ITERATIONS = 200_000

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
ALERT_ENV = "HOME_NET_AUDIT_ALERT"
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
    """
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
    out = run(["arp", "-a"])
    table = {}
    for line in out.splitlines():
        ip_m = re.search(r"\(([\d.]+)\)", line)
        mac_m = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
        if ip_m and mac_m:
            # Validate/normalise the IP so a malformed capture (e.g. leading
            # zeros) can't later crash sorted(..., key=ipaddress.ip_address).
            try:
                ip = str(ipaddress.ip_address(ip_m.group(1)))
            except ValueError:
                continue
            raw = mac_m.group(1).split(":")
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


def check_port(host, port, timeout=0.6):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return s.connect_ex((host, port)) == 0
        finally:
            s.close()
    except OSError:
        # socket() itself can raise (e.g. EMFILE "too many open files" under
        # high worker counts); treat any socket error as "port not open".
        return False


def scan_ports(host, ports, workers=100):
    open_ports = []
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = {pool.submit(check_port, host, p): p for p in ports}
        for fut in futures.as_completed(results):
            try:
                if fut.result():
                    open_ports.append(results[fut])
            except OSError:
                # A single failed probe should not abort the whole scan.
                pass
    return sorted(open_ports)


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
        return "(randomized/private MAC)"
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
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_dns_query(), (target, 53))
        data, addr = sock.recvfrom(512)
    except (socket.timeout, OSError):
        return {"intercepted": False, "responder": None, "risk": "OK",
                "note": f"No answer from {target}, which is the correct result — "
                        "port 53 is not being transparently redirected."}
    finally:
        sock.close()

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
    """Return the append-only chain of past baseline seals, oldest first."""
    entries = []
    try:
        with open(HISTORY_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
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


def save_baseline(state, passphrase=None):
    """Seal `state` into the baseline and extend the tamper-evidence chain.

    Returns the record that was written. Passing no passphrase still chains and
    seals, but with a bare hash rather than an HMAC — see seal_payload.
    """
    history = read_history()
    prev = history[-1]["seal"] if history else None
    seq = (history[-1]["seq"] + 1) if history else 1

    record = {
        "format": BASELINE_FORMAT,
        "seq": seq,
        "prev": prev,
        "keyed": passphrase is not None,
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
    """Return the raw baseline record, whatever format it is in, or None."""
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


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
      absent        no baseline saved yet
      legacy        pre-integrity baseline; nothing to verify
      ok            seal recomputes and the chain agrees
      unverifiable  sealed with a passphrase that was not supplied
      modified      the seal does not match the contents
      rolled_back   valid record, but older than the chain has already recorded
      chain_missing the record claims history that is not there
    """
    record = load_baseline_record()
    if record is None:
        return {"status": "absent", "keyed": False,
                "detail": "No baseline saved yet."}
    if not isinstance(record, dict) or record.get("format") != BASELINE_FORMAT:
        return {"status": "legacy", "keyed": False,
                "detail": "Baseline predates integrity checking and is unauthenticated. "
                          "Re-save it to start a verifiable chain."}

    keyed = bool(record.get("keyed"))
    if keyed and passphrase is None:
        return {"status": "unverifiable", "keyed": True,
                "detail": "Baseline is sealed with a passphrase; supply it to verify."}

    key = None
    if keyed:
        kdf = record.get("kdf") or {}
        try:
            salt = bytes.fromhex(kdf.get("salt", ""))
        except ValueError:
            return {"status": "modified", "keyed": True,
                    "detail": "Key derivation parameters are malformed."}
        key = derive_baseline_key(passphrase, salt,
                                  kdf.get("iterations", KDF_ITERATIONS))

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

def baseline_receipt(record):
    """The minimum that proves a run happened, and nothing more.

    Deliberately excludes the audit state. A receipt is enough to detect a
    rollback or a wiped history later, and shipping MAC addresses, network
    topology and any accepted credentials to a remote endpoint would create a
    fresh disclosure risk for exactly the users this is meant to protect.
    Publishing the full record is available but has to be asked for.
    """
    return {
        "seq": record.get("seq"),
        "seal": record.get("seal"),
        "prev": record.get("prev"),
        "keyed": record.get("keyed"),
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


def _publish_https(payload, url, token, mode):
    headers = {"Content-Type": "application/json", "User-Agent": "home_net_audit"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=canonical_json(payload), headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        code = r.getcode()
    return {"published": True, "mode": mode,
            "detail": f"Receipt accepted by {url} (HTTP {code})."}


def read_receipts(source):
    """Read back a receipt log to compare against. Returns [] if unreadable."""
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
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return entries


def compare_with_receipts(record, receipts):
    """Check the local baseline against the off-host record of what ran.

    This is what catches the attack local sealing cannot: wiping
    ~/.home_net_audit and letting the next run start clean. Locally that is
    indistinguishable from a genuine first run — but the receipt log still shows
    run 7, and a local baseline claiming run 1 gives it away.

    Returns {status, detail}. Statuses: ok, no_receipts, history_truncated,
    seal_mismatch.
    """
    if not receipts:
        return {"status": "no_receipts",
                "detail": "No off-host receipts to compare against."}

    highest = max((r.get("seq") or 0) for r in receipts)
    local_seq = (record or {}).get("seq") or 0

    if local_seq < highest:
        return {"status": "history_truncated",
                "detail": f"Off-host receipts record {highest} runs but this machine's "
                          f"baseline is at run {local_seq}. Local history has been "
                          "truncated or deleted — the strongest single indicator "
                          "available that something removed the evidence."}

    match = [r for r in receipts if r.get("seq") == local_seq]
    if match and record and match[-1].get("seal") != record.get("seal"):
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
    """The cheap half of the audit: what an attacker has to change to redirect you."""
    gateway = get_default_gateway()
    arp = read_arp_table()
    return {
        "gateway": gateway,
        "gateway_mac": arp.get(gateway) if gateway else None,
        "ipv6_routers": get_ipv6_routers(),
        "dns": get_dns_servers(),
        "neighbours": sorted(arp),
    }


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
            return _publish_https(payload, destination,
                                  token or os.environ.get(SINK_TOKEN_ENV), "alert")
        return _publish_path(payload, destination, "alert")
    except Exception as e:                      # noqa: BLE001 - reported, not raised
        return {"published": False,
                "detail": f"Could not deliver the alert to {destination}: {e}"}


def run_monitor(interval=MONITOR_INTERVAL, iterations=None, alert_to=None,
                sleeper=time.sleep, printer=print):
    """Poll the cheap checks and alert on change.

    `iterations=None` runs until interrupted; a number bounds it, which is what
    makes this testable without waiting. Returns every event raised.
    """
    previous = None
    raised = []
    count = 0
    printer(f"Monitoring every {interval}s. Watching the gateway, its MAC, IPv6 "
            "routers, DNS and the neighbour table.")
    if not resolve_alert_sink(alert_to):
        printer("  Note: no alert destination set. Findings will print here only — "
                f"set {ALERT_ENV} so they leave this machine.")
    try:
        while iterations is None or count < iterations:
            snapshot = monitor_snapshot()
            for event in diff_snapshots(previous, snapshot):
                raised.append(event)
                printer(f"  [{event['severity']:6}] {event['detail']}")
                result = send_alert(event, alert_to)
                if not result["published"]:
                    printer(f"           (not delivered: {result['detail']})")
            previous = snapshot
            count += 1
            if iterations is None or count < iterations:
                sleeper(interval)
    except KeyboardInterrupt:
        printer("\nStopped.")
    return raised


def describe_receipt_status(report):
    risk = {
        "ok": "OK",
        "no_receipts": "REVIEW",
        "history_truncated": "HIGH",
        "seal_mismatch": "HIGH",
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
    }.get(report.get("status"), "REVIEW")
    return f"  [{risk:6}] Baseline integrity: {report.get('detail', '')}"


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
        macs = {d["mac"] for d in entry.get("devices", []) if d["mac"] != "unknown"}
        stable = {m for m in macs if not is_randomized_mac(m)}
        return stable, macs - stable

    old_macs, old_private = _split(old)
    new_macs, new_private = _split(new)
    appeared = new_macs - old_macs
    vanished = old_macs - new_macs
    if appeared:
        notes.append(f"NEW device(s) since baseline: {', '.join(sorted(appeared))}")
    if vanished:
        notes.append(f"Device(s) gone since baseline: {', '.join(sorted(vanished))}")
    if len(new_private) > len(old_private):
        notes.append(
            f"{len(new_private)} device(s) using rotating private addresses, up "
            f"from {len(old_private)}. These cannot be identified across runs, so "
            "they are counted rather than named; a rise can be new devices or the "
            "same ones having re-randomised.")
    old_ports = set(old.get("router_open_ports", []))
    new_ports = set(new.get("router_open_ports", []))
    if new_ports - old_ports:
        notes.append(f"NEW open port(s) on router: {sorted(new_ports - old_ports)}")
    if old_ports - new_ports:
        notes.append(f"Port(s) now closed on router: {sorted(old_ports - new_ports)}")
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
_DSL_PATTERNS = {
    "downstream_kbps":   [re.compile(r"[Dd]own(?:stream)?[^<]{0,40}?(\d{3,6})\s*[Kk]bps")],
    "upstream_kbps":     [re.compile(r"[Uu]p(?:stream)?[^<]{0,40}?(\d{3,6})\s*[Kk]bps")],
    "downstream_snr_db": [re.compile(r"[Dd]own(?:stream)?[^<]{0,40}?SNR[^<]{0,20}([\d.]+)")],
    "upstream_snr_db":   [re.compile(r"[Uu]p(?:stream)?[^<]{0,40}?SNR[^<]{0,20}([\d.]+)")],
    "downstream_attn_db":[re.compile(r"[Dd]own(?:stream)?[^<]{0,40}?[Aa]ttenuation[^<]{0,20}([\d.]+)")],
    "upstream_attn_db":  [re.compile(r"[Uu]p(?:stream)?[^<]{0,40}?[Aa]ttenuation[^<]{0,20}([\d.]+)")],
}


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
        return stats, "Could not retrieve DSL stats — auth failed or unknown page paths"

    for key, pats in _DSL_PATTERNS.items():
        for pat in pats:
            m = pat.search(raw)
            if m:
                try:
                    stats[key] = float(m.group(1))
                except ValueError:
                    pass
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
            if candidate and not candidate.endswith("Networks") \
                    and not candidate.endswith("Information"):
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
    """
    magic = data.find(b"\x63\x82\x53\x63")
    if magic < 0:
        return {}
    options = {}
    i = magic + 4
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
                data, addr = sock.recvfrom(1024)
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
        return [], f"Could not bind to port 68 (try sudo): {e}"
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(msearch.encode(), (SSDP_ADDR, SSDP_PORT))
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
                text = data.decode("utf-8", "ignore")
                loc_m = re.search(r"(?i)LOCATION:\s*(\S+)", text)
                if loc_m:
                    location = loc_m.group(1).strip()
                    break
            except socket.timeout:
                break
    except OSError:
        pass
    finally:
        sock.close()

    if not location:
        return [], "No UPnP device found via SSDP (router may have UPnP disabled)"

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
        return {"mappings": [], "error": "No gateway"}

    print(f"  Querying UPnP on gateway {gateway} via SSDP...")
    mappings, err = get_upnp_port_mappings(gateway)

    if err:
        print(f"  [INFO] {err}")
        return {"mappings": [], "note": err}

    if not mappings:
        print("  No active UPnP port mappings found.")
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
        # Force a fresh ARP entry by pinging the gateway
        subprocess.run(["ping", "-c", "1", "-t", "1", gateway],
                       capture_output=True)
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

    Returns list of (username, password, port, method) tuples.
    """
    import base64
    successes = []
    ports_to_try = [80, 8080, 8443, 443]

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

        if auth_code in (401, 403):
            return False  # rejected

        # Step 3: verify the response body is an admin page, not a login form
        return _body_is_authed(body)

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
        for ep in endpoints:
            # First GET the endpoint — skip if it doesn't exist or has no login form
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

            for pl in payloads:
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
                    continue
                if _body_is_authed(body):
                    return True
        return False

    lockout_note = None
    try:
        for port in ports_to_try:
            scheme = "https" if port in (443, 8443) else "http"
            base = f"{scheme}://{gateway}:{port}"
            if not check_port(gateway, port, timeout=1.0):
                continue

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

    return successes, lockout_note


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
    successes, lockout_note = probe_default_credentials(gateway)

    if lockout_note:
        print(f"\n  [STOPPED] {lockout_note}")
        print("            Aborted early to avoid locking you out of your router.")

    if successes:
        print(f"\n  [HIGH] Default credentials ACCEPTED on gateway {gateway}:")
        for user, pwd, port, method in successes:
            display_pwd = pwd if pwd else "(empty)"
            print(f"    Port {port} ({method}): {user} / {display_pwd}")
        print("\n  Change your router admin password immediately!")
    elif not lockout_note:
        print("  [OK] No default credentials accepted (or admin page not reachable).")

    return {"gateway": gateway, "successes": successes}


# ---------------------------------------------------------------------------
# NEW FEATURE 6: Router hostname check
# ---------------------------------------------------------------------------

def check_router_hostname(gateway):
    """
    Perform a reverse DNS lookup on the gateway IP.
    An unexpected or suspicious hostname may indicate a rogue router.
    Returns dict: {gateway, hostname, suspicious}
    """
    try:
        hostname = socket.gethostbyaddr(gateway)[0]
    except socket.herror:
        hostname = None
    except Exception:
        hostname = None

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

    return {"gateway": gateway, "hostname": hostname, "suspicious": suspicious, "note": note}


def action_router_hostname():
    hr("ROUTER HOSTNAME CHECK")
    gateway = get_default_gateway()
    if not gateway:
        print("  Could not determine gateway.")
        return {}

    result = check_router_hostname(gateway)
    print(f"  Gateway IP : {result['gateway']}")
    print(f"  Hostname   : {result['hostname'] or '(none)'}")
    risk = "HIGH" if result["suspicious"] else "OK"
    print(f"  [{risk}] {result['note']}")
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
            proto = parts[0].upper().replace("6", "").replace("4", "")
            # macOS netstat uses a DOT before the port (e.g. "*.59882").
            m = re.search(r"[.:](\d+)$", parts[3])
            if m:
                key = (proto, int(m.group(1)))
                if key not in listeners:
                    listeners[key] = {"proto": proto, "port": int(m.group(1)),
                                      "pid": "?", "process": "?"}

    return sorted(listeners.values(), key=lambda x: x["port"])


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

    flagged = []
    print(f"\n  {'Port':<7} {'Proto':<6} {'Process':<22} Note")
    print(f"  {'-'*5:<7} {'-'*5:<6} {'-'*20:<22} {'-'*30}")
    for s in services:
        port = s["port"]
        note = SYSTEM_PORTS.get(port, "")
        marker = "  "
        if port >= 1024 and not note:
            marker = "* "
            flagged.append(s)
        print(f"{marker} {port:<7} {s['proto']:<6} {s['process']:<22} {note}")

    if flagged:
        print(f"\n  * {len(flagged)} non-system listener(s) marked above. Verify you recognise them.")
    else:
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
            smb_cfg = (m.group(1) == "enabled")
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
    elif result["block_all"]:
        result["note"] = "Block all mode — maximum restriction. Verify legitimate apps still work."
    elif result["stealth_mode"]:
        result["note"] = "Enabled with stealth mode — good configuration."
    else:
        result["note"] = "Enabled (stealth mode off). Consider enabling stealth mode for extra protection."

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
        body = f"""<table><tbody>
          <tr><td><strong>SSID</strong></td><td>{_esc(w.get('ssid','?'))}</td></tr>
          <tr><td><strong>Auth</strong></td><td>{_esc(w.get('auth','?'))}</td></tr>
          <tr><td><strong>Risk</strong></td><td>{risk_badge(w.get('risk','?'))}</td></tr>
          <tr><td><strong>Note</strong></td><td>{_esc(w.get('note',''))}</td></tr>
        </tbody></table>"""
        sections_html += section("Wi-Fi Security", body)

    # ARP spoofing
    if "arp_spoof" in state:
        a = state["arp_spoof"]
        risk = "HIGH" if a.get("spoofing_suspected") else "OK"
        body = f"""<p>{risk_badge(risk)} Gateway: {_esc(a.get('gateway','?'))}</p>
                   <p>MACs seen: {_esc(', '.join(a.get('macs_seen', []) or ['none']))}</p>"""
        if a.get("spoofing_suspected"):
            body += "<p style='color:red'><strong>⚠ Multiple MACs detected — possible ARP poisoning!</strong></p>"
        sections_html += section("ARP Spoofing Check", body)

    # Firewall
    if "firewall" in state:
        fw = state["firewall"]
        risk = "OK" if fw.get("enabled") else "HIGH"
        body = f"""<p>{risk_badge(risk)} Firewall: {'ON' if fw.get('enabled') else 'OFF'}</p>
                   <p>Stealth mode: {'ON' if fw.get('stealth_mode') else 'OFF'}</p>
                   <p>{_esc(fw.get('note',''))}</p>"""
        sections_html += section("Firewall Status", body)

    # Sharing services
    if "sharing" in state:
        rows = []
        colours = []
        for s in state["sharing"]:
            state_str = "ON" if s["enabled"] else "OFF"
            rows.append([s["name"], state_str, risk_badge(s["risk"]), s["note"]])
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
            body = f"<p>{risk_badge('OK')} No default credentials accepted.</p>"
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
            note = state["upnp"].get("note", "No UPnP port mappings found.")
            body = f"<p>{note}</p>"
        sections_html += section("UPnP Port Mappings", body)

    # DHCP
    if "dhcp" in state:
        responders = state["dhcp"].get("responders", [])
        if len(responders) > 1:
            rows = [[r["ip"], r["offered_ip"]] for r in responders]
            body = f"<p>{risk_badge('HIGH')} Multiple DHCP servers detected!</p>" + \
                   table(["Server IP", "Offered IP"], rows)
        elif responders:
            body = f"<p>{risk_badge('OK')} One DHCP server: {responders[0]['ip']}</p>"
        else:
            body = "<p>No DHCP responses captured.</p>"
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
        risk = "HIGH" if rh.get("suspicious") else "OK"
        body = f"""<p>{risk_badge(risk)} Gateway: {_esc(rh.get('gateway','?'))}</p>
                   <p>Hostname: {_esc(rh.get('hostname') or '(none)')}</p>
                   <p>{_esc(rh.get('note',''))}</p>"""
        sections_html += section("Router Hostname Check", body)

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

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

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
    open_ports = scan_ports(host, port_set)
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
            display_name = name or vend
            tag = f"  {display_name}" if display_name else ""
            flag = "" if display_name else "  <-- unlabelled"
            print(f"    {d['ip']:<15} {mac}{tag}{flag}")
            if not display_name:
                unlabelled.append(mac)
            total += 1

    print(f"\n  Total: {total} device(s) across {len(display_order)} subnet(s) scanned.")
    if unlabelled:
        print(f"  {len(unlabelled)} unidentified device(s). Tag them with:")
        print(f"    python3 home_net_audit.py --label MAC='Device Name' ...")


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
    return ordered


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
                d["vendor"] = "(randomized/private MAC)"
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
    """
    hr("CONNECTED DEVICES")
    interfaces = get_all_interfaces()
    local_ip = get_local_ip()
    labels = load_labels()
    networks = load_networks()

    subnets_to_sweep = resolve_subnets(subnet_overrides, extra_subnets, interfaces, local_ip)
    if not subnets_to_sweep:
        print("  Could not determine any subnet. Pass one with --subnet 192.168.1.0/24")
        return []

    all_devices = collect_devices(subnets_to_sweep, labels, networks,
                                  no_vendors=no_vendors, sweep_note="  (this takes ~10-30s)")
    _print_devices_grouped(all_devices, labels, networks, scanned_subnets=subnets_to_sweep)
    return all_devices


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
    passphrase = resolve_passphrase(prompt=True)
    save_baseline(state, passphrase=passphrase)
    print(f"Baseline saved to {BASELINE_FILE}")
    if passphrase is None:
        print("  Note: saved unsealed. Set a passphrase (or "
              f"{PASSPHRASE_ENV}) so the baseline cannot be silently rewritten.")
    print(f"Timestamp: {state.get('timestamp', '?')}")
    keys = [k for k in state if k != "timestamp"]
    print(f"Saved sections: {', '.join(keys)}")


def action_compare_baseline(state):
    hr("CHANGE DETECTION (vs saved baseline)")
    print(describe_baseline_integrity(verify_baseline(resolve_passphrase())))
    _sink = resolve_sink()
    if _sink:
        print(describe_receipt_status(compare_with_receipts(
            load_baseline_record(), read_receipts(_sink))))
    old = load_baseline()
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
        tplink_ip = upstream_ip or "192.168.1.1"
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
            load_baseline_record(), read_receipts(_sink))))
    old = load_baseline()
    if old:
        changes = diff_baseline(old, state)
        print(f"Baseline from: {old.get('timestamp', '?')}")
        if changes:
            print("CHANGES DETECTED:")
            for c in changes:
                print("  ! " + c)
        else:
            print("No changes since baseline.")
    else:
        print("No baseline saved yet. Use option 5 after reviewing results.")

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
            devices = action_discover_devices(no_vendors=no_v, subnet_overrides=subnet_overrides)
            ts(); session_state["devices"] = devices

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
                    "Run with no arguments for an interactive menu.")
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
        save_baseline(state, passphrase=passphrase)
        print(f"\nBaseline saved to {BASELINE_FILE}")
        if passphrase is None:
            print(f"Note: saved unsealed. Use --seal-baseline or set "
                  f"{PASSPHRASE_ENV} to make it tamper-evident.")

    if args.html_report:
        path = generate_html_report(state)
        print(f"HTML report saved to {path}")


if __name__ == "__main__":
    main()
