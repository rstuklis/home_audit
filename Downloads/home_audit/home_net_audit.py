#!/usr/bin/env python3
"""
home_net_audit.py
=================
A defensive, read-only audit of YOUR OWN home network, designed to run in
Terminal on macOS using only the Python standard library (no pip installs).

It does four things:
  1. Identifies your router (the default gateway).
  2. Port-scans the router and flags risky / unexpected open services.
  3. Discovers every device currently on your LAN so you can spot intruders.
  4. Reports your DNS settings (a common target of router compromise) and
     can compare today's findings against a saved baseline to detect changes.

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
  SNMP  = Simple Network Management Protocol (device management; info leak risk)
  SMB   = Server Message Block (Windows file sharing; should not be on a router)
  CWMP  = CPE WAN Management Protocol, aka TR-069 (ISP remote mgmt; CVE-prone)
"""

import argparse
import concurrent.futures as futures
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASELINE_DIR = os.path.expanduser("~/.home_net_audit")
BASELINE_FILE = os.path.join(BASELINE_DIR, "baseline.json")

# Ports worth checking on the router, with a plain-English risk note.
# (port: (service, risk_level, explanation))
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

# A small "fast" set for quick scans; --full scans 1-65535.
COMMON_PORTS = sorted(set(list(PORTS_OF_INTEREST.keys()) + [
    25, 110, 143, 3389, 5353, 5900, 8000, 8888, 9000, 1883
]))

# Well-known public DNS resolvers. If your router/Mac uses one of these or your
# ISP's own, that's normal. An unfamiliar address is worth investigating, as
# DNS hijacking is a common symptom of router compromise.
KNOWN_DNS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}

# ---------------------------------------------------------------------------
# Helpers for talking to macOS
# ---------------------------------------------------------------------------

def run(cmd, timeout=10):
    """Run a shell command, return stdout as text (empty string on failure)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
        return out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def get_default_gateway():
    """Return the router's IP (the default gateway) on macOS."""
    out = run(["route", "-n", "get", "default"])
    m = re.search(r"gateway:\s*([\d.]+)", out)
    if m:
        return m.group(1)
    # Fallback for other layouts
    out = run(["netstat", "-rn"])
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if len(parts) >= 2 and re.match(r"[\d.]+$", parts[1]):
                return parts[1]
    return None


def get_local_ip():
    """Best-effort local IP by opening a throwaway UDP socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def guess_subnet(local_ip):
    """Assume a /24 (255.255.255.0) home network, the overwhelming default."""
    if not local_ip:
        return None
    net = ipaddress.ip_network(local_ip + "/24", strict=False)
    return net


def get_dns_servers():
    """Parse `scutil --dns` for the resolvers macOS is actually using."""
    out = run(["scutil", "--dns"])
    servers = []
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*([\d.]+)", out):
        ip = m.group(1)
        if ip not in servers:
            servers.append(ip)
    return servers


def read_arp_table():
    """Return {ip: mac} from the system ARP cache (`arp -a`)."""
    out = run(["arp", "-a"])
    table = {}
    for line in out.splitlines():
        ip_m = re.search(r"\(([\d.]+)\)", line)
        mac_m = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
        if ip_m and mac_m:
            # Normalise MAC to two-digit lowercase octets
            raw = mac_m.group(1).split(":")
            mac = ":".join(f"{int(x, 16):02x}" for x in raw)
            table[ip_m.group(1)] = mac
    return table


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def check_port(host, port, timeout=0.6):
    """Return True if a TCP connection to host:port succeeds."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def scan_ports(host, ports, workers=200):
    """Concurrently scan a list of ports on one host; return sorted open ports."""
    open_ports = []
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = {pool.submit(check_port, host, p): p for p in ports}
        for fut in futures.as_completed(results):
            if fut.result():
                open_ports.append(results[fut])
    return sorted(open_ports)


def ping(ip):
    """Single ping (macOS syntax). Returns the ip if it replies, else None."""
    out = subprocess.run(["ping", "-c", "1", "-t", "1", str(ip)],
                        capture_output=True, text=True)
    return str(ip) if out.returncode == 0 else None


def is_real_host(ip, mac, subnet):
    """Exclude network/broadcast/multicast pseudo-entries that ARP reports.

    The ARP cache often contains the subnet broadcast address (x.x.x.255,
    MAC ff:ff:ff:ff:ff:ff) and multicast groups such as 224.0.0.251 used by
    mDNS (MAC prefix 01:00:5e). These are not real devices on the network.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    if ip == str(subnet.network_address) or ip == str(subnet.broadcast_address):
        return False
    if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith(("01:00:5e", "33:33")):
        return False
    return True


def discover_devices(subnet, workers=120):
    """Ping-sweep the subnet, then read the ARP cache to map IP -> MAC."""
    hosts = [h for h in subnet.hosts()]
    alive = set()
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(ping, hosts):
            if res:
                alive.add(res)
    arp = read_arp_table()          # populated by the sweep above
    devices = []
    for ip in sorted(alive | set(arp.keys()),
                     key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp.get(ip, "unknown")
        if is_real_host(ip, mac, subnet):
            devices.append({"ip": ip, "mac": mac})
    return devices


# A few high-confidence OUI (Organisationally Unique Identifier) prefixes used
# as an offline fallback when the online lookup is unavailable. The online API
# covers everything else.
OUI_HINTS = {
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi (Trading) Ltd",
    "e4:5f:01": "Raspberry Pi (Trading) Ltd",
    "3c:28:6d": "Google",
    "38:8b:59": "Google",
    "34:64:a9": "Hewlett Packard",
}


def is_randomized_mac(mac):
    """True if the locally-administered bit is set (a privacy-randomized MAC).

    Modern phones/laptops rotate a random MAC per network for privacy, so these
    have no real manufacturer to look up. The giveaway is bit 0x02 of octet one.
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def lookup_vendor(mac):
    """Best-effort OUI -> vendor. Labels randomized MACs; offline fallback."""
    if mac == "unknown":
        return ""
    if is_randomized_mac(mac):
        return "(randomized/private MAC)"
    prefix = ":".join(mac.split(":")[:3])
    try:
        import urllib.request
        req = urllib.request.Request("https://api.macvendors.com/" + mac,
                                     headers={"User-Agent": "home_net_audit"})
        with urllib.request.urlopen(req, timeout=4) as r:
            name = r.read().decode("utf-8", "ignore").strip()
            if name:
                return name
    except Exception:
        pass
    return OUI_HINTS.get(prefix, "")


def check_tls(host, port=443):
    """Inspect the admin HTTPS certificate, if present."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert(binary_form=False) or {}
                der = ss.getpeercert(binary_form=True)
                return {"present": True, "cert_bytes": len(der) if der else 0}
    except Exception:
        return {"present": False}


# ---------------------------------------------------------------------------
# Baseline (change detection)
# ---------------------------------------------------------------------------

def load_baseline():
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_baseline(state):
    os.makedirs(BASELINE_DIR, exist_ok=True)
    with open(BASELINE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def diff_baseline(old, new):
    """Return human-readable changes between two audit states."""
    notes = []
    old_macs = {d["mac"] for d in old.get("devices", []) if d["mac"] != "unknown"}
    new_macs = {d["mac"] for d in new.get("devices", []) if d["mac"] != "unknown"}
    appeared = new_macs - old_macs
    vanished = old_macs - new_macs
    if appeared:
        notes.append(f"NEW device(s) since baseline: {', '.join(sorted(appeared))}")
    if vanished:
        notes.append(f"Device(s) gone since baseline: {', '.join(sorted(vanished))}")

    old_ports = set(old.get("router_open_ports", []))
    new_ports = set(new.get("router_open_ports", []))
    if new_ports - old_ports:
        notes.append(f"NEW open port(s) on router: {sorted(new_ports - old_ports)}")
    if old_ports - new_ports:
        notes.append(f"Port(s) now closed on router: {sorted(old_ports - new_ports)}")

    if set(old.get("dns", [])) != set(new.get("dns", [])):
        notes.append(f"DNS servers CHANGED: was {old.get('dns')}, now {new.get('dns')}")
    return notes


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def hr(title=""):
    print("\n" + "=" * 64)
    if title:
        print(title)
        print("=" * 64)


def main():
    ap = argparse.ArgumentParser(description="Defensive audit of your own home network.")
    ap.add_argument("--subnet", help="Override subnet, e.g. 192.168.1.0/24")
    ap.add_argument("--full", action="store_true", help="Full router port scan (1-65535, slower)")
    ap.add_argument("--no-vendors", action="store_true", help="Skip online vendor lookups (faster)")
    ap.add_argument("--save-baseline", action="store_true", help="Save this run as the comparison baseline")
    ap.add_argument("--no-discovery", action="store_true", help="Skip the LAN device sweep")
    args = ap.parse_args()

    if sys.platform != "darwin":
        print("Note: written for macOS. Some system commands may differ on this OS.\n")

    state = {"timestamp": datetime.now(timezone.utc).isoformat()}

    # --- Router ---
    hr("ROUTER")
    gateway = get_default_gateway()
    local_ip = get_local_ip()
    print(f"Your Mac's IP : {local_ip}")
    print(f"Router (gateway): {gateway}")
    state["gateway"] = gateway

    if gateway:
        port_set = range(1, 65536) if args.full else COMMON_PORTS
        print(f"Scanning {'all 65535' if args.full else len(COMMON_PORTS)} ports on the router...")
        t0 = time.time()
        open_ports = scan_ports(gateway, port_set)
        state["router_open_ports"] = open_ports
        print(f"Done in {time.time()-t0:.1f}s. Open ports: {open_ports or 'none found'}")

        hr("ROUTER SERVICE ASSESSMENT")
        if not open_ports:
            print("No open ports detected on the router from the LAN side.")
        for p in open_ports:
            svc, risk, note = PORTS_OF_INTEREST.get(p, ("unknown", "REVIEW", "Unrecognised service; investigate."))
            print(f"  [{risk:6}] {p:>5}  {svc:<14} {note}")

        tls = check_tls(gateway)
        print(f"\nHTTPS admin certificate present: {tls.get('present')}")
        if open_ports and 80 in open_ports and 443 not in open_ports:
            print("  Note: port 80 is open without 443. If your router exposes a")
            print("  browser-based admin page, prefer HTTPS for it. But app-managed")
            print("  mesh systems (Google Nest Wifi, eero, etc.) have NO web login —")
            print("  on those, 80/5000/8080 are local service ports used by the")
            print("  vendor's app, not an exposed admin panel. What actually matters")
            print("  is WAN (internet-side) exposure, not these LAN-side ports.")

    # --- DNS ---
    hr("DNS SETTINGS")
    dns = get_dns_servers()
    state["dns"] = dns
    if not dns:
        print("Could not read DNS settings.")
    for d in dns:
        label = KNOWN_DNS.get(d)
        if label:
            print(f"  {d}  (recognised public resolver: {label})")
        elif gateway and d == gateway:
            print(f"  {d}  (your router — normal; it forwards to your ISP)")
        else:
            print(f"  {d}  <-- unfamiliar. Confirm this is your ISP/router. "
                  f"Unexpected DNS can indicate hijacking.")

    # --- Devices ---
    if not args.no_discovery:
        hr("CONNECTED DEVICES")
        subnet = ipaddress.ip_network(args.subnet, strict=False) if args.subnet else guess_subnet(local_ip)
        if subnet:
            print(f"Sweeping {subnet} (this takes ~10-30s)...")
            devices = discover_devices(subnet)
            if not args.no_vendors:
                print("Looking up device vendors (the free API is rate-limited, "
                      "so this adds a few seconds)...")
                for d in devices:
                    mac = d["mac"]
                    hits_api = mac != "unknown" and not is_randomized_mac(mac)
                    d["vendor"] = lookup_vendor(mac)
                    if hits_api:
                        time.sleep(1.1)  # be polite to the free vendor API
            state["devices"] = devices
            print(f"\nFound {len(devices)} device(s):")
            for d in devices:
                vend = f"  {d.get('vendor','')}" if d.get("vendor") else ""
                print(f"  {d['ip']:<15} {d['mac']}{vend}")
            print("\nReview this list: anything you don't recognise is worth chasing down.")
        else:
            print("Could not determine subnet; pass one with --subnet 192.168.1.0/24")

    # --- Baseline comparison ---
    hr("CHANGE DETECTION (vs saved baseline)")
    old = load_baseline()
    if old:
        changes = diff_baseline(old, state)
        print(f"Baseline from: {old.get('timestamp','?')}")
        if changes:
            print("CHANGES DETECTED:")
            for c in changes:
                print("  ! " + c)
        else:
            print("No changes since baseline.")
    else:
        print("No baseline saved yet. Run again with --save-baseline once you've")
        print("confirmed everything above looks correct, to enable change detection.")

    if args.save_baseline:
        save_baseline(state)
        print(f"\nBaseline saved to {BASELINE_FILE}")

    hr()
    print("Audit complete. This is a snapshot, not a guarantee.")
    print("For deeper checks, consider `nmap` and your router vendor's advisories.")


if __name__ == "__main__":
    main()
