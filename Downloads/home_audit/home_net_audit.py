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
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASELINE_DIR = os.path.expanduser("~/.home_net_audit")
BASELINE_FILE = os.path.join(BASELINE_DIR, "baseline.json")
LABELS_FILE   = os.path.join(BASELINE_DIR, "labels.json")
NETWORKS_FILE = os.path.join(BASELINE_DIR, "networks.json")

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

def run(cmd, timeout=10):
    """Run a shell command, return stdout as text (empty string on failure)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def get_default_gateway():
    out = run(["route", "-n", "get", "default"])
    m = re.search(r"gateway:\s*([\d.]+)", out)
    if m:
        return m.group(1)
    out = run(["netstat", "-rn"])
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if len(parts) >= 2 and re.match(r"[\d.]+$", parts[1]):
                return parts[1]
    return None


def get_all_interfaces():
    out = run(["ifconfig", "-a"])
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
            except ValueError:
                pass
    return results


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


def get_dns_servers():
    out = run(["scutil", "--dns"])
    servers = []
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*([\d.]+)", out):
        ip = m.group(1)
        if ip not in servers:
            servers.append(ip)
    return servers


def read_arp_table():
    out = run(["arp", "-a"])
    table = {}
    for line in out.splitlines():
        ip_m = re.search(r"\(([\d.]+)\)", line)
        mac_m = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
        if ip_m and mac_m:
            raw = mac_m.group(1).split(":")
            mac = ":".join(f"{int(x, 16):02x}" for x in raw)
            table[ip_m.group(1)] = mac
    return table


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def check_port(host, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def scan_ports(host, ports, workers=200):
    open_ports = []
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = {pool.submit(check_port, host, p): p for p in ports}
        for fut in futures.as_completed(results):
            if fut.result():
                open_ports.append(results[fut])
    return sorted(open_ports)


def ping(ip):
    out = subprocess.run(["ping", "-c", "1", "-t", "1", str(ip)],
                         capture_output=True, text=True)
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
    for ip in sorted(alive | set(arp.keys()),
                     key=lambda x: tuple(int(p) for p in x.split("."))):
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
    except Exception:
        pass
    return OUI_HINTS.get(prefix, "")


def check_tls(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                return {"present": True, "cert_bytes": len(der) if der else 0}
    except Exception:
        return {"present": False}


# ---------------------------------------------------------------------------
# Baseline
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
# Speed test & DSL stats
# ---------------------------------------------------------------------------

def speed_test(duration=6):
    dl_url = "https://speed.cloudflare.com/__down?bytes=10000000"
    dl_mbps = None
    try:
        req = urllib.request.Request(dl_url, headers={"User-Agent": "home_net_audit"})
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
            dl_mbps = (total * 8) / elapsed / 1_000_000
    except Exception:
        pass

    ul_url = "https://speed.cloudflare.com/__up"
    ul_mbps = None
    try:
        data = os.urandom(5_000_000)
        req = urllib.request.Request(ul_url, data=data,
                                     headers={"User-Agent": "home_net_audit",
                                              "Content-Type": "application/octet-stream"})
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=15):
            pass
        elapsed = time.time() - t0
        if elapsed > 0:
            ul_mbps = (len(data) * 8) / elapsed / 1_000_000
    except Exception:
        pass

    return dl_mbps, ul_mbps


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
    if not jar._cookies and "success" not in login_resp.lower():
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

    patterns = {
        "downstream_kbps":   [r"[Dd]own(?:stream)?[^<]{0,40}?(\d{3,6})\s*[Kk]bps"],
        "upstream_kbps":     [r"[Uu]p(?:stream)?[^<]{0,40}?(\d{3,6})\s*[Kk]bps"],
        "downstream_snr_db": [r"[Dd]own(?:stream)?[^<]{0,40}?SNR[^<]{0,20}([\d.]+)"],
        "upstream_snr_db":   [r"[Uu]p(?:stream)?[^<]{0,40}?SNR[^<]{0,20}([\d.]+)"],
        "downstream_attn_db":[r"[Dd]own(?:stream)?[^<]{0,40}?[Aa]ttenuation[^<]{0,20}([\d.]+)"],
        "upstream_attn_db":  [r"[Uu]p(?:stream)?[^<]{0,40}?[Aa]ttenuation[^<]{0,20}([\d.]+)"],
    }
    for key, pats in patterns.items():
        for pat in pats:
            m = re.search(pat, raw)
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

def check_wifi_security():
    """
    Use the airport utility to report the current Wi-Fi (Wireless Fidelity)
    security mode. WEP (Wired Equivalent Privacy) is broken; open networks
    have no encryption at all.
    Returns a dict with keys: ssid, auth, cipher, risk, note.
    """
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    out = run([airport, "-I"])
    if not out:
        # Fallback: try system_profiler
        out = run(["system_profiler", "SPAirPortDataType"], timeout=15)

    result = {"ssid": None, "auth": None, "cipher": None, "risk": "UNKNOWN", "note": ""}

    # Parse airport -I output
    ssid_m = re.search(r"\s+SSID:\s*(.+)", out)
    auth_m  = re.search(r"(?i)link auth:\s*(\S+)", out)
    cipher_m = re.search(r"(?i)(?:cipher|encryption):\s*(\S+)", out)

    if ssid_m:
        result["ssid"] = ssid_m.group(1).strip()
    if auth_m:
        result["auth"] = auth_m.group(1).strip()
    if cipher_m:
        result["cipher"] = cipher_m.group(1).strip()

    # Also try grabbing from system_profiler if airport gave nothing useful
    if not result["auth"]:
        sp_auth = re.search(r"Security:\s*(.+)", out)
        if sp_auth:
            result["auth"] = sp_auth.group(1).strip()

    auth = (result["auth"] or "").lower()
    if not auth or auth in ("none", "open"):
        result["risk"] = "HIGH"
        result["note"] = "OPEN network — all traffic is unencrypted. Use WPA2 or WPA3."
    elif "wep" in auth:
        result["risk"] = "HIGH"
        result["note"] = "WEP is cryptographically broken. Upgrade to WPA2 or WPA3 immediately."
    elif "wpa3" in auth:
        result["risk"] = "GOOD"
        result["note"] = "WPA3 — current best practice."
    elif "wpa2" in auth:
        result["risk"] = "OK"
        result["note"] = "WPA2 — acceptable. WPA3 preferred if your router supports it."
    elif "wpa" in auth:
        result["risk"] = "MEDIUM"
        result["note"] = "WPA (original) has known weaknesses. Upgrade to WPA2 or WPA3."
    else:
        result["risk"] = "REVIEW"
        result["note"] = f"Unrecognised auth type '{result['auth']}'. Investigate."

    return result


def action_wifi_security():
    hr("WI-FI SECURITY MODE")
    r = check_wifi_security()
    print(f"  SSID (network name) : {r['ssid'] or 'unknown'}")
    print(f"  Auth / encryption   : {r['auth'] or 'unknown'}")
    if r["cipher"]:
        print(f"  Cipher              : {r['cipher']}")
    print(f"  Risk                : [{r['risk']}]")
    print(f"  Note                : {r['note']}")
    return r


# ---------------------------------------------------------------------------
# NEW FEATURE 2: Rogue DHCP detector
# ---------------------------------------------------------------------------

def check_rogue_dhcp(local_ip, timeout=4):
    """
    Send a DHCP (Dynamic Host Configuration Protocol) DISCOVER broadcast and
    collect all OFFER responses. More than one responder means a rogue DHCP
    server is present — a serious network security risk.
    Returns list of dicts: [{ip, mac, offered_ip}]
    """
    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68

    # Build a minimal DHCP DISCOVER packet
    xid = os.urandom(4)
    mac_bytes = bytes.fromhex(
        run(["ifconfig"]).split("ether")[1].split()[0].replace(":", "")
        if "ether" in run(["ifconfig"]) else "aabbccddeeff"
    )[:6]
    mac_bytes = mac_bytes.ljust(6, b"\x00")

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
                    responders.append({"ip": server_ip, "offered_ip": offered_ip})
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
    local_ip = get_local_ip()
    print("  Sending DHCP DISCOVER broadcast (waiting 4s for responses)...")
    responders, err = check_rogue_dhcp(local_ip)
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
    out = run(["netstat", "-anp", "tcp"], timeout=10)
    out += run(["netstat", "-anp", "udp"], timeout=10)
    # Also try lsof for process names
    lsof_out = run(["lsof", "-i", "-n", "-P", "-s", "TCP:LISTEN"], timeout=10)

    listeners = {}

    # Parse lsof output (more useful: has process names)
    for line in lsof_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        process = parts[0]
        pid = parts[1]
        addr_field = parts[8] if len(parts) > 8 else ""
        if "->" in addr_field:
            continue
        m = re.match(r"(?:\*|\d+[\d.]*):(\d+)$", addr_field)
        if m:
            port = int(m.group(1))
            key = ("TCP", port)
            if key not in listeners:
                listeners[key] = {"proto": "TCP", "port": port,
                                  "pid": pid, "process": process}

    # Parse netstat as fallback / UDP supplement
    for line in out.splitlines():
        if "LISTEN" in line or line.startswith("udp"):
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0].upper().replace("6", "").replace("4", "")
            local = parts[3] if len(parts) > 3 else ""
            # macOS netstat uses a DOT before the port (e.g. "*.59882",
            # "127.0.0.1.19292"); accept a dot or a colon separator.
            m = re.search(r"[.:](\d+)$", local)
            if m:
                port = int(m.group(1))
                key = (proto, port)
                if key not in listeners:
                    listeners[key] = {"proto": proto, "port": port,
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

def check_sharing_services():
    """
    Query macOS for enabled sharing services. Each enabled service is an
    inbound network attack surface. Returns list of enabled service dicts.
    """
    services = []

    checks = [
        ("Remote Login (SSH)",    ["systemsetup", "-getremotelogin"],       r"Remote Login:\s*(\w+)"),
        ("Remote Management",     ["systemsetup", "-getremoteappleevents"], r"Remote Apple Events:\s*(\w+)"),
        ("Screen Sharing",        ["defaults", "read", "/var/db/launchd.db/com.apple.launchd/overrides.plist",
                                   "com.apple.screensharing"],              r"Disabled\s*=\s*(\d)"),
        ("File Sharing (AFP/SMB)",["launchctl", "list", "com.apple.smbd"], None),
        ("Printer Sharing",       ["launchctl", "list", "com.apple.cupsd"], None),
        ("Bluetooth Sharing",     ["defaults", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"], None),
    ]

    # Use systemsetup for reliable results
    ssh_out = run(["systemsetup", "-getremotelogin"], timeout=5)
    ssh_on = "on" in ssh_out.lower()
    services.append({
        "name": "Remote Login (SSH)",
        "enabled": ssh_on,
        "risk": "REVIEW" if ssh_on else "OK",
        "note": "SSH enabled — fine if intentional; disable if not needed." if ssh_on else "Disabled.",
    })

    rae_out = run(["systemsetup", "-getremoteappleevents"], timeout=5)
    rae_on = "on" in rae_out.lower()
    services.append({
        "name": "Remote Apple Events",
        "enabled": rae_on,
        "risk": "REVIEW" if rae_on else "OK",
        "note": "Allows remote Apple Script control." if rae_on else "Disabled.",
    })

    # Screen sharing via launchctl
    ss_out = run(["launchctl", "list", "com.apple.screensharing"], timeout=5)
    ss_on = bool(ss_out and "PID" in ss_out and "-\t0\t" not in ss_out)
    services.append({
        "name": "Screen Sharing / VNC",
        "enabled": ss_on,
        "risk": "HIGH" if ss_on else "OK",
        "note": "Screen visible to anyone with credentials; use only if needed." if ss_on else "Disabled.",
    })

    # SMB file sharing
    smb_out = run(["launchctl", "list", "com.apple.smbd"], timeout=5)
    smb_on = bool(smb_out and "PID" in smb_out)
    services.append({
        "name": "File Sharing (SMB)",
        "enabled": smb_on,
        "risk": "REVIEW" if smb_on else "OK",
        "note": "File shares visible on the network." if smb_on else "Disabled.",
    })

    # AirDrop / AirPlay via discoveryd / mDNSResponder — just note it's always on
    services.append({
        "name": "mDNS / Bonjour",
        "enabled": True,
        "risk": "INFO",
        "note": "Always on; advertises this Mac's services to the local network.",
    })

    return services


def action_sharing_services():
    hr("SHARING SERVICES CHECK")
    print("  Checking macOS sharing services (may require sudo for full info)...")
    services = check_sharing_services()

    for s in services:
        state = "ON " if s["enabled"] else "OFF"
        print(f"  [{s['risk']:6}] {state}  {s['name']:<30} {s['note']}")

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

    result["enabled"] = "enabled" in global_out.lower() or "state = 1" in global_out.lower()
    result["stealth_mode"] = "enabled" in stealth_out.lower()
    result["block_all"] = "enabled" in blockall_out.lower()

    if not result["enabled"]:
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
    enabled_str = "ON" if fw["enabled"] else "OFF"
    stealth_str  = "ON" if fw["stealth_mode"] else "OFF"
    blockall_str = "ON" if fw["block_all"] else "OFF"

    risk = "OK" if fw["enabled"] else "HIGH"
    print(f"  [{risk}] Application Firewall : {enabled_str}")
    print(f"          Stealth Mode         : {stealth_str}")
    print(f"          Block All            : {blockall_str}")
    print(f"          Note                 : {fw['note']}")
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

def action_port_scan(full_scan=False, upstream_ip=None):
    hr("PORT SCAN")
    interfaces, local_ip, gateway = print_network_info()

    def audit_host(label, host):
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
        print(f"  HTTPS (TLS) certificate present: {tls.get('present')}")
        if open_ports and 80 in open_ports and 443 not in open_ports:
            print("  Note: port 80 open without 443. App-managed mesh systems")
            print("  (Google Nest, eero) use 80/5000 locally — not a web admin panel.")
        return open_ports

    open_ports = []
    if gateway:
        open_ports = audit_host("default gateway", gateway)
    else:
        print("Could not determine default gateway.")

    if upstream_ip:
        hr("UPSTREAM MODEM")
        audit_host("upstream modem", upstream_ip)

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

    if subnet_overrides:
        subnets_to_sweep = [ipaddress.ip_network(s, strict=False) for s in subnet_overrides]
    elif interfaces:
        subnets_to_sweep = list({net for _, _, net in interfaces})
    else:
        fb = guess_subnet(local_ip)
        subnets_to_sweep = [fb] if fb else []

    # Append any extra subnets the user specified (e.g. Pearl network)
    if extra_subnets:
        for s in extra_subnets:
            net = ipaddress.ip_network(s, strict=False)
            if net not in subnets_to_sweep:
                subnets_to_sweep.append(net)

    if not subnets_to_sweep:
        print("  Could not determine any subnet. Pass one with --subnet 192.168.1.0/24")
        return []

    all_devices = []
    seen_ips = set()
    for subnet in subnets_to_sweep:
        net_name = network_name_for_subnet(str(subnet), networks)
        print(f"  Sweeping {subnet}  [{net_name}]  (this takes ~10-30s)...")
        devices = discover_devices(subnet)
        for d in devices:
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
            if labels.get(mac.lower()):
                d["vendor"] = ""
            elif mac == "unknown" or is_randomized_mac(mac):
                d["vendor"] = lookup_vendor(mac)
            else:
                d["vendor"] = lookup_vendor(mac)
                time.sleep(1.1)

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
    save_baseline(state)
    print(f"Baseline saved to {BASELINE_FILE}")
    print(f"Timestamp: {state.get('timestamp', '?')}")
    keys = [k for k in state if k != "timestamp"]
    print(f"Saved sections: {', '.join(keys)}")


def action_compare_baseline(state):
    hr("CHANGE DETECTION (vs saved baseline)")
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
                      extra_subnets=None, probe_creds=False):
    state = {"timestamp": datetime.now(timezone.utc).isoformat()}

    hr("NETWORK INTERFACES")
    interfaces, local_ip, gateway = print_network_info()
    state["gateway"] = gateway

    # Port scan
    hr("ROUTER / GATEWAY PORT SCAN")
    def audit_host(label, host):
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
        print(f"  HTTPS (TLS) certificate present: {tls.get('present')}")
        if open_ports and 80 in open_ports and 443 not in open_ports:
            print("  Note: port 80 open without 443. Mesh systems use 80/5000 locally.")
        return open_ports

    if gateway:
        state["router_open_ports"] = audit_host("default gateway", gateway)
    if upstream_ip:
        hr("UPSTREAM MODEM")
        state["upstream_open_ports"] = audit_host("upstream modem", upstream_ip)

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
    hr("CONNECTED DEVICES")
    labels = load_labels()
    networks = load_networks()
    if subnet_overrides:
        subnets_to_sweep = [ipaddress.ip_network(s, strict=False) for s in subnet_overrides]
    elif interfaces:
        subnets_to_sweep = list({net for _, _, net in interfaces})
    else:
        fb = guess_subnet(local_ip)
        subnets_to_sweep = [fb] if fb else []

    if extra_subnets:
        for s in extra_subnets:
            net = ipaddress.ip_network(s, strict=False)
            if net not in subnets_to_sweep:
                subnets_to_sweep.append(net)

    if subnets_to_sweep:
        all_devices = []
        seen_ips = set()
        for subnet in subnets_to_sweep:
            net_name = network_name_for_subnet(str(subnet), networks)
            print(f"  Sweeping {subnet}  [{net_name}]...")
            for d in discover_devices(subnet):
                if d["ip"] not in seen_ips:
                    seen_ips.add(d["ip"])
                    all_devices.append({**d, "subnet": str(subnet)})
        if not no_vendors and all_devices:
            for d in all_devices:
                mac = d["mac"]
                if not labels.get(mac.lower()) and mac != "unknown" and not is_randomized_mac(mac):
                    d["vendor"] = lookup_vendor(mac)
                    time.sleep(1.1)
                else:
                    d["vendor"] = lookup_vendor(mac)
        state["devices"] = all_devices
        _print_devices_grouped(all_devices, labels, networks, scanned_subnets=subnets_to_sweep)

    # Speed test
    if not no_speedtest:
        hr("SPEED TEST")
        print("Testing speed via Cloudflare...")
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
            print("Testing speed via Cloudflare (~15s)...")
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
                    help="TP-Link admin password to fetch DSL line stats")
    ap.add_argument("--probe-creds", action="store_true",
                    help="Actively test default admin credentials against the gateway. "
                         "NOT read-only and can trigger router lockout; off by default.")
    ap.add_argument("--html-report", action="store_true",
                    help="Save an HTML report after the audit")
    ap.add_argument("--menu", action="store_true",
                    help="Force interactive menu")
    args = ap.parse_args()

    cli_args_given = any([
        args.subnet, getattr(args, "extra_subnet", None), args.upstream,
        args.full, args.no_vendors, args.no_save_baseline, args.label,
        args.no_discovery, args.no_speedtest, args.tplink_password,
        args.probe_creds, args.html_report,
    ])

    if not cli_args_given or args.menu:
        interactive_menu()
        return

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
        tplink_password=args.tplink_password,
        subnet_overrides=args.subnet,
        extra_subnets=getattr(args, "extra_subnet", None),
        probe_creds=args.probe_creds,
    )

    if not args.no_save_baseline:
        save_baseline(state)
        print(f"\nBaseline saved to {BASELINE_FILE}")

    if args.html_report:
        path = generate_html_report(state)
        print(f"HTML report saved to {path}")


if __name__ == "__main__":
    main()
