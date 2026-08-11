#!/usr/bin/env python3
"""
save_baseline_now.py
====================
One-shot helper: discovers devices on 192.168.87.0/24 (loveshack) and
saves the result as the home_net_audit baseline. Run once to establish
a clean known-good snapshot for future change detection.

Usage:
    python3 ~/Downloads/home_audit/save_baseline_now.py
"""

import sys
import os

# Ensure we import from the same directory as this script
sys.path.insert(0, os.path.dirname(__file__))

from home_net_audit import (
    get_default_gateway,
    get_dns_servers,
    scan_ports,
    discover_devices,
    lookup_vendor,
    is_randomized_mac,
    load_labels,
    load_networks,
    save_baseline,
    network_name_for_subnet,
    COMMON_PORTS,
)
import ipaddress
from datetime import datetime, timezone

TARGET_SUBNET = "192.168.87.0/24"

print(f"Building baseline for {TARGET_SUBNET} (loveshack)...")
print("=" * 60)

state = {"timestamp": datetime.now(timezone.utc).isoformat()}

# Gateway
gateway = get_default_gateway()
state["gateway"] = gateway
print(f"Gateway     : {gateway}")

# DNS
dns = get_dns_servers()
state["dns"] = dns
print(f"DNS servers : {dns}")

# Port scan of gateway
if gateway:
    print(f"\nScanning {len(COMMON_PORTS)} common ports on {gateway}...")
    open_ports = scan_ports(gateway, COMMON_PORTS)
    state["router_open_ports"] = open_ports
    print(f"Open ports  : {open_ports or 'none'}")

# Device discovery
subnet = ipaddress.ip_network(TARGET_SUBNET, strict=False)
print(f"\nSweeping {TARGET_SUBNET} (this takes ~15s)...")
devices = discover_devices(subnet)

labels  = load_labels()
networks = load_networks()

print(f"\nFound {len(devices)} device(s):")
for d in devices:
    mac  = d["mac"]
    name = labels.get(mac.lower(), "")
    if not name and mac != "unknown" and not is_randomized_mac(mac):
        d["vendor"] = lookup_vendor(mac)
    else:
        d["vendor"] = ""
    d["subnet"] = TARGET_SUBNET
    display = name or d.get("vendor", "") or "<unlabelled>"
    print(f"  {d['ip']:<15} {mac}  {display}")

state["devices"] = devices

# Save
save_baseline(state)
print(f"\n{'='*60}")
print(f"Baseline saved.  ({len(devices)} device(s), {len(open_ports) if gateway else 0} open port(s))")
print(f"Timestamp: {state['timestamp']}")
print("\nRun the main audit later and use option 6 to compare against this baseline.")
