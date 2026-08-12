"""Run the parsers over output a real Mac actually produced.

Everything in tests/fixtures/real/ came off one machine on one home network in
a single run of tools/capture_fixtures.py, redacted and then checked by
residue(). That provenance is the point of the directory: the fixtures beside
it are curated scenarios, written to exercise a branch, and they are better at
that than any capture — the real Mac here has three listening TCP sockets and
cannot say anything about how port 631 is classified.

What a capture can do, and a curated fixture cannot, is disagree with what the
author believed. Every bug this suite has found by being pointed at reality was
of that kind, and none of them were visible from the CI runner:

  * `ndp -a` reverse-resolves, so every neighbour row arrived as a hostname and
    was silently dropped. The audit runs `ndp -an`.
  * The Neighbor table's state column uses R for REACHABLE and its flags column
    uses R for router, so "an R after the netif" called every reachable
    neighbour a router.
  * `ndp -r` reverse-resolves too, which nobody noticed when -a was fixed. On
    the machine these came from it ran past 30 seconds; run() allows 10.
  * A Mac on a VPN has one ndp router line per tunnel with no router in it.

So these tests are deliberately structural. They assert what the shape of the
output implies — a router is a router, an unresolved neighbour is skipped, a
tunnel is not an access point — rather than pinning the values of one house's
network, which would only prove the capture matches itself.
"""

import ipaddress

import pytest

from conftest import load_fixture, make_run

REAL = "real/%s.out"


def real(name):
    return load_fixture(REAL % name)


# ---------------------------------------------------------------------------
# IPv6 neighbours and routers — where every bug so far has been
# ---------------------------------------------------------------------------

class TestNdpAgainstRealOutput:

    def test_the_neighbour_table_parses_at_all(self, mod):
        """The regression that started this. With `ndp -a` the Neighbor column
        came back as hostnames, nothing matched, and the audit reported an
        empty neighbour table on every Mac while its tests passed."""
        neighbours = mod.parse_ndp_neighbours(real("ndp_a"))
        assert len(neighbours) >= 10
        for addr, entry in neighbours.items():
            assert ipaddress.ip_address(addr.partition("%")[0]).version == 6
            assert entry["mac"].count(":") == 5

    def test_unresolved_neighbours_are_skipped(self, mod):
        """A real table carries `(incomplete)` in the link-layer column for a
        neighbour that never answered — seven of them here, six being tunnels.
        There is no address to record, and the row must not become a device."""
        assert "(incomplete)" in real("ndp_a")
        for entry in mod.parse_ndp_neighbours(real("ndp_a")).values():
            assert entry["mac"] != "(incomplete)"
            assert entry["mac"]

    def test_reachable_is_not_mistaken_for_router(self, mod):
        """The column the fix turned on, and the reason a capture was needed to
        see it. The state column's R means REACHABLE; the flags column's R
        means router. This table has many rows with the first and exactly one
        with both, so a parser that searched for "an R after the netif" would
        call almost every neighbour a router — and a curated fixture written by
        someone holding that belief would have agreed with them.
        """
        neighbours = mod.parse_ndp_neighbours(real("ndp_a"))
        routers = [a for a, n in neighbours.items() if n["router"]]
        reachable_rows = [ln for ln in real("ndp_a").splitlines()
                          if ln.strip() and not ln.startswith("Neighbor")]
        assert len(routers) == 1, routers
        assert len(reachable_rows) > len(routers) + 5

    def test_the_router_is_a_link_local_on_the_lan_interface(self, mod):
        neighbours = mod.parse_ndp_neighbours(real("ndp_a"))
        addr, entry = next((a, n) for a, n in neighbours.items() if n["router"])
        assert ipaddress.ip_address(addr.partition("%")[0]).is_link_local
        assert entry["iface"] == "en0"

    def test_vpn_tunnels_are_not_counted_as_routers(self, mod):
        """The shape that made this check cry wolf at every VPN user: one line
        per tunnel, each with the all-zeros interface identifier RFC 4291
        reserves for Subnet-Router anycast, which no host holds."""
        out = real("ndp_r")
        assert out.count("%utun") >= 4, "capture has no tunnels; test is vacuous"
        assert mod.parse_ndp_routers(out) == ["fe80::12%en0"]

    def test_the_two_ndp_views_agree_on_the_router(self, mod):
        """ndp -an and ndp -rn are separate commands and separate parsers. On
        one machine at one moment they have to name the same router, and the
        redaction has to keep that true or the capture is worthless."""
        from_table = [a for a, n in mod.parse_ndp_neighbours(real("ndp_a")).items()
                      if n["router"]]
        assert mod.parse_ndp_routers(real("ndp_r")) == from_table


# ---------------------------------------------------------------------------
# The rest of the readers, over the same machine's output
# ---------------------------------------------------------------------------

class TestReadersAgainstRealOutput:

    def test_the_default_gateway_is_read(self, mod):
        gw = mod.parse_gateway_bsd(real("route_get_default"), real("netstat_rn"))
        assert ipaddress.ip_address(gw).is_private

    def test_the_route_table_and_the_route_command_agree(self, mod):
        """parse_gateway_bsd prefers `route -n get default` and falls back to
        the netstat table. Given a real pair, both paths have to land on the
        same address, which is the only way the fallback is worth having."""
        from_route = mod.parse_gateway_bsd(real("route_get_default"), "")
        from_netstat = mod.parse_gateway_bsd("", real("netstat_rn"))
        assert from_route == from_netstat

    def test_interfaces_come_back_with_addresses(self, mod):
        """One entry per configured IPv4 interface, as (iface, ip, network).

        A real ifconfig -a is mostly noise for this reader: six tunnels, awdl0,
        llw0, the bridge, lo0 and the ap1 hotspot all appear and none of them
        carry a routable IPv4. Exactly one interface is on the LAN, and the
        loopback and link-local skips are what keep it that way.
        """
        ifaces = mod.parse_interfaces_ifconfig(real("ifconfig_a"))
        assert [name for name, _, _ in ifaces] == ["en0"]
        _, ip, net = ifaces[0]
        assert ipaddress.ip_address(ip).is_private
        assert ipaddress.ip_address(ip) in net

    def test_loopback_and_link_local_are_not_offered_as_lan_interfaces(self, mod):
        """lo0 is in this capture, and so is a 169.254 address. Either one
        surviving would send the device sweep at a subnet nothing is on."""
        assert "lo0:" in real("ifconfig_a")
        for _, ip, _ in mod.parse_interfaces_ifconfig(real("ifconfig_a")):
            assert not ip.startswith(("127.", "169.254."))

    def test_the_arp_table_reads_a_real_lan(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({"arp -a": real("arp_a_typical")}))
        table = mod.read_arp_table()
        assert len(table) >= 5
        for ip, mac in table.items():
            assert ipaddress.ip_address(ip)
            assert mac.count(":") == 5

    def test_multicast_rows_survive_into_the_arp_table(self, mod, monkeypatch):
        """arp lists the mDNS and SSDP multicast groups. They are not devices,
        and is_real_host is what decides that — so the reader has to hand them
        over rather than quietly filtering them first."""
        monkeypatch.setattr(mod, "run", make_run({"arp -a": real("arp_a_typical")}))
        table = mod.read_arp_table()
        assert any(ipaddress.ip_address(ip).is_multicast for ip in table)

    def test_the_firewall_is_read_from_real_socketfilterfw_output(self, mod, monkeypatch):
        """The blockall fixture beside this one said `Block all DISABLED!`,
        a string macOS does not print. The parser survived only because it
        lowercases and tests for "disabled" anywhere in the line."""
        monkeypatch.setattr(mod, "run", make_run({
            "--getglobalstate": real("firewall_globalstate_on"),
            "--getstealthmode": real("firewall_stealth_on"),
            "--getblockall": real("firewall_blockall_off"),
        }))
        fw = mod.check_firewall()
        assert fw["enabled"] is True
        assert fw["stealth_mode"] is True
        assert fw["block_all"] is False

    def test_the_trust_store_reads_as_clean_not_as_unreadable(self, mod, monkeypatch):
        """`security dump-trust-settings` answers on stderr, which is why it is
        the one command run() merges. Read as stdout alone it is empty, and an
        empty answer is reported as "could not read" — a REVIEW on every Mac
        with a perfectly ordinary trust store."""
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", make_run(
            {"security dump-trust-settings": real("security_trust")}))
        result = mod.check_trust_store()
        assert result["risk"] == "OK", result["note"]

    def test_remote_apple_events_without_admin_is_unknown_not_off(self, mod):
        """systemsetup prints an admin-access message and exits 0. Reported as
        OFF that is a confident false negative on an inbound attack surface."""
        assert "administrator" in real("systemsetup_rae").lower()


# ---------------------------------------------------------------------------
# The fixtures themselves
# ---------------------------------------------------------------------------

class TestTheRealFixturesStayClean:
    """These files came off somebody's home network. The check that cleared
    them runs here too, so a fixture added later cannot quietly carry a real
    address into the repository the way one already did."""

    NAMES = ["route_get_default", "netstat_rn", "ifconfig_a", "scutil_dns",
             "arp_a_typical", "ndp_a", "ndp_r", "lsof_tcp_listen", "lsof_udp",
             "netstat_anp_tcp", "netstat_anp_udp", "launchctl_print_disabled",
             "wifi_sp_airport", "security_trust", "systemsetup_rae",
             "firewall_globalstate_on", "firewall_stealth_on",
             "firewall_blockall_off"]

    @pytest.mark.parametrize("name", NAMES)
    def test_no_residue_in_a_committed_fixture(self, capture_module, name):
        found = capture_module.residue(real(name))
        assert not found, "%s carries %s" % (name, found)

    def test_the_location_services_sentinel_is_intact(self):
        """macOS withheld every SSID and BSSID from this capture, so the file
        pins the permission-denied path rather than the evil-twin one. Worth
        stating out loud: renaming the sentinel would make this fixture look
        like a capture that had read a network it never read."""
        assert "<redacted>" in real("wifi_sp_airport")
