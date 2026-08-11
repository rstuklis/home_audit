"""The Linux reading dialect, for running the audit from a second device.

Roadmap P0. Sealing the baseline stops it being rewritten, but the endpoint is
still both the observer and the thing observed: an attacker who deletes
~/.home_net_audit outright leaves the next run looking like a first run, and no
local mechanism can tell those apart. The answer is an independent witness — a
Linux box on the same LAN — which needs the network readers to speak iproute2
as well as they speak BSD.

The dispatch deliberately avoids sys.platform. Each reader tries its sources in
order and takes the first that parses; run() yields "" for a binary that is not
installed, so macOS falls through to the BSD tools and Linux to iproute2 with no
platform detection to get wrong. A host with both installed still works.

Host-posture checks (firewall, sharing services, Wi-Fi security) are NOT ported
and should not be: they describe whichever machine is running the audit, and on
an observer Pi that is not the machine anyone cares about. The observer's job is
to watch the network.
"""

import ipaddress
import subprocess

import pytest

from conftest import load_fixture, make_run

IP_ROUTE_CMD = "ip route show default"
IP_ADDR_CMD = "ip -o -4 addr show"
IP_NEIGH_CMD = "ip neigh show"
ROUTE_CMD = "route -n get default"
NETSTAT_CMD = "netstat -rn"
ARP_CMD = "arp -a"
IFCONFIG_CMD = "ifconfig -a"
SCUTIL_CMD = "scutil --dns"

IP_ROUTE = load_fixture("ip_route_default.out")
IP_ROUTE_NO_DEFAULT = load_fixture("ip_route_no_default.out")
IP_ADDR = load_fixture("ip_addr_show.out")
IP_NEIGH = load_fixture("ip_neigh_show.out")
RESOLV_CONF = load_fixture("resolv_conf.out")


class TestGatewayFromIproute:
    def test_default_via_is_read(self, mod):
        assert mod.parse_gateway_iproute(IP_ROUTE) == "192.168.1.1"

    def test_a_table_with_no_default_route_yields_none(self, mod):
        assert mod.parse_gateway_iproute(IP_ROUTE_NO_DEFAULT) is None

    def test_empty_output_yields_none(self, mod):
        assert mod.parse_gateway_iproute("") is None

    def test_a_non_address_via_value_is_rejected(self, mod):
        # `default dev tun0` on a point-to-point link has no gateway address;
        # returning a device name would aim every router probe at nothing.
        assert mod.parse_gateway_iproute("default via tun0 dev tun0\n") is None

    def test_only_the_default_row_is_considered(self, mod):
        out = ("10.8.0.0/24 via 10.8.0.1 dev tun0\n"
               "default via 192.168.1.1 dev eth0\n")
        assert mod.parse_gateway_iproute(out) == "192.168.1.1"

    def test_a_linux_host_reaches_the_iproute_source(self, mod, monkeypatch):
        # On Linux the BSD tools are absent, so run() returns "" for both and
        # the third source answers. This is the whole dispatch in one test.
        monkeypatch.setattr(mod, "run", make_run({IP_ROUTE_CMD: IP_ROUTE}))
        assert mod.get_default_gateway() == "192.168.1.1"

    def test_the_bsd_source_still_wins_when_present(self, mod, monkeypatch):
        # A Mac with iproute2 installed must not change behaviour.
        monkeypatch.setattr(mod, "run", make_run({
            ROUTE_CMD: "   gateway: 10.0.0.1\n",
            IP_ROUTE_CMD: IP_ROUTE,
        }))
        assert mod.get_default_gateway() == "10.0.0.1"

    def test_iproute_is_not_consulted_when_bsd_answers(self, mod, monkeypatch):
        fake = make_run({ROUTE_CMD: "   gateway: 10.0.0.1\n"})
        monkeypatch.setattr(mod, "run", fake)
        mod.get_default_gateway()
        assert IP_ROUTE_CMD not in fake.calls


class TestInterfacesFromIproute:
    def test_addresses_and_prefixes_are_read(self, mod):
        result = mod.parse_interfaces_iproute(IP_ADDR)
        assert ("eth0", "192.168.1.50", ipaddress.ip_network("192.168.1.0/24")) in result
        assert ("wlan0", "10.0.0.5", ipaddress.ip_network("10.0.0.0/16")) in result

    def test_loopback_is_excluded(self, mod):
        assert all(ip != "127.0.0.1" for _, ip, _ in mod.parse_interfaces_iproute(IP_ADDR))

    def test_link_local_is_excluded(self, mod):
        # 169.254.x means DHCP failed; sweeping it finds nothing and wastes the
        # scan. The BSD reader excludes it too — the dialects must agree.
        assert all(not ip.startswith("169.254.")
                   for _, ip, _ in mod.parse_interfaces_iproute(IP_ADDR))

    def test_the_interface_name_comes_from_its_own_row(self, mod):
        # iproute2 puts the name on every line, unlike ifconfig's block format,
        # so a mis-parse here would attach addresses to the wrong interface.
        by_name = {name: ip for name, ip, _ in mod.parse_interfaces_iproute(IP_ADDR)}
        assert by_name["eth0"] == "192.168.1.50"
        assert by_name["wlan0"] == "10.0.0.5"

    def test_a_docker_bridge_is_reported_like_any_other_interface(self, mod):
        # Not filtered: an observer Pi running containers genuinely has it, and
        # silently dropping interfaces is how subnets go unswept.
        names = [n for n, _, _ in mod.parse_interfaces_iproute(IP_ADDR)]
        assert "docker0" in names

    def test_a_malformed_row_is_skipped_without_raising(self, mod):
        out = ("2: eth0    inet 999.1.1.1/24 scope global eth0\n"
               "3: eth1    inet 192.168.5.10/24 scope global eth1\n")
        assert mod.parse_interfaces_iproute(out) == [
            ("eth1", "192.168.5.10", ipaddress.ip_network("192.168.5.0/24"))]

    def test_an_impossible_prefix_is_skipped(self, mod):
        assert mod.parse_interfaces_iproute("2: eth0    inet 192.168.1.5/99\n") == []

    def test_empty_output_yields_no_interfaces(self, mod):
        assert mod.parse_interfaces_iproute("") == []

    def test_a_linux_host_reaches_the_iproute_source(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({IP_ADDR_CMD: IP_ADDR}))
        names = [n for n, _, _ in mod.get_all_interfaces()]
        assert "eth0" in names and "wlan0" in names

    def test_ifconfig_still_wins_when_present(self, mod, monkeypatch):
        ifconfig = ("en0: flags=8863<UP> mtu 1500\n"
                    "\tinet 172.20.0.9 netmask 0xffffff00 broadcast 172.20.0.255\n")
        monkeypatch.setattr(mod, "run", make_run({
            IFCONFIG_CMD: ifconfig, IP_ADDR_CMD: IP_ADDR}))
        assert mod.get_all_interfaces() == [
            ("en0", "172.20.0.9", ipaddress.ip_network("172.20.0.0/24"))]


class TestNeighbourTableFromIproute:
    def test_addresses_and_macs_are_read(self, mod):
        table = mod.parse_neigh_iproute(IP_NEIGH)
        assert table["192.168.1.1"] == "3c:22:fb:11:22:33"
        assert table["192.168.1.42"] == "a4:83:e7:1b:9c:2d"

    def test_short_octets_are_zero_padded_like_the_bsd_reader(self, mod):
        # The two dialects must produce identical MAC strings, or a device seen
        # by the Mac and by the observer would diff as two different devices.
        assert mod.parse_neigh_iproute(IP_NEIGH)["192.168.1.77"] == "00:01:02:03:04:05"

    def test_failed_entries_are_dropped(self, mod):
        assert "192.168.1.99" not in mod.parse_neigh_iproute(IP_NEIGH)

    def test_incomplete_entries_are_dropped(self, mod):
        assert "192.168.1.20" not in mod.parse_neigh_iproute(IP_NEIGH)

    def test_every_returned_ip_parses_as_an_address(self, mod):
        # Same invariant the BSD reader guarantees: discover_devices sorts by
        # ipaddress.ip_address and a bad key would crash the sweep.
        for ip in mod.parse_neigh_iproute(IP_NEIGH):
            ipaddress.ip_address(ip)

    def test_an_ipv6_neighbour_is_kept_but_cannot_join_an_ipv4_sweep(self, mod):
        table = mod.parse_neigh_iproute(IP_NEIGH)
        v6 = [ip for ip in table if ":" in ip]
        assert v6, "the fixture should contain an IPv6 neighbour"
        subnet = ipaddress.ip_network("192.168.1.0/24")
        for ip in v6:
            assert mod.is_real_host(ip, table[ip], subnet) is False

    def test_empty_output_yields_an_empty_table(self, mod):
        assert mod.parse_neigh_iproute("") == {}

    def test_garbage_is_skipped_without_raising(self, mod):
        assert mod.parse_neigh_iproute("not a neighbour line at all\n\n") == {}

    def test_a_linux_host_reaches_the_neighbour_source(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({IP_NEIGH_CMD: IP_NEIGH}))
        assert mod.read_arp_table()["192.168.1.1"] == "3c:22:fb:11:22:33"

    def test_arp_still_wins_when_present(self, mod, monkeypatch):
        arp = "? (10.0.0.1) at 1:2:3:4:5:6 on en0 ifscope [ethernet]\n"
        monkeypatch.setattr(mod, "run", make_run({ARP_CMD: arp, IP_NEIGH_CMD: IP_NEIGH}))
        assert mod.read_arp_table() == {"10.0.0.1": "01:02:03:04:05:06"}


class TestResolvConf:
    def test_nameservers_are_read_in_order(self, mod):
        assert mod.parse_resolv_conf(RESOLV_CONF)[:2] == [
            "192.168.1.1", "2606:4700:4700::1111"]

    def test_comments_are_stripped(self, mod):
        assert "1.1.1.1" in mod.parse_resolv_conf(RESOLV_CONF)

    def test_a_full_line_comment_is_ignored(self, mod):
        assert mod.parse_resolv_conf("# nameserver 9.9.9.9\n") == []

    def test_non_nameserver_directives_are_ignored(self, mod):
        servers = mod.parse_resolv_conf(RESOLV_CONF)
        assert "lan" not in servers and "edns0" not in servers

    def test_a_malformed_address_is_dropped(self, mod):
        # Same contract as the scutil reader: garbage must not reach the
        # baseline, where it would diff as a change forever.
        assert "not-an-address" not in mod.parse_resolv_conf(RESOLV_CONF)

    def test_duplicates_are_collapsed_preserving_order(self, mod):
        text = "nameserver 1.1.1.1\nnameserver 9.9.9.9\nnameserver 1.1.1.1\n"
        assert mod.parse_resolv_conf(text) == ["1.1.1.1", "9.9.9.9"]

    def test_ipv6_is_not_truncated(self, mod):
        # The bug fixed in the scutil reader must not reappear in this one.
        assert mod.parse_resolv_conf("nameserver 2606:4700:4700::1111\n") == [
            "2606:4700:4700::1111"]

    def test_a_linux_host_falls_back_to_resolv_conf(self, mod, monkeypatch, tmp_path):
        path = tmp_path / "resolv.conf"
        path.write_text(RESOLV_CONF, encoding="utf-8")
        monkeypatch.setattr(mod, "RESOLV_CONF_FILE", str(path))
        monkeypatch.setattr(mod, "run", make_run({}))     # no scutil
        assert mod.get_dns_servers()[0] == "192.168.1.1"

    def test_scutil_still_wins_when_present(self, mod, monkeypatch, tmp_path):
        path = tmp_path / "resolv.conf"
        path.write_text("nameserver 9.9.9.9\n", encoding="utf-8")
        monkeypatch.setattr(mod, "RESOLV_CONF_FILE", str(path))
        monkeypatch.setattr(mod, "run", make_run({
            SCUTIL_CMD: "  nameserver[0] : 1.1.1.1\n"}))
        assert mod.get_dns_servers() == ["1.1.1.1"]

    def test_a_missing_resolv_conf_is_not_an_error(self, mod, monkeypatch, tmp_path):
        monkeypatch.setattr(mod, "RESOLV_CONF_FILE", str(tmp_path / "nope"))
        monkeypatch.setattr(mod, "run", make_run({}))
        assert mod.get_dns_servers() == []


class TestPingFlagsPerPlatform:
    """-t is a deadline on macOS but a TTL on Linux.

    Sending a probe with TTL 1 makes every host beyond the first hop look dead,
    so on a Linux observer the original flag would have quietly emptied the
    device sweep rather than failing loudly.
    """

    def _record(self, mod, monkeypatch, platform):
        seen = {}

        def fake_run(cmd, *a, **k):
            seen["cmd"] = cmd
            seen["kwargs"] = k
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(mod.sys, "platform", platform)
        monkeypatch.setattr(subprocess, "run", fake_run)
        mod.ping("192.168.1.42")
        return seen

    def test_macos_uses_the_deadline_flag(self, mod, monkeypatch):
        assert "-t" in self._record(mod, monkeypatch, "darwin")["cmd"]

    def test_linux_uses_the_reply_timeout_flag(self, mod, monkeypatch):
        cmd = self._record(mod, monkeypatch, "linux")["cmd"]
        assert "-W" in cmd
        assert "-t" not in cmd, "-t is a TTL on Linux and would hide every remote host"

    @pytest.mark.parametrize("platform", ["darwin", "linux"])
    def test_a_single_probe_and_a_hard_timeout_on_both(self, mod, monkeypatch, platform):
        seen = self._record(mod, monkeypatch, platform)
        assert seen["cmd"][:3] == ["ping", "-c", "1"]
        assert seen["kwargs"]["timeout"] is not None

    @pytest.mark.parametrize("platform", ["darwin", "linux"])
    def test_the_address_is_last_on_both(self, mod, monkeypatch, platform):
        assert self._record(mod, monkeypatch, platform)["cmd"][-1] == "192.168.1.42"


class TestDialectsAgree:
    """The two readers must produce identical structures for the same LAN.

    An observer and the Mac diffing against one shared baseline is the point of
    this work; if the dialects disagreed on formatting, every device would look
    changed depending on which machine ran the audit.
    """

    def test_both_neighbour_readers_normalise_macs_identically(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({
            ARP_CMD: "? (192.168.1.77) at 0:1:2:3:4:5 on en0 ifscope [ethernet]\n"}))
        bsd = mod.read_arp_table()
        monkeypatch.setattr(mod, "run", make_run({
            IP_NEIGH_CMD: "192.168.1.77 dev eth0 lladdr 0:1:2:3:4:5 REACHABLE\n"}))
        assert mod.read_arp_table() == bsd

    def test_both_interface_readers_produce_the_same_triple(self, mod):
        bsd = mod.parse_interfaces_ifconfig(
            "eth0: flags=4163<UP> mtu 1500\n"
            "\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n")
        linux = mod.parse_interfaces_iproute(
            "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n")
        assert bsd == linux

    def test_both_gateway_readers_return_a_bare_address_string(self, mod):
        assert (mod.parse_gateway_bsd("   gateway: 192.168.1.1\n")
                == mod.parse_gateway_iproute("default via 192.168.1.1 dev eth0\n")
                == "192.168.1.1")
