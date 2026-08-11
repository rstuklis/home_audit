"""Tests for the three macOS system parsers that answer "where am I?".

    get_default_gateway()  home_net_audit.py lines 134-145
    get_all_interfaces()   home_net_audit.py lines 148-174
    get_dns_servers()      home_net_audit.py lines 194-201

Everything downstream is built on these three: the gateway is the host every
router check probes, the interface list is what resolve_subnets() sweeps, and
the DNS list is what gets diffed against KNOWN_DNS and the saved baseline. A
parse miss here does not crash — it silently shrinks the audit, which is the
failure mode the suite exists to catch.

All three go through run(), so every test drives them by mapping a command to
captured output; nothing here executes a real command.
"""

import ipaddress

import pytest

from conftest import load_fixture, make_run

# Substrings make_run dispatches on. None is a prefix of another, so the
# route -> netstat fallback ordering can be read straight off fake.calls.
ROUTE_CMD = "route -n get default"
NETSTAT_CMD = "netstat -rn"
IFCONFIG_CMD = "ifconfig -a"
SCUTIL_CMD = "scutil --dns"

ROUTE_WITH_GATEWAY = load_fixture("route_get_default.out")
ROUTE_NO_GATEWAY = load_fixture("route_get_default_no_gateway.out")
NETSTAT_TABLE = load_fixture("netstat_rn.out")
NETSTAT_LINK_DEFAULT = load_fixture("netstat_rn_default_via_link.out")
IFCONFIG_ALL = load_fixture("ifconfig_a.out")
SCUTIL_DNS = load_fixture("scutil_dns.out")


def _netstat_table(gateway_col):
    """A one-default-route `netstat -rn` table with the Gateway column set."""
    return (
        "Routing tables\n"
        "\n"
        "Internet:\n"
        "Destination        Gateway            Flags               Netif Expire\n"
        f"default            {gateway_col:<18} UGScg                 en0\n"
        "127                127.0.0.1          UCS                   lo0\n"
        "127.0.0.1          127.0.0.1          UH                    lo0\n"
    )


@pytest.fixture
def gateway(mod, monkeypatch):
    """Call get_default_gateway() with both command outputs supplied.

    Anything not passed defaults to "" — what run() yields when the binary is
    missing or the call times out. `gateway.calls` records what actually ran.
    """
    def _gateway(route_out="", netstat_out=""):
        fake = make_run({ROUTE_CMD: route_out, NETSTAT_CMD: netstat_out})
        monkeypatch.setattr(mod, "run", fake)
        _gateway.calls = fake.calls
        return mod.get_default_gateway()

    _gateway.calls = []
    return _gateway


@pytest.fixture
def interfaces(mod, monkeypatch):
    """Call get_all_interfaces() over the supplied `ifconfig -a` output."""
    def _interfaces(ifconfig_out=""):
        fake = make_run({IFCONFIG_CMD: ifconfig_out})
        monkeypatch.setattr(mod, "run", fake)
        _interfaces.calls = fake.calls
        return mod.get_all_interfaces()

    _interfaces.calls = []
    return _interfaces


@pytest.fixture
def dns_servers(mod, monkeypatch):
    """Call get_dns_servers() over the supplied `scutil --dns` output."""
    def _dns(scutil_out=""):
        fake = make_run({SCUTIL_CMD: scutil_out})
        monkeypatch.setattr(mod, "run", fake)
        _dns.calls = fake.calls
        return mod.get_dns_servers()

    _dns.calls = []
    return _dns


class TestGetDefaultGatewayFromRoute:
    def test_gateway_is_read_from_the_route_command(self, gateway):
        assert gateway(route_out=ROUTE_WITH_GATEWAY) == "192.168.1.1"

    def test_netstat_is_not_run_when_route_answers(self, gateway):
        gateway(route_out=ROUTE_WITH_GATEWAY, netstat_out=NETSTAT_TABLE)
        assert gateway.calls == [ROUTE_CMD]

    def test_route_answer_wins_over_a_disagreeing_netstat_table(self, gateway):
        # Both sources available and disagreeing: route is authoritative.
        # A reversed precedence would report the stale/secondary router.
        assert gateway(
            route_out=ROUTE_WITH_GATEWAY,
            netstat_out=_netstat_table("10.0.0.1"),
        ) == "192.168.1.1"


class TestGetDefaultGatewayNetstatFallback:
    def test_falls_back_to_netstat_when_route_prints_no_gateway_line(self, gateway):
        # A full-tunnel VPN default route is point-to-point: `route -n get
        # default` names the interface and prints no gateway: line at all.
        assert gateway(
            route_out=ROUTE_NO_GATEWAY,
            netstat_out=NETSTAT_TABLE,
        ) == "192.168.1.1"

    def test_netstat_is_consulted_only_after_route_has_failed(self, gateway):
        gateway(route_out=ROUTE_NO_GATEWAY, netstat_out=NETSTAT_TABLE)
        assert gateway.calls == [ROUTE_CMD, NETSTAT_CMD]

    def test_default_row_is_found_even_when_other_routes_precede_it(self, gateway):
        # Guards against "first row with an IP in column 2" — the 127 rows
        # would otherwise hand back the loopback as the router.
        table = (
            "Routing tables\n"
            "\n"
            "Internet:\n"
            "Destination        Gateway            Flags               Netif Expire\n"
            "127                127.0.0.1          UCS                   lo0\n"
            "127.0.0.1          127.0.0.1          UH                    lo0\n"
            "default            192.168.1.1        UGScg                 en0\n"
        )
        assert gateway(route_out=ROUTE_NO_GATEWAY, netstat_out=table) == "192.168.1.1"

    @pytest.mark.parametrize("gateway_col", [
        "link#4",
        "link#14",
        "en0",
        "utun3",
        "fe80::%utun4",
    ], ids=["link_id", "high_link_id", "ethernet_name", "tunnel_name", "ipv6_scoped"])
    def test_non_numeric_gateway_column_is_rejected(self, gateway, gateway_col):
        # A point-to-point or IPv6 default route puts an interface reference in
        # the Gateway column. Returning it would send every router probe at a
        # hostname that does not resolve, so "unknown" is the correct answer.
        assert gateway(
            route_out=ROUTE_NO_GATEWAY,
            netstat_out=_netstat_table(gateway_col),
        ) is None

    def test_link_level_default_route_yields_no_gateway(self, gateway):
        # Realistic full table: the IPv4 default goes via link#14 on utun4 and
        # the IPv6 default via a scoped link-local. Neither is a router address.
        assert gateway(
            route_out=ROUTE_NO_GATEWAY,
            netstat_out=NETSTAT_LINK_DEFAULT,
        ) is None

    def test_no_routing_information_at_all_yields_none(self, gateway):
        assert gateway(route_out="", netstat_out="") is None

    def test_both_commands_are_tried_before_giving_up(self, gateway):
        gateway(route_out="", netstat_out="")
        assert gateway.calls == [ROUTE_CMD, NETSTAT_CMD]


class TestGetAllInterfacesNetmaskForms:
    def test_hex_netmask_is_converted_to_a_prefix_network(self, interfaces):
        result = interfaces(IFCONFIG_ALL)
        assert ("en0", "192.168.1.50", ipaddress.ip_network("192.168.1.0/24")) in result

    def test_dotted_netmask_is_converted_to_a_prefix_network(self, interfaces):
        out = "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tinet 10.0.0.5 netmask 255.255.0.0 broadcast 10.0.255.255\n"
        assert interfaces(out) == [
            ("en0", "10.0.0.5", ipaddress.ip_network("10.0.0.0/16")),
        ]

    def test_host_bits_do_not_reject_the_network(self, interfaces):
        # ip_network(strict=False) is required: the address is a host address,
        # not the network address, so strict parsing would raise ValueError and
        # the interface would silently vanish.
        out = "en0:\n\tinet 192.168.1.50 netmask 0xffffff00\n"
        assert interfaces(out)[0][2] == ipaddress.ip_network("192.168.1.0/24")


class TestGetAllInterfacesFiltering:
    def test_loopback_address_is_excluded(self, interfaces):
        ips = [ip for _, ip, _ in interfaces(IFCONFIG_ALL)]
        assert "127.0.0.1" not in ips

    def test_loopback_interface_contributes_nothing(self, interfaces):
        names = [iface for iface, _, _ in interfaces(IFCONFIG_ALL)]
        assert "lo0" not in names

    def test_link_local_address_is_excluded(self, interfaces):
        # en5 in the capture is an unconfigured USB NIC that self-assigned
        # 169.254.113.87/16. Sweeping that /16 is 65k pointless probes.
        ips = [ip for _, ip, _ in interfaces(IFCONFIG_ALL)]
        assert "169.254.113.87" not in ips

    def test_interfaces_without_an_ipv4_address_are_omitted(self, interfaces):
        names = [iface for iface, _, _ in interfaces(IFCONFIG_ALL)]
        for absent in ("utun0", "awdl0", "bridge0", "gif0", "stf0", "anpi0"):
            assert absent not in names

    def test_inet6_lines_are_never_parsed_as_addresses(self, interfaces):
        result = interfaces(IFCONFIG_ALL)
        assert result, "capture parsed to nothing; the rest of this test is vacuous"
        for _, ip, net in result:
            assert ipaddress.ip_address(ip).version == 4
            assert isinstance(net, ipaddress.IPv4Network)

    def test_empty_output_returns_an_empty_list(self, interfaces):
        assert interfaces("") == []


class TestGetAllInterfacesNaming:
    def test_every_configured_interface_is_returned(self, interfaces):
        assert interfaces(IFCONFIG_ALL) == [
            ("en0", "192.168.1.50", ipaddress.ip_network("192.168.1.0/24")),
            ("en8", "10.42.0.7", ipaddress.ip_network("10.42.0.0/22")),
        ]

    def test_name_carries_from_the_header_across_intervening_lines(self, interfaces):
        # The inet line itself never names its interface; the name comes from
        # the last "name:" header seen, several lines earlier.
        out = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\toptions=6463<RXCSUM,TXCSUM,TSO4,TSO6,CHANNEL_IO>\n"
            "\tether 3c:22:fb:8a:11:4e\n"
            "\tinet6 fe80::14e2:8a1f:fe22:3c4d%en0 prefixlen 64 secured scopeid 0xc\n"
            "\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "\tmedia: autoselect\n"
            "\tstatus: active\n"
            "en8: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tether 64:4b:f0:1c:77:03\n"
            "\tinet 10.42.0.7 netmask 0xfffffc00 broadcast 10.42.3.255\n"
            "\tstatus: active\n"
        )
        assert [iface for iface, _, _ in interfaces(out)] == ["en0", "en8"]

    def test_two_addresses_on_one_interface_both_keep_that_name(self, interfaces):
        # `ifconfig en0 alias` adds a second inet line under the same header.
        out = (
            "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
            "\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "\tinet 192.168.7.50 netmask 0xffffff00 broadcast 192.168.7.255\n"
        )
        assert interfaces(out) == [
            ("en0", "192.168.1.50", ipaddress.ip_network("192.168.1.0/24")),
            ("en0", "192.168.7.50", ipaddress.ip_network("192.168.7.0/24")),
        ]


class TestGetAllInterfacesMalformedInput:
    # The trailing en8 stanza in each case is the point: a bad netmask must
    # skip its own address and leave the rest of the parse running.
    GOOD_TAIL = "en8: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tinet 10.42.0.7 netmask 0xfffffc00 broadcast 10.42.3.255\n"
    GOOD_ENTRY = ("en8", "10.42.0.7", ipaddress.ip_network("10.42.0.0/22"))

    def test_netmask_wider_than_32_bits_is_skipped_not_raised(self, interfaces):
        # Regression, commit 0a79294 ("get_all_interfaces: also catch
        # OverflowError from a >32-bit netmask"): int("0xffffffffff", 16)
        # .to_bytes(4, "big") raises OverflowError, which the original
        # `except ValueError` at line 170 did not catch — one malformed stanza
        # aborted the whole interface scan.
        out = "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tinet 192.168.1.50 netmask 0xffffffffff\n" + self.GOOD_TAIL
        assert interfaces(out) == [self.GOOD_ENTRY]

    @pytest.mark.parametrize("netmask", [
        "255.255.300.0",
        "255.0.255.0",
        "0xffff00ff",
    ], ids=["octet_out_of_range", "non_contiguous_dotted", "non_contiguous_hex"])
    def test_unusable_netmask_is_skipped_not_raised(self, interfaces, netmask):
        out = f"en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tinet 192.168.1.50 netmask {netmask}\n" + self.GOOD_TAIL
        assert interfaces(out) == [self.GOOD_ENTRY]

    def test_address_line_before_any_header_is_ignored(self, interfaces):
        out = "\tinet 192.168.1.50 netmask 0xffffff00\n" + self.GOOD_TAIL
        assert interfaces(out) == [self.GOOD_ENTRY]

    def test_point_to_point_address_line_is_not_parsed(self, interfaces):
        # DOCUMENTS ACTUAL BEHAVIOUR, not an endorsement. A P2P interface
        # prints "inet A --> B netmask M"; the regex at line 156 requires the
        # netmask to follow the address directly, so VPN/tether interfaces
        # never appear. That suppression happens to agree with commit 0a79294,
        # which deliberately kept VPN subnets out of the sweep — but it is a
        # side effect of the regex, not a stated rule. If P2P support is ever
        # added, this expectation is the one to revisit.
        out = (
            "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n"
            "\tinet 10.211.55.2 --> 10.211.55.2 netmask 0xffffff00\n"
        )
        assert interfaces(out) == []


class TestGetDnsServers:
    def test_resolvers_are_returned_in_first_seen_order(self, dns_servers):
        # Order is the router-first ordering the resolver actually uses, and
        # action_check_dns prints it as such. Sorting it (or round-tripping
        # through a set) would misreport which resolver is primary.
        assert dns_servers(SCUTIL_DNS) == [
            "192.168.1.1",
            "9.9.9.9",
            "1.1.1.1",
            "10.8.0.1",
        ]

    def test_scoped_query_repeats_are_collapsed(self, dns_servers):
        # scutil repeats the same resolvers under "DNS configuration (for
        # scoped queries)"; the capture lists 192.168.1.1 twice.
        result = dns_servers(SCUTIL_DNS)
        assert len(result) == len(set(result))

    def test_a_resolver_only_present_in_the_scoped_section_is_kept(self, dns_servers):
        # Deduping must not degenerate into "only read the first block": the
        # VPN resolver on utun4 appears nowhere else.
        assert "10.8.0.1" in dns_servers(SCUTIL_DNS)

    def test_empty_output_returns_an_empty_list(self, dns_servers):
        assert dns_servers("") == []

    def test_resolvers_are_read_from_scutil(self, dns_servers):
        dns_servers(SCUTIL_DNS)
        assert dns_servers.calls == [SCUTIL_CMD]

    def test_a_link_local_resolver_is_reported_with_its_zone(self, dns_servers):
        """fe80::1%en0 is a real resolver — the router advertising itself by RA.

        The old `[\\d.]+` pattern could not match it at all, so it vanished
        silently. That was never correct: on an IPv6-only network it made the
        tool report no DNS configuration whatsoever. The zone suffix is part of
        the address and must survive, since fe80::1 is only meaningful per-link.
        """
        out = (
            "DNS configuration\n"
            "\n"
            "resolver #1\n"
            "  nameserver[0] : fe80::1%en0\n"
            "  nameserver[1] : 1.1.1.1\n"
            "  if_index : 12 (en0)\n"
        )
        assert dns_servers(out) == ["fe80::1%en0", "1.1.1.1"]

    def test_a_malformed_nameserver_is_dropped_rather_than_recorded(self, dns_servers):
        # Anything that is not an address must not reach the baseline, where it
        # would diff as a change forever. Mirrors read_arp_table's contract.
        out = (
            "resolver #1\n"
            "  nameserver[0] : not-an-address\n"
            "  nameserver[1] : 999.1.1.1\n"
            "  nameserver[2] : 2606:4700:4700::zzzz\n"
            "  nameserver[3] : 1.1.1.1\n"
        )
        assert dns_servers(out) == ["1.1.1.1"]

    def test_an_equivalent_ipv6_form_is_normalised_so_it_is_not_a_false_change(self, dns_servers):
        # 2606:4700:4700:0:0:0:0:1111 and 2606:4700:4700::1111 are the same
        # resolver. Storing them verbatim would diff as a DNS change between
        # runs — a false hijacking alarm.
        expanded = dns_servers("  nameserver[0] : 2606:4700:4700:0:0:0:0:1111\n")
        compact = dns_servers("  nameserver[0] : 2606:4700:4700::1111\n")
        assert expanded == compact == ["2606:4700:4700::1111"]

    def test_well_known_ipv6_resolvers_are_recognised_not_flagged_unfamiliar(self, mod, dns_servers):
        """The half of the fix that actually stops the false alarm.

        Repairing the regex alone would only change the warning from
        '2606 <-- unfamiliar' to '2606:4700:4700::1111 <-- unfamiliar'. The
        resolver has to be in KNOWN_DNS in the same normalised form
        get_dns_servers emits, or a dual-stack Mac still nags on every run.
        """
        out = (
            "  nameserver[0] : 2606:4700:4700::1111\n"
            "  nameserver[1] : 2001:4860:4860::8888\n"
            "  nameserver[2] : 2620:fe::fe\n"
        )
        for server in dns_servers(out):
            assert mod.KNOWN_DNS.get(server), f"{server} would be flagged unfamiliar"

    def test_every_known_dns_key_is_a_valid_normalised_address(self, mod):
        # A typo'd or non-canonical key in KNOWN_DNS silently never matches,
        # which reintroduces the false alarm without failing anything.
        for key in mod.KNOWN_DNS:
            addr, sep, zone = key.partition("%")
            assert str(ipaddress.ip_address(addr)) + sep + zone == key, key

    def test_ipv6_nameserver_is_never_truncated_into_a_bogus_server(self, dns_servers):
        # Cloudflare/Google/Quad9 IPv6 resolvers all start with digits
        # (2606:, 2001:, 2620:), so any Mac on an IPv6-enabled ISP hits this.
        out = (
            "DNS configuration\n"
            "\n"
            "resolver #1\n"
            "  nameserver[0] : 1.1.1.1\n"
            "  nameserver[1] : 2606:4700:4700::1111\n"
            "  nameserver[2] : 2001:4860:4860::8888\n"
            "  if_index : 12 (en0)\n"
            "  flags    : Request A records, Request AAAA records\n"
        )
        result = dns_servers(out)
        assert result == [
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ], "IPv6 resolvers must be kept whole, in first-seen order"
        assert "2606" not in result, "the truncated hextet must never appear"
