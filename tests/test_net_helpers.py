"""Tier 3: the pure network helpers.

These have no I/O of their own beyond check_port's single socket, so they are
called directly rather than through a command fake. Two of them are security
boundaries:

* ``is_real_host`` decides which ARP entries belong to the subnet being swept.
  Commit 0a79294 added the membership check after a sweep of 192.168.85.0/24
  picked 192.168.87.x entries out of the machine-wide ARP cache and reported
  them under the wrong network.
* ``check_port`` / ``scan_ports`` must degrade to "closed" on a socket error
  instead of aborting the sweep (same commit: EMFILE under high worker counts).
"""

import errno
import ipaddress
import socket
import subprocess

import pytest

from conftest import make_check_port, make_run

HOME = ipaddress.ip_network("192.168.85.0/24")
OTHER = ipaddress.ip_network("192.168.87.0/24")
FLAT = ipaddress.ip_network("192.168.0.0/16")
NORMAL_MAC = "a4:83:e7:1b:9c:2d"


class TestIsRealHost:
    @pytest.mark.parametrize(
        "subnet, ip, mac, expected",
        [
            # --- genuine hosts -------------------------------------------------
            (HOME, "192.168.85.42", NORMAL_MAC, True),
            (HOME, "192.168.85.1", "b8:27:eb:4f:1a:7c", True),
            (HOME, "192.168.85.254", NORMAL_MAC, True),
            # An unresolved ARP entry is still a host; only the MAC is missing.
            (HOME, "192.168.85.77", "unknown", True),
            # .255 is a normal host address inside a /16 — the broadcast test
            # must compare against the subnet's own broadcast, not the octet.
            (FLAT, "192.168.1.255", NORMAL_MAC, True),
            # --- cross-subnet ARP bleed (commit 0a79294) -----------------------
            (HOME, "192.168.87.42", NORMAL_MAC, False),
            (HOME, "10.0.0.5", NORMAL_MAC, False),
            (HOME, "192.168.84.255", NORMAL_MAC, False),
            # --- structural addresses -----------------------------------------
            (HOME, "192.168.85.0", NORMAL_MAC, False),
            (HOME, "192.168.85.255", "ff:ff:ff:ff:ff:ff", False),
            (HOME, "192.168.85.255", NORMAL_MAC, False),
            (FLAT, "192.168.255.255", NORMAL_MAC, False),
            # 0.0.0.0 cannot be a member of any subnet that is not rooted at it,
            # so the is_unspecified guard can only ever be reached via 0.0.0.0/x.
            (HOME, "0.0.0.0", NORMAL_MAC, False),
            (ipaddress.ip_network("0.0.0.0/8"), "0.0.0.0", NORMAL_MAC, False),
            # --- pseudo-entries by MAC ----------------------------------------
            (HOME, "192.168.85.100", "ff:ff:ff:ff:ff:ff", False),
            (HOME, "192.168.85.251", "01:00:5e:00:00:fb", False),
            (HOME, "192.168.85.16", "33:33:00:00:00:fb", False),
            # --- garbage in, False out (never an exception) --------------------
            (HOME, "not-an-ip", NORMAL_MAC, False),
            (HOME, "192.168.85.999", NORMAL_MAC, False),
            (HOME, "", NORMAL_MAC, False),
            (HOME, "192.168.085.1", NORMAL_MAC, False),
            (HOME, "192.168.85.1/24", NORMAL_MAC, False),
        ],
        ids=[
            "in_subnet_unicast",
            "gateway",
            "last_usable_host",
            "unknown_mac_is_still_a_host",
            "dot255_is_a_host_inside_a_slash16",
            "adjacent_subnet_arp_bleed",
            "unrelated_rfc1918_subnet",
            "one_subnet_below",
            "network_address",
            "broadcast_address_with_broadcast_mac",
            "broadcast_address_with_normal_mac",
            "slash16_broadcast_address",
            "unspecified_outside_subnet",
            "unspecified_inside_zero_network",
            "broadcast_mac",
            "ipv4_multicast_mac_prefix",
            "ipv6_multicast_mac_prefix",
            "unparseable_ip",
            "octet_out_of_range",
            "empty_ip",
            "leading_zero_octet",
            "cidr_where_an_ip_belongs",
        ],
    )
    def test_membership_and_pseudo_entry_filtering(self, mod, subnet, ip, mac, expected):
        assert mod.is_real_host(ip, mac, subnet) is expected

    def test_multicast_group_inside_a_multicast_subnet_is_rejected(self, mod):
        # Isolates the is_multicast guard: 224.0.0.251 (mDNS) is a member of
        # 224.0.0.0/4 and is neither its network nor its broadcast address, so
        # only the multicast check can reject it.
        assert mod.is_real_host("224.0.0.251", NORMAL_MAC,
                                ipaddress.ip_network("224.0.0.0/4")) is False

    def test_single_host_slash32_subnet_excludes_its_only_address(self, mod):
        # Documents an edge case rather than endorsing it: in a /32 the network
        # and broadcast addresses are the host itself, so `--subnet x.x.x.x/32`
        # can never report a device. No in-tree caller produces a /32 today
        # (get_all_interfaces' regex skips point-to-point `inet a --> b` lines).
        assert mod.is_real_host("192.168.85.24", NORMAL_MAC,
                                ipaddress.ip_network("192.168.85.24/32")) is False

    def test_ipv6_arp_entry_is_not_a_member_of_an_ipv4_sweep(self, mod):
        assert mod.is_real_host("fe80::10c1:2b3f:8a44:9e7c", NORMAL_MAC, HOME) is False

    def test_every_arp_ip_outside_the_swept_subnet_is_dropped(self, mod):
        # End-to-end shape of the 0a79294 regression: a machine-wide ARP cache
        # holding two subnets must yield only the swept one.
        arp = {
            "192.168.85.1": "b8:27:eb:4f:1a:7c",
            "192.168.85.24": NORMAL_MAC,
            "192.168.87.10": "3c:22:fb:0d:5e:71",
            "192.168.87.99": "dc:a6:32:11:8e:04",
            "224.0.0.251": "01:00:5e:00:00:fb",
        }
        kept = [ip for ip, mac in arp.items() if mod.is_real_host(ip, mac, HOME)]
        assert kept == ["192.168.85.1", "192.168.85.24"]


class TestIsRandomizedMac:
    @pytest.mark.parametrize(
        "mac, expected",
        [
            ("aa:bb:cc:dd:ee:ff", True),
            ("02:00:00:00:00:01", True),
            ("6e:1f:3a:9c:44:07", True),
            ("b8:27:eb:4f:1a:7c", False),
            ("a4:83:e7:1b:9c:2d", False),
            ("3c:22:fb:0d:5e:71", False),
            ("00:00:00:00:00:00", False),
        ],
        ids=[
            "aa_has_locally_administered_bit",
            "02_is_the_bit_itself",
            "6e_random_ios_style",
            "raspberry_pi_globally_unique",
            "apple_globally_unique",
            "globally_unique_with_bit_clear",
            "all_zero",
        ],
    )
    def test_locally_administered_bit_of_the_first_octet(self, mod, mac, expected):
        assert mod.is_randomized_mac(mac) is expected

    @pytest.mark.parametrize(
        "mac",
        ["unknown", "", "zz:bb:cc:dd:ee:ff", ":", "not a mac at all"],
        ids=["unknown_placeholder", "empty", "non_hex_octet", "bare_colon", "prose"],
    )
    def test_unparseable_macs_are_not_randomized_and_do_not_raise(self, mod, mac):
        assert mod.is_randomized_mac(mac) is False

    def test_return_value_is_a_bool_not_the_masked_int(self, mod):
        # `int(...) & 0x02` is 2, not True; callers compare with `is`/store as JSON.
        assert mod.is_randomized_mac("aa:bb:cc:dd:ee:ff") is True


class TestGuessSubnet:
    @pytest.mark.parametrize(
        "ip, expected",
        [
            ("192.168.85.24", "192.168.85.0/24"),
            ("10.0.0.7", "10.0.0.0/24"),
            ("172.16.5.200", "172.16.5.0/24"),
        ],
    )
    def test_returns_the_slash24_containing_the_address(self, mod, ip, expected):
        assert mod.guess_subnet(ip) == ipaddress.ip_network(expected)

    def test_result_is_a_network_object_not_a_string(self, mod):
        assert isinstance(mod.guess_subnet("192.168.85.24"), ipaddress.IPv4Network)

    @pytest.mark.parametrize("value", [None, ""], ids=["none", "empty_string"])
    def test_no_local_ip_yields_no_guess(self, mod, value):
        assert mod.guess_subnet(value) is None


class TestNetworkNameForSubnet:
    NETWORKS = {
        "192.168.85.0/24": "Home LAN",
        "192.168.87.0/24": "Guest LAN",
    }

    def test_exact_cidr_key_returns_the_friendly_name(self, mod):
        assert mod.network_name_for_subnet("192.168.85.0/24", self.NETWORKS) == "Home LAN"

    def test_host_bits_normalise_to_the_network_address_before_lookup(self, mod):
        assert mod.network_name_for_subnet("192.168.85.24/24", self.NETWORKS) == "Home LAN"

    def test_unknown_subnet_falls_back_to_the_subnet_string(self, mod):
        assert mod.network_name_for_subnet("10.9.9.0/24", self.NETWORKS) == "10.9.9.0/24"

    def test_unparseable_subnet_returns_itself_rather_than_raising(self, mod):
        assert mod.network_name_for_subnet("not-a-subnet", self.NETWORKS) == "not-a-subnet"

    def test_a_saved_key_that_kept_its_host_bits_still_matches(self, mod):
        # networks.json is hand-editable, so a key may not be normalised; the
        # raw-string fallback is what makes such an entry usable.
        networks = {"192.168.85.24/24": "Hand-edited entry"}
        assert mod.network_name_for_subnet("192.168.85.24/24", networks) == "Hand-edited entry"

    def test_empty_network_map_returns_the_subnet_string(self, mod):
        assert mod.network_name_for_subnet("192.168.85.0/24", {}) == "192.168.85.0/24"


def _iface(name, ip, cidr):
    """One get_all_interfaces() row: (iface, ip, ip_network)."""
    return (name, ip, ipaddress.ip_network(cidr))


class TestResolveSubnets:
    def test_overrides_replace_auto_detection_entirely(self, mod):
        ifaces = [_iface("en0", "192.168.85.24", "192.168.85.0/24")]
        assert mod.resolve_subnets(["10.0.0.0/24"], None, ifaces, "192.168.85.24") == [
            ipaddress.ip_network("10.0.0.0/24")
        ]

    def test_override_order_is_the_scan_order(self, mod):
        result = mod.resolve_subnets(
            ["10.0.0.0/24", "192.168.85.0/24", "172.16.5.0/24"], None, [], None)
        assert result == [
            ipaddress.ip_network("10.0.0.0/24"),
            ipaddress.ip_network("192.168.85.0/24"),
            ipaddress.ip_network("172.16.5.0/24"),
        ]

    def test_host_bits_in_an_override_are_tolerated(self, mod):
        assert mod.resolve_subnets(["192.168.1.55/24"], None, [], None) == [
            ipaddress.ip_network("192.168.1.0/24")
        ]

    def test_invalid_override_is_skipped_with_a_message_naming_it(self, mod, capsys):
        result = mod.resolve_subnets(
            ["192.168.85.0/24", "192.168.1.0/99"], None, [], None)
        out = capsys.readouterr().out
        assert result == [ipaddress.ip_network("192.168.85.0/24")]
        assert "192.168.1.0/99" in out
        assert "kipping" in out

    def test_invalid_extra_is_skipped_with_a_message_naming_it(self, mod, capsys):
        result = mod.resolve_subnets(
            None, ["10.0.0.0/24", "banana"], [], None)
        out = capsys.readouterr().out
        assert result == [ipaddress.ip_network("10.0.0.0/24")]
        assert "banana" in out
        assert "extra" in out

    def test_extras_are_appended_after_the_auto_detected_interface_subnet(self, mod):
        ifaces = [_iface("en0", "192.168.85.24", "192.168.85.0/24")]
        result = mod.resolve_subnets(None, ["10.0.0.0/24"], ifaces, "192.168.85.24")
        assert result == [
            ipaddress.ip_network("192.168.85.0/24"),
            ipaddress.ip_network("10.0.0.0/24"),
        ]

    def test_extras_are_appended_after_overrides(self, mod):
        result = mod.resolve_subnets(["192.168.85.0/24"], ["10.0.0.0/24"], [], None)
        assert result == [
            ipaddress.ip_network("192.168.85.0/24"),
            ipaddress.ip_network("10.0.0.0/24"),
        ]

    def test_a_subnet_in_both_overrides_and_extras_is_swept_once_in_override_order(self, mod):
        result = mod.resolve_subnets(
            ["192.168.85.0/24", "10.0.0.0/24"], ["192.168.85.0/24"], [], None)
        assert result == [
            ipaddress.ip_network("192.168.85.0/24"),
            ipaddress.ip_network("10.0.0.0/24"),
        ]

    def test_repeated_and_differently_written_duplicates_collapse_to_one(self, mod):
        result = mod.resolve_subnets(
            ["192.168.85.0/24", "192.168.85.24/24", "192.168.85.0/24"], None, [], None)
        assert result == [ipaddress.ip_network("192.168.85.0/24")]

    def test_falls_back_to_the_local_ip_slash24_when_nothing_is_detected(self, mod):
        assert mod.resolve_subnets(None, None, [], "192.168.4.17") == [
            ipaddress.ip_network("192.168.4.0/24")
        ]

    def test_interfaces_win_over_the_local_ip_guess(self, mod):
        ifaces = [_iface("en0", "192.168.85.24", "192.168.85.0/25")]
        assert mod.resolve_subnets(None, None, ifaces, "10.0.0.7") == [
            ipaddress.ip_network("192.168.85.0/25")
        ]

    def test_nothing_at_all_yields_no_subnets(self, mod):
        assert mod.resolve_subnets(None, None, [], None) == []

    def test_extras_alone_are_enough_to_produce_a_sweep(self, mod):
        assert mod.resolve_subnets(None, ["10.0.0.0/24"], [], None) == [
            ipaddress.ip_network("10.0.0.0/24")
        ]

    def test_all_overrides_invalid_yields_no_sweep_rather_than_auto_detection(self, mod, capsys):
        # Documents current behaviour rather than asserting it is right: once
        # the user passes --subnet, auto-detection is off, so a wholly invalid
        # override list scans nothing instead of silently falling back.
        ifaces = [_iface("en0", "192.168.85.24", "192.168.85.0/24")]
        result = mod.resolve_subnets(["nonsense"], None, ifaces, "192.168.85.24")
        assert result == []
        assert "nonsense" in capsys.readouterr().out

    def test_real_ifconfig_output_feeds_straight_into_resolve_subnets(
            self, mod, monkeypatch, fixture):
        monkeypatch.setattr(mod, "run", make_run(
            {"ifconfig -a": fixture("ifconfig_two_subnets.out")}))
        ifaces = mod.get_all_interfaces()
        # The triple shape resolve_subnets destructures is (iface, ip, network).
        assert [name for name, _, _ in ifaces] == ["en0", "en1"]
        assert set(mod.resolve_subnets(None, None, ifaces, None)) == {
            ipaddress.ip_network("192.168.85.0/24"),
            ipaddress.ip_network("192.168.87.0/24"),
        }

    def test_interface_order_is_preserved_so_the_primary_link_is_swept_first(self, mod):
        """Auto-detected interfaces are swept in the order they were found.

        This was a known bug: resolve_subnets used to launder the interfaces
        through a set, so the returned order was the set's iteration order and
        the primary link (en0) could be swept and reported after a secondary
        one. It is now a plain list comprehension, with the order-preserving
        de-duplication below doing the work the set was redundant with.

        Ten subnets rather than two, deliberately. While the bug existed the
        symptom was build-dependent — a two-subnet case matched insertion order
        in 378 of the 780 pairs across 192.168.0-39.0/24, and CI showed x86_64
        Linux and macOS arm64 disagreeing at both two and ten subnets. Ten keeps
        the assertion strong enough that any reintroduction of set-laundering
        shows up as a real ordering difference rather than a coin flip.
        """
        expected = [ipaddress.ip_network(f"192.168.{i}.0/24") for i in range(10, 20)]
        ifaces = [_iface(f"en{n}", f"192.168.{i}.24", str(net))
                  for n, (i, net) in enumerate(zip(range(10, 20), expected))]

        got = mod.resolve_subnets(None, None, ifaces, None)
        assert got == expected
        assert len(got) == len(set(got)) == 10

    def test_a_subnet_on_two_interfaces_is_swept_once(self, mod):
        ifaces = [
            _iface("en0", "192.168.85.24", "192.168.85.0/24"),
            _iface("en1", "192.168.85.25", "192.168.85.0/24"),
        ]
        assert mod.resolve_subnets(None, None, ifaces, None) == [
            ipaddress.ip_network("192.168.85.0/24")
        ]


class FakeSocket:
    """Stand-in for socket.socket recording what check_port / get_local_ip do to it.

    check_port drives ``connect_ex``; get_local_ip drives ``connect`` +
    ``getsockname``. ``send``/``sendto`` fail the test outright: get_local_ip's
    UDP connect is a pure routing lookup that must never put a packet on the
    wire, and the failure has to survive the ``except OSError`` in the code
    under test — pytest.fail raises a BaseException subclass, so it does.
    """

    def __init__(self, connect_ex_result=0, connect_ex_error=None,
                 sockname=("192.168.1.50", 51234), connect_error=None):
        self.connect_ex_result = connect_ex_result
        self.connect_ex_error = connect_ex_error
        self.sockname = sockname
        self.connect_error = connect_error
        self.family = None
        self.type = None
        self.timeout = None
        self.connect_args = None
        self.closed = False
        self.sent = []

    def settimeout(self, value):
        self.timeout = value

    def connect_ex(self, address):
        self.connect_args = address
        if self.connect_ex_error is not None:
            raise self.connect_ex_error
        return self.connect_ex_result

    def connect(self, address):
        self.connect_args = address
        if self.connect_error is not None:
            raise self.connect_error

    def getsockname(self):
        return self.sockname

    def send(self, *args, **kwargs):
        self._refuse_to_transmit("send", args)

    def sendto(self, *args, **kwargs):
        self._refuse_to_transmit("sendto", args)

    def _refuse_to_transmit(self, name, args):
        self.sent.append((name, args))
        pytest.fail(f"the code under test called {name}{args!r}; the UDP "
                    "connect trick must not transmit anything")

    def close(self):
        self.closed = True


def install_fake_socket(monkeypatch, sock=None, construct_error=None):
    """Replace socket.socket with a factory; returns the list of sockets made."""
    made = []

    def factory(family=None, type=None, *args, **kwargs):
        if construct_error is not None:
            raise construct_error
        s = sock if sock is not None else FakeSocket()
        s.family, s.type = family, type
        made.append(s)
        return s

    monkeypatch.setattr(socket, "socket", factory)
    return made


class TestCheckPort:
    def test_connect_ex_zero_means_open(self, mod, monkeypatch):
        install_fake_socket(monkeypatch, FakeSocket(connect_ex_result=0))
        assert mod.check_port("192.168.85.1", 443) is True

    @pytest.mark.parametrize(
        "errno_value",
        [61, 60, 65, 111],
        ids=["ECONNREFUSED", "ETIMEDOUT", "EHOSTUNREACH", "linux_ECONNREFUSED"],
    )
    def test_non_zero_connect_ex_means_closed(self, mod, monkeypatch, errno_value):
        install_fake_socket(monkeypatch, FakeSocket(connect_ex_result=errno_value))
        assert mod.check_port("192.168.85.1", 443) is False

    def test_probes_the_requested_host_and_port_over_tcp(self, mod, monkeypatch):
        made = install_fake_socket(monkeypatch)
        mod.check_port("192.168.85.1", 8080)
        assert made[0].connect_args == ("192.168.85.1", 8080)
        assert (made[0].family, made[0].type) == (socket.AF_INET, socket.SOCK_STREAM)

    def test_timeout_is_applied_before_connecting(self, mod, monkeypatch):
        made = install_fake_socket(monkeypatch)
        mod.check_port("192.168.85.1", 22, timeout=2.5)
        assert made[0].timeout == 2.5

    def test_default_timeout_is_short_enough_for_a_full_sweep(self, mod, monkeypatch):
        made = install_fake_socket(monkeypatch)
        mod.check_port("192.168.85.1", 22)
        assert made[0].timeout == 0.6

    def test_socket_is_closed_on_the_success_path(self, mod, monkeypatch):
        made = install_fake_socket(monkeypatch)
        mod.check_port("192.168.85.1", 22)
        assert made[0].closed is True

    def test_socket_is_closed_even_when_connect_ex_raises(self, mod, monkeypatch):
        # A leaked descriptor per failed probe is what drives the EMFILE below.
        sock = FakeSocket(connect_ex_error=OSError(65, "No route to host"))
        made = install_fake_socket(monkeypatch, sock)
        assert mod.check_port("192.168.85.1", 22) is False
        assert made[0].closed is True

    def test_socket_construction_failure_reports_closed_not_an_exception(self, mod, monkeypatch):
        # Regression, commit 0a79294: with high --workers the process runs out
        # of descriptors and socket() itself raises EMFILE. That must degrade to
        # "port not open" instead of tearing down the sweep.
        install_fake_socket(monkeypatch,
                            construct_error=OSError(24, "Too many open files"))
        assert mod.check_port("192.168.85.1", 22) is False

    def test_timeout_error_from_connect_ex_is_treated_as_closed(self, mod, monkeypatch):
        # socket.timeout is an OSError subclass; a slow host must not raise.
        install_fake_socket(monkeypatch,
                            FakeSocket(connect_ex_error=socket.timeout("timed out")))
        assert mod.check_port("192.168.85.1", 22) is False


class TestScanPorts:
    """scan_ports fans probe_port out over a thread pool and keeps the opens.

    The fake seam is `probe_port`, not `check_port`: scan_ports needs the
    three-state answer (open / closed / unreachable) that check_port's boolean
    throws away. A boolean fake still works here because True and False are two
    of those three states; the unreachable case is covered in
    TestScanPortsDetailed below.
    """

    def test_returns_only_open_ports_sorted_ascending(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "probe_port", make_check_port([80, 22, 8080]))
        assert mod.scan_ports("192.168.85.1", [443, 8080, 22, 80, 445]) == [22, 80, 8080]

    def test_no_open_ports_yields_an_empty_list(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "probe_port", make_check_port([]))
        assert mod.scan_ports("192.168.85.1", [22, 80, 443]) == []

    def test_empty_port_list_yields_an_empty_list(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "probe_port", make_check_port([22]))
        assert mod.scan_ports("192.168.85.1", []) == []

    def test_every_requested_port_is_probed_on_the_requested_host(self, mod, monkeypatch):
        probed = []

        def spy(host, port, timeout=0.6):
            probed.append((host, port))
            return port == 22

        monkeypatch.setattr(mod, "probe_port", spy)
        mod.scan_ports("192.168.85.1", [22, 80, 443], workers=4)
        assert sorted(probed) == [("192.168.85.1", 22), ("192.168.85.1", 80),
                                  ("192.168.85.1", 443)]

    def test_one_probe_raising_oserror_does_not_abort_the_scan(self, mod, monkeypatch):
        # Regression, commit 0a79294: fut.result() re-raises in the collecting
        # thread, so an unguarded EMFILE on one port lost every other result.
        def flaky(host, port, timeout=0.6):
            if port == 445:
                raise OSError(24, "Too many open files")
            return port in (22, 80)

        monkeypatch.setattr(mod, "probe_port", flaky)
        assert mod.scan_ports("192.168.85.1", [22, 80, 443, 445]) == [22, 80]

    def test_a_probe_that_raises_is_reported_closed_not_open(self, mod, monkeypatch):
        def always_raises(host, port, timeout=0.6):
            raise OSError(24, "Too many open files")

        monkeypatch.setattr(mod, "probe_port", always_raises)
        assert mod.scan_ports("192.168.85.1", [22, 80]) == []

    def test_a_duplicated_input_port_is_probed_and_reported_twice(self, mod, monkeypatch):
        # Documents current behaviour rather than endorsing it: the future map
        # is keyed by future, not by port, so a caller-supplied duplicate lands
        # in the result twice. Latent only — both in-tree callers pass a
        # de-duplicated sequence (COMMON_PORTS is sorted(set(...)), or range()).
        monkeypatch.setattr(mod, "probe_port", make_check_port([22]))
        assert mod.scan_ports("192.168.85.1", [22, 22, 80]) == [22, 22]

    def test_accepts_any_iterable_of_ports_not_just_a_list(self, mod, monkeypatch):
        # action_port_scan passes range(1, 65536) for a full scan.
        monkeypatch.setattr(mod, "probe_port", make_check_port([22, 80]))
        assert mod.scan_ports("192.168.85.1", range(20, 90)) == [22, 80]


class TestScanPortsDetailed:
    """scan_ports_detailed separates "nothing is listening" from "I was blocked".

    macOS Local Network privacy denies a launchd/cron-scheduled process any
    connection to its own subnet. The refusal is instant EHOSTUNREACH, so a
    blocked scan of 25 ports finishes in ~0ms with zero opens — identical, once
    collapsed to a boolean, to a router with everything closed. Every scheduled
    run of this tool reported "no open ports on your router" for that reason,
    and saved the empty list into the baseline as fact. These tests pin the
    distinction that stops it.
    """

    @staticmethod
    def _fake(open_ports=(), unreachable=()):
        def probe(host, port, timeout=0.6):
            if port in unreachable:
                return None
            return port in open_ports
        return probe

    def test_all_probes_unreachable_is_reported_as_blocked(self, mod, monkeypatch):
        ports = [22, 80, 443]
        monkeypatch.setattr(mod, "probe_port", self._fake(unreachable=ports))
        result = mod.scan_ports_detailed("192.168.87.1", ports)
        assert result["blocked"] is True
        assert result["open"] == []
        assert result["unreachable"] == 3

    def test_a_genuinely_closed_host_is_not_reported_as_blocked(self, mod, monkeypatch):
        # Every port closed is a real, reportable finding; it must not be
        # confused with the blocked case just because both yield no opens.
        monkeypatch.setattr(mod, "probe_port", self._fake())
        result = mod.scan_ports_detailed("192.168.87.1", [22, 80, 443])
        assert result["blocked"] is False
        assert result["open"] == []

    def test_a_partial_failure_is_not_blocked(self, mod, monkeypatch):
        # Blocked means EVERY probe was refused. One unreachable port beside a
        # real answer is noise, not a denied scan — the host clearly answered.
        monkeypatch.setattr(mod, "probe_port",
                            self._fake(open_ports=[80], unreachable=[443]))
        result = mod.scan_ports_detailed("192.168.87.1", [80, 443])
        assert result["blocked"] is False
        assert result["open"] == [80]

    def test_no_ports_probed_is_not_blocked(self, mod, monkeypatch):
        # Guards the `probed > 0` term: an empty port list must not divide by
        # nothing and declare the host unreachable.
        monkeypatch.setattr(mod, "probe_port", self._fake())
        assert mod.scan_ports_detailed("192.168.87.1", [])["blocked"] is False

    def test_scan_ports_still_returns_just_the_open_list(self, mod, monkeypatch):
        # The thin wrapper keeps its old contract for the callers that only
        # ever wanted the opens.
        monkeypatch.setattr(mod, "probe_port",
                            self._fake(open_ports=[80, 22], unreachable=[443]))
        assert mod.scan_ports("192.168.87.1", [443, 80, 22]) == [22, 80]


class TestProbePortTriState:
    """probe_port's three states, driven through a fake socket.

    connect_ex returns the errno rather than raising, so the unreachable case
    is a return value, not an exception — which is exactly why it was so easy
    to collapse into "closed".
    """

    @staticmethod
    def _socket_returning(rc):
        class FakeSocket:
            def settimeout(self, t): pass
            def connect_ex(self, addr): return rc
            def close(self): pass
        return lambda *a, **k: FakeSocket()

    def test_rc_zero_is_open(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "socket", self._socket_returning(0))
        assert mod.probe_port("192.168.87.1", 80) is True

    def test_connection_refused_is_closed(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "socket",
                            self._socket_returning(errno.ECONNREFUSED))
        assert mod.probe_port("192.168.87.1", 80) is False

    def test_timeout_is_closed_not_unreachable(self, mod, monkeypatch):
        # A filtered port that never answers is "closed" for our purposes; only
        # an unreachable-class errno means the probe never left the machine.
        monkeypatch.setattr(mod.socket, "socket",
                            self._socket_returning(errno.ETIMEDOUT))
        assert mod.probe_port("192.168.87.1", 80) is False

    @pytest.mark.parametrize("code", [errno.EHOSTUNREACH, errno.ENETUNREACH,
                                      errno.ENETDOWN, errno.EHOSTDOWN])
    def test_unreachable_errnos_are_none(self, mod, monkeypatch, code):
        # EHOSTUNREACH (65 on macOS, 113 on Linux) is what Local Network
        # privacy returns; compare via the errno module, never the raw number.
        monkeypatch.setattr(mod.socket, "socket", self._socket_returning(code))
        assert mod.probe_port("192.168.87.1", 80) is None

    def test_socket_construction_failing_unreachably_is_none(self, mod, monkeypatch):
        def boom(*a, **k):
            raise OSError(errno.EHOSTUNREACH, "No route to host")
        monkeypatch.setattr(mod.socket, "socket", boom)
        assert mod.probe_port("192.168.87.1", 80) is None

    def test_emfile_is_closed_not_unreachable(self, mod, monkeypatch):
        # Regression guard, commit 0a79294: EMFILE under a 100-worker pool is a
        # local resource limit, not a network verdict. It must stay "closed" so
        # a busy scan is never mistaken for a denied one.
        def boom(*a, **k):
            raise OSError(errno.EMFILE, "Too many open files")
        monkeypatch.setattr(mod.socket, "socket", boom)
        assert mod.probe_port("192.168.87.1", 80) is False

    def test_check_port_stays_boolean_for_the_unreachable_case(self, mod, monkeypatch):
        # check_port's callers ask about one known port on localhost and want a
        # yes/no; unreachable must read as not-open, never as None.
        monkeypatch.setattr(mod.socket, "socket",
                            self._socket_returning(errno.EHOSTUNREACH))
        assert mod.check_port("127.0.0.1", 22) is False


class TestGetLocalIp:
    """get_local_ip() — the routing trick behind the sweep's fallback subnet.

    A UDP socket is "connected" to 8.8.8.8:80 purely so the kernel picks a
    source address; nothing is transmitted. resolve_subnets falls back to
    guess_subnet(get_local_ip()) when no interface is detected, so whatever
    this returns decides which /24 gets swept.
    """

    def test_returns_the_sockets_own_address_not_the_peer(self, mod, monkeypatch):
        install_fake_socket(monkeypatch,
                            FakeSocket(sockname=("192.168.85.24", 51234)))
        assert mod.get_local_ip() == "192.168.85.24"

    def test_returns_the_host_half_of_getsockname_not_the_port(self, mod, monkeypatch):
        # getsockname() is an (ip, port) tuple; only element 0 is the address.
        install_fake_socket(monkeypatch,
                            FakeSocket(sockname=("10.0.0.7", 60123)))
        result = mod.get_local_ip()
        assert result == "10.0.0.7"
        assert isinstance(result, str)

    def test_uses_a_udp_socket(self, mod, monkeypatch):
        # SOCK_DGRAM is what makes connect() a routeless address lookup; a
        # SOCK_STREAM socket would open a real TCP session to a public host.
        made = install_fake_socket(monkeypatch)
        mod.get_local_ip()
        assert (made[0].family, made[0].type) == (socket.AF_INET, socket.SOCK_DGRAM)

    def test_connects_to_the_public_dns_anchor(self, mod, monkeypatch):
        made = install_fake_socket(monkeypatch)
        mod.get_local_ip()
        assert made[0].connect_args == ("8.8.8.8", 80)

    def test_nothing_is_ever_transmitted_to_the_anchor(self, mod, monkeypatch):
        # The fake fails the test the moment send/sendto is touched; this
        # assertion is the second half of that guard.
        made = install_fake_socket(monkeypatch)
        mod.get_local_ip()
        assert made[0].sent == []

    @pytest.mark.parametrize(
        "error",
        [
            OSError(51, "Network is unreachable"),
            OSError(65, "No route to host"),
            socket.timeout("timed out"),
        ],
        ids=["enetunreach_airplane_mode", "ehostunreach", "timeout"],
    )
    def test_no_route_yields_none_rather_than_propagating(self, mod, monkeypatch, error):
        # None is exactly what guess_subnet is documented to tolerate, so an
        # offline Mac degrades to "no subnet" instead of a traceback.
        install_fake_socket(monkeypatch, FakeSocket(connect_error=error))
        assert mod.get_local_ip() is None

    def test_socket_is_closed_on_the_success_path(self, mod, monkeypatch):
        made = install_fake_socket(monkeypatch)
        mod.get_local_ip()
        assert made[0].closed is True

    def test_socket_is_closed_when_connect_raises(self, mod, monkeypatch):
        # The `finally` is load-bearing: a descriptor leaked here feeds the same
        # EMFILE failure class as the check_port regression above.
        made = install_fake_socket(monkeypatch,
                                   FakeSocket(connect_error=OSError(51, "Network is unreachable")))
        assert mod.get_local_ip() is None
        assert made[0].closed is True

    def test_the_sweep_fallback_subnet_is_the_local_ips_slash24(self, mod, monkeypatch):
        # End-to-end shape of the resolve_subnets fallback path.
        install_fake_socket(monkeypatch,
                            FakeSocket(sockname=("192.168.1.50", 51234)))
        assert mod.guess_subnet(mod.get_local_ip()) == ipaddress.ip_network("192.168.1.0/24")

    def test_an_unreachable_anchor_produces_no_fallback_subnet(self, mod, monkeypatch):
        install_fake_socket(monkeypatch,
                            FakeSocket(connect_error=OSError(51, "Network is unreachable")))
        assert mod.guess_subnet(mod.get_local_ip()) is None


class RecordingSubprocessRun:
    """Stand-in for subprocess.run that records argv and kwargs, or raises.

    ping() calls subprocess.run directly rather than going through mod.run,
    so make_run/make_subprocess_run don't apply here.
    """

    def __init__(self, returncode=0, error=None):
        self.returncode = returncode
        self.error = error
        self.commands = []
        self.kwargs = []

    def __call__(self, cmd, **kwargs):
        self.commands.append(list(cmd))
        self.kwargs.append(dict(kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(args=cmd, returncode=self.returncode,
                                           stdout="", stderr="")


def install_fake_ping(monkeypatch, returncode=0, error=None):
    """Replace subprocess.run for the duration of one test; returns the recorder."""
    fake = RecordingSubprocessRun(returncode=returncode, error=error)
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


class TestPing:
    """ping(ip) — one ICMP probe per host in the sweep.

    Its docstring names the defect it exists to prevent: on Linux `-t` sets the
    TTL rather than a deadline, so without the hard subprocess timeout a hung
    host would block its worker thread and stall the whole sweep.
    """

    def test_a_replying_host_returns_its_ip(self, mod, monkeypatch):
        install_fake_ping(monkeypatch, returncode=0)
        assert mod.ping("192.168.85.24") == "192.168.85.24"

    def test_a_replying_host_returns_a_str_not_an_address_object(self, mod, monkeypatch):
        # The type is load-bearing. discover_devices does alive.add(res), then
        # unions that set with read_arp_table()'s string keys and looks each
        # entry up with arp.get(ip). An IPv4Address would compare unequal to the
        # equivalent str, so every pinged host would be counted twice — once as
        # an object with no MAC, once as the ARP string — and the object copy
        # would lose its MAC. subnet.hosts() yields IPv4Address objects, so this
        # is the shape discover_devices actually passes in.
        install_fake_ping(monkeypatch, returncode=0)
        result = mod.ping(ipaddress.ip_address("192.168.85.24"))
        assert result == "192.168.85.24"
        assert isinstance(result, str)

    @pytest.mark.parametrize(
        "returncode",
        [1, 2, 68],
        ids=["no_reply", "ping_usage_error", "unknown_host"],
    )
    def test_a_non_zero_exit_means_the_host_is_not_alive(self, mod, monkeypatch, returncode):
        install_fake_ping(monkeypatch, returncode=returncode)
        assert mod.ping("192.168.85.24") is None

    def test_a_ping_that_never_exits_is_reported_dead_not_raised(self, mod, monkeypatch):
        # The regression pin for the docstring's hard-deadline guard: without
        # the timeout=, this call would block its worker thread forever.
        install_fake_ping(monkeypatch,
                          error=subprocess.TimeoutExpired(cmd=["ping"], timeout=2))
        assert mod.ping("192.168.85.24") is None

    @pytest.mark.parametrize(
        "error",
        [
            FileNotFoundError(2, "No such file or directory: 'ping'"),
            PermissionError(13, "Permission denied"),
            OSError(23, "Too many open files in system"),
        ],
        ids=["ping_binary_missing", "not_permitted", "enfile_under_load"],
    )
    def test_an_os_level_failure_is_reported_dead_not_raised(self, mod, monkeypatch, error):
        # pool.map in discover_devices re-raises in the collecting thread, so an
        # unguarded OSError on one host would lose the whole sweep's results.
        install_fake_ping(monkeypatch, error=error)
        assert mod.ping("192.168.85.24") is None

    def test_a_hard_deadline_is_always_set(self, mod, monkeypatch):
        # `-t 1` is a TTL on Linux, not a deadline — only this kwarg bounds the
        # call. `is not None` rather than a truthiness test: timeout=0 would be
        # a different bug, not this one.
        fake = install_fake_ping(monkeypatch)
        mod.ping("192.168.85.24")
        assert fake.kwargs[0]["timeout"] is not None

    def test_the_deadline_is_short_enough_to_keep_the_sweep_moving(self, mod, monkeypatch):
        # 254 hosts / 50 workers means every second of deadline costs ~5s of sweep.
        fake = install_fake_ping(monkeypatch)
        mod.ping("192.168.85.24")
        assert fake.kwargs[0]["timeout"] <= 5

    def test_sends_exactly_one_probe(self, mod, monkeypatch):
        fake = install_fake_ping(monkeypatch)
        mod.ping("192.168.85.24")
        assert fake.commands[0][:3] == ["ping", "-c", "1"]

    def test_the_target_is_passed_as_text(self, mod, monkeypatch):
        # subprocess would reject an IPv4Address in argv; str(ip) is what makes
        # discover_devices' subnet.hosts() objects usable here.
        fake = install_fake_ping(monkeypatch)
        mod.ping(ipaddress.ip_address("192.168.85.24"))
        assert fake.commands[0][-1] == "192.168.85.24"
        assert all(isinstance(part, str) for part in fake.commands[0])

    def test_ping_output_is_captured_rather_than_printed_over_the_report(self, mod, monkeypatch):
        fake = install_fake_ping(monkeypatch)
        mod.ping("192.168.85.24")
        assert fake.kwargs[0]["capture_output"] is True

    def test_one_call_per_ping_not_a_retry_loop(self, mod, monkeypatch):
        # A retry would multiply the deadline the docstring is defending.
        fake = install_fake_ping(monkeypatch, returncode=1)
        mod.ping("192.168.85.24")
        assert len(fake.commands) == 1
