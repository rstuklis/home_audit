"""Tests for read_arp_table (home_net_audit.py lines 204-220).

The function turns `arp -a` into {ip: mac}. Two things make it fragile enough
to be worth pinning line by line:

1.  macOS prints MAC octets without leading zeros ("1:2:3:4:5:6"), so the raw
    text is never directly comparable to a stored baseline MAC. The parser has
    to zero-pad and lowercase every octet.
2.  Its output is fed straight into `sorted(..., key=ipaddress.ip_address)` by
    discover_devices (line 302). Before commit 0a79294 the table was keyed on
    the raw regex capture (`table[ip_m.group(1)] = mac`), so a single malformed
    ARP line — the regex `\\(([\\d.]+)\\)` happily captures "192.168.1.999" —
    made that sort raise ValueError and took the whole audit down. The fix
    pushes every IP through ipaddress.ip_address and drops what fails; the
    tests in TestMalformedIPsAreDropped and TestSortInvariant pin exactly that.

TestDiscoverDevices covers the consumer, discover_devices (lines 293-306),
because the merge it performs is what gives read_arp_table's output meaning:
ping and the ARP cache are two independent discovery sources, unioned, sorted
numerically, and then filtered as a single stream by is_real_host.
"""

import ipaddress
import re

import pytest

from conftest import load_fixture, make_run

ARP_CMD = "arp -a"
NEIGH_CMD = "ip neigh show"

TYPICAL = "arp_a_typical.out"
MALFORMED = "arp_a_malformed_ip.out"

# discover_devices pings every address in subnet.hosts(), so the sweep has to be
# small to stay fast: this /29 has six usable hosts (.97-.102), with .96 as the
# network address and .103 as the broadcast. It is also chosen so that .97, .100
# and .102 sort differently as strings ('.100' < '.102' < '.97') than as
# addresses — that is what makes the ordering assertion below discriminate.
SWEPT = ipaddress.ip_network("192.168.1.96/29")
NEIGHBOUR_IP = "192.168.87.42"          # a host on another subnet of this Mac

KNOWN_MAC = "3c:37:86:1f:a2:0b"
OTHER_MAC = "a4:83:e7:1b:2c:3d"


@pytest.fixture
def read_arp(mod, monkeypatch):
    """Run read_arp_table() against a supplied `arp -a` capture.

    Exposes the fake's `.calls` so a test can assert which command ran.
    """
    def _read(output):
        fake = make_run({ARP_CMD: output})
        monkeypatch.setattr(mod, "run", fake)
        _read.calls = fake.calls
        return mod.read_arp_table()

    _read.calls = []
    return _read


def one_entry(read_arp, line):
    """Parse a single ARP line and return its (ip, mac) pair."""
    table = read_arp(line + "\n")
    assert len(table) == 1, f"expected exactly one entry from {line!r}, got {table!r}"
    return next(iter(table.items()))


class TestCommandInvoked:
    def test_reads_the_system_arp_cache_then_falls_back_to_iproute(self, read_arp):
        # `arp -a` first; `ip neigh show` only when it yields nothing, so a
        # Linux observer sees the same neighbour table by its own name.
        read_arp("")
        assert read_arp.calls == [ARP_CMD, NEIGH_CMD]

    def test_missing_arp_binary_yields_an_empty_table(self, mod, monkeypatch):
        # The real run() returns "" when the binary is absent or times out;
        # that must read as "no devices known", not as a crash.
        monkeypatch.setattr(mod, "run", make_run({}))
        assert mod.read_arp_table() == {}


class TestMacNormalisation:
    @pytest.mark.parametrize(
        "raw_mac, expected",
        [
            ("1:2:3:4:5:6", "01:02:03:04:05:06"),
            ("8:0:27:9a:1c:3f", "08:00:27:9a:1c:3f"),
            ("0:1c:42:d3:9:f1", "00:1c:42:d3:09:f1"),
            ("1:0:5e:0:0:fb", "01:00:5e:00:00:fb"),
            ("0:0:0:0:0:0", "00:00:00:00:00:00"),
        ],
        ids=["all-short", "leading-zero-first", "mixed", "multicast", "all-zero"],
    )
    def test_short_octets_are_zero_padded_to_two_digits(self, read_arp, raw_mac, expected):
        # macOS drops leading zeros in `arp -a`; a baseline MAC comparison is
        # only meaningful if every octet is widened back to two digits.
        _, mac = one_entry(read_arp, f"? (192.168.1.9) at {raw_mac} on en0 ifscope [ethernet]")
        assert mac == expected

    def test_full_width_mac_passes_through_unchanged(self, read_arp):
        _, mac = one_entry(
            read_arp,
            "homepod.lan (192.168.1.42) at a4:83:e7:1b:2c:3d on en0 ifscope [ethernet]",
        )
        assert mac == "a4:83:e7:1b:2c:3d"

    def test_uppercase_mac_is_normalised_to_lowercase(self, read_arp):
        # OUI_HINTS and is_randomized_mac both key off lowercase octets, so an
        # uppercase capture that survived as-is would silently miss every hint.
        _, mac = one_entry(
            read_arp,
            "? (192.168.1.7) at A4:83:E7:1B:2C:3D on en0 ifscope [ethernet]",
        )
        assert mac == "a4:83:e7:1b:2c:3d"

    def test_mixed_case_short_octets_are_padded_and_lowercased_together(self, read_arp):
        _, mac = one_entry(
            read_arp,
            "? (192.168.1.8) at B:2:AB:cD:0:F on en0 ifscope [ethernet]",
        )
        assert mac == "0b:02:ab:cd:00:0f"

    def test_every_mac_from_a_real_capture_is_six_lowercase_octets(self, read_arp, fixture):
        table = read_arp(fixture(TYPICAL))
        assert table, "fixture parsed to nothing; the capture or the parser is broken"
        for ip, mac in table.items():
            assert re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac), \
                f"{ip} produced a non-canonical MAC {mac!r}"


class TestIncompleteAndPartialLines:
    def test_incomplete_entry_is_dropped(self, read_arp):
        # An unresolved ARP slot prints "(incomplete)" where the MAC goes;
        # it must not become a device with a bogus address.
        table = read_arp("? (192.168.1.20) at (incomplete) on en0 [ethernet]\n")
        assert table == {}

    def test_line_with_an_ip_but_no_mac_is_skipped(self, read_arp):
        table = read_arp("router (192.168.1.30) on en0 ifscope [ethernet]\n")
        assert table == {}

    def test_line_with_a_mac_but_no_ip_is_skipped(self, read_arp):
        table = read_arp("? at 3c:37:86:1f:a2:0b on en0 ifscope [ethernet]\n")
        assert table == {}

    def test_truncated_mac_of_five_octets_is_not_accepted(self, read_arp):
        # Five octets is not a MAC; padding it would fabricate an address.
        table = read_arp("? (192.168.1.31) at 1:2:3:4:5 on en0 ifscope [ethernet]\n")
        assert table == {}

    @pytest.mark.parametrize(
        "garbage",
        [
            "",
            "   ",
            "arp: writing to routing socket: Invalid argument",
            "???",
            "(192.168.1.1)",
            "3c:37:86:1f:a2:0b",
            "() at () on en0",
            "bridge100 flags=8a63<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>",
        ],
        ids=[
            "blank", "whitespace", "error-text", "question-marks",
            "ip-only", "mac-only", "empty-parens", "ifconfig-noise",
        ],
    )
    def test_garbage_lines_are_skipped_without_raising(self, read_arp, garbage):
        assert read_arp(garbage + "\n") == {}

    def test_garbage_between_good_lines_does_not_lose_the_good_ones(self, read_arp):
        table = read_arp(
            "arp: writing to routing socket: Invalid argument\n"
            "? (192.168.1.1) at 1:2:3:4:5:6 on en0 ifscope [ethernet]\n"
            "???\n"
            "? (192.168.1.2) at a:b:c:d:e:f on en0 ifscope [ethernet]\n"
        )
        assert table == {
            "192.168.1.1": "01:02:03:04:05:06",
            "192.168.1.2": "0a:0b:0c:0d:0e:0f",
        }

    def test_empty_output_gives_an_empty_table(self, read_arp):
        assert read_arp("") == {}


class TestMalformedIPsAreDropped:
    """Regression cover for commit 0a79294.

    The IP regex is `\\(([\\d.]+)\\)` — it matches any run of digits and dots,
    including things that are not addresses. Pre-fix those strings were used
    as dict keys verbatim and blew up the caller's sort.
    """

    @pytest.mark.parametrize(
        "bad_ip",
        [
            "192.168.1.999",
            "999.999.999.999",
            "192.168.1.256",
            "192.168.1.2.3",
            "192.168.1",
            "1.2.3.4.5",
            "...",
            "192.168.001.5",
        ],
        ids=[
            "octet-999", "all-octets-999", "octet-256", "five-octets",
            "three-octets", "five-numbers", "dots-only", "leading-zeros",
        ],
    )
    def test_unparseable_ip_is_dropped_not_returned(self, read_arp, bad_ip):
        # "leading-zeros" documents actual behaviour rather than an obvious
        # intent: the source comment on line 211 names leading zeros as the
        # thing being "normalised", but ipaddress has rejected ambiguous
        # octal-looking octets since 3.9.5, so 192.168.001.5 is dropped rather
        # than folded to 192.168.1.5. Either way the sort cannot crash, which
        # is what the fix was for. macOS never emits padded octets anyway.
        table = read_arp(f"? ({bad_ip}) at 9a:bc:de:f0:12:34 on en0 ifscope [ethernet]\n")
        assert table == {}, f"{bad_ip!r} leaked into the ARP table as {list(table)!r}"

    def test_a_malformed_line_does_not_discard_its_neighbours(self, read_arp, fixture):
        table = read_arp(fixture(MALFORMED))
        assert table == {
            "192.168.1.1": "3c:37:86:1f:a2:0b",
            "192.168.1.10": "00:11:32:aa:bb:cc",
            "192.168.1.254": "6c:4b:90:1e:8f:22",
        }

    def test_every_returned_ip_parses_as_an_ip_address(self, read_arp, fixture):
        # This is the invariant discover_devices' sort key depends on; asserting
        # it directly means a future parser change that reintroduces raw strings
        # fails here rather than at some unrelated call site.
        table = read_arp(fixture(MALFORMED))
        assert table, "fixture parsed to nothing; the regression cover would be vacuous"
        for ip in table:
            ipaddress.ip_address(ip)

    def test_returned_ips_are_in_canonical_string_form(self, read_arp, fixture):
        table = read_arp(fixture(TYPICAL))
        for ip in table:
            assert str(ipaddress.ip_address(ip)) == ip


class TestDictSemantics:
    def test_a_later_line_overwrites_the_earlier_mac_for_the_same_ip(self, read_arp):
        # The ARP cache can list an IP twice (e.g. per-interface scoped entries);
        # last one wins, matching the plain dict assignment on line 219.
        table = read_arp(
            "? (192.168.1.50) at 1:2:3:4:5:6 on en0 ifscope [ethernet]\n"
            "? (192.168.1.50) at aa:bb:cc:dd:ee:ff on en1 ifscope [ethernet]\n"
        )
        assert table == {"192.168.1.50": "aa:bb:cc:dd:ee:ff"}

    def test_a_valid_line_after_a_malformed_one_for_the_same_prefix_still_lands(self, read_arp):
        table = read_arp(
            "? (192.168.1.999) at 1:2:3:4:5:6 on en0 ifscope [ethernet]\n"
            "? (192.168.1.99) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
        )
        assert table == {"192.168.1.99": "aa:bb:cc:dd:ee:ff"}


class TestRealisticCapture:
    def test_typical_capture_parses_every_complete_entry(self, read_arp, fixture):
        assert read_arp(fixture(TYPICAL)) == {
            "192.168.1.1": "3c:37:86:1f:a2:0b",
            "192.168.1.5": "08:00:27:9a:1c:3f",
            "192.168.1.42": "a4:83:e7:1b:2c:3d",
            "192.168.1.77": "00:1c:42:d3:09:f1",
            "192.168.1.255": "ff:ff:ff:ff:ff:ff",
            "224.0.0.251": "01:00:5e:00:00:fb",
            "239.255.255.250": "01:00:5e:7f:ff:fa",
        }

    def test_broadcast_and_multicast_entries_are_kept_for_is_real_host_to_judge(
        self, read_arp, fixture
    ):
        # read_arp_table is a pure parser: pseudo-entries are filtered later by
        # is_real_host (lines 288-289), which needs the padded 01:00:5e prefix
        # the parser produces. Dropping them here would make that check dead.
        table = read_arp(fixture(TYPICAL))
        assert table["192.168.1.255"] == "ff:ff:ff:ff:ff:ff"
        assert table["224.0.0.251"].startswith("01:00:5e")

    def test_hostname_prefixed_and_question_mark_lines_parse_the_same_way(self, read_arp):
        table = read_arp(
            "? (192.168.1.1) at 1:2:3:4:5:6 on en0 ifscope [ethernet]\n"
            "printer.lan (192.168.1.2) at 1:2:3:4:5:6 on en0 ifscope [ethernet]\n"
        )
        assert table == {
            "192.168.1.1": "01:02:03:04:05:06",
            "192.168.1.2": "01:02:03:04:05:06",
        }


class TestSortInvariant:
    """The exact crash commit 0a79294 fixed."""

    def test_malformed_capture_still_sorts_by_ip_address(self, read_arp, fixture):
        table = read_arp(fixture(MALFORMED))
        assert sorted(table, key=ipaddress.ip_address) == [
            "192.168.1.1", "192.168.1.10", "192.168.1.254",
        ]

    def test_fixture_really_contains_an_entry_that_would_crash_the_sort(self):
        # Fixture-rot guard: if the malformed line were ever removed, the tests
        # above would keep passing for the wrong reason. Pre-fix the parser did
        # `table[ip_m.group(1)] = mac`, i.e. it keyed on exactly these captures.
        raw_captures = re.findall(r"\(([\d.]+)\)", load_fixture(MALFORMED))
        with pytest.raises(ValueError):
            sorted(raw_captures, key=ipaddress.ip_address)

    def test_discover_devices_survives_a_malformed_arp_entry(self, mod, monkeypatch):
        # End-to-end shape of the original failure: discover_devices sorts the
        # union of ping results and ARP keys with ipaddress.ip_address as key.
        monkeypatch.setattr(mod, "ping", lambda ip: None)
        monkeypatch.setattr(mod, "run", make_run({ARP_CMD: load_fixture(MALFORMED)}))
        devices = mod.discover_devices(ipaddress.ip_network("192.168.1.0/24"))
        assert devices == [
            {"ip": "192.168.1.1", "mac": "3c:37:86:1f:a2:0b"},
            {"ip": "192.168.1.10", "mac": "00:11:32:aa:bb:cc"},
            {"ip": "192.168.1.254", "mac": "6c:4b:90:1e:8f:22"},
        ]


def ping_answering(alive):
    """Build a ping stub: probing a listed address reports it, anything else None.

    Shaped like the real ping (line 267), which returns `str(ip)` on a reply and
    None otherwise — returning the IPv4Address object instead would poison the
    `alive | set(arp.keys())` union with a second key type.
    """
    alive = {str(a) for a in alive}

    def _ping(ip):
        return str(ip) if str(ip) in alive else None

    return _ping


@pytest.fixture
def discover(mod, monkeypatch):
    """Run discover_devices with both of its discovery sources under control.

    `alive` is what the ping sweep replies to; `arp` is the machine-wide ARP
    cache. Patching read_arp_table (rather than `run`) keeps these tests about
    the merge, not about the parser that TestRealisticCapture already pins.
    """
    def _discover(subnet, alive=(), arp=None, ping=None):
        monkeypatch.setattr(mod, "ping", ping or ping_answering(alive))
        monkeypatch.setattr(mod, "read_arp_table", lambda: dict(arp or {}))
        return mod.discover_devices(subnet)

    return _discover


class TestDiscoverDevices:
    """The two-source merge on lines 293-306.

    ping sweeps the subnet; read_arp_table reads the machine-wide ARP cache.
    Neither sees everything — a host with a stale/absent ARP entry only answers
    ping, and a host that ignores ICMP is only ever known from ARP — so the
    union is the point of the function, not an implementation detail.
    """

    def test_a_host_that_only_answers_ping_is_reported_with_an_unknown_mac(self, discover):
        # The ping half of the union in isolation: with no ARP entry, line 303's
        # `arp.get(ip, "unknown")` default is the MAC, and is_real_host has to
        # accept that literal string or the host disappears from the audit.
        assert discover(SWEPT, alive=["192.168.1.97"], arp={}) == [
            {"ip": "192.168.1.97", "mac": "unknown"},
        ]

    def test_a_host_known_only_from_arp_is_reported_without_a_ping_reply(self, discover):
        # The other half: a device that drops ICMP is still a device.
        assert discover(SWEPT, alive=[], arp={"192.168.1.100": KNOWN_MAC}) == [
            {"ip": "192.168.1.100", "mac": KNOWN_MAC},
        ]

    def test_a_host_in_both_sources_keeps_its_real_mac(self, discover):
        # A set union of IPs, not of records: the ARP MAC must win over the
        # "unknown" the ping side would otherwise contribute.
        assert discover(SWEPT, alive=["192.168.1.100"],
                        arp={"192.168.1.100": KNOWN_MAC}) == [
            {"ip": "192.168.1.100", "mac": KNOWN_MAC},
        ]

    def test_a_host_in_both_sources_is_reported_exactly_once(self, discover):
        # diff_baseline (line 420) builds a set of MACs, so a duplicated device
        # would not show up there — it has to be caught here.
        devices = discover(
            SWEPT,
            alive=["192.168.1.97", "192.168.1.100", "192.168.1.102"],
            arp={"192.168.1.97": KNOWN_MAC, "192.168.1.100": OTHER_MAC},
        )
        ips = [d["ip"] for d in devices]
        assert ips == ["192.168.1.97", "192.168.1.100", "192.168.1.102"]

    def test_merged_devices_are_sorted_by_address_not_by_string(self, discover):
        # Line 302 sorts with key=ipaddress.ip_address. Plain sorted() would put
        # .100 and .102 ahead of .97 and the report would read as nonsense.
        devices = discover(
            SWEPT,
            alive=["192.168.1.97", "192.168.1.102"],
            arp={"192.168.1.100": KNOWN_MAC},
        )
        ips = [d["ip"] for d in devices]
        assert ips == ["192.168.1.97", "192.168.1.100", "192.168.1.102"]
        # Guard that the assertion above is not satisfied by either ordering.
        assert sorted(ips) != ips

    def test_ordering_holds_when_each_source_contributes_out_of_order(self, discover):
        # The union is a set, so neither source's own order can leak through.
        devices = discover(
            SWEPT,
            alive=["192.168.1.102", "192.168.1.98"],
            arp={"192.168.1.101": KNOWN_MAC, "192.168.1.97": OTHER_MAC},
        )
        assert [d["ip"] for d in devices] == [
            "192.168.1.97", "192.168.1.98", "192.168.1.101", "192.168.1.102",
        ]

    def test_a_ping_reply_from_outside_the_swept_subnet_is_dropped(self, discover):
        # The cross-subnet boundary of commit 0a79294, on the ping side. The
        # union is filtered as one stream (line 304), so membership is enforced
        # no matter which source produced the address — an address tagged with
        # the wrong network group is exactly the bug that commit fixed.
        devices = discover(
            SWEPT,
            ping=lambda ip: NEIGHBOUR_IP if str(ip) == "192.168.1.97" else None,
            arp={},
        )
        assert devices == []

    def test_an_arp_entry_from_another_subnet_does_not_join_this_sweep(self, discover):
        # Same boundary on the ARP side: `arp -a` is machine-wide, so entries
        # for every other interface's subnet are in the table on every run.
        devices = discover(
            SWEPT,
            alive=["192.168.1.97"],
            arp={NEIGHBOUR_IP: KNOWN_MAC, "192.168.1.100": OTHER_MAC},
        )
        assert devices == [
            {"ip": "192.168.1.97", "mac": "unknown"},
            {"ip": "192.168.1.100", "mac": OTHER_MAC},
        ]

    def test_each_device_has_exactly_an_ip_and_a_mac(self, discover):
        # save_baseline persists these records verbatim and diff_baseline reads
        # d["mac"] off them, so the key set is a contract, not an accident.
        devices = discover(
            SWEPT,
            alive=["192.168.1.97"],
            arp={"192.168.1.100": KNOWN_MAC},
        )
        assert devices, "no devices merged; the key assertion would be vacuous"
        for d in devices:
            assert set(d) == {"ip", "mac"}

    def test_every_usable_address_is_probed_and_none_is_probed_twice(self, mod, monkeypatch):
        # The sweep runs over subnet.hosts() (line 294), which excludes the
        # network and broadcast addresses — .96 and .103 must never be pinged.
        probed = []

        def counting_ping(ip):
            probed.append(str(ip))
            return None

        monkeypatch.setattr(mod, "ping", counting_ping)
        monkeypatch.setattr(mod, "read_arp_table", dict)
        mod.discover_devices(SWEPT)
        assert sorted(probed, key=ipaddress.ip_address) == [
            "192.168.1.97", "192.168.1.98", "192.168.1.99",
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
        ]

    def test_no_replies_and_an_empty_arp_cache_yield_no_devices(self, discover):
        assert discover(SWEPT, alive=[], arp={}) == []
