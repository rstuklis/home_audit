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
"""

import ipaddress
import re

import pytest

from conftest import load_fixture, make_run

ARP_CMD = "arp -a"

TYPICAL = "arp_a_typical.out"
MALFORMED = "arp_a_malformed_ip.out"


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
    def test_reads_the_system_arp_cache(self, read_arp):
        read_arp("")
        assert read_arp.calls == [ARP_CMD]

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
