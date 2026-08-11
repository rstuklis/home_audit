"""Tests for tools/capture_fixtures.py — the redactor that turns a real Mac's
command output into committable fixtures.

This is a maintenance tool rather than part of the audit, but it earns tests
for a specific reason: it has two failure modes that are silent and opposite.
Redact too little and a public repository gains the owner's SSID, BSSIDs and
account name. Redact too much, or in the wrong place, and the fixture stops
describing reality while still looking plausible — which is worse than having
no fixture, because the parsers are then verified against fiction.

Both modes were live in the first version of the script. It substituted MACs
and IPv6 addresses in separate passes, so every replacement MAC was re-matched
by the IPv6 pattern and rewritten: `at a4:83:e7:01:01:01` came out as
`at 2001:db8::1`, and the arp and ndp fixtures would have been nonsense. And
its SSID rule was "a bare `Name:` line", which also describes `Locale:`,
`Country Code:`, `Firmware Version:` and `en0:`.

So the tests below come in two families: nothing identifying survives, and
the parsers see the same structure before and after.
"""

import importlib.util
import re
import sys

import pytest

from conftest import PROJECT_DIR, load_fixture, make_run

MAC_SHAPE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _load_capture_module():
    path = PROJECT_DIR / "tools" / "capture_fixtures.py"
    spec = importlib.util.spec_from_file_location("capture_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["capture_fixtures"] = module
    spec.loader.exec_module(module)
    return module


cap = _load_capture_module()


@pytest.fixture
def red():
    return cap.Redactor()


# ---------------------------------------------------------------------------
# Address-shaped tokens
# ---------------------------------------------------------------------------

class TestAddressRedaction:

    def test_a_mac_stays_a_mac(self, red):
        """The regression that started this file.

        Substituting MACs and addresses in separate passes let the IPv6
        pattern match the MAC replacement — colon-separated hex is colon-
        separated hex — and every LAN MAC in the fixtures became an IPv6
        address. One pass with an ordered alternation fixes it, because re.sub
        never rescans the text it has just written.
        """
        out = red.addresses("? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ifscope")
        mac = out.split(" at ")[1].split()[0]
        assert MAC_SHAPE.match(mac), out
        assert "aa:bb:cc:dd:ee:ff" not in out

    def test_broadcast_and_multicast_macs_survive(self, red):
        """arp lists ff:ff:ff:ff:ff:ff for the broadcast row and 01:00:5e:...
        for multicast. They are protocol constants, identify nobody, and the
        parsers read them."""
        text = "ff:ff:ff:ff:ff:ff 01:00:5e:00:00:fb 33:33:00:00:00:01"
        assert red.addresses(text) == text

    def test_one_real_mac_maps_to_one_fake_mac(self, red):
        """Consistency across files is the property that keeps a capture
        usable: the router's MAC has to be the same value in arp and in ndp,
        or the cross-table checks have nothing left to compare."""
        first = red.addresses("? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0")
        second = red.addresses("fe80::1%en0 aa:bb:cc:dd:ee:ff en0 router")
        assert first.split(" at ")[1].split()[0] == second.split()[1]

    def test_distinct_macs_stay_distinct(self, red):
        out = red.addresses("aa:bb:cc:dd:ee:ff and 11:22:33:44:55:66")
        a, b = out.split(" and ")
        assert a != b

    def test_the_locally_administered_bit_is_preserved(self, red):
        """A randomised MAC and a vendor MAC are different evidence. Collapsing
        them would erase the distinction from every fixture."""
        vendor = red.addresses("a4:83:e7:11:22:33").strip()
        random = red.addresses("06:11:22:33:44:55").strip()
        assert not int(vendor.split(":")[0], 16) & 0x02
        assert int(random.split(":")[0], 16) & 0x02

    def test_link_local_v6_keeps_its_prefix(self, red):
        """The interface ID is MAC-derived and must go; the fe80:: prefix is
        what check_ipv6_routers reads to know it is looking at a link-local."""
        out = red.addresses("fe80::1cb2:33ff:fe44:5566%en0")
        assert out.startswith("fe80::")
        assert "1cb2" not in out
        assert out.endswith("%en0")

    def test_global_v6_moves_into_the_documentation_range(self, red):
        out = red.addresses("2a01:4b00:1234:5678::42")
        assert out.startswith("2001:db8::")

    def test_multicast_loopback_and_unspecified_v6_survive(self, red):
        text = "ff02::1 ff02::2 ff02::fb ::1 ::"
        assert red.addresses(text) == text

    def test_a_timestamp_is_not_an_address(self, red):
        """`Firmware Version: wl0: Sep 12 2024 21:44:11 version 22.10.375.6`
        matches the IPv6 pattern twice over. Validating the match as an actual
        address is what stops the redactor corrupting unrelated text."""
        text = "wl0: Sep 12 2024 21:44:11 version 22.10.375.6.32.7.128 FWID 01-4d95ba9d"
        assert red.addresses(text) == text

    def test_private_v4_is_kept(self, red):
        """RFC1918 identifies nobody, and the subnet arithmetic in the parsers
        is real work that a fixture should exercise."""
        text = "10.0.0.1 172.16.5.4 192.168.1.1 127.0.0.1 169.254.1.1 224.0.0.251"
        assert red.addresses(text) == text

    def test_public_v4_is_replaced(self, red):
        out = red.addresses("nameserver[1] : 45.90.28.193")
        assert "45.90.28.193" not in out
        assert "198.51.100." in out

    def test_replacements_stay_inside_one_documentation_range(self, red):
        """The audit probes 192.0.2.1 (TEST-NET-1) to detect DNS interception,
        so a replacement landing there would read as that probe rather than as
        a redaction. Everything goes to TEST-NET-2 instead."""
        out = red.addresses(" ".join("45.90.%d.%d" % (i, i) for i in range(1, 30)))
        for token in out.split():
            assert token.startswith("198.51.100."), token

    def test_the_widely_used_public_resolvers_are_kept(self, red):
        """The DNS check works by recognising these. Redacting 8.8.8.8 into an
        arbitrary address turns a fixture that says "a known provider" into one
        that says "an unfamiliar resolver" — the opposite finding."""
        text = "8.8.8.8 1.1.1.1 9.9.9.9 208.67.222.222 2606:4700:4700::1111 2620:fe::fe"
        assert red.addresses(text) == text

    def test_isp_resolvers_are_still_redacted(self, mod, red):
        """An ISP resolver names a provider and a region even though the audit
        recognises it, so it is redacted like any other public address."""
        isp = [a for a, label in mod.KNOWN_DNS.items() if "ISP" in label]
        assert isp, "KNOWN_DNS no longer labels any resolver as an ISP's"
        out = red.addresses(" ".join(isp))
        for addr in isp:
            assert addr not in out

    def test_the_preserved_list_agrees_with_the_audits_own_table(self, mod):
        """Two copies of a list drift. This is the check that keeps them
        together, and it states the rule rather than the contents: everything
        preserved must be a resolver the audit knows, and none of it may be an
        ISP's."""
        assert set(cap.PRESERVED_DNS) <= set(mod.KNOWN_DNS)
        assert not any("ISP" in mod.KNOWN_DNS[a] for a in cap.PRESERVED_DNS)

    def test_hostnames_are_replaced(self, red):
        out = red.addresses("living-room-tv.local and rebecca-macbook.lan")
        assert "living-room-tv" not in out
        assert "rebecca-macbook" not in out


# ---------------------------------------------------------------------------
# Wi-Fi: the section that carries the most identifying data
# ---------------------------------------------------------------------------

WIFI_WITH_BSSIDS = """Wi-Fi:

      Interfaces:
        en0:
          Card Type: AirPort Extreme  (0x14E4, 0x4387)
          Firmware Version:
          MAC Address: a4:83:e7:9c:1b:40
          Locale: FCC
          Country Code:
          Supported Channels:
          Status: Connected
          Current Network Information:
            Fjordbakken 5GHz:
              PHY Mode: 802.11ax
              BSSID: 3c:22:fb:11:22:33
              Channel: 149 (5GHz, 80MHz)
              Country Code:
              Security: WPA3 Personal
          Other Local Wi-Fi Networks:
            Fjordbakken 5GHz:
              PHY Mode: 802.11ax
              BSSID: 9a:00:11:22:33:44
              Security: WPA3 Personal
            NETGEAR58-guest:
              PHY Mode: 802.11n
              BSSID: 3c:22:fb:aa:bb:cc
              Security: None
"""


class TestWifiRedaction:

    def test_the_only_lines_that_change_are_the_network_names(self, red):
        """`Locale:`, `Country Code:`, `Firmware Version:`, `Supported
        Channels:` and `en0:` are all bare `Name:` lines. The rule that only
        looks at the line renames every one of them and destroys the fixture.

        Asserting `"Country Code:" in out` does not catch that, because the
        string also occurs at a depth the rule leaves alone — the assertion
        passes while the file is being mangled. So this compares the two texts
        line by line and names exactly which lines are allowed to differ.
        """
        raw = load_fixture("wifi_sp_airport_not_associated.out")
        out = red.wifi(raw)
        before, after = raw.splitlines(), out.splitlines()
        assert len(before) == len(after)
        changed = [(a, b) for a, b in zip(before, after) if a != b]
        assert [a.strip() for a, _ in changed] == \
            ["Fjordbakken 5GHz:", "NETGEAR58-guest:"]
        # Indentation carries the structure; a rename must not shift it.
        for a, b in changed:
            assert len(a) - len(a.lstrip()) == len(b) - len(b.lstrip())

    def test_neighbouring_ssids_are_renamed(self, red):
        out = red.wifi(load_fixture("wifi_sp_airport_not_associated.out"))
        assert "Fjordbakken" not in out
        assert "NETGEAR58-guest" not in out
        assert "HomeNet:" in out

    def test_the_connected_network_keeps_one_name_across_both_sections(self, red):
        """An evil twin is a second BSSID advertising the SSID you are
        connected to. If the connected block and the neighbours block got
        different fake names, the fixture would no longer describe one."""
        out = red.wifi(WIFI_WITH_BSSIDS)
        assert out.count("HomeNet:") == 2
        assert "Fjordbakken" not in out

    def test_the_parser_sees_the_same_shape_after_redaction(self, mod, red):
        """The fidelity half. Same number of networks, same number of BSSIDs
        per network — only the names change."""
        before = mod.parse_wifi_networks(WIFI_WITH_BSSIDS)
        after = mod.parse_wifi_networks(red.wifi(WIFI_WITH_BSSIDS))
        assert sorted(len(v) for v in before.values()) == \
            sorted(len(v) for v in after.values())
        assert len(before) == len(after) == 2

    def test_bssids_are_redacted_by_the_address_pass(self, mod, red):
        """A BSSID is the access point's MAC: it geolocates the network in
        public wardriving databases, which is precisely the exposure this tool
        exists to reduce."""
        out = red.apply("wifi_sp_airport", WIFI_WITH_BSSIDS)
        for real in ("3c:22:fb:11:22:33", "9a:00:11:22:33:44", "3c:22:fb:aa:bb:cc"):
            assert real not in out
        networks = mod.parse_wifi_networks(out)
        assert all(MAC_SHAPE.match(b) for v in networks.values() for b in v)


# ---------------------------------------------------------------------------
# Columns that carry an identity rather than an address
# ---------------------------------------------------------------------------

class TestColumnRedaction:

    def test_the_account_name_does_not_survive(self, red):
        """On a personal Mac the login account is usually the owner's name.

        Routed through apply() rather than lsof() directly: the dispatch is
        part of the behaviour, and a test that calls the method by hand still
        passes when apply() stops calling it.
        """
        text = ("COMMAND      PID           USER   FD   TYPE\n"
                "node       15042  rebeccastuklis   23u  IPv4\n"
                "cupsd        227           root    8u  IPv4\n")
        out = red.apply("lsof_tcp_listen", text)
        assert "rebeccastuklis" not in out
        assert "root" in out           # system accounts name a role, not a person

    def test_two_accounts_stay_distinct(self, red):
        text = ("node       15042  rebeccastuklis   23u  IPv4\n"
                "node       15043         jbourne   24u  IPv4\n")
        users = [line.split()[2] for line in red.apply("lsof_tcp_listen", text).splitlines()]
        assert len(set(users)) == 2

    def test_system_accounts_are_left_alone(self, red):
        text = "mDNSResponde  345 _mdnsresponder    7u  IPv4\n"
        assert red.lsof(text) == text

    def test_process_names_and_ports_are_untouched(self, red):
        """Which daemons are listening on which ports is the entire content of
        this fixture. Redacting it would leave nothing to test."""
        out = red.apply("lsof_tcp_listen", load_fixture("lsof_tcp_listen.out"))
        for keep in ("launchd", "rapportd", "cupsd", "127.0.0.1:631", "(LISTEN)"):
            assert keep in out

    def test_isp_search_domains_are_replaced(self, red):
        """A home Mac's search domain is often the ISP's, which narrows the
        owner to a provider and a region."""
        text = ("  search domain[0] : hsd1.ca.comcast.net\n"
                "  domain   : local\n"
                "  domain   : 254.169.in-addr.arpa\n"
                "  domain   : 8.e.f.ip6.arpa\n")
        out = red.dns_domains(text)
        assert "comcast" not in out
        assert "domain   : local" in out
        assert "254.169.in-addr.arpa" in out
        assert "8.e.f.ip6.arpa" in out


# ---------------------------------------------------------------------------
# Fidelity: the parsers must see the same structure either way
# ---------------------------------------------------------------------------

class TestParsersAgree:
    """Run the audit's own parsers over the real fixtures and over their
    redacted forms, and require the same structure out of both.

    This is the test that would have caught the MAC-to-IPv6 bug on the first
    run: a neighbour table whose link-layer column has become an IPv6 address
    parses to nothing at all.
    """

    def test_ndp_neighbours(self, mod, red):
        raw = load_fixture("ndp_a.out")
        before = mod.parse_ndp_neighbours(raw)
        after = mod.parse_ndp_neighbours(red.apply("ndp_a", raw))
        assert before, "fixture parsed empty; the comparison would be vacuous"
        assert len(before) == len(after)
        assert sorted(n["iface"] for n in before.values()) == \
            sorted(n["iface"] for n in after.values())
        assert sorted(n["router"] for n in before.values()) == \
            sorted(n["router"] for n in after.values())
        assert all(MAC_SHAPE.match(n["mac"]) for n in after.values())

    def test_ndp_routers(self, mod, red):
        raw = load_fixture("ndp_r_two_routers.out")
        before = mod.parse_ndp_routers(raw)
        after = mod.parse_ndp_routers(red.apply("ndp_r", raw))
        assert len(before) == len(after) == 2
        assert all(a.startswith("fe80::") for a in after)

    def test_ifconfig_interfaces(self, mod, red):
        raw = load_fixture("ifconfig_a.out")
        before = mod.parse_interfaces_ifconfig(raw)
        after = mod.parse_interfaces_ifconfig(red.apply("ifconfig_a", raw))
        assert before
        assert before == after      # every address here is RFC1918 and kept

    def test_arp_table(self, mod, red, monkeypatch):
        raw = load_fixture("arp_a_typical.out")
        monkeypatch.setattr(mod, "run", make_run({"arp": raw}))
        before = mod.read_arp_table()
        monkeypatch.setattr(mod, "run", make_run({"arp": red.apply("arp_a_typical", raw)}))
        after = mod.read_arp_table()
        assert before
        assert sorted(before) == sorted(after)          # same IPs: RFC1918 kept
        assert len(set(before.values())) == len(set(after.values()))
        assert set(before.values()) != set(after.values())   # MACs really changed

    def test_dns_servers(self, mod, red, monkeypatch):
        raw = load_fixture("scutil_dns.out")
        monkeypatch.setattr(mod, "run", make_run({"scutil --dns": raw}))
        before = mod.get_dns_servers()
        monkeypatch.setattr(mod, "run", make_run({"scutil --dns": red.apply("scutil_dns", raw)}))
        after = mod.get_dns_servers()
        assert before
        assert len(before) == len(after)


# ---------------------------------------------------------------------------
# The capture step itself
# ---------------------------------------------------------------------------

class TestCaptureContract:

    def test_only_the_commands_the_audit_merges_are_merged(self):
        """run() returns stdout unless the caller asks for stderr, and only
        `security dump-trust-settings` asks. Capturing a merged stream for
        anything else would hide the very mismatch this script is meant to
        surface."""
        assert cap.MERGE_STDERR == {"security_trust"}

    def test_stderr_only_output_is_reported_not_captured(self, monkeypatch):
        import subprocess as sp
        completed = sp.CompletedProcess(args=[], returncode=0, stdout="",
                                        stderr="Remote Apple Events: On\n")
        monkeypatch.setattr(cap.subprocess, "run", lambda *a, **k: completed)
        text, note = cap.capture("systemsetup_rae", ["systemsetup"])
        assert text is None
        assert "stderr" in note

    def test_every_command_has_a_fixture_name_shaped_like_the_existing_set(self):
        """The output filenames are meant to be diffed against tests/fixtures,
        so they have to use the same naming and extension."""
        for name in cap.COMMANDS:
            assert re.match(r"^[a-z0-9_]+$", name), name

    def test_the_redaction_report_lists_every_substitution(self, red):
        """The user is asked to check the mapping rather than trust it, so the
        mapping has to be complete."""
        red.apply("wifi_sp_airport", WIFI_WITH_BSSIDS)
        red.apply("lsof_tcp_listen", "node 15042 rebeccastuklis 23u IPv4\n")
        report = "\n".join(red.report())
        assert "3c:22:fb:11:22:33" in report
        assert "Fjordbakken 5GHz" in report
        assert "rebeccastuklis" in report

    def test_the_report_is_never_written_to_disk(self):
        """It contains the real values by definition."""
        source = (PROJECT_DIR / "tools" / "capture_fixtures.py").read_text()
        body = source.split("def main(")[1]
        assert "report()" in body
        write_block = body.split("with open(")[1].split("\n\n")[0]
        assert "report" not in write_block

    def test_the_output_directory_is_gitignored(self):
        """The two-step workflow — capture, read, then copy across — only
        protects anything if step two cannot be skipped by accident. Pinning
        the script's default against the ignore rule means changing one
        without the other fails here rather than in a public commit."""
        source = (PROJECT_DIR / "tools" / "capture_fixtures.py").read_text()
        out_dir = re.search(r'"--out", default="([^"]+)"', source).group(1)
        ignored = (PROJECT_DIR / ".gitignore").read_text().splitlines()
        assert out_dir + "/" in ignored

    def test_refuses_to_run_off_a_mac(self, monkeypatch, capsys):
        monkeypatch.setattr(cap.sys, "platform", "linux")
        assert cap.main([]) == 1
        assert "Mac" in capsys.readouterr().err
