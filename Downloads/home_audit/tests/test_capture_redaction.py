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

import ast
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


def audit_commands():
    """Every command home_net_audit actually executes, read from its source.

    Read statically rather than by calling anything: the point is to compare
    the capture tool's command list against the real one, and a test that
    imported a hand-maintained copy would only ever prove the copy matches
    itself.

    Elements the source builds at run time (`"system/" + label`) come back as
    "*" and match anything in that position.
    """
    tree = ast.parse((PROJECT_DIR / "home_net_audit.py").read_text())
    consts = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            consts[node.targets[0].id] = node.value.value

    def resolve(element):
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            return element.value
        if isinstance(element, ast.Name) and element.id in consts:
            return consts[element.id]
        return "*"

    commands = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name != "run" or not isinstance(node.args[0], ast.List):
            continue
        commands.add(tuple(resolve(e) for e in node.args[0].elts))
    return commands


def matches(captured, executed):
    return len(captured) == len(executed) and all(
        want == "*" or want == got for want, got in zip(executed, captured))


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

    def test_arp_device_names_are_replaced(self, red):
        """`arp -a` resolves names, so this column lists the household's
        devices. A suffix-less name has nothing for the generic hostname
        pattern to key off, which is why the column is redacted by position."""
        text = ("? (192.168.1.1) at 3c:37:86:1f:a2:0b on en0 ifscope [ethernet]\n"
                "rebeccas-iphone (192.168.1.42) at 8:0:27:9a:1c:3f on en0 [ethernet]\n"
                "living-room-tv.lan (192.168.1.7) at a4:83:e7:1b:2c:3d on en0 [ethernet]\n")
        out = red.apply("arp_a_typical", text)
        assert "rebeccas-iphone" not in out
        assert "living-room-tv" not in out
        assert out.startswith("? (192.168.1.1)")     # unresolved rows stay

    def test_a_device_name_is_replaced_once_not_twice(self, red):
        """The suffixed name is caught by the address pass and the bare one by
        the column pass. Running both must not remap the first pass's output,
        or the printed mapping becomes fake-to-fake and unreadable."""
        text = "living-room-tv.lan (192.168.1.7) at a4:83:e7:1b:2c:3d on en0\n"
        out = red.apply("arp_a_typical", text)
        assert len(red.hosts) == 1
        assert out.split()[0] in red.hosts.values()

    def test_multicast_names_are_kept(self, red):
        """mdns.mcast.net is on every Mac and identifies nobody."""
        text = "mdns.mcast.net (224.0.0.251) at 1:0:5e:0:0:fb on en0 permanent\n"
        assert red.apply("arp_a_typical", text) == text

    def test_the_arp_parser_sees_the_same_table(self, mod, red, monkeypatch):
        raw = load_fixture("arp_a_typical.out")
        monkeypatch.setattr(mod, "run", make_run({"arp": raw}))
        before = mod.read_arp_table()
        monkeypatch.setattr(mod, "run",
                            make_run({"arp": red.apply("arp_a_typical", raw)}))
        assert sorted(before) == sorted(mod.read_arp_table())

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

    def test_every_captured_command_is_one_the_audit_runs(self):
        """The property the whole tool rests on, and the one whose absence has
        now cost twice.

        `ndp -a` reverse-resolves, so the Neighbor column arrives as a
        hostname and every row is dropped — the CI capture documented that
        command for weeks while the audit ran `ndp -an`, and the fixtures
        described output nothing produced. The same slip went the other way in
        this tool's first version, which captured `arp -an` while the audit
        runs `arp -a`.

        Comparing against the audit's source rather than a list written here
        is the whole point: a hand-kept copy only proves it matches itself.
        """
        executed = audit_commands()
        assert executed, "found no run([...]) calls; the extractor is broken"
        for name, cmd in cap.COMMANDS.items():
            assert any(matches(cmd, e) for e in executed), \
                "%s captures %r, which the audit never runs" % (name, " ".join(cmd))

    def test_the_ci_capture_workflow_runs_the_same_commands(self):
        """The workflow is what actually drifted: it captured `ndp -a` for
        weeks while the audit ran `ndp -an`, so every run printed a neighbour
        table the audit never sees. Same invariant, applied to the shell in
        the YAML — its capture helpers are invoked as `cap <name> <argv...>`.

        A skip here means this protection is off, and `-ra` in pytest.ini
        prints skips, so it says so out loud rather than passing quietly.
        """
        for parent in [PROJECT_DIR] + list(PROJECT_DIR.parents):
            workflow = parent / ".github" / "workflows" / "capture-fixtures.yml"
            if workflow.exists():
                break
        else:
            pytest.skip("capture-fixtures.yml not found above %s" % PROJECT_DIR)

        executed = audit_commands()
        captured = re.findall(r"^\s*(?:cap|split)\s+\w+\s+(.+)$",
                              workflow.read_text(), re.MULTILINE)
        assert captured, "found no cap/split lines; the extractor is broken"
        for line in captured:
            cmd = tuple(line.split())
            assert any(matches(cmd, e) for e in executed), \
                "the workflow captures %r, which the audit never runs" % line

    def test_the_extractor_resolves_the_indirect_invocations(self):
        """Two commands are not plain literals in the audit — the firewall
        binary is a local variable and the launchctl label is concatenated.
        If the extractor quietly missed them the test above would be weaker
        than it looks, so pin that it finds both."""
        executed = audit_commands()
        assert any(e[0].endswith("socketfilterfw") for e in executed)
        assert ("launchctl", "print", "*") in executed

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


# ---------------------------------------------------------------------------
# Sentinels, spellings and truncation
#
# Every case below came out of the first capture on a real Mac. The summary
# the tool printed was the only thing that surfaced them: each one produces a
# fixture that parses cleanly, looks like plausible macOS output, and asserts
# something the machine never said.
# ---------------------------------------------------------------------------

class TestSentinelsSurvive:
    """Some address-shaped strings are protocol constants, and the parsers
    read them as constants. Redacting those does not protect anybody — it
    edits the meaning of the row."""

    def test_the_vpn_placeholder_keeps_its_empty_interface_id(self, red):
        """The one that would have reverted a shipped fix.

        `ndp -rn` prints `fe80::%utun0` for a tunnel that carries a default
        route but has no router to name, and parse_ndp_routers drops exactly
        those — that is what stops every VPN user being told they have four
        routers. Redacted to `fe80::1%utun0` the placeholder becomes a host
        the parser must keep, so a fixture built this way would have tested
        for the behaviour that was just removed.
        """
        assert red.addresses("fe80::%utun0") == "fe80::%utun0"

    def test_tunnel_placeholders_still_drop_after_redaction(self, mod, red):
        raw = ("fe80::%utun0 if=utun0, flags=IST, pref=medium, expire=Never\n"
               "fe80::%utun1 if=utun1, flags=IST, pref=medium, expire=Never\n"
               "fe80::1465:426a:443:4ac2%en0 if=en0, flags=O, pref=medium\n")
        before = mod.parse_ndp_routers(raw)
        after = mod.parse_ndp_routers(red.addresses(raw))
        assert len(before) == 1, "fixture wrong; the comparison would be vacuous"
        assert len(after) == len(before)

    def test_the_unresolved_neighbour_marker_is_not_given_a_vendor(self, red):
        """arp and ndp print an all-zero link-layer address for a neighbour
        that never answered. Turned into an Apple-OUI MAC it reads as a host
        that resolved, and the parsers' skip-the-incomplete-row arms — some of
        the least covered code in the project — stop being reached at all."""
        assert red.addresses("0:0:0:0:0:0") == "0:0:0:0:0:0"
        assert red.addresses("00:00:00:00:00:00") == "00:00:00:00:00:00"


class TestOneDeviceOneIdentity:
    """The Redactor's docstring promises that a MAC seen in two tables becomes
    one fake MAC, because the cross-table checks have nothing to find
    otherwise. These are the two ways the first version broke that promise."""

    def test_padded_and_unpadded_spellings_are_the_same_nic(self, red):
        """ifconfig pads an octet below 0x10, arp and ndp do not. One NIC,
        two spellings, and keying on the spelling gave it two identities.

        The capture that found this showed it on the bridge interface, which
        is now preserved outright — so the example here is an ordinary NIC,
        the case where the padding actually has to be reconciled.
        """
        unpadded = red.addresses("3c:22:fb:a:b:c")
        padded = red.addresses("3c:22:fb:0a:0b:0c")
        assert unpadded == padded

    def test_a_column_truncated_address_is_not_a_second_host(self, red):
        """netstat cuts an address to fit its column, so the link-local that
        ifconfig prints in full arrives from the routing table with its tail
        missing. Substituted independently the two spellings became two
        unrelated hosts and the routing table could no longer be lined up
        against the interface list."""
        full = "fe80::1465:426a:443:4ac2%en0"
        red.prime([full + "\n" + "fe80::1465:426a\n"])
        assert red.addresses("fe80::1465:426a") == red.addresses(full)

    def test_an_ambiguous_prefix_is_left_alone_rather_than_guessed(self, red):
        """`fe80::1` is a string prefix of a dozen link-locals without being a
        truncation of any of them, and collapsing it would merge real distinct
        hosts. Below the column width the tool does not guess."""
        red.prime(["fe80::1465:426a:443:4ac2%en0 fe80::1449:180f:e408:8ac7%en0"])
        assert red.addresses("fe80::1") != red.addresses(
            "fe80::1465:426a:443:4ac2%en0")


class TestTheSummaryIsReadable:
    """The mapping is the only thing standing between a real capture and a
    public repository, so it is read by a person. What it says has to be
    worth reading."""

    def test_a_value_mapped_to_itself_is_not_called_a_substitution(self, red):
        red.addresses("ff:ff:ff:ff:ff:ff")
        assert not [ln for ln in red.report() if "ff:ff:ff:ff:ff:ff" in ln]

    def test_a_collapsed_truncation_is_declared(self, red):
        red.prime(["fe80::1465:426a:443:4ac2%en0\nfe80::1465:426a\n"])
        assert any("truncated" in ln for ln in red.warnings())

    def test_a_truncation_it_cannot_resolve_is_declared_too(self, red):
        """Two hosts sharing a long prefix: the cut form could be either, so
        the tool keeps it separate and says so, rather than picking one and
        silently merging two devices into one."""
        red.prime(["fe80::abcd:1234:5678:1111%en0 fe80::abcd:1234:5678:2222%en0"])
        red.addresses("fe80::abcd:1234")
        assert any("matches several" in ln for ln in red.warnings())


class TestAppleBridgeAddresses:
    """The secure-enclave bridge interface carries the same literal MACs on
    every Mac that has one. They name a model, not a machine — and redacting
    them manufactured an ambiguity the tool then had to ask a person about."""

    def test_the_fixed_bridge_macs_are_left_alone(self, red):
        for mac in ("ac:de:48:00:11:22", "ac:de:48:33:44:55"):
            assert red.addresses(mac) == mac

    def test_the_unpadded_spelling_is_recognised_too(self, red):
        """ndp prints it unpadded. It is the same constant, and it has to come
        back spelled the way the tool that produced it spelled it."""
        assert red.addresses("ac:de:48:0:11:22") == "ac:de:48:0:11:22"

    def test_their_derived_link_locals_are_left_alone(self, red):
        for addr in ("fe80::aede:48ff:fe00:1122%en5",
                     "fe80::aede:48ff:fe33:4455%en5"):
            assert red.addresses(addr) == addr

    def test_the_shared_truncation_no_longer_needs_adjudicating(self, red):
        """fe80::aede:48ff is a prefix of both, which is precisely why it
        could not be resolved. Neither is substituted now, so the cut form
        must not be either — and there is nothing left to ask about."""
        red.prime(["fe80::aede:48ff:fe00:1122%en5 fe80::aede:48ff:fe33:4455%en5"])
        assert red.addresses("fe80::aede:48ff") == "fe80::aede:48ff"
        assert not red.warnings()
