"""Rogue Router Advertisement detection — roadmap P1.

The attack: send Router Advertisements, become the IPv6 default gateway via
SLAAC, and because macOS prefers IPv6 the victim's traffic reroutes through you.
Nothing about the IPv4 network changes, so until now this tool reported a
perfectly clean result while every packet went the wrong way. It was the one
attack in scope that produced no signal at all.

Detection here is deliberately comparative rather than absolute. A network with
one advertising router is normal, and plenty legitimately have two — a count
threshold alone would cry wolf forever, which is how a check gets ignored. What
matters is a router that was not there before, so the baseline does the work and
the count is the weaker secondary signal.

Both dialects parse into the same shape, for the same reason as the IPv4
readers: the Mac and an observer diff against one shared baseline, so they must
agree on what they saw.
"""

import pytest

from conftest import load_fixture, make_run

NDP_A = "ndp -an"   # -n matters: see TestCapturedFromARealMac
NDP_R = "ndp -r"
IP6_NEIGH = "ip -6 neigh show"
IP6_ROUTE = "ip -6 route show default"

NDP_A_OUT = load_fixture("ndp_a.out")
NDP_R_OUT = load_fixture("ndp_r.out")
NDP_R_TWO = load_fixture("ndp_r_two_routers.out")
IP6_NEIGH_OUT = load_fixture("ip6_neigh.out")
IP6_ROUTE_OUT = load_fixture("ip6_route_default.out")
IP6_ROUTE_TWO = load_fixture("ip6_route_two_routers.out")

ROUTER = "fe80::1%en0"
ROGUE = "fe80::c8b:2ff:fe1a:2b3c%en0"


class TestMacosNdpParsing:
    def test_neighbours_and_macs_are_read(self, mod):
        n = mod.parse_ndp_neighbours(NDP_A_OUT)
        assert n["fe80::1%en0"]["mac"] == "3c:22:fb:11:22:33"
        assert n["2001:db8:1:0:1c3c:c1ff:fe2a:3b4c%en0"]["mac"] == "a4:83:e7:1b:9c:2d"

    def test_the_router_flag_is_read(self, mod):
        # The R column is the entire reason for parsing this table.
        n = mod.parse_ndp_neighbours(NDP_A_OUT)
        assert n["fe80::1%en0"]["router"] is True
        assert n["2001:db8:1:0:1c3c:c1ff:fe2a:3b4c%en0"]["router"] is False

    def test_short_octets_are_zero_padded(self, mod):
        # Must match the IPv4 readers' normalisation or one device would look
        # like two across the Mac and an observer.
        n = mod.parse_ndp_neighbours(NDP_A_OUT)
        assert n[ROGUE]["mac"] == "0e:8b:02:1a:2b:3c"

    def test_incomplete_entries_are_dropped(self, mod):
        assert "fe80::dead:beef%en0" not in mod.parse_ndp_neighbours(NDP_A_OUT)

    def test_the_header_row_is_skipped(self, mod):
        assert all(":" in a for a in mod.parse_ndp_neighbours(NDP_A_OUT))

    def test_the_zone_is_preserved(self, mod):
        # fe80::1 is only meaningful per-link; dropping %en0 would merge
        # distinct routers on different interfaces into one.
        assert all("%" in a for a in mod.parse_ndp_neighbours(NDP_A_OUT)
                   if a.startswith("fe80"))

    def test_empty_output_yields_nothing(self, mod):
        assert mod.parse_ndp_neighbours("") == {}

    def test_routers_are_read_from_ndp_r(self, mod):
        assert mod.parse_ndp_routers(NDP_R_OUT) == [ROUTER]

    def test_two_advertising_routers_are_both_read(self, mod):
        assert mod.parse_ndp_routers(NDP_R_TWO) == [ROUTER, ROGUE]

    def test_ipv4_addresses_are_not_mistaken_for_routers(self, mod):
        assert mod.parse_ndp_routers("192.168.1.1 if=en0\n") == []

    def test_garbage_is_skipped_without_raising(self, mod):
        assert mod.parse_ndp_routers("no addresses here\n\n") == []


class TestCapturedFromARealMac:
    """Three bugs that only a genuine capture could have surfaced.

    The authored fixture had the columns as `S Flags`; real macOS prints
    `St Flgs Prbs`. That difference mattered more than cosmetics.
    """

    def test_a_reachable_neighbour_is_not_mistaken_for_a_router(self, mod):
        # THE bug. The state column uses R for REACHABLE and the flags column
        # uses R for router. Checking for "an R somewhere after the netif"
        # flagged every reachable neighbour on the LAN as an IPv6 router, which
        # would have fired the rogue-RA alarm on a perfectly healthy network.
        reachable_not_router = (
            "Neighbor            Linklayer Address  Netif Expire    St Flgs Prbs\n"
            "fe80::5%en0         a4:83:e7:1b:9c:2d  en0   23h58m12s R\n")
        parsed = mod.parse_ndp_neighbours(reachable_not_router)
        assert parsed["fe80::5%en0"]["router"] is False

    def test_the_router_flag_is_read_from_its_own_column(self, mod):
        router = ("Neighbor            Linklayer Address  Netif Expire    St Flgs Prbs\n"
                  "fe80::1%en0         3c:22:fb:11:22:33  en0   23h59m58s R  R\n")
        assert mod.parse_ndp_neighbours(router)["fe80::1%en0"]["router"] is True

    def test_a_hostname_in_the_neighbor_column_is_skipped_not_crashed(self, mod):
        # Without -n, ndp reverse-resolves and the column is a hostname. Every
        # entry then failed to parse and was dropped in silence — the reason the
        # command now passes -n. A hostname row is still handled defensively.
        named = ("Neighbor            Linklayer Address  Netif Expire    St Flgs Prbs\n"
                 "runner-host.local   ca:97:2e:f8:7e:e9  en0   permanent R  R\n")
        assert mod.parse_ndp_neighbours(named) == {}

    def test_the_neighbour_command_disables_name_resolution(self, mod, monkeypatch):
        fake = make_run({})
        monkeypatch.setattr(mod, "run", fake)
        mod.get_ipv6_neighbours()
        assert any(c.split() == ["ndp", "-an"] for c in fake.calls), \
            "ndp must be called with -n or every neighbour parses as a hostname"

    def test_an_incomplete_entry_is_dropped(self, mod):
        # Real captures are full of these on interfaces with no neighbour.
        incomplete = ("Neighbor            Linklayer Address  Netif Expire    St Flgs Prbs\n"
                      "fe80::9%en0         (incomplete)       en0   expired   I\n")
        assert mod.parse_ndp_neighbours(incomplete) == {}


class TestLinuxIproute6Parsing:
    def test_neighbours_and_macs_are_read(self, mod):
        n = mod.parse_neigh6_iproute(IP6_NEIGH_OUT)
        assert n["fe80::1"]["mac"] == "3c:22:fb:11:22:33"
        assert n["2001:db8:1::5"]["iface"] == "eth0"

    def test_the_router_keyword_is_read(self, mod):
        n = mod.parse_neigh6_iproute(IP6_NEIGH_OUT)
        assert n["fe80::1"]["router"] is True
        assert n["2001:db8:1::5"]["router"] is False

    def test_failed_entries_are_dropped(self, mod):
        assert "fe80::dead" not in mod.parse_neigh6_iproute(IP6_NEIGH_OUT)

    def test_short_octets_are_zero_padded(self, mod):
        n = mod.parse_neigh6_iproute(IP6_NEIGH_OUT)
        assert n["fe80::c8b:2ff:fe1a:2b3c"]["mac"] == "0e:8b:02:1a:2b:3c"

    def test_default_routes_yield_their_via_address(self, mod):
        assert mod.parse_routes6_iproute(IP6_ROUTE_OUT) == ["fe80::1"]

    def test_two_default_routes_yield_two_routers(self, mod):
        assert mod.parse_routes6_iproute(IP6_ROUTE_TWO) == [
            "fe80::1", "fe80::c8b:2ff:fe1a:2b3c"]

    def test_non_default_routes_are_ignored(self, mod):
        out = ("2001:db8::/64 dev eth0 proto ra metric 1024\n"
               "default via fe80::1 dev eth0 proto ra\n")
        assert mod.parse_routes6_iproute(out) == ["fe80::1"]

    def test_a_route_without_a_via_is_skipped(self, mod):
        # `default dev tun0` is point-to-point; there is no router address.
        assert mod.parse_routes6_iproute("default dev tun0 proto static\n") == []

    def test_empty_output_yields_nothing(self, mod):
        assert mod.parse_routes6_iproute("") == []
        assert mod.parse_neigh6_iproute("") == {}


class TestDialectDispatch:
    def test_macos_sources_are_used_when_available(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({NDP_R: NDP_R_OUT}))
        assert mod.get_ipv6_routers() == [ROUTER]

    def test_linux_falls_through_to_the_routing_table(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({IP6_ROUTE: IP6_ROUTE_OUT}))
        assert mod.get_ipv6_routers() == ["fe80::1"]

    def test_the_neighbour_router_flag_is_the_last_resort(self, mod, monkeypatch):
        # No ndp, no default route — fall back to whoever flagged itself.
        monkeypatch.setattr(mod, "run", make_run({IP6_NEIGH: IP6_NEIGH_OUT}))
        assert mod.get_ipv6_routers() == ["fe80::1", "fe80::c8b:2ff:fe1a:2b3c"]

    def test_neighbours_prefer_ndp_over_iproute(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({
            NDP_A: NDP_A_OUT, IP6_NEIGH: IP6_NEIGH_OUT}))
        assert "fe80::1%en0" in mod.get_ipv6_neighbours()

    def test_nothing_anywhere_is_not_an_error(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({}))
        assert mod.get_ipv6_routers() == []
        assert mod.get_ipv6_neighbours() == {}


class TestRiskClassification:
    def _with(self, mod, monkeypatch, routers_out):
        monkeypatch.setattr(mod, "run", make_run({NDP_R: routers_out}))

    def test_a_single_known_router_is_quiet(self, mod, monkeypatch):
        """The false-positive discipline this project keeps relearning.

        A check is not finished when it parses correctly; it is finished when
        it is quiet on a healthy network. A stable single router must not warn,
        or the reader stops looking at the section that would show a real one.
        """
        self._with(mod, monkeypatch, NDP_R_OUT)
        result = mod.check_ipv6_routers(known=[ROUTER])
        assert result["risk"] == "OK"
        assert result["unexpected"] == []

    def test_an_unexpected_router_is_high(self, mod, monkeypatch):
        self._with(mod, monkeypatch, NDP_R_TWO)
        result = mod.check_ipv6_routers(known=[ROUTER])
        assert result["risk"] == "HIGH"
        assert result["unexpected"] == [ROGUE]
        assert "rogue" in result["note"].lower()

    def test_two_routers_with_no_baseline_is_still_high(self, mod, monkeypatch):
        # Nothing to compare against, but two advertisers is itself suspect.
        self._with(mod, monkeypatch, NDP_R_TWO)
        assert mod.check_ipv6_routers()["risk"] == "HIGH"

    def test_two_routers_both_in_the_baseline_are_not_flagged(self, mod, monkeypatch):
        # A network that legitimately has two must not alarm forever.
        self._with(mod, monkeypatch, NDP_R_TWO)
        result = mod.check_ipv6_routers(known=[ROUTER, ROGUE])
        assert result["unexpected"] == []
        assert result["risk"] != "HIGH"

    def test_no_ipv6_router_is_informational_not_a_problem(self, mod, monkeypatch):
        self._with(mod, monkeypatch, "")
        result = mod.check_ipv6_routers()
        assert result["risk"] == "INFO"
        assert result["routers"] == []

    def test_a_first_run_says_so_rather_than_implying_safety(self, mod, monkeypatch):
        self._with(mod, monkeypatch, NDP_R_OUT)
        note = mod.check_ipv6_routers()["note"]
        assert "no baseline" in note.lower()

    def test_a_router_that_disappeared_does_not_read_as_unexpected(self, mod, monkeypatch):
        self._with(mod, monkeypatch, NDP_R_OUT)
        assert mod.check_ipv6_routers(known=[ROUTER, ROGUE])["unexpected"] == []


class TestBaselineDiffReportsNewRouters:
    def test_a_new_advertising_router_produces_a_note(self, mod):
        notes = mod.diff_baseline({"ipv6_routers": [ROUTER]},
                                  {"ipv6_routers": [ROUTER, ROGUE]})
        assert len(notes) == 1
        assert ROGUE in notes[0]
        assert "rogue" in notes[0].lower()

    def test_a_router_that_stopped_advertising_produces_a_note(self, mod):
        notes = mod.diff_baseline({"ipv6_routers": [ROUTER, ROGUE]},
                                  {"ipv6_routers": [ROUTER]})
        assert len(notes) == 1 and ROGUE in notes[0]

    def test_an_unchanged_router_set_is_silent(self, mod):
        assert mod.diff_baseline({"ipv6_routers": [ROUTER]},
                                 {"ipv6_routers": [ROUTER]}) == []

    def test_reordering_is_not_a_change(self, mod):
        assert mod.diff_baseline({"ipv6_routers": [ROUTER, ROGUE]},
                                 {"ipv6_routers": [ROGUE, ROUTER]}) == []

    def test_absent_keys_do_not_raise_or_alarm(self, mod):
        # Baselines saved before this check existed have no such key.
        assert mod.diff_baseline({}, {}) == []
        assert mod.diff_baseline({}, {"ipv6_routers": []}) == []

    def test_a_first_baseline_with_routers_is_reported_once(self, mod):
        notes = mod.diff_baseline({}, {"ipv6_routers": [ROUTER]})
        assert len(notes) == 1 and ROUTER in notes[0]


class TestReporting:
    def test_the_action_prints_neighbours_and_a_risk_line(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "run", make_run({
            NDP_A: NDP_A_OUT, NDP_R: NDP_R_TWO}))
        result = mod.action_ipv6_routers(known=[ROUTER])
        out = capsys.readouterr().out
        assert "HIGH" in out
        assert "advertising as a router" in out
        assert result["unexpected"] == [ROGUE]

    def test_the_rogue_is_named_in_the_output(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "run", make_run({NDP_R: NDP_R_TWO}))
        mod.action_ipv6_routers(known=[ROUTER])
        assert ROGUE in capsys.readouterr().out

    def test_a_clean_network_does_not_print_high(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "run", make_run({
            NDP_A: NDP_A_OUT, NDP_R: NDP_R_OUT}))
        mod.action_ipv6_routers(known=[ROUTER])
        assert "HIGH" not in capsys.readouterr().out


class TestDialectsAgree:
    def test_both_neighbour_readers_produce_the_same_shape(self, mod):
        mac_side = mod.parse_ndp_neighbours(
            "fe80::1%en0    3c:22:fb:11:22:33  en0   23h S R\n")["fe80::1%en0"]
        linux_side = mod.parse_neigh6_iproute(
            "fe80::1 dev en0 lladdr 3c:22:fb:11:22:33 router STALE\n")["fe80::1"]
        assert mac_side["mac"] == linux_side["mac"]
        assert mac_side["router"] == linux_side["router"] is True
        assert set(mac_side) == set(linux_side)

    def test_both_router_readers_return_a_list_of_addresses(self, mod):
        assert (mod.parse_ndp_routers("fe80::1%en0 if=en0, flags=O\n")
                == ["fe80::1%en0"])
        assert (mod.parse_routes6_iproute("default via fe80::1 dev en0 proto ra\n")
                == ["fe80::1"])
