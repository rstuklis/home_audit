"""DHCP option baselining and evil-twin detection — roadmap P2, second cluster.

Both close the same class of gap: a check that counts things missing an attack
that does not change the count.

`check_rogue_dhcp` counted responders. One perfectly ordinary DHCP server can
hand out a poisoned gateway, resolver or static route while the count stays at
one the whole time — and option 121 is the quiet one, because a pushed static
route reroutes a subnet without touching the default gateway or needing to win
a DHCP race.

An evil twin is the same shape in Wi-Fi: your SSID is still there, still
connectable, still the right name. There is simply a second access point
offering it.
"""

import socket
import struct

import pytest

from conftest import load_fixture, make_run

SP_CMD = "system_profiler SPAirPortDataType"


def dhcp_packet(options=b""):
    """A DHCP reply: 236-byte fixed header, magic cookie, then option TLVs."""
    return b"\x02" + b"\x00" * 235 + b"\x63\x82\x53\x63" + options + b"\xff"


def tlv(code, value):
    return bytes([code, len(value)]) + value


def ip(addr):
    return socket.inet_aton(addr)


class TestDhcpOptionParsing:
    def test_options_are_split_into_codes(self, mod):
        packet = dhcp_packet(tlv(53, b"\x02") + tlv(3, ip("192.168.1.1")))
        options = mod.parse_dhcp_options(packet)
        assert options[53] == b"\x02"
        assert options[3] == ip("192.168.1.1")

    def test_padding_is_skipped(self, mod):
        packet = dhcp_packet(b"\x00\x00" + tlv(3, ip("192.168.1.1")))
        assert mod.parse_dhcp_options(packet)[3] == ip("192.168.1.1")

    def test_parsing_stops_at_the_end_marker(self, mod):
        packet = dhcp_packet(tlv(3, ip("192.168.1.1"))) + tlv(6, ip("9.9.9.9"))
        assert 6 not in mod.parse_dhcp_options(packet)

    def test_a_packet_without_the_magic_cookie_yields_nothing(self, mod):
        assert mod.parse_dhcp_options(b"\x02" + b"\x00" * 240) == {}

    def test_a_truncated_option_does_not_raise(self, mod):
        packet = dhcp_packet() [:-1] + bytes([3, 8, 1, 2])   # claims 8 bytes, has 2
        assert isinstance(mod.parse_dhcp_options(packet), dict)

    def test_multiple_addresses_in_one_option_are_all_read(self, mod):
        packet = dhcp_packet(tlv(6, ip("1.1.1.1") + ip("9.9.9.9")))
        assert mod.describe_dhcp_offer(packet)["dns"] == ["1.1.1.1", "9.9.9.9"]


class TestClasslessStaticRoutes:
    def test_a_route_is_decoded_to_prefix_and_gateway(self, mod):
        # 10.0.0.0/8 via 192.168.1.66
        value = bytes([8]) + bytes([10]) + ip("192.168.1.66")
        assert mod.decode_classless_routes(value) == ["10.0.0.0/8 via 192.168.1.66"]

    def test_a_24_prefix_carries_three_significant_octets(self, mod):
        value = bytes([24]) + bytes([192, 168, 5]) + ip("192.168.1.66")
        assert mod.decode_classless_routes(value) == ["192.168.5.0/24 via 192.168.1.66"]

    def test_a_default_route_has_no_significant_octets(self, mod):
        # width 0 — this is the whole internet redirected, the worst case.
        value = bytes([0]) + ip("192.168.1.66")
        assert mod.decode_classless_routes(value) == ["0.0.0.0/0 via 192.168.1.66"]

    def test_several_routes_in_one_option_are_all_decoded(self, mod):
        value = (bytes([8]) + bytes([10]) + ip("192.168.1.66") +
                 bytes([16]) + bytes([172, 16]) + ip("192.168.1.77"))
        assert mod.decode_classless_routes(value) == [
            "10.0.0.0/8 via 192.168.1.66", "172.16.0.0/16 via 192.168.1.77"]

    def test_an_impossible_prefix_width_stops_parsing(self, mod):
        assert mod.decode_classless_routes(bytes([99]) + ip("1.2.3.4")) == []

    def test_a_truncated_route_is_dropped(self, mod):
        assert mod.decode_classless_routes(bytes([8]) + bytes([10]) + b"\x01\x02") == []

    def test_option_121_is_read_from_an_offer(self, mod):
        packet = dhcp_packet(tlv(121, bytes([8]) + bytes([10]) + ip("192.168.1.66")))
        assert mod.describe_dhcp_offer(packet)["static_routes"] == [
            "10.0.0.0/8 via 192.168.1.66"]

    def test_the_microsoft_option_249_is_read_too(self, mod):
        packet = dhcp_packet(tlv(249, bytes([8]) + bytes([10]) + ip("192.168.1.66")))
        assert mod.describe_dhcp_offer(packet)["static_routes"] == [
            "10.0.0.0/8 via 192.168.1.66"]

    def test_an_offer_with_no_routes_reports_none(self, mod):
        assert mod.describe_dhcp_offer(dhcp_packet())["static_routes"] == []


class TestDhcpOfferDiff:
    def test_a_new_static_route_is_reported(self, mod):
        notes = mod.diff_dhcp_offer(
            {"router": ["192.168.1.1"], "dns": [], "static_routes": []},
            {"router": ["192.168.1.1"], "dns": [],
             "static_routes": ["10.0.0.0/8 via 192.168.1.66"]})
        assert len(notes) == 1
        assert "without changing the default gateway" in notes[0]

    def test_a_changed_gateway_is_reported(self, mod):
        notes = mod.diff_dhcp_offer(
            {"router": ["192.168.1.1"], "dns": [], "static_routes": []},
            {"router": ["192.168.1.66"], "dns": [], "static_routes": []})
        assert "gateway" in notes[0]

    def test_changed_dns_is_reported(self, mod):
        notes = mod.diff_dhcp_offer(
            {"router": [], "dns": ["192.168.1.1"], "static_routes": []},
            {"router": [], "dns": ["9.9.9.9"], "static_routes": []})
        assert "DNS servers" in notes[0]

    def test_an_unchanged_offer_is_silent(self, mod):
        offer = {"router": ["192.168.1.1"], "dns": ["192.168.1.1"], "static_routes": []}
        assert mod.diff_dhcp_offer(offer, dict(offer)) == []

    def test_a_first_offer_is_not_a_change(self, mod):
        assert mod.diff_dhcp_offer(None, {"router": ["192.168.1.1"]}) == []

    def test_a_route_disappearing_is_not_reported(self, mod):
        # Only additions redirect traffic; a withdrawn route is not an attack.
        notes = mod.diff_dhcp_offer(
            {"router": [], "dns": [], "static_routes": ["10.0.0.0/8 via 192.168.1.66"]},
            {"router": [], "dns": [], "static_routes": []})
        assert notes == []

    def test_a_missing_field_does_not_produce_a_false_change(self, mod):
        # An offer that simply omitted option 3 must not read as a gateway change.
        assert mod.diff_dhcp_offer(
            {"router": ["192.168.1.1"], "dns": [], "static_routes": []},
            {"router": [], "dns": [], "static_routes": []}) == []


SP_TWIN = """      Interfaces:
        en0:
          Card Type: Wi-Fi
          Current Network Information:
            HomeNet:
              PHY Mode: 802.11ax
              BSSID: 3c:22:fb:11:22:33
              Channel: 36
              Security: WPA3 Personal
          Other Local Wi-Fi Networks:
            NeighbourNet:
              PHY Mode: 802.11n
              BSSID: aa:bb:cc:dd:ee:ff
              Security: WPA2 Personal
            HomeNet:
              PHY Mode: 802.11n
              BSSID: e:8b:2:1a:2b:3c
              Security: WPA2 Personal
"""

SP_CLEAN = """      Interfaces:
        en0:
          Current Network Information:
            HomeNet:
              BSSID: 3c:22:fb:11:22:33
              Security: WPA3 Personal
          Other Local Wi-Fi Networks:
            NeighbourNet:
              BSSID: aa:bb:cc:dd:ee:ff
              Security: WPA2 Personal
"""

SP_REDACTED = """      Interfaces:
        en0:
          Current Network Information:
            HomeNet:
              BSSID: <redacted>
              Security: WPA3 Personal
"""


class TestWifiNetworkParsing:
    def test_bssids_are_grouped_by_ssid(self, mod):
        networks = mod.parse_wifi_networks(SP_TWIN)
        assert networks["NeighbourNet"] == ["aa:bb:cc:dd:ee:ff"]
        assert len(networks["HomeNet"]) == 2

    def test_the_connected_and_other_sections_are_merged(self, mod):
        # The evil twin lives in 'Other Local Wi-Fi Networks' while the real AP
        # is in the connected block; reading only one section would miss it.
        assert "3c:22:fb:11:22:33" in mod.parse_wifi_networks(SP_TWIN)["HomeNet"]
        assert "0e:8b:02:1a:2b:3c" in mod.parse_wifi_networks(SP_TWIN)["HomeNet"]

    def test_short_octets_are_zero_padded(self, mod):
        assert "0e:8b:02:1a:2b:3c" in mod.parse_wifi_networks(SP_TWIN)["HomeNet"]

    def test_redacted_bssids_are_skipped(self, mod):
        assert mod.parse_wifi_networks(SP_REDACTED) == {}

    def test_section_headers_are_not_mistaken_for_ssids(self, mod):
        networks = mod.parse_wifi_networks(SP_TWIN)
        assert "Other Local Wi-Fi Networks" not in networks
        assert "Current Network Information" not in networks

    def test_empty_output_yields_nothing(self, mod):
        assert mod.parse_wifi_networks("") == {}

    def test_the_interface_name_is_not_an_ssid(self, mod):
        # "en0:" is structure. It used to be accepted as a network name, which
        # is how BSSIDs ended up filed under it — see TestSsidsEndingInAHeaderWord.
        assert "en0" not in mod.parse_wifi_networks(SP_TWIN)


SP_SSID_ENDING_IN_NETWORKS = """      Interfaces:
        en0:
          Current Network Information:
            HomeNet:
              BSSID: 3c:22:fb:11:22:33
              Security: WPA3 Personal
          Other Local Wi-Fi Networks:
            AAA Guest Networks:
              BSSID: aa:bb:cc:dd:ee:ff
              Security: WPA2 Personal
"""

SP_OWN_SSID_ENDING_IN_NETWORKS = """      Interfaces:
        en0:
          Current Network Information:
            Wong Networks:
              BSSID: 3c:22:fb:11:22:33
              Security: WPA3 Personal
"""


class TestSsidsEndingInAHeaderWord:
    """The section-header test was a suffix match, and its reject branch leaked.

    Any real SSID ending in "Networks" or "Information" was thrown away — and
    because the branch left `ssid` pointing at the *previous* network, that
    network's BSSIDs were then filed under it. Listed first under "Other Local
    Wi-Fi Networks", a neighbour called "AAA Guest Networks" therefore handed
    its BSSID to the SSID you are connected to, which is the exact definition
    check_evil_twin raises a HIGH for. The false BSSID was then written into
    the baseline, so it persisted.
    """

    def test_a_neighbours_bssid_is_not_filed_under_the_connected_ssid(self, mod):
        networks = mod.parse_wifi_networks(SP_SSID_ENDING_IN_NETWORKS)
        assert "aa:bb:cc:dd:ee:ff" not in networks.get("HomeNet", []), \
            "a neighbour's BSSID under your own SSID reads as an evil twin"

    def test_such_an_ssid_is_kept_as_its_own_network(self, mod):
        networks = mod.parse_wifi_networks(SP_SSID_ENDING_IN_NETWORKS)
        assert networks.get("AAA Guest Networks") == ["aa:bb:cc:dd:ee:ff"]

    def test_your_own_ssid_ending_in_networks_is_still_found(self, mod):
        # The mirror case: every BSSID landed under "en0", so check_evil_twin
        # found nothing for the real SSID and reported "No BSSID visible —
        # grant Location Services", blaming permissions for a parser bug.
        networks = mod.parse_wifi_networks(SP_OWN_SSID_ENDING_IN_NETWORKS)
        assert networks == {"Wong Networks": ["3c:22:fb:11:22:33"]}


class TestEvilTwinDetection:
    def test_a_second_ap_advertising_your_ssid_is_high(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: SP_TWIN}))
        result = mod.check_evil_twin(known=["3c:22:fb:11:22:33"])
        assert result["risk"] == "HIGH"
        assert result["unexpected"] == ["0e:8b:02:1a:2b:3c"]
        assert "evil twin" in result["note"]

    def test_a_known_single_ap_is_quiet(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: SP_CLEAN}))
        assert mod.check_evil_twin(known=["3c:22:fb:11:22:33"])["risk"] == "OK"

    def test_a_mesh_with_several_known_bssids_does_not_alarm(self, mod, monkeypatch):
        # Legitimate multi-AP networks must not flag forever, same reasoning as
        # the multi-router case in rogue-RA detection.
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: SP_TWIN}))
        result = mod.check_evil_twin(
            known=["3c:22:fb:11:22:33", "0e:8b:02:1a:2b:3c"])
        assert result["unexpected"] == []
        assert result["risk"] == "OK"

    def test_a_neighbours_ssid_is_not_our_business(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: SP_TWIN}))
        result = mod.check_evil_twin(known=["3c:22:fb:11:22:33",
                                            "0e:8b:02:1a:2b:3c"])
        assert "aa:bb:cc:dd:ee:ff" not in result["bssids"]

    def test_redaction_is_reported_as_unreadable_not_clean(self, mod, monkeypatch):
        # Without sudo system_profiler hides the BSSID. Reporting OK here would
        # claim a check passed that never ran.
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: SP_REDACTED}))
        result = mod.check_evil_twin()
        assert result["risk"] == "REVIEW"
        assert "sudo" in result["note"]

    def test_a_first_run_says_there_is_no_baseline(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: SP_CLEAN}))
        assert "no baseline" in mod.check_evil_twin()["note"].lower()

    def test_the_action_marks_the_unexpected_bssid(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: SP_TWIN}))
        mod.action_evil_twin(known=["3c:22:fb:11:22:33"])
        out = capsys.readouterr().out
        assert "not in baseline" in out and "HIGH" in out


class TestBaselineDiff:
    def test_a_new_bssid_is_reported(self, mod):
        notes = mod.diff_baseline({"wifi_bssids": ["3c:22:fb:11:22:33"]},
                                  {"wifi_bssids": ["3c:22:fb:11:22:33",
                                                   "0e:8b:02:1a:2b:3c"]})
        assert len(notes) == 1 and "evil twin" in notes[0]

    def test_an_unchanged_bssid_set_is_silent(self, mod):
        assert mod.diff_baseline({"wifi_bssids": ["3c:22:fb:11:22:33"]},
                                 {"wifi_bssids": ["3c:22:fb:11:22:33"]}) == []

    def test_an_ap_going_away_is_not_reported(self, mod):
        assert mod.diff_baseline({"wifi_bssids": ["a", "b"]},
                                 {"wifi_bssids": ["a"]}) == []

    def test_a_dhcp_static_route_change_reaches_the_diff(self, mod):
        old = {"dhcp": {"responders": [{"router": [], "dns": [], "static_routes": []}]}}
        new = {"dhcp": {"responders": [{"router": [], "dns": [],
                                        "static_routes": ["0.0.0.0/0 via 192.168.1.66"]}]}}
        notes = mod.diff_baseline(old, new)
        assert any("static route" in n for n in notes)

    def test_absent_keys_do_not_raise(self, mod):
        assert mod.diff_baseline({}, {}) == []
