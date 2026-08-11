"""Wi-Fi security mode: `_parse_connected_wifi_block` and `check_wifi_security`.

Both functions were rewritten in commit 4c349fd to fix two security-relevant
defects, and most of this module exists to keep them fixed:

  1.  The old code ran ``re.search(r"Security:\\s*(.+)", out)`` over the WHOLE
      system_profiler blob, so the first "Security:" line anywhere — the
      awdl0/AirDrop peer-to-peer block, or a NEIGHBOUR under "Other Local Wi-Fi
      Networks:" — was reported as the user's own network's security mode.
  2.  The old code branched on ``if not auth or auth in ("none", "open")`` and
      raised a HIGH "OPEN network" alarm when it had simply failed to parse
      anything. A parse failure now reports REVIEW; HIGH is reserved for a
      literal macOS "None"/"open" value on the connected block.

Indentation in the fixtures is load-bearing: the parser works purely by column
position, so the .out files reproduce system_profiler's real column layout.
"""

import pytest

from conftest import make_run

CONNECTED_SSID = "Fjordbakken 5GHz"


def _sp_airport(security="WPA3 Personal", ssid=CONNECTED_SSID):
    """A minimal but layout-faithful `system_profiler SPAirPortDataType` blob.

    Used for the classification table, where a full 70-line capture would bury
    the one value under test. Pass security=None to omit the Security line
    entirely (what happens when the field is unavailable without sudo).
    """
    security_line = "" if security is None else f"              Security: {security}\n"
    return (
        "Wi-Fi:\n"
        "\n"
        "      Interfaces:\n"
        "        en0:\n"
        "          Card Type: AirPort Extreme  (0x14E4, 0x4387)\n"
        "          MAC Address: a4:83:e7:9c:1b:40\n"
        "          Status: Connected\n"
        "          Current Network Information:\n"
        f"            {ssid}:\n"
        "              PHY Mode: 802.11ax\n"
        "              Channel: 149 (5GHz, 80MHz)\n"
        "              Country Code: US\n"
        "              Network Type: Infrastructure\n"
        f"{security_line}"
        "              Signal / Noise: -47 dBm / -92 dBm\n"
        "              Transmit Rate: 1441\n"
    )


def _wifi(mod, monkeypatch, output):
    """Run check_wifi_security() against a canned system_profiler output."""
    monkeypatch.setattr(mod, "run", make_run({"system_profiler SPAirPortDataType": output}))
    return mod.check_wifi_security()


# ---------------------------------------------------------------------------
# _parse_connected_wifi_block
# ---------------------------------------------------------------------------

class TestParseConnectedWifiBlock:
    def test_returns_the_connected_ssid_from_the_en0_block(self, mod, fixture):
        ssid, _ = mod._parse_connected_wifi_block(fixture("wifi_sp_airport_wpa3.out"))
        assert ssid == CONNECTED_SSID

    def test_body_holds_the_connected_networks_own_fields(self, mod, fixture):
        _, body = mod._parse_connected_wifi_block(fixture("wifi_sp_airport_wpa3.out"))
        assert "Security: WPA3 Personal" in body
        assert "Channel: 149 (5GHz, 80MHz)" in body
        assert "Transmit Rate: 1441" in body

    def test_neighbour_security_none_never_leaks_into_the_body(self, mod, fixture):
        # Regression, commit 4c349fd: the pre-fix code read the first "Security:"
        # in the whole blob, which was NETGEAR58-guest's "Security: None".
        _, body = mod._parse_connected_wifi_block(fixture("wifi_sp_airport_wpa3.out"))
        assert "Security: None" not in body
        assert "Security: WEP" not in body

    def test_neighbour_ssids_never_leak_into_the_body(self, mod, fixture):
        _, body = mod._parse_connected_wifi_block(fixture("wifi_sp_airport_wpa3.out"))
        for neighbour in ("NETGEAR58-guest", "xfinitywifi", "HP-Print-3A-OfficeJet"):
            assert neighbour not in body

    def test_body_is_bounded_by_other_local_wifi_networks(self, mod, fixture):
        _, body = mod._parse_connected_wifi_block(fixture("wifi_sp_airport_wpa3.out"))
        assert "Other Local Wi-Fi Networks" not in body

    def test_awdl0_block_is_skipped_even_when_listed_first(self, mod, fixture):
        # awdl0 is deliberately the FIRST interface in this fixture: its
        # "Current Network Information:" has no bare 'name:' key, only fields,
        # so a parser that took the first header would report the AirDrop
        # peer-to-peer link (Security: None) as the user's network.
        ssid, body = mod._parse_connected_wifi_block(fixture("wifi_sp_airport_wpa3.out"))
        assert ssid == CONNECTED_SSID
        assert "Peer-to-Peer (IBSS)" not in body

    def test_not_associated_output_yields_no_block_at_all(self, mod, fixture):
        # en0 is "Not Associated", so only awdl0 and the neighbour list carry a
        # Security value. Neither may be adopted as the connected network.
        ssid, body = mod._parse_connected_wifi_block(
            fixture("wifi_sp_airport_not_associated.out"))
        assert (ssid, body) == (None, "")

    def test_redacted_ssid_is_returned_verbatim_by_the_parser(self, mod, fixture):
        # The parser reports what system_profiler printed; translating
        # "<redacted>" to None is check_wifi_security's job, not the parser's.
        ssid, body = mod._parse_connected_wifi_block(fixture("wifi_sp_airport_redacted.out"))
        assert ssid == "<redacted>"
        assert "Security: WPA2 Personal" in body

    @pytest.mark.parametrize("text", ["", "\n\n\n", "   \n\t\n"],
                             ids=["empty", "newlines", "whitespace"])
    def test_input_with_no_content_returns_none_and_empty_body(self, mod, text):
        assert mod._parse_connected_wifi_block(text) == (None, "")

    def test_header_followed_by_a_field_value_line_is_not_matched(self, mod):
        # This is the awdl0 shape reduced to its essentials.
        text = (
            "          Current Network Information:\n"
            "            PHY Mode: 802.11\n"
            "            Network Type: Peer-to-Peer (IBSS)\n"
            "            Security: None\n"
        )
        assert mod._parse_connected_wifi_block(text) == (None, "")

    def test_header_followed_by_a_same_indent_key_is_not_matched(self, mod):
        # A name key must be indented DEEPER than the header; a sibling at the
        # same column belongs to the enclosing interface, not to the network.
        text = (
            "          Current Network Information:\n"
            "          Other Local Wi-Fi Networks:\n"
            "            NETGEAR58-guest:\n"
            "              Security: None\n"
        )
        assert mod._parse_connected_wifi_block(text) == (None, "")

    def test_header_as_the_last_line_is_not_matched(self, mod):
        # Truncated output (system_profiler killed by the run() timeout).
        text = "        en0:\n          Status: Connected\n          Current Network Information:\n"
        assert mod._parse_connected_wifi_block(text) == (None, "")

    def test_blank_lines_between_header_and_name_key_are_tolerated(self, mod):
        text = (
            "          Current Network Information:\n"
            "\n"
            "   \n"
            "            Fjordbakken 5GHz:\n"
            "              Security: WPA3 Personal\n"
        )
        ssid, body = mod._parse_connected_wifi_block(text)
        assert ssid == "Fjordbakken 5GHz"
        assert "Security: WPA3 Personal" in body

    def test_blank_line_inside_the_block_does_not_truncate_the_body(self, mod):
        text = (
            "          Current Network Information:\n"
            "            Fjordbakken 5GHz:\n"
            "              PHY Mode: 802.11ax\n"
            "\n"
            "              Security: WPA3 Personal\n"
        )
        _, body = mod._parse_connected_wifi_block(text)
        assert "Security: WPA3 Personal" in body

    def test_body_stops_at_other_local_wifi_networks_even_when_nested_deeper(self, mod):
        # The indentation guard alone would not stop here, so this pins the
        # explicit "Other Local Wi-Fi Networks:" bound that the fix added.
        text = (
            "          Current Network Information:\n"
            "            Fjordbakken 5GHz:\n"
            "              Security: WPA3 Personal\n"
            "              Other Local Wi-Fi Networks:\n"
            "                NETGEAR58-guest:\n"
            "                  Security: None\n"
        )
        ssid, body = mod._parse_connected_wifi_block(text)
        assert ssid == "Fjordbakken 5GHz"
        assert body.strip() == "Security: WPA3 Personal"

    def test_body_ends_when_a_shallower_sibling_key_starts(self, mod):
        text = (
            "        en0:\n"
            "          Current Network Information:\n"
            "            Fjordbakken 5GHz:\n"
            "              Security: WPA3 Personal\n"
            "        en1:\n"
            "          Current Network Information:\n"
            "            NeighboursRouter:\n"
            "              Security: None\n"
        )
        ssid, body = mod._parse_connected_wifi_block(text)
        assert ssid == "Fjordbakken 5GHz"
        assert "Security: None" not in body

    def test_ssid_containing_a_colon_is_not_recognised(self, mod):
        # DOCUMENTS ACTUAL BEHAVIOUR, not an endorsement. SSIDs may legally
        # contain ':', but the parser rejects any name key with an inner colon
        # because it cannot otherwise be told apart from a 'Field: value' line
        # (home_net_audit.py:595). The result is a missed parse -> REVIEW, which
        # is fail-safe rather than a false all-clear, so it is reported rather
        # than xfailed.
        text = (
            "          Current Network Information:\n"
            "            Home:5GHz:\n"
            "              Security: WPA3 Personal\n"
        )
        assert mod._parse_connected_wifi_block(text) == (None, "")

    def test_nameless_block_whose_first_field_is_empty_is_mistaken_for_a_name(self, mod):
        # DOCUMENTS ACTUAL BEHAVIOUR. "Country Code:" with no value is
        # indistinguishable from a bare name key at line 595, so a nameless
        # awdl0-style block ordered this way is matched and its (meaningless)
        # first field becomes the SSID. It stays fail-safe: every real field
        # sits at the same column as the pseudo-name, so the body comes back
        # empty and check_wifi_security reports REVIEW, never HIGH. Real awdl0
        # output leads with "PHY Mode: 802.11", so this ordering is contrived.
        text = (
            "          Current Network Information:\n"
            "            Country Code:\n"
            "            PHY Mode: 802.11\n"
            "            Security: None\n"
        )
        assert mod._parse_connected_wifi_block(text) == ("Country Code", "")


# ---------------------------------------------------------------------------
# check_wifi_security — how it asks
# ---------------------------------------------------------------------------

class TestCheckWifiSecurityCommand:
    def test_queries_system_profiler_for_the_airport_data_type(self, mod, monkeypatch):
        fake = make_run({"system_profiler SPAirPortDataType": _sp_airport()})
        monkeypatch.setattr(mod, "run", fake)
        mod.check_wifi_security()
        assert fake.calls == ["system_profiler SPAirPortDataType"]

    def test_allows_system_profiler_longer_than_the_default_timeout(self, mod, monkeypatch):
        # SPAirPortDataType routinely takes >10s (it rescans); the module-wide
        # 10s default would turn every audit into a spurious REVIEW.
        seen = {}

        def recording_run(cmd, timeout=10):
            seen["cmd"] = list(cmd)
            seen["timeout"] = timeout
            return _sp_airport()

        monkeypatch.setattr(mod, "run", recording_run)
        mod.check_wifi_security()
        assert seen["cmd"] == ["system_profiler", "SPAirPortDataType"]
        assert seen["timeout"] == 15

    def test_result_exposes_the_documented_keys(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport())
        assert set(result) == {"ssid", "auth", "cipher", "risk", "note"}

    def test_cipher_is_never_populated_from_system_profiler(self, mod, monkeypatch):
        # DOCUMENTS ACTUAL BEHAVIOUR: SPAirPortDataType has no cipher field, so
        # the key is always None and action_wifi_security's cipher line never
        # prints. The key is kept for API compatibility with the old airport
        # implementation.
        assert _wifi(mod, monkeypatch, _sp_airport())["cipher"] is None


# ---------------------------------------------------------------------------
# check_wifi_security — risk classification
# ---------------------------------------------------------------------------

class TestCheckWifiSecurityClassification:
    @pytest.mark.parametrize("security, expected_risk", [
        ("None", "HIGH"),
        ("open", "HIGH"),
        ("WEP", "HIGH"),
        ("Dynamic WEP", "HIGH"),
        ("WPA3 Personal", "GOOD"),
        ("WPA3 Enterprise", "GOOD"),
        ("WPA2/WPA3 Personal", "OK"),
        ("WPA2 Personal", "OK"),
        ("WPA2 Enterprise", "OK"),
        ("WPA/WPA2 Personal", "MEDIUM"),
        ("WPA Personal", "MEDIUM"),
        ("Enhanced Open (OWE)", "REVIEW"),
        ("Unrecognised Mode 7", "REVIEW"),
    ], ids=["none", "open", "wep", "dynamic_wep", "wpa3", "wpa3_enterprise",
            "wpa2_wpa3_transitional", "wpa2", "wpa2_enterprise", "wpa_wpa2_mixed",
            "wpa_original", "owe", "unknown"])
    def test_security_value_maps_to_risk(self, mod, monkeypatch, security, expected_risk):
        result = _wifi(mod, monkeypatch, _sp_airport(security))
        assert result["auth"] == security
        assert result["risk"] == expected_risk

    @pytest.mark.parametrize("security", [
        "None", "WEP", "WPA3 Personal", "WPA2/WPA3 Personal", "WPA2 Personal",
        "WPA/WPA2 Personal", "WPA Personal", "Unrecognised Mode 7", None,
    ])
    def test_every_outcome_carries_advice_and_a_real_risk_label(self, mod, monkeypatch,
                                                                security):
        # "UNKNOWN" is the dict's initial placeholder; leaking it would mean a
        # branch fell through without deciding anything.
        result = _wifi(mod, monkeypatch, _sp_airport(security))
        assert result["risk"] in {"HIGH", "MEDIUM", "OK", "GOOD", "REVIEW"}
        assert result["note"].strip()

    def test_open_network_note_says_traffic_is_unencrypted(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("None"))
        assert "unencrypted" in result["note"].lower()

    def test_unrecognised_auth_note_quotes_the_offending_value(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("Unrecognised Mode 7"))
        assert "Unrecognised Mode 7" in result["note"]


class TestParseFailureIsNotAnOpenNetwork:
    """Regression, commit 4c349fd: `if not auth or auth in ("none", "open")`.

    A failure to read the security mode used to be reported as a confirmed OPEN
    network at HIGH risk. Every assertion here checks risk != "HIGH" explicitly,
    because that false alarm is the whole point of these tests.
    """

    def test_missing_security_line_is_review_not_high(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport(security=None))
        assert result["auth"] is None
        assert result["risk"] != "HIGH"
        assert result["risk"] == "REVIEW"

    def test_empty_system_profiler_output_is_review_not_high(self, mod, monkeypatch):
        # run() returns "" when the command is missing, fails or times out.
        result = _wifi(mod, monkeypatch, "")
        assert result["risk"] != "HIGH"
        assert result["risk"] == "REVIEW"
        assert result["ssid"] is None and result["auth"] is None

    def test_run_returning_none_is_review_not_high(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", lambda cmd, timeout=10: None)
        result = mod.check_wifi_security()
        assert result["risk"] != "HIGH"
        assert result["risk"] == "REVIEW"

    def test_not_associated_is_review_not_high(self, mod, monkeypatch, fixture):
        # awdl0's peer-to-peer block reports "Security: None" in this capture.
        # Adopting it would raise a HIGH "OPEN network" alarm for a Mac that is
        # not on Wi-Fi at all.
        result = _wifi(mod, monkeypatch, fixture("wifi_sp_airport_not_associated.out"))
        assert result["risk"] != "HIGH"
        assert result["risk"] == "REVIEW"

    def test_review_note_suggests_sudo_rather_than_alarming(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, "")
        assert "sudo" in result["note"].lower()
        assert "OPEN network" not in result["note"]


class TestNeighbourValuesNeverDecideTheVerdict:
    """Regression, commit 4c349fd: `re.search(r"Security:\\s*(.+)", out)`.

    The old code searched the entire system_profiler blob, so whichever
    "Security:" line came first won — usually a neighbour's or awdl0's.
    """

    def test_neighbours_open_network_does_not_downgrade_a_wpa3_connection(
            self, mod, monkeypatch, fixture):
        result = _wifi(mod, monkeypatch, fixture("wifi_sp_airport_wpa3.out"))
        assert result["auth"] == "WPA3 Personal"
        assert result["risk"] == "GOOD"

    def test_neighbours_wpa3_does_not_mask_our_own_open_network(
            self, mod, monkeypatch, fixture):
        # Inverse leak: we are on an open cafe network while a WPA3 neighbour is
        # in range. The HIGH alarm must still fire.
        result = _wifi(mod, monkeypatch, fixture("wifi_sp_airport_open.out"))
        assert result["ssid"] == "Sunrise Cafe Free WiFi"
        assert result["auth"] == "None"
        assert result["risk"] == "HIGH"

    def test_connected_ssid_is_reported_not_a_neighbours(self, mod, monkeypatch, fixture):
        result = _wifi(mod, monkeypatch, fixture("wifi_sp_airport_wpa3.out"))
        assert result["ssid"] == CONNECTED_SSID


class TestRedactedSsid:
    def test_redacted_ssid_is_reported_as_unknown(self, mod, monkeypatch, fixture):
        # system_profiler prints "<redacted>" unless run with sudo; passing that
        # placeholder through would print a literal "<redacted>" as the network
        # name instead of the "run with sudo" hint.
        result = _wifi(mod, monkeypatch, fixture("wifi_sp_airport_redacted.out"))
        assert result["ssid"] is None

    def test_redaction_does_not_stop_the_security_classification(
            self, mod, monkeypatch, fixture):
        result = _wifi(mod, monkeypatch, fixture("wifi_sp_airport_redacted.out"))
        assert result["auth"] == "WPA2 Personal"
        assert result["risk"] == "OK"

    def test_redacted_open_network_still_raises_the_high_alarm(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("None", ssid="<redacted>"))
        assert result["ssid"] is None
        assert result["risk"] == "HIGH"


class TestBranchOrder:
    """The classification is a first-match-wins if/elif chain; ordering is the
    logic. These pin each branch against the one below it."""

    def test_wpa3_does_not_fall_through_to_the_wpa2_branch(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("WPA3 Personal"))
        assert result["risk"] == "GOOD"
        assert "WPA3" in result["note"]
        assert "acceptable" not in result["note"]

    def test_wpa3_does_not_fall_through_to_the_original_wpa_branch(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("WPA3 Personal"))
        assert result["risk"] != "MEDIUM"
        assert "known weaknesses" not in result["note"]

    def test_wpa2_does_not_fall_through_to_the_original_wpa_branch(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("WPA2 Personal"))
        assert result["risk"] == "OK"
        assert "known weaknesses" not in result["note"]

    def test_wpa2_alone_is_not_promoted_to_the_wpa3_verdict(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("WPA2 Personal"))
        assert result["risk"] != "GOOD"
        assert "current best practice" not in result["note"]

    def test_transitional_wpa2_wpa3_is_ok_not_good(self, mod, monkeypatch):
        # A WPA2 fallback is still reachable, so the transitional mode must not
        # earn the unqualified WPA3 verdict.
        result = _wifi(mod, monkeypatch, _sp_airport("WPA2/WPA3 Personal"))
        assert result["risk"] == "OK"
        assert "transitional" in result["note"].lower()

    def test_transitional_wpa2_wpa3_is_not_demoted_to_the_mixed_wpa_verdict(
            self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("WPA2/WPA3 Personal"))
        assert result["risk"] != "MEDIUM"

    def test_mixed_wpa_wpa2_is_medium_not_plain_wpa2_ok(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("WPA/WPA2 Personal"))
        assert result["risk"] == "MEDIUM"
        assert "legacy WPA fallback" in result["note"]

    def test_wep_wins_over_any_wpa_token_in_the_same_string(self, mod, monkeypatch):
        # WEP is broken outright; a WPA2 substring must not soften the verdict.
        result = _wifi(mod, monkeypatch, _sp_airport("WEP (WPA2 fallback)"))
        assert result["risk"] == "HIGH"
        assert "WEP" in result["note"]

    def test_literal_none_wins_over_the_parse_failure_branch(self, mod, monkeypatch):
        result = _wifi(mod, monkeypatch, _sp_airport("None"))
        assert result["risk"] == "HIGH"
        assert "sudo" not in result["note"].lower()
