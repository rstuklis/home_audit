"""The HomeAuditWiFi helper — the only reader left once macOS redacts the SSID.

macOS gives the SSID and every BSSID only to a process with Location Services
access. The tool used to tell its owner to grant that to their terminal, which
cannot be done: Terminal never asks, and the list has no way to add an app that
has not asked. tools/wifi_helper builds a small app that asks for itself; these
tests pin how its reply is trusted (barely), when it is consulted (only after
system_profiler was redacted), and what the reader is told when it is absent.
"""

import json

import pytest

REDACTED = "wifi_sp_airport_redacted.out"


def _reply(**over):
    base = {"helper": 1, "location_services_on": True, "authorization": "authorized",
            "interface": "en0", "ssid": "loveshack", "bssid": "3c:28:6d:5e:20:8a",
            "same_ssid_bssids": ["3c:28:6d:5e:20:8a", "38:8b:59:e0:f1:72"],
            "networks_seen": 20}
    base.update(over)
    return json.dumps(base)


@pytest.fixture
def helper(mod, monkeypatch, tmp_path):
    """Install a fake helper and choose what it prints. Returns the run log."""
    def install(output, sp_airport=""):
        path = tmp_path / "HomeAuditWiFi"
        path.write_text("")
        monkeypatch.setenv(mod.WIFI_HELPER_ENV, str(path))
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        calls = []

        def fake_run(cmd, timeout=10, merge_stderr=False):
            calls.append(list(cmd))
            if cmd[0] == str(path):
                return output
            if cmd[0] == "system_profiler":
                return sp_airport
            return ""
        monkeypatch.setattr(mod, "run", fake_run)
        return calls
    return install


class TestReadingTheReply:
    def test_a_good_reply_yields_the_ssid_and_bssids(self, mod, helper):
        helper(_reply())
        r = mod.read_wifi_helper(scan=True)
        assert r["installed"] and r["authorization"] == "authorized"
        assert r["ssid"] == "loveshack"
        assert r["bssids"] == ["38:8b:59:e0:f1:72", "3c:28:6d:5e:20:8a"]

    def test_scan_is_only_requested_when_asked_for(self, mod, helper):
        calls = helper(_reply())
        mod.read_wifi_helper()
        mod.read_wifi_helper(scan=True)
        assert calls[0][1:] == [] and calls[1][1:] == ["--scan"]

    def test_an_absent_helper_is_not_run(self, mod, monkeypatch, tmp_path):
        monkeypatch.setenv(mod.WIFI_HELPER_ENV, str(tmp_path / "nope"))
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", lambda *a, **k: pytest.fail("ran a missing helper"))
        assert mod.read_wifi_helper()["installed"] is False

    def test_it_is_never_run_off_macos(self, mod, helper, monkeypatch):
        helper(_reply())
        monkeypatch.setattr(mod.sys, "platform", "linux")
        assert mod.read_wifi_helper()["installed"] is False

    def test_the_default_path_follows_home(self, mod, monkeypatch, tmp_path):
        # Resolved at call time: an import-time path would point tests (and a
        # sudo run) at whichever home directory happened to be set back then.
        monkeypatch.delenv(mod.WIFI_HELPER_ENV, raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert mod.wifi_helper_path().startswith(str(tmp_path))

    @pytest.mark.parametrize("output", ["", "not json", "[]", '{"ssid": "x"}', "null"])
    def test_a_reply_it_cannot_understand_is_an_error_not_a_network(self, mod, helper, output):
        helper(output)
        r = mod.read_wifi_helper()
        assert r["ssid"] is None and r["error"]

    def test_cowlan_bssids_without_leading_zeros_are_normalised(self, mod, helper):
        helper(_reply(bssid="0:1a:2b:3c:4d:5e", same_ssid_bssids=["0:1A:2B:3C:4D:5E"]))
        r = mod.read_wifi_helper(scan=True)
        assert r["bssid"] == "00:1a:2b:3c:4d:5e"
        assert r["bssids"] == ["00:1a:2b:3c:4d:5e"]

    def test_the_associated_access_point_counts_even_if_the_scan_missed_it(self, mod, helper):
        helper(_reply(same_ssid_bssids=["38:8b:59:e0:f1:72"]))
        assert "3c:28:6d:5e:20:8a" in mod.read_wifi_helper(scan=True)["bssids"]

    @pytest.mark.parametrize("bad", [["zz:zz:zz:zz:zz:zz"], ["1:2:3"], [None, 7, {}], "3c:28:6d:5e:20:8a"])
    def test_malformed_bssids_are_dropped(self, mod, helper, bad):
        helper(_reply(bssid=None, same_ssid_bssids=bad))
        assert mod.read_wifi_helper(scan=True)["bssids"] == []

    @pytest.mark.parametrize("bad", ["", "x" * 33, "evil\x1b[31m", "two\nlines", 42, None, ["a"]])
    def test_an_ssid_that_could_not_be_a_real_one_is_refused(self, mod, helper, bad):
        helper(_reply(ssid=bad))
        assert mod.read_wifi_helper()["ssid"] is None

    def test_location_services_switched_off_is_reported_as_such(self, mod, helper):
        helper(_reply(location_services_on=False, ssid=None, bssid=None))
        assert mod.read_wifi_helper()["authorization"] == "location_services_off"


class TestTheNote:
    def test_without_the_helper_it_says_how_to_build_one(self, mod):
        note = mod.wifi_name_withheld_note({"installed": False})
        assert "tools/wifi_helper/build.sh" in note
        assert "Location Services" in note

    def test_it_no_longer_tells_anyone_to_grant_access_to_a_terminal(self, mod):
        # The advice that could not be followed.
        note = mod.wifi_name_withheld_note({"installed": False})
        assert "grant it to this terminal" not in note.lower()

    def test_it_still_rules_out_sudo(self, mod):
        assert "sudo" in mod.wifi_name_withheld_note({"installed": False})

    @pytest.mark.parametrize("auth", ["denied", "restricted", "not_determined"])
    def test_an_unapproved_helper_names_the_app_to_allow(self, mod, auth):
        note = mod.wifi_name_withheld_note({"installed": True, "authorization": auth})
        assert "Home Audit Wi-Fi" in note and auth in note and "--prompt" in note

    def test_an_approved_helper_with_no_network_does_not_blame_permissions(self, mod):
        note = mod.wifi_name_withheld_note({"installed": True, "authorization": "authorized"})
        assert "Wi-Fi?" in note and "Allow" not in note


class TestEvilTwinUsesIt:
    def test_a_redacted_report_falls_back_to_the_helper(self, mod, helper, fixture):
        helper(_reply(), sp_airport=fixture(REDACTED))
        r = mod.check_evil_twin()
        assert r["ssid"] == "loveshack"
        assert r["bssids"] == ["38:8b:59:e0:f1:72", "3c:28:6d:5e:20:8a"]
        assert r["risk"] == "OK"

    def test_an_unknown_bssid_from_the_helper_is_still_a_high_alarm(self, mod, helper, fixture):
        helper(_reply(), sp_airport=fixture(REDACTED))
        r = mod.check_evil_twin(known=["3c:28:6d:5e:20:8a"])
        assert r["risk"] == "HIGH" and r["unexpected"] == ["38:8b:59:e0:f1:72"]

    def test_the_helper_is_not_consulted_when_system_profiler_answered(self, mod, helper):
        sp = ("        Current Network Information:\n"
              "            HomeNet:\n"
              "              BSSID: 3c:22:fb:11:22:33\n"
              "              Security: WPA2 Personal\n")
        calls = helper(_reply(), sp_airport=sp)
        r = mod.check_evil_twin()
        assert r["ssid"] == "HomeNet"
        assert all(c[0] == "system_profiler" for c in calls)

    def test_no_helper_and_a_redacted_report_is_a_review_with_instructions(self, mod, monkeypatch, tmp_path, fixture):
        monkeypatch.setenv(mod.WIFI_HELPER_ENV, str(tmp_path / "absent"))
        monkeypatch.setattr(mod, "run", lambda cmd, timeout=10, merge_stderr=False:
                            fixture(REDACTED) if cmd[0] == "system_profiler" else "")
        r = mod.check_evil_twin()
        assert r["risk"] == "REVIEW" and "build.sh" in r["note"]


class TestWifiSecurityUsesIt:
    def test_the_name_comes_from_the_helper_when_redacted(self, mod, helper, fixture):
        calls = helper(_reply(), sp_airport=fixture(REDACTED))
        assert mod.check_wifi_security()["ssid"] == "loveshack"
        assert not any("--scan" in c for c in calls), "the name check does not need a scan"

    def test_not_being_on_wifi_at_all_does_not_run_the_helper(self, mod, helper):
        calls = helper(_reply(), sp_airport="")
        mod.check_wifi_security()
        assert all(c[0] == "system_profiler" for c in calls)


class TestRememberedBssids:
    def test_a_node_one_scan_missed_is_not_forgotten(self, mod):
        assert mod.remembered_bssids(["a", "b"], ["a"]) == ["a", "b"]

    def test_a_newly_heard_node_is_learned(self, mod):
        assert mod.remembered_bssids(["a"], ["a", "c"]) == ["a", "c"]

    def test_a_run_that_read_nothing_forgets_nothing(self, mod):
        assert mod.remembered_bssids(["a", "b"], []) == ["a", "b"]

    def test_none_and_junk_are_tolerated(self, mod):
        assert mod.remembered_bssids(None, None) == []
        assert mod.remembered_bssids(["a", 3, None], ["a"]) == ["a"]


class TestFirstReadableRun:
    def test_a_mesh_seen_for_the_first_time_is_not_a_set_of_evil_twins(self, mod):
        # Every Mac's baseline holds [] until the helper exists. The first run
        # that can see the owner's own access points must not alarm on them.
        assert mod.diff_baseline({"wifi_bssids": []},
                                 {"wifi_bssids": ["3c:28:6d:5e:20:8a", "38:8b:59:e0:f1:72"]}) == []

    def test_a_new_bssid_against_a_real_list_still_alarms(self, mod):
        notes = mod.diff_baseline({"wifi_bssids": ["a"]}, {"wifi_bssids": ["a", "b"]})
        assert any("NEW access point" in n for n in notes)


class TestSiblingRadios:
    """38:8b:59:e0:f1:72 and :76 are one Google Nest — a radio per band."""

    KNOWN = ["38:8b:59:e0:f1:72", "3c:28:6d:5e:20:8b"]

    def test_split(self, mod):
        sib, strangers = mod.split_unexpected_bssids(
            ["38:8b:59:e0:f1:76", "de:ad:be:ef:00:01"], self.KNOWN)
        assert sib == ["38:8b:59:e0:f1:76"] and strangers == ["de:ad:be:ef:00:01"]

    def test_a_second_radio_on_a_known_unit_is_review_not_high(self, mod, helper, fixture):
        helper(_reply(same_ssid_bssids=["38:8b:59:e0:f1:72", "38:8b:59:e0:f1:76"],
                      bssid="38:8b:59:e0:f1:72"), sp_airport=fixture(REDACTED))
        r = mod.check_evil_twin(known=self.KNOWN)
        assert r["risk"] == "REVIEW"
        assert r["unexpected"] == ["38:8b:59:e0:f1:76"]

    def test_a_stranger_is_still_high_even_beside_a_sibling(self, mod, helper, fixture):
        helper(_reply(same_ssid_bssids=["38:8b:59:e0:f1:76", "de:ad:be:ef:00:01"],
                      bssid="38:8b:59:e0:f1:72"), sp_airport=fixture(REDACTED))
        r = mod.check_evil_twin(known=self.KNOWN)
        assert r["risk"] == "HIGH" and "de:ad:be:ef:00:01" in r["note"]
        assert "38:8b:59:e0:f1:76" not in r["note"].split("which")[0]

    def test_the_same_vendor_is_not_enough_to_be_a_sibling(self, mod):
        sib, strangers = mod.split_unexpected_bssids(["38:8b:59:aa:bb:cc"], self.KNOWN)
        assert sib == [] and strangers == ["38:8b:59:aa:bb:cc"]

    def test_change_detection_words_a_sibling_differently(self, mod):
        notes = mod.diff_baseline({"wifi_bssids": self.KNOWN},
                                  {"wifi_bssids": self.KNOWN + ["38:8b:59:e0:f1:76"]})
        assert len(notes) == 1 and "Another radio" in notes[0]
        assert "evil twin" not in notes[0]

    def test_change_detection_still_alarms_on_a_stranger(self, mod):
        notes = mod.diff_baseline({"wifi_bssids": self.KNOWN},
                                  {"wifi_bssids": self.KNOWN + ["de:ad:be:ef:00:01"]})
        assert any("evil twin" in n for n in notes)
