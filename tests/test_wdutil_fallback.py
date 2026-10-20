"""wdutil SSID fallback — macOS Sequoia withholds the SSID from any process
without Location Services access, and a launchd background job has no way to
hold that grant. `sudo -n /usr/bin/wdutil info` is the one root path macOS
still allows; without a NOPASSWD rule for wdutil the sudo call fails instantly
and every check behaves exactly as it did before the fallback existed.
"""

import plistlib

import pytest

from conftest import load_fixture, make_run

SP_CMD = "system_profiler SPAirPortDataType"
WDUTIL_CMD = "sudo -n /usr/bin/wdutil info"
SCUTIL_CMD = "scutil"


def scutil_output(ssid="TestNet-5G", bssid="AA:BB:CC:DD:EE:01"):
    """Dynamic-store output whose CachedScanRecord is a real NSKeyedArchiver
    plist, as 15.7 emits: top-level SSID_STR scrubbed, the cache not.
    Synthetic values only — fixtures live in a public repo.
    """
    objs = ["$null",
            {"NS.keys": [plistlib.UID(2), plistlib.UID(3)],
             "NS.objects": [plistlib.UID(4), plistlib.UID(5)],
             "$class": plistlib.UID(6)},
            "SSID_STR", "BSSID", ssid, bssid,
            {"$classname": "NSMutableDictionary",
             "$classes": ["NSMutableDictionary", "NSDictionary", "NSObject"]}]
    blob = plistlib.dumps(
        {"$version": 100000, "$archiver": "NSKeyedArchiver",
         "$top": {"root": plistlib.UID(1)}, "$objects": objs},
        fmt=plistlib.FMT_BINARY)
    return ("<dictionary> {\n"
            "  BSSID : <data> 0x020000000000\n"
            "  CHANNEL : 149\n"
            "  CachedScanRecord : <data> 0x" + blob.hex() + "\n"
            "  SSID : <data> 0x00\n"
            "  SSID_STR : \n"
            "}")

WDUTIL_OK = """\
————————————————————
WIFI
————————————————————
    MAC Address          : aa:bb:cc:dd:ee:ff
    Interface Name       : en0
    Power                : On [On]
    Op Mode              : STA
    SSID                 : TestNet-5G
    BSSID                : AA:BB:CC:DD:EE:01
    RSSI                 : -52 dBm
    Security             : WPA2 Personal
"""

WDUTIL_REDACTED = """\
    Interface Name       : en0
    SSID                 : <redacted>
    BSSID                : <redacted>
    Security             : WPA2 Personal
"""


@pytest.fixture
def sp_redacted():
    return load_fixture("wifi_sp_airport_redacted.out")


class TestWdutilFallback:
    def test_reads_ssid_and_normalises_the_bssid(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({WDUTIL_CMD: WDUTIL_OK}))
        ssid, bssid = mod._wdutil_wifi_fallback()
        assert ssid == "TestNet-5G"
        assert bssid == "aa:bb:cc:dd:ee:01"

    def test_a_missing_sudoers_rule_yields_nothing(self, mod, monkeypatch):
        # sudo -n without a NOPASSWD rule fails; run() returns "" for that.
        monkeypatch.setattr(mod, "run", make_run({}))
        assert mod._wdutil_wifi_fallback() == (None, None)

    def test_wdutil_without_root_is_still_redacted(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({WDUTIL_CMD: WDUTIL_REDACTED}))
        assert mod._wdutil_wifi_fallback() == (None, None)


class TestScutilFallback:
    def test_reads_ssid_and_bssid_from_the_cached_record(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run({SCUTIL_CMD: scutil_output()}))
        assert mod._scutil_wifi_fallback() == ("TestNet-5G", "aa:bb:cc:dd:ee:01")

    def test_a_hostile_or_garbage_blob_yields_nothing(self, mod, monkeypatch):
        garbage = "<dictionary> {\n  CachedScanRecord : <data> 0xdeadbeef\n}"
        monkeypatch.setattr(mod, "run", make_run({SCUTIL_CMD: garbage}))
        assert mod._scutil_wifi_fallback() == (None, None)

    def test_a_scrubbed_store_with_no_record_yields_nothing(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", make_run(
            {SCUTIL_CMD: "<dictionary> {\n  SSID_STR : \n}"}))
        assert mod._scutil_wifi_fallback() == (None, None)

    def test_scutil_is_preferred_and_wdutil_is_the_backstop(self, mod, monkeypatch):
        both = make_run({
            SCUTIL_CMD: scutil_output(ssid="ScutilNet", bssid="AA:BB:CC:DD:EE:02"),
            WDUTIL_CMD: WDUTIL_OK})
        monkeypatch.setattr(mod, "run", both)
        assert mod._redacted_wifi_fallback() == ("ScutilNet", "aa:bb:cc:dd:ee:02")
        wdutil_only = make_run({WDUTIL_CMD: WDUTIL_OK})
        monkeypatch.setattr(mod, "run", wdutil_only)
        assert mod._redacted_wifi_fallback() == ("TestNet-5G", "aa:bb:cc:dd:ee:01")


class TestChecksUseTheFallback:
    def test_evil_twin_arms_from_scutil_when_profiler_redacts(
            self, mod, monkeypatch, sp_redacted):
        monkeypatch.setattr(mod, "run", make_run({
            SP_CMD: sp_redacted, SCUTIL_CMD: scutil_output()}))
        result = mod.check_evil_twin()
        assert result["ssid"] == "TestNet-5G"
        assert result["bssids"] == ["aa:bb:cc:dd:ee:01"]
        assert result["risk"] == "OK"

    def test_evil_twin_arms_from_wdutil_when_profiler_redacts(
            self, mod, monkeypatch, sp_redacted):
        monkeypatch.setattr(mod, "run", make_run({
            SP_CMD: sp_redacted, WDUTIL_CMD: WDUTIL_OK}))
        result = mod.check_evil_twin()
        assert result["ssid"] == "TestNet-5G"
        assert result["bssids"] == ["aa:bb:cc:dd:ee:01"]
        assert result["risk"] == "OK"

    def test_a_new_association_is_review_not_high_and_accumulates(
            self, mod, monkeypatch, sp_redacted):
        # wdutil sees only the associated AP, so a mesh roam and an evil twin
        # look identical — REVIEW once, then remembered, never a paging HIGH.
        monkeypatch.setattr(mod, "run", make_run({
            SP_CMD: sp_redacted, WDUTIL_CMD: WDUTIL_OK}))
        result = mod.check_evil_twin(known=["aa:aa:aa:aa:aa:aa"])
        assert result["risk"] == "REVIEW"
        assert result["unexpected"] == ["aa:bb:cc:dd:ee:01"]
        assert result["bssids"] == ["aa:aa:aa:aa:aa:aa", "aa:bb:cc:dd:ee:01"]

    def test_roaming_back_to_a_known_ap_is_quiet_and_keeps_the_union(
            self, mod, monkeypatch, sp_redacted):
        monkeypatch.setattr(mod, "run", make_run({
            SP_CMD: sp_redacted, WDUTIL_CMD: WDUTIL_OK}))
        known = ["aa:bb:cc:dd:ee:01", "aa:aa:aa:aa:aa:aa"]
        result = mod.check_evil_twin(known=known)
        assert result["risk"] == "OK"
        # The union survives the save, so the sibling AP is not forgotten.
        assert result["bssids"] == known

    def test_first_visibility_is_not_called_an_evil_twin_in_the_diff(self, mod):
        # Empty old wifi_bssids means earlier runs could not see, not that no
        # AP existed — the diff must not assert certainty the same report's
        # Evil Twin section explicitly withholds.
        notes = mod.diff_baseline(
            {"wifi_bssids": []},
            {"wifi_bssids": ["aa:bb:cc:dd:ee:01"],
             "evil_twin": {"source": "association_record"}})
        # Upstream's rule since the Wi-Fi helper: an empty old list is never
        # compared against at all, so the first readable run adds no note.
        assert notes == []

    def test_a_fallback_roam_defers_to_the_evil_twin_section_in_the_diff(self, mod):
        notes = mod.diff_baseline(
            {"wifi_bssids": ["aa:bb:cc:dd:ee:01"]},
            {"wifi_bssids": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
             "evil_twin": {"source": "association_record"}})
        joined = " ".join(notes).lower()
        assert "is an evil twin" not in joined
        assert "association record" in joined

    def test_a_scan_sourced_new_bssid_still_alarms_in_the_diff(self, mod):
        notes = mod.diff_baseline(
            {"wifi_bssids": ["aa:bb:cc:dd:ee:01"]},
            {"wifi_bssids": ["aa:bb:cc:dd:ee:01", "66:77:88:99:aa:bb"]})
        assert any("evil twin" in n.lower() for n in notes)

    def test_an_unassociated_mac_never_attempts_any_fallback(self, mod, monkeypatch):
        runner = make_run({SP_CMD: load_fixture("wifi_sp_airport_not_associated.out")})
        monkeypatch.setattr(mod, "run", runner)
        mod.check_evil_twin()
        mod.check_wifi_security()
        assert not any("sudo" in c or "scutil" in c for c in runner.calls)

    def test_wifi_security_names_the_network_via_wdutil(
            self, mod, monkeypatch, sp_redacted):
        monkeypatch.setattr(mod, "run", make_run({
            SP_CMD: sp_redacted, WDUTIL_CMD: WDUTIL_OK}))
        result = mod.check_wifi_security()
        assert result["ssid"] == "TestNet-5G"
        # Security still comes from the profiler block, which is never gated.
        assert result["risk"] == "OK"

    def test_without_the_rule_redaction_reports_exactly_as_before(
            self, mod, monkeypatch, sp_redacted):
        monkeypatch.setattr(mod, "run", make_run({SP_CMD: sp_redacted}))
        result = mod.check_evil_twin()
        assert result["ssid"] is None
        assert result["risk"] == "REVIEW"
        assert "Location Services" in result["note"]
