"""A device-chosen LOCATION URL with an impossible port must not end the audit.

urllib.parse.urlsplit(...).port is evaluated lazily and raises ValueError for a
port that is not a number or is above 65535. _upnp_url_points_at used to guard
only the urlsplit call and read .scheme/.hostname, which never raise, so a reply
such as "LOCATION: http://192.168.86.5:99999/desc.xml" passed the check and the
caller's `parts.port` raised outside any handler — in a full audit, after the
sweep and before save_baseline, the HTML report and the email. Found by
adversarial review of the 2026-10-20 merge.
"""

import pytest


class TestUrlPointsAt:
    def test_a_normal_location_still_passes(self, mod):
        assert mod._upnp_url_points_at("http://192.168.86.5:1900/desc.xml", "192.168.86.5")
        assert mod._upnp_url_points_at("http://192.168.86.5/desc.xml", "192.168.86.5")

    @pytest.mark.parametrize("url", [
        "http://192.168.86.5:99999/desc.xml",   # above 65535
        "http://192.168.86.5:abc/desc.xml",     # not a number
        "http://192.168.86.5:-1/desc.xml",
    ])
    def test_an_impossible_port_fails_the_check_instead_of_raising(self, mod, url):
        assert mod._upnp_url_points_at(url, "192.168.86.5") is False

    def test_another_host_still_fails(self, mod):
        assert mod._upnp_url_points_at("http://192.168.86.6/desc.xml", "192.168.86.5") is False


class TestNameSourcesCannotAbortTheAudit:
    def test_a_parsing_error_in_one_source_is_contained(self, mod, monkeypatch):
        def boom(ips):
            raise ValueError("Port out of range 0-65535")
        monkeypatch.setattr(mod, "mdns_device_names", boom)
        monkeypatch.setattr(mod, "upnp_device_names", boom)
        monkeypatch.setattr(mod, "gateway_device_names",
                            lambda ips, gw: ({"192.168.86.5": "plug.lan"}, False))
        devices = [{"ip": "192.168.86.5", "mac": "3c:22:fb:00:00:05"}]
        note = mod.collect_device_names(devices, "192.168.86.1")
        assert note == ""
        assert devices[0]["names"] == {"dns": "plug.lan"}
