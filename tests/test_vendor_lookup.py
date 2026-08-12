"""MAC-to-vendor resolution (`lookup_vendor`).

Three branches decide the answer before, or instead of, the network:

  1. A locally-administered ("randomized/private") MAC is reported as such
     without any lookup — modern phones rotate these and the OUI is meaningless.
  2. Otherwise the macvendors.com API is consulted.
  3. If that call fails or returns nothing, a small built-in OUI table is the
     fallback.

The fallback path is the one that matters offline and the one a refactor is most
likely to break, so it gets the most attention here. The sandbox forbids the
real HTTP call; each test supplies the API's answer (or an error) directly.
"""

import urllib.error
import urllib.request


class _Resp:
    def __init__(self, body):
        self._body = body.encode() if isinstance(body, str) else body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, *n): return self._body


def _api(monkeypatch, answer):
    """Stub urlopen: return `answer` as the body, or raise if it's an exception."""
    def fake(req, timeout=None):
        if isinstance(answer, BaseException):
            raise answer
        return _Resp(answer)
    monkeypatch.setattr(urllib.request, "urlopen", fake)


class TestRandomizedMac:
    def test_a_private_mac_is_labelled_without_any_lookup(self, mod, monkeypatch):
        # 0x02 set in the first octet => locally administered. If the code
        # reached the network here the sandbox would raise; it must not.
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("must not hit the network")))
        assert mod.lookup_vendor("a2:11:22:33:44:55") == "(randomized/private MAC)"

    def test_unknown_sentinel_returns_empty(self, mod):
        assert mod.lookup_vendor("unknown") == ""


class TestApiSuccess:
    def test_a_vendor_name_from_the_api_is_returned_verbatim(self, mod, monkeypatch):
        _api(monkeypatch, "Ubiquiti Inc")
        assert mod.lookup_vendor("b4:fb:e4:00:11:22") == "Ubiquiti Inc"

    def test_surrounding_whitespace_from_the_api_is_stripped(self, mod, monkeypatch):
        _api(monkeypatch, "  Netgear\n")
        assert mod.lookup_vendor("b4:fb:e4:00:11:22") == "Netgear"


class TestFallbackToOuiTable:
    def test_api_failure_falls_back_to_the_builtin_oui_hint(self, mod, monkeypatch):
        # macvendors.com is rate-limited and often unreachable; the built-in
        # table is what keeps the report useful offline. b8:27:eb is a Pi.
        _api(monkeypatch, urllib.error.URLError("no route to host"))
        assert mod.lookup_vendor("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"

    def test_an_empty_api_body_falls_back_to_the_oui_hint(self, mod, monkeypatch):
        # The API answers 200 with an empty body for OUIs it doesn't know; that
        # empty string must not shadow a hint we do have.
        _api(monkeypatch, "")
        assert mod.lookup_vendor("3c:28:6d:aa:bb:cc") == "Google"

    def test_unknown_prefix_with_no_hint_and_no_api_returns_empty(self, mod, monkeypatch):
        _api(monkeypatch, urllib.error.URLError("offline"))
        assert mod.lookup_vendor("00:00:5e:00:53:01") == ""

    def test_the_prefix_lookup_uses_the_first_three_octets(self, mod, monkeypatch):
        # OUI is the vendor-assigned first 24 bits; the rest is device-specific
        # and must not affect the table hit.
        _api(monkeypatch, urllib.error.URLError("offline"))
        assert mod.lookup_vendor("dc:a6:32:ff:ee:dd") == "Raspberry Pi (Trading) Ltd"
