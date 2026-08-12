"""Reverse-DNS classification of the gateway (`check_router_hostname`).

The network act — one `socket.gethostbyaddr` call — is trivial; the value is in
what the function *concludes* from the name it gets back. That conclusion is a
regex sweep against a list of cloud-provider domains feeding a `suspicious`
tri-state and a human note, and it is exactly the "a substring/regex test
misfired" bug class the rest of this suite is built around. The sandbox forbids
the real lookup, so each test supplies the hostname and pins the verdict.
"""

import socket


def _patch_ptr(monkeypatch, result):
    """Make gethostbyaddr return a name, or raise the error the code catches.

    Pass a string for the resolved hostname, or an exception instance to drive
    the failure branch (the real call raises socket.herror on NXDOMAIN).
    """
    def fake(ip):
        if isinstance(result, BaseException):
            raise result
        return (result, [], [ip])
    monkeypatch.setattr(socket, "gethostbyaddr", fake)


class TestNoReverseDns:
    def test_absent_ptr_is_not_suspicious(self, mod, monkeypatch):
        _patch_ptr(monkeypatch, socket.herror("NXDOMAIN"))
        r = mod.check_router_hostname("192.168.1.1")
        assert r["hostname"] is None
        assert r["suspicious"] is False

    def test_absent_ptr_is_called_normal_not_left_blank(self, mod, monkeypatch):
        # A home router with no PTR record is the common case; the note must say
        # so rather than read as an empty / failed check.
        _patch_ptr(monkeypatch, socket.herror("NXDOMAIN"))
        r = mod.check_router_hostname("192.168.1.1")
        assert "normal" in r["note"].lower()

    def test_a_generic_lookup_failure_also_degrades_to_none(self, mod, monkeypatch):
        # gethostbyaddr can raise more than socket.herror (timeouts surface as
        # socket.gaierror / OSError); the broad except must swallow them too.
        _patch_ptr(monkeypatch, OSError("resolver down"))
        r = mod.check_router_hostname("192.168.1.1")
        assert r["hostname"] is None
        assert r["suspicious"] is False


class TestNormalHostname:
    def test_an_ordinary_router_name_is_not_flagged(self, mod, monkeypatch):
        _patch_ptr(monkeypatch, "router.asus.com")
        r = mod.check_router_hostname("192.168.1.1")
        assert r["hostname"] == "router.asus.com"
        assert r["suspicious"] is False
        assert "normal" in r["note"].lower()

    def test_a_local_mdns_name_is_not_flagged(self, mod, monkeypatch):
        _patch_ptr(monkeypatch, "gateway.local")
        r = mod.check_router_hostname("192.168.1.1")
        assert r["suspicious"] is False


class TestCloudProviderHostname:
    # A gateway whose PTR points at a public cloud host is the signal worth
    # raising: it suggests traffic is being funnelled somewhere it shouldn't be.
    def test_aws_hostname_is_flagged(self, mod, monkeypatch):
        _patch_ptr(monkeypatch, "ec2-13-52-1-2.us-west-1.compute.amazonaws.com")
        r = mod.check_router_hostname("192.168.1.1")
        assert r["suspicious"] is True
        assert "amazonaws" in r["note"].lower()

    def test_digitalocean_hostname_is_flagged(self, mod, monkeypatch):
        _patch_ptr(monkeypatch, "somebox.digitalocean.com")
        r = mod.check_router_hostname("10.0.0.1")
        assert r["suspicious"] is True

    def test_the_match_is_case_insensitive(self, mod, monkeypatch):
        # DNS names are case-insensitive and real resolvers preserve whatever
        # case the zone used; the classifier must not miss an uppercased one.
        _patch_ptr(monkeypatch, "host.AMAZONAWS.COM")
        r = mod.check_router_hostname("192.168.1.1")
        assert r["suspicious"] is True

    def test_a_domain_that_merely_contains_a_provider_word_is_still_matched(
            self, mod, monkeypatch):
        # The patterns are substrings by design; document that so a future
        # tightening to anchored matches is a deliberate choice, not a slip.
        _patch_ptr(monkeypatch, "myrouter.linode.com")
        assert mod.check_router_hostname("192.168.1.1")["suspicious"] is True
