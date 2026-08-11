"""Interception detection — roadmap P2's first cluster.

Three checks that answer one question: is someone in the path?

  * the router's TLS certificate fingerprint, which was already being fetched
    and thrown away — only its byte length was kept, which detects nothing
  * admin-added trust settings, since installing a root CA is how TLS
    interception is actually set up on an endpoint
  * an active probe for transparent DNS redirection, which reading the
    resolver configuration cannot reveal by construction

The DNS probe is the one worth understanding. It queries 192.0.2.1 — TEST-NET-1
from RFC 5737, reserved for documentation and routed nowhere. A query sent there
must time out. Anything that answers is transparently handling port 53, which
means the resolvers `scutil --dns` reports are not the ones actually in use.
"""

import hashlib
import socket
import struct

import pytest

from conftest import make_run

SECURITY_CMD = "security dump-trust-settings -d"
CLEAN = "No Trust Settings were found.\n"
DIRTY = (
    "Number of trusted certs = 1\n"
    "Cert 0: Corporate Proxy Root CA\n"
    "   Number of trust settings : 1\n"
    "   Trust Setting 0:\n"
    "      Result = kSecTrustSettingsResultTrustRoot\n"
)


class TestCertificateFingerprint:
    def _fake_tls(self, mod, monkeypatch, der):
        class FakeTLS:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def getpeercert(self, binary_form=False): return der

        class FakeCtx:
            check_hostname = True
            verify_mode = None
            def wrap_socket(self, sock, server_hostname=None): return FakeTLS()

        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(mod.ssl, "create_default_context", lambda: FakeCtx())
        monkeypatch.setattr(socket, "create_connection",
                            lambda addr, timeout=None: FakeSock())

    def test_the_certificate_is_hashed_not_just_counted(self, mod, monkeypatch):
        """The whole point: the DER bytes were fetched and discarded before."""
        der = b"a fake certificate"
        self._fake_tls(mod, monkeypatch, der)
        result = mod.check_tls("192.168.1.1")
        assert result["sha256"] == hashlib.sha256(der).hexdigest()
        assert result["present"] is True

    def test_a_different_certificate_gives_a_different_fingerprint(self, mod, monkeypatch):
        self._fake_tls(mod, monkeypatch, b"cert one")
        first = mod.check_tls("192.168.1.1")["sha256"]
        self._fake_tls(mod, monkeypatch, b"cert two")
        assert mod.check_tls("192.168.1.1")["sha256"] != first

    def test_the_same_certificate_is_stable_across_calls(self, mod, monkeypatch):
        # Otherwise every run would report a changed certificate.
        self._fake_tls(mod, monkeypatch, b"cert one")
        assert mod.check_tls("192.168.1.1")["sha256"] == \
            mod.check_tls("192.168.1.1")["sha256"]

    def test_a_peer_with_no_certificate_yields_no_fingerprint(self, mod, monkeypatch):
        self._fake_tls(mod, monkeypatch, None)
        result = mod.check_tls("192.168.1.1")
        assert result["present"] is True and result["sha256"] is None

    def test_an_unreachable_host_is_reported_not_raised(self, mod, monkeypatch):
        def boom(addr, timeout=None):
            raise OSError("connection refused")
        monkeypatch.setattr(socket, "create_connection", boom)
        result = mod.check_tls("192.168.1.1")
        assert result["present"] is False and result["sha256"] is None


class TestCertificateChangeIsDiffed:
    def test_a_changed_router_certificate_is_reported(self, mod):
        notes = mod.diff_baseline({"router_tls": {"sha256": "a" * 64}},
                                  {"router_tls": {"sha256": "b" * 64}})
        assert len(notes) == 1
        assert "certificate CHANGED" in notes[0]

    def test_an_unchanged_certificate_is_silent(self, mod):
        assert mod.diff_baseline({"router_tls": {"sha256": "a" * 64}},
                                 {"router_tls": {"sha256": "a" * 64}}) == []

    def test_a_first_sighting_is_not_a_change(self, mod):
        # Nothing to compare against; alarming here would fire on every new
        # baseline and teach the reader to ignore the message.
        assert mod.diff_baseline({}, {"router_tls": {"sha256": "a" * 64}}) == []

    def test_a_certificate_becoming_unreachable_is_not_a_change(self, mod):
        # The router rebooting mid-scan must not read as interception.
        assert mod.diff_baseline({"router_tls": {"sha256": "a" * 64}},
                                 {"router_tls": {"present": False, "sha256": None}}) == []

    def test_absent_keys_do_not_raise(self, mod):
        assert mod.diff_baseline({}, {}) == []


class TestTrustStore:
    def test_a_clean_mac_reports_ok(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", make_run({SECURITY_CMD: CLEAN}))
        result = mod.check_trust_store()
        assert result["risk"] == "OK"
        assert result["entries"] == []

    def test_an_admin_added_root_is_high(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", make_run({SECURITY_CMD: DIRTY}))
        result = mod.check_trust_store()
        assert result["risk"] == "HIGH"
        assert any("Corporate Proxy Root CA" in e for e in result["entries"])
        assert "read TLS traffic" in result["note"]

    def test_unreadable_output_is_review_not_ok(self, mod, monkeypatch):
        # Failing to look is not the same as looking and finding nothing.
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", make_run({}))
        result = mod.check_trust_store()
        assert result["risk"] == "REVIEW"
        assert result["risk"] != "OK"

    def test_it_is_skipped_off_macos_rather_than_guessed(self, mod, monkeypatch):
        # Host-posture, same rule as the firewall and sharing checks: on an
        # observer this would describe the wrong machine.
        monkeypatch.setattr(mod.sys, "platform", "linux")
        result = mod.check_trust_store()
        assert result["supported"] is False
        assert result["risk"] == "INFO"

    def test_no_command_runs_off_macos(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "linux")
        fake = make_run({})
        monkeypatch.setattr(mod, "run", fake)
        mod.check_trust_store()
        assert fake.calls == []


class TestDnsQueryConstruction:
    def test_the_query_is_well_formed(self, mod):
        packet = mod.build_dns_query("example.com", qid=0x1234)
        qid, flags, qdcount = struct.unpack("!HHH", packet[:6])
        assert qid == 0x1234
        assert flags == 0x0100          # standard query, recursion desired
        assert qdcount == 1

    def test_the_name_is_length_prefixed_and_terminated(self, mod):
        packet = mod.build_dns_query("example.com")
        assert b"\x07example\x03com\x00" in packet

    def test_it_asks_for_an_a_record_in_the_internet_class(self, mod):
        qtype, qclass = struct.unpack("!HH", mod.build_dns_query("example.com")[-4:])
        assert (qtype, qclass) == (1, 1)


class TestDnsInterceptionProbe:
    def _fake_socket(self, monkeypatch, reply=None, error=None):
        class FakeSocket:
            def __init__(self, *a, **k): self.closed = False
            def settimeout(self, t): pass
            def sendto(self, data, addr): self.sent = (data, addr)
            def recvfrom(self, n):
                if error:
                    raise error
                return reply
            def close(self): self.closed = True

        created = []

        def factory(*a, **k):
            s = FakeSocket(*a, **k)
            created.append(s)
            return s

        monkeypatch.setattr(socket, "socket", factory)
        return created

    def test_silence_from_test_net_is_the_correct_result(self, mod, monkeypatch):
        self._fake_socket(monkeypatch, error=socket.timeout())
        result = mod.probe_dns_interception()
        assert result["intercepted"] is False
        assert result["risk"] == "OK"

    def test_any_answer_means_interception(self, mod, monkeypatch):
        """192.0.2.1 routes nowhere, so a reply can only come from the path."""
        self._fake_socket(monkeypatch, reply=(b"\x4a\x4a\x81\x80", ("192.168.1.1", 53)))
        result = mod.probe_dns_interception()
        assert result["intercepted"] is True
        assert result["risk"] == "HIGH"
        assert result["responder"] == "192.168.1.1"

    def test_the_responder_is_named_in_the_note(self, mod, monkeypatch):
        self._fake_socket(monkeypatch, reply=(b"x", ("10.0.0.1", 53)))
        assert "10.0.0.1" in mod.probe_dns_interception()["note"]

    def test_a_network_error_is_not_interception(self, mod, monkeypatch):
        # No route to the test net is the normal, healthy outcome.
        self._fake_socket(monkeypatch, error=OSError("network unreachable"))
        assert mod.probe_dns_interception()["intercepted"] is False

    def test_the_socket_is_closed_on_both_paths(self, mod, monkeypatch):
        created = self._fake_socket(monkeypatch, error=socket.timeout())
        mod.probe_dns_interception()
        assert created[0].closed is True

        created = self._fake_socket(monkeypatch, reply=(b"x", ("10.0.0.1", 53)))
        mod.probe_dns_interception()
        assert created[0].closed is True

    def test_the_probe_targets_the_reserved_documentation_range(self, mod, monkeypatch):
        created = self._fake_socket(monkeypatch, error=socket.timeout())
        mod.probe_dns_interception()
        _, addr = created[0].sent
        assert addr == ("192.0.2.1", 53), "must be TEST-NET-1, which routes nowhere"

    def test_an_alternative_target_can_be_supplied(self, mod, monkeypatch):
        created = self._fake_socket(monkeypatch, error=socket.timeout())
        mod.probe_dns_interception(target="198.51.100.1")
        assert created[0].sent[1] == ("198.51.100.1", 53)


class TestReporting:
    def test_the_action_reports_both_checks(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", make_run({SECURITY_CMD: CLEAN}))
        monkeypatch.setattr(mod, "probe_dns_interception",
                            lambda: {"intercepted": False, "responder": None,
                                     "risk": "OK", "note": "clean"})
        result = mod.action_interception_checks()
        out = capsys.readouterr().out
        assert "Trust store" in out and "DNS path" in out
        assert set(result) == {"trust_store", "dns_interception"}

    def test_a_dirty_trust_store_prints_its_entries(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", make_run({SECURITY_CMD: DIRTY}))
        monkeypatch.setattr(mod, "probe_dns_interception",
                            lambda: {"intercepted": False, "responder": None,
                                     "risk": "OK", "note": "clean"})
        mod.action_interception_checks()
        assert "Corporate Proxy Root CA" in capsys.readouterr().out
