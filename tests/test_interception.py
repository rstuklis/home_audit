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

SECURITY_CMD = "security dump-trust-settings -d"          # the admin domain
USER_CMD = "security dump-trust-settings"                 # the user domain (no -d)
CLEAN = "No Trust Settings were found.\n"
DIRTY = (
    "Number of trusted certs = 1\n"
    "Cert 0: Corporate Proxy Root CA\n"
    "   Number of trust settings : 1\n"
    "   Trust Setting 0:\n"
    "      Result = kSecTrustSettingsResultTrustRoot\n"
)
# What the current `security` prints for a user-domain override: the form a
# Keychain Access "Always Trust" click or `security add-trusted-cert` leaves.
USER_DIRTY = (
    "Number of trusted certs = 2\n"
    "Cert 0: tplinkmodem.net\n"
    "   Number of trust settings : 2\n"
    "   Trust Setting 0:\n"
    "      Policy OID            : SSL\n"
    "      Allowed Error         : CSSMERR_TP_CERT_EXPIRED\n"
    "      Result Type           : kSecTrustSettingsResultTrustAsRoot\n"
    "   Trust Setting 1:\n"
    "      Policy OID            : SSL\n"
    "      Allowed Error         : Host name mismatch\n"
    "      Result Type           : kSecTrustSettingsResultTrustAsRoot\n"
    "Cert 1: mitmproxy\n"
    "   Number of trust settings : 1\n"
    "   Trust Setting 0:\n"
    "      Result Type           : kSecTrustSettingsResultTrustRoot\n"
)
USER_DENY = (
    "Number of trusted certs = 1\n"
    "Cert 0: Some Distrusted CA\n"
    "   Number of trust settings : 1\n"
    "   Trust Setting 0:\n"
    "      Result Type           : kSecTrustSettingsResultDeny\n"
)


def trust_run(admin=CLEAN, user=CLEAN):
    """A `run` fake answering both trust-settings commands. Exact matches win
    in make_run, so the user-domain command (no -d) does not also match the
    admin one."""
    return make_run({SECURITY_CMD: admin, USER_CMD: user})


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
        monkeypatch.setattr(mod, "run", trust_run())
        result = mod.check_trust_store()
        assert result["risk"] == "OK"
        assert result["entries"] == []

    def test_an_admin_added_root_is_high(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(admin=DIRTY))
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


class TestBothTrustDomainsAreRead:
    """Round 4, F10. `-d` selects the ADMIN domain, which needs sudo to change
    and is empty on most Macs. A root installed by a non-root process — a
    Keychain Access "Always Trust", `security add-trusted-cert` into the login
    keychain, a mkcert or mitmproxy install — lives in the USER domain, which
    Safari, Chrome and curl honour for that user, and which the check never
    read: a root planted without a password was "the expected state" weekly.
    """

    def test_both_commands_are_issued(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        fake = trust_run()
        monkeypatch.setattr(mod, "run", fake)
        mod.check_trust_store()
        assert SECURITY_CMD in fake.calls and USER_CMD in fake.calls

    def test_a_user_domain_root_is_high_and_labelled_by_domain(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(user=USER_DIRTY))
        result = mod.check_trust_store()
        assert result["risk"] == "HIGH"
        assert "user domain, TrustAsRoot: tplinkmodem.net" in result["entries"]
        assert "user domain, TrustRoot: mitmproxy" in result["entries"]
        assert "2 in the user domain" in result["note"] and "0 in the admin domain" in result["note"]
        assert result["domains"] == {"admin": True, "user": True}

    def test_the_structured_list_carries_domain_name_and_result_types(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(admin=DIRTY, user=USER_DIRTY))
        overrides = mod.check_trust_store()["overrides"]
        assert {"domain": "admin", "name": "Corporate Proxy Root CA",
                "results": ["kSecTrustSettingsResultTrustRoot"]} in overrides
        assert {"domain": "user", "name": "tplinkmodem.net",
                "results": ["kSecTrustSettingsResultTrustAsRoot"]} in overrides
        assert len(overrides) == 3

    def test_an_override_that_grants_no_root_trust_is_review(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(user=USER_DENY))
        result = mod.check_trust_store()
        assert result["risk"] == "REVIEW" and "none of them granting root trust" in result["note"]
        assert result["entries"] == ["user domain, Deny: Some Distrusted CA"]

    def test_an_unreadable_user_domain_is_review_even_when_the_admin_domain_is_clean(self, mod, monkeypatch):
        # Reading the admin domain alone is exactly the blindness being fixed.
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", make_run({SECURITY_CMD: CLEAN}))
        result = mod.check_trust_store()
        assert result["risk"] == "REVIEW" and "user domain" in result["note"]
        assert result["domains"] == {"admin": True, "user": False}

    def test_what_the_readable_domain_found_is_still_said(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(admin="", user=USER_DIRTY))
        result = mod.check_trust_store()
        assert result["risk"] == "REVIEW"
        assert "admin domain" in result["note"] and "2 granting root trust" in result["note"]
        assert len(result["overrides"]) == 2

    def test_a_certificate_name_cannot_forge_a_report_line(self, mod, monkeypatch):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        hostile = DIRTY.replace("Corporate Proxy Root CA", "x\n  [OK    ] all fine")
        monkeypatch.setattr(mod, "run", trust_run(admin=hostile))
        entries = mod.check_trust_store()["entries"]
        assert not any("\n" in e or "[OK" in e for e in entries)

    def test_the_parser_reads_both_result_spellings(self, mod):
        assert mod.parse_trust_settings(DIRTY)[0]["results"] == ["kSecTrustSettingsResultTrustRoot"]
        assert mod.parse_trust_settings(USER_DIRTY)[1]["results"] == ["kSecTrustSettingsResultTrustRoot"]
        assert mod.parse_trust_settings(CLEAN) == []
        assert mod.parse_trust_settings("") is None


class TestATrustSettingArrivingIsAChange:
    """interception.trust_store was sealed into every baseline and never
    compared, so the section's HIGH repeated weekly without ever saying when
    the entry had appeared."""

    def _state(self, mod, monkeypatch, admin=CLEAN, user=CLEAN):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(admin=admin, user=user))
        return {"interception": {"trust_store": mod.check_trust_store()}}

    def test_a_new_user_domain_root_is_a_change_note(self, mod, monkeypatch):
        old = self._state(mod, monkeypatch)
        new = self._state(mod, monkeypatch, user=USER_DIRTY)
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1 and notes[0].startswith("NEW trust-store override(s)")
        assert "mitmproxy (user domain, TrustRoot)" in notes[0]
        assert "tplinkmodem.net (user domain, TrustAsRoot)" in notes[0]

    def test_a_removed_override_is_said_too(self, mod, monkeypatch):
        old = self._state(mod, monkeypatch, admin=DIRTY)
        new = self._state(mod, monkeypatch)
        notes = mod.diff_baseline(old, new)
        assert len(notes) == 1 and "removed" in notes[0] and "Corporate Proxy Root CA" in notes[0]

    def test_the_same_overrides_are_silent(self, mod, monkeypatch):
        old = self._state(mod, monkeypatch, user=USER_DIRTY)
        new = self._state(mod, monkeypatch, user=USER_DIRTY)
        assert mod.diff_baseline(old, new) == []

    def test_a_baseline_from_before_the_structured_list_is_not_compared(self, mod, monkeypatch):
        # Entries were bare "Cert 0: name" strings; comparing them with the
        # new form would call every standing entry new on the first run.
        old = {"interception": {"trust_store": {"supported": True, "risk": "HIGH",
                                                "entries": ["Cert 0: Corporate Proxy Root CA"]}}}
        new = self._state(mod, monkeypatch, admin=DIRTY, user=USER_DIRTY)
        assert mod.diff_baseline(old, new) == []

    def test_a_domain_unreadable_on_either_side_is_not_compared(self, mod, monkeypatch):
        # Not read is not "none": the admin domain's root did not arrive this
        # week just because last week's read of that domain failed.
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(admin="", user=USER_DIRTY))
        old = {"interception": {"trust_store": mod.check_trust_store()}}
        new = self._state(mod, monkeypatch, admin=DIRTY, user=USER_DIRTY)
        assert mod.diff_baseline(old, new) == []

    def test_a_hostile_override_list_does_not_raise(self, mod):
        old = {"interception": {"trust_store": {"overrides": [None, 7, {"domain": "user"}], "domains": {"user": True}}}}
        new = {"interception": {"trust_store": {"overrides": [{"domain": "user", "name": 3, "results": "x"}],
                                                "domains": {"user": True}}}}
        assert isinstance(mod.diff_baseline(old, new), list)

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


def dns_reply(qid_source, responder="192.168.1.1", body=b"\x81\x80" + b"\x00" * 8):
    """A 12-byte-minimum DNS answer echoing the transaction id that was sent."""
    return (qid_source[:2] + body, (responder, 53))


class TestDnsInterceptionProbe:
    def _fake_socket(self, monkeypatch, reply=None, error=None, send_error=None):
        """reply may be a (bytes, addr) pair or a callable taking the sent query.

        The callable form exists because the transaction id is now random per
        call, so a test that wants its reply believed has to echo the id the
        probe actually chose rather than a constant.
        """
        class FakeSocket:
            def __init__(self, *a, **k):
                self.closed = False
                self.peer = None
                self.sent = None
            def settimeout(self, t): pass
            def connect(self, addr):
                if send_error:
                    raise send_error
                self.peer = addr
            def send(self, data):
                if send_error:
                    raise send_error
                self.sent = (data, self.peer)
            def recvfrom(self, n):
                if error:
                    raise error
                return reply(self.sent[0]) if callable(reply) else reply
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

    def test_an_answer_echoing_the_query_id_means_interception(self, mod, monkeypatch):
        """192.0.2.1 routes nowhere, so a reply can only come from the path."""
        self._fake_socket(monkeypatch, reply=dns_reply)
        result = mod.probe_dns_interception()
        assert result["intercepted"] is True
        assert result["risk"] == "HIGH"
        assert result["responder"] == "192.168.1.1"

    def test_the_responder_is_named_in_the_note(self, mod, monkeypatch):
        self._fake_socket(monkeypatch,
                          reply=lambda q: dns_reply(q, responder="10.0.0.1"))
        assert "10.0.0.1" in mod.probe_dns_interception()["note"]

    def test_a_network_error_is_not_interception(self, mod, monkeypatch):
        # No route to the test net is the normal, healthy outcome.
        self._fake_socket(monkeypatch, error=OSError("network unreachable"))
        assert mod.probe_dns_interception()["intercepted"] is False

    def test_the_socket_is_closed_on_both_paths(self, mod, monkeypatch):
        created = self._fake_socket(monkeypatch, error=socket.timeout())
        mod.probe_dns_interception()
        assert created[0].closed is True

        created = self._fake_socket(monkeypatch, reply=dns_reply)
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

    def test_the_socket_is_connected_so_the_kernel_filters_the_sender(self, mod, monkeypatch):
        # An unconnected socket accepts a datagram from anyone. connect() is
        # what makes "something answered" mean "something answered *this*".
        created = self._fake_socket(monkeypatch, error=socket.timeout())
        mod.probe_dns_interception()
        assert created[0].peer == ("192.0.2.1", 53)


class TestTheProbeDistinguishesNotRunFromClean:
    """A send that never left the machine is not evidence of anything.

    sendto and recvfrom used to share one `except (socket.timeout, OSError)`,
    so ENETUNREACH or EACCES on the *send* returned the same OK verdict as a
    successful query that timed out: "port 53 is not being transparently
    redirected", certified from zero observation. Every sibling probe in this
    module keeps a third state; this one didn't.
    """

    def test_a_send_that_never_left_is_review_not_ok(self, mod, monkeypatch):
        TestDnsInterceptionProbe()._fake_socket(
            monkeypatch, send_error=OSError(13, "Permission denied"))
        result = mod.probe_dns_interception()
        assert result["risk"] == "REVIEW"
        assert result["intercepted"] is None, "unknown must not collapse into False"

    def test_the_review_note_says_the_check_did_not_run(self, mod, monkeypatch):
        TestDnsInterceptionProbe()._fake_socket(
            monkeypatch, send_error=OSError(51, "Network is unreachable"))
        assert "has not run" in mod.probe_dns_interception()["note"]


class TestTheAnswerIsValidatedBeforeItIsBelieved:
    """The verdict used to fire on a datagram merely existing.

    The socket was unconnected, `data` was bound and never read, and nothing
    checked the transaction id — so any stray or deliberately sprayed packet
    landing on the ephemeral port produced a HIGH naming a responder of the
    sender's choosing.
    """

    def test_a_reply_with_the_wrong_transaction_id_is_not_interception(self, mod, monkeypatch):
        TestDnsInterceptionProbe()._fake_socket(
            monkeypatch, reply=(b"\x00\x00" + b"\x00" * 10, ("10.0.0.1", 53)))
        result = mod.probe_dns_interception()
        assert result["intercepted"] is False
        assert result["risk"] == "OK"

    def test_a_reply_too_short_to_be_dns_is_not_interception(self, mod, monkeypatch):
        TestDnsInterceptionProbe()._fake_socket(
            monkeypatch, reply=lambda q: (q[:2], ("10.0.0.1", 53)))
        assert mod.probe_dns_interception()["intercepted"] is False

    def test_the_transaction_id_is_not_a_constant(self, mod, monkeypatch):
        # It was hard-coded at 0x4a4a, which an attacker can simply echo.
        seen = set()
        for _ in range(8):
            created = TestDnsInterceptionProbe()._fake_socket(
                monkeypatch, error=socket.timeout())
            mod.probe_dns_interception()
            seen.add(created[0].sent[0][:2])
        assert len(seen) > 1, "the query id must be random per call"


class TestReporting:
    def test_the_action_reports_both_checks(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run())
        monkeypatch.setattr(mod, "probe_dns_interception",
                            lambda: {"intercepted": False, "responder": None,
                                     "risk": "OK", "note": "clean"})
        result = mod.action_interception_checks()
        out = capsys.readouterr().out
        assert "Trust store" in out and "DNS path" in out
        assert set(result) == {"trust_store", "dns_interception"}

    def test_a_dirty_trust_store_prints_its_entries(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod.sys, "platform", "darwin")
        monkeypatch.setattr(mod, "run", trust_run(admin=DIRTY, user=USER_DIRTY))
        monkeypatch.setattr(mod, "probe_dns_interception",
                            lambda: {"intercepted": False, "responder": None,
                                     "risk": "OK", "note": "clean"})
        mod.action_interception_checks()
        assert "Corporate Proxy Root CA" in capsys.readouterr().out
