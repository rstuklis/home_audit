"""Evidence provenance — which findings would survive a lying gateway.

The report prints as one flat list of risk-tagged lines, which implies they are
equally well founded. They are not. Some are reads of this machine's own kernel
state, some are measurements this tool made itself, and some are simply what the
device under assessment said when asked about itself.

The distinction is not decoration. A clean result obtained by asking the suspect
is not a clean result, and the checks most likely to produce one — UPnP mappings,
the router's own admin pages, a reverse DNS answer served by the router — were
the ones printing OK.

Two properties these tests hold the design to, and the second is the one that is
easy to get backwards:

  * a clean self-reported finding must not read as a passed security check, for
    the same reason an unkeyed seal verifies without being forgery-proof.
  * provenance is NOT a severity axis. A self-reported finding that INCRIMINATES
    is strong evidence — the router volunteered something against its own
    interest — and must keep its full severity. Only the clean result is weak.
"""

import pytest


GW = "192.168.1.1"


def state_with(**over):
    base = {
        "gateway": GW,
        "dns": [GW],
        "router_open_ports": [443],
        "firewall": {"enabled": True},
    }
    base.update(over)
    return base


class TestFindingsAreClassifiedByWhatTheyRestOn:
    def test_the_hosts_own_state_is_observed(self, mod):
        for key in ("gateway", "dns", "firewall", "listening", "sharing", "wifi"):
            assert mod.EVIDENCE[key][0] == mod.OBSERVED, key

    def test_the_tools_own_measurements_are_measured(self, mod):
        for key in ("router_open_ports", "router_tls", "ipv6", "interception"):
            assert mod.EVIDENCE[key][0] == mod.MEASURED, key

    def test_what_the_gateway_says_about_itself_is_self_reported(self, mod):
        for key in ("upnp", "dsl", "default_creds"):
            assert mod.EVIDENCE[key][0] == mod.SELF_REPORTED, key

    def test_the_dns_interception_probe_is_not_resolver_dependent(self, mod):
        """It bypasses the configured resolver on purpose, which is the point.

        It queries a TEST-NET address directly, so any answer at all proves
        redirection. Classing it with the resolver-dependent checks would throw
        away the one check built specifically not to trust the resolver.
        """
        assert mod.EVIDENCE["interception"][0] == mod.MEASURED

    def test_only_findings_this_run_produced_are_listed(self, mod):
        grouped = mod.findings_by_evidence(state_with())
        assert "upnp" not in grouped.get(mod.SELF_REPORTED, [])
        assert "gateway" in grouped[mod.OBSERVED]

    def test_a_key_present_but_unmeasured_is_not_a_finding(self, mod):
        # None means the run did not take the measurement, which the rest of
        # this tool is careful never to read as a result.
        grouped = mod.findings_by_evidence(state_with(router_open_ports=None))
        assert "router_open_ports" not in grouped.get(mod.MEASURED, [])


class TestOneKeyCanRestOnTwoDifferentGrounds:
    """The device list is read locally; the vendor names are fetched remotely."""

    def test_vendor_names_are_third_party_even_though_devices_are_observed(self, mod):
        state = state_with(devices=[{"ip": "192.168.1.5", "mac": "a4:83:e7:11:22:33",
                                     "vendor": "Apple, Inc."}])
        grouped = mod.findings_by_evidence(state)
        assert "devices" in grouped[mod.OBSERVED]
        assert "device_vendors" in grouped[mod.THIRD_PARTY]

    def test_a_sweep_run_with_no_vendors_makes_no_third_party_claim(self, mod):
        state = state_with(devices=[{"ip": "192.168.1.5", "mac": "a4:83:e7:11:22:33"}])
        grouped = mod.findings_by_evidence(state)
        assert "devices" in grouped[mod.OBSERVED]
        assert mod.THIRD_PARTY not in grouped

    def test_how_many_dhcp_servers_answered_is_measured_but_what_they_said_is_not(self, mod):
        """The split the rogue-DHCP check already knows about, made explicit.

        Counting responders is a fact about the wire. The gateway, resolver and
        static routes inside an offer are values the server chose to send, and a
        rogue that answers alone still reads as the only one.
        """
        state = state_with(dhcp={"responders": [{"ip": GW, "offered_ip": "192.168.1.50"}]})
        grouped = mod.findings_by_evidence(state)
        assert "dhcp" in grouped[mod.MEASURED]
        assert "dhcp_offer_contents" in grouped[mod.SELF_REPORTED]

    def test_no_dhcp_responders_makes_no_self_reported_claim(self, mod):
        grouped = mod.findings_by_evidence(state_with(dhcp={"responders": []}))
        assert mod.SELF_REPORTED not in grouped


class TestTheReportNamesWhatItCannotVouchFor:
    def test_a_run_with_nothing_to_qualify_stays_silent(self, mod):
        # No paragraph explaining that no paragraph is needed.
        assert mod.describe_evidence_basis(state_with()) is None

    def test_self_reported_findings_are_named_with_their_basis(self, mod):
        line = mod.describe_evidence_basis(state_with(upnp={"mappings": []}))
        assert "UPnP port mappings" in line
        assert "self-reported" in line
        assert "own list of its port mappings" in line

    def test_it_says_a_clean_result_is_not_evidence_of_absence(self, mod):
        line = mod.describe_evidence_basis(state_with(upnp={"mappings": []}))
        assert "not the same as" in line and "nothing to find" in line

    def test_it_says_an_admission_is_worth_more_than_a_clean_result(self, mod):
        """Provenance read as severity would bury the strongest evidence here."""
        line = mod.describe_evidence_basis(state_with(upnp={"mappings": []}))
        assert "against its own interest" in line

    def test_it_credits_the_findings_a_gateway_cannot_touch(self, mod):
        line = mod.describe_evidence_basis(state_with(upnp={"mappings": []}))
        assert "cannot edit" in line
        # ...and does not overclaim: a compromised host still reaches them.
        assert "compromised HOST" in line

    def test_a_malformed_state_costs_the_section_not_the_audit(self, mod):
        assert mod.findings_by_evidence({"devices": "not-a-list"}) is not None
        assert mod.describe_evidence_basis(None) is None


class TestTheGatewayIsNotAWitnessAboutItself:
    """check_router_hostname detects a rogue router via the rogue router's DNS.

    The lookup goes through this machine's configured resolver, which on a home
    network is normally the gateway. So the check asks the suspect to confirm
    its own identity, and a rogue one answers exactly as an honest one does. The
    most likely output of all — no PTR record — used to print as [OK].
    """

    def test_a_resolver_that_is_the_gateway_is_recorded_as_self_attesting(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "gethostbyaddr",
                            lambda ip: ("router.lan", [], [ip]))
        result = mod.check_router_hostname(GW, resolvers=[GW])
        assert result["self_attested"] is True

    def test_an_independent_resolver_is_not_self_attesting(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "gethostbyaddr",
                            lambda ip: ("router.lan", [], [ip]))
        result = mod.check_router_hostname(GW, resolvers=["1.1.1.1"])
        assert result["self_attested"] is False

    def test_not_supplying_resolvers_leaves_it_unestablished(self, mod, monkeypatch):
        # Unknown, not "no" — the distinction the rest of this tool insists on.
        monkeypatch.setattr(mod.socket, "gethostbyaddr",
                            lambda ip: ("router.lan", [], [ip]))
        assert mod.check_router_hostname(GW)["self_attested"] is None

    def test_a_self_attested_clean_answer_is_not_reported_as_a_passed_check(self, mod,
                                                                           monkeypatch):
        """The most important test here.

        A rogue router produces this exact output, so printing OK would certify
        a check that cannot fail closed.
        """
        monkeypatch.setattr(mod, "get_default_gateway", lambda: GW)
        monkeypatch.setattr(mod, "get_dns_servers", lambda: [GW])
        monkeypatch.setattr(mod.socket, "gethostbyaddr", lambda ip: ("router.lan", [], [ip]))
        lines = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: lines.append(" ".join(map(str, a))))
        mod.action_router_hostname()
        printed = "\n".join(lines)
        assert "[OK]" not in printed
        assert "[INFO]" in printed
        assert "vouch for its own identity" in printed

    def test_an_incriminating_answer_keeps_full_severity_even_when_self_attested(self, mod,
                                                                                monkeypatch):
        """Evidence from a witness with a motive is strongest when it accuses."""
        monkeypatch.setattr(mod, "get_default_gateway", lambda: GW)
        monkeypatch.setattr(mod, "get_dns_servers", lambda: [GW])
        monkeypatch.setattr(mod.socket, "gethostbyaddr",
                            lambda ip: ("ec2-1-2-3-4.amazonaws.com", [], [ip]))
        lines = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: lines.append(" ".join(map(str, a))))
        result = mod.action_router_hostname()
        assert result["suspicious"] is True
        assert "[HIGH]" in "\n".join(lines)

    def test_an_independently_resolved_clean_answer_may_still_read_ok(self, mod, monkeypatch):
        # Nothing is gained by refusing to pass a check that a third party
        # answered; the caveat is specific, not blanket pessimism.
        monkeypatch.setattr(mod, "get_default_gateway", lambda: GW)
        monkeypatch.setattr(mod, "get_dns_servers", lambda: ["1.1.1.1"])
        monkeypatch.setattr(mod.socket, "gethostbyaddr", lambda ip: ("router.lan", [], [ip]))
        lines = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: lines.append(" ".join(map(str, a))))
        mod.action_router_hostname()
        assert "[OK]" in "\n".join(lines)


class TestAbsenceIsNotEvidenceOfAbsence:
    def test_an_empty_upnp_list_is_reported_as_the_routers_account_not_a_fact(self, mod,
                                                                             monkeypatch):
        monkeypatch.setattr(mod, "get_default_gateway", lambda: GW)
        monkeypatch.setattr(mod, "get_upnp_port_mappings", lambda gw: ([], None))
        lines = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: lines.append(" ".join(map(str, a))))
        mod.action_upnp_dump()
        printed = "\n".join(lines)
        assert "its own account" in printed
        assert "hiding a mapping omits it here" in printed
