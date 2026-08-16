"""Tests for check_listening_services (home_net_audit.py:1292-1341).

The function fuses four command outputs into one deduplicated listener table:
``lsof`` twice (TCP then UDP, for process names) and ``netstat`` twice (to fill
whatever lsof could not see). Two shipped regressions live in that fusion and
are pinned here:

  * commit 9db3ab7 - macOS netstat separates host from port with a DOT
    ("*.59882"), not a colon. The original regex demanded a colon, so every
    single UDP listener was dropped; the fix took the count from 0 to 11.
  * commit ab61550 - the lsof NAME regex was IPv4-only and could not match the
    bracketed "[ipv6]:port" form, so IPv6 listeners vanished. The same commit
    added the second lsof call, without which UDP listeners were reported with
    process "?" instead of a real name.
"""

import pytest

from conftest import make_run

LSOF_TCP = "lsof -nP -iTCP -sTCP:LISTEN"
LSOF_UDP = "lsof -nP -iUDP"
NETSTAT_TCP = "netstat -anp tcp"
NETSTAT_UDP = "netstat -anp udp"

LSOF_HEADER = (
    "COMMAND      PID           USER   FD   TYPE             DEVICE "
    "SIZE/OFF NODE NAME\n"
)
NETSTAT_HEADER = (
    "Active Internet connections (including servers)\n"
    "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n"
)


def wire(monkeypatch, mod, lsof_tcp="", lsof_udp="", netstat_tcp="", netstat_udp=""):
    """Point mod.run at the four commands check_listening_services issues.

    Returns the fake so a test can inspect ``.calls``.
    """
    fake = make_run({
        LSOF_TCP: lsof_tcp,
        LSOF_UDP: lsof_udp,
        NETSTAT_TCP: netstat_tcp,
        NETSTAT_UDP: netstat_udp,
    })
    monkeypatch.setattr(mod, "run", fake)
    return fake


def pairs(services):
    return [(s["proto"], s["port"]) for s in services]


def by_key(services):
    return {(s["proto"], s["port"]): s for s in services}


@pytest.fixture
def full_scan(monkeypatch, mod, fixture):
    """The realistic four-command capture, parsed."""
    wire(monkeypatch, mod,
         lsof_tcp=fixture("lsof_tcp_listen.out"),
         lsof_udp=fixture("lsof_udp.out"),
         netstat_tcp=fixture("netstat_anp_tcp.out"),
         netstat_udp=fixture("netstat_anp_udp.out"))
    return mod.check_listening_services()


class TestCommandsIssued:
    def test_issues_the_four_enumeration_commands_in_lsof_first_order(
            self, monkeypatch, mod, fixture):
        # Order is load-bearing, not cosmetic: netstat cannot supply process
        # names, so both lsof passes must populate the table before netstat
        # gets a chance to claim a (proto, port) key with "?".
        fake = wire(monkeypatch, mod,
                    lsof_tcp=fixture("lsof_tcp_listen.out"),
                    lsof_udp=fixture("lsof_udp.out"),
                    netstat_tcp=fixture("netstat_anp_tcp.out"),
                    netstat_udp=fixture("netstat_anp_udp.out"))
        mod.check_listening_services()
        assert fake.calls == [LSOF_TCP, LSOF_UDP, NETSTAT_TCP, NETSTAT_UDP]

    def test_all_four_commands_empty_yields_empty_list_without_raising(
            self, monkeypatch, mod):
        wire(monkeypatch, mod)
        assert mod.check_listening_services() == []


class TestLsofNameParsing:
    @pytest.mark.parametrize("proto,port,process,pid", [
        ("TCP", 22, "launchd", "1"),
        ("TCP", 52310, "rapportd", "612"),
        ("TCP", 631, "cupsd", "227"),
        ("UDP", 5353, "mDNSRespo", "228"),
        ("UDP", 49281, "sharingd", "701"),
    ], ids=["bracketed-ipv6", "ipv4-wildcard", "host-colon-port",
            "udp-wildcard", "bracketed-ipv6-with-zone-id"])
    def test_lsof_name_forms_yield_port_with_real_process_and_pid(
            self, full_scan, proto, port, process, pid):
        # Regression, commit ab61550: the bracketed rows are the ones the old
        # IPv4-only regex silently discarded, and the UDP rows only exist
        # because that commit added the second `lsof -nP -iUDP` call.
        entry = by_key(full_scan).get((proto, port))
        assert entry is not None, f"{proto} listener on port {port} was dropped"
        assert (entry["process"], entry["pid"]) == (process, pid)

    @pytest.mark.parametrize("stream,proto,name", [
        ("lsof_tcp", "TCP", "127.0.0.1:52944->104.18.32.7:443"),
        ("lsof_udp", "UDP", "192.168.87.24:61234->142.250.70.238:443"),
    ], ids=["tcp-established", "udp-connected"])
    def test_lsof_name_containing_an_arrow_is_not_a_listener(
            self, monkeypatch, mod, stream, proto, name):
        out = LSOF_HEADER + (
            f"firefox     3312          alice   77u  IPv4 0x9e0a1b2c3d4e5f01"
            f"      0t0  {proto} {name} (ESTABLISHED)\n"
        )
        wire(monkeypatch, mod, **{stream: out})
        # Both the local ephemeral port and the remote port must stay out; the
        # trailing-":port" regex would otherwise happily match the remote :443.
        assert mod.check_listening_services() == []

    def test_unbound_udp_socket_star_star_is_not_a_listener(self, monkeypatch, mod):
        out = LSOF_HEADER + (
            "mDNSRespo    228 _mdnsresponder   12u  IPv4 0x9e0a1b2c3d4e5fa2"
            "      0t0  UDP *:*\n"
        )
        wire(monkeypatch, mod, lsof_udp=out)
        assert mod.check_listening_services() == []

    def test_truncated_lsof_line_is_skipped_without_raising(self, monkeypatch, mod):
        out = LSOF_HEADER + (
            "sshd         431           root    4u  IPv4 0x9e0a1b2c3d4e5f02"
            "      0t0  TCP\n"
            "cupsd        227           root    8u  IPv4 0x9e0a1b2c3d4e5f03"
            "      0t0  TCP 127.0.0.1:631 (LISTEN)\n"
        )
        wire(monkeypatch, mod, lsof_tcp=out)
        assert pairs(mod.check_listening_services()) == [("TCP", 631)]

    def test_first_lsof_line_is_consumed_as_the_header(self, monkeypatch, mod):
        # `lsof` always emits a COMMAND/PID/... banner, so the parser drops
        # line 0 unconditionally. Feeding header-less output therefore loses
        # its first row - that is the documented cost of the [1:] slice, and
        # this test fails the moment someone removes it.
        out = (
            "launchd        1           root   28u  IPv6 0x9e0a1b2c3d4e5f60"
            "      0t0  TCP *:22 (LISTEN)\n"
            "cupsd        227           root    8u  IPv4 0x9e0a1b2c3d4e5f63"
            "      0t0  TCP 127.0.0.1:631 (LISTEN)\n"
        )
        wire(monkeypatch, mod, lsof_tcp=out)
        assert pairs(mod.check_listening_services()) == [("TCP", 631)]

    def test_same_proto_and_port_on_two_lsof_rows_yields_one_entry(self, full_scan):
        # rapportd binds 52310 on both IPv4 and IPv6; the table is keyed on
        # (proto, port), so the pair must collapse to a single listener.
        tcp_52310 = [s for s in full_scan if s["proto"] == "TCP" and s["port"] == 52310]
        assert len(tcp_52310) == 1


class TestNetstatParsing:
    @pytest.mark.parametrize("proto,port", [
        ("UDP", 59882),
        ("TCP", 8080),
    ], ids=["wildcard-dot-port", "host-dot-port"])
    def test_dot_separated_local_address_is_captured(self, full_scan, proto, port):
        # Regression, commit 9db3ab7: macOS netstat writes "*.59882" and
        # "127.0.0.1.8080" with a DOT. The colon-only regex matched neither,
        # which is why every UDP listener disappeared.
        assert (proto, port) in pairs(full_scan)

    @pytest.mark.parametrize("proto_col,expected", [
        ("tcp4", "TCP"), ("tcp6", "TCP"), ("tcp46", "TCP"),
    ], ids=["tcp4", "tcp6", "tcp46"])
    def test_tcp_address_family_digits_are_stripped_from_proto(
            self, monkeypatch, mod, proto_col, expected):
        line = f"{proto_col}       0      0  *.9100                 *.*                    LISTEN\n"
        wire(monkeypatch, mod, netstat_tcp=NETSTAT_HEADER + line)
        assert pairs(mod.check_listening_services()) == [(expected, 9100)]

    @pytest.mark.parametrize("proto_col,expected", [
        ("udp4", "UDP"), ("udp6", "UDP"), ("udp46", "UDP"),
    ], ids=["udp4", "udp6", "udp46"])
    def test_udp_address_family_digits_are_stripped_from_proto(
            self, monkeypatch, mod, proto_col, expected):
        line = f"{proto_col}       0      0  *.9101                 *.*\n"
        wire(monkeypatch, mod, netstat_udp=NETSTAT_HEADER + line)
        assert pairs(mod.check_listening_services()) == [(expected, 9101)]

    @pytest.mark.parametrize("port", [52944, 52901, 52877, 443],
                             ids=["established-local", "established-local-2",
                                  "close-wait-local", "remote-https"])
    def test_non_listening_tcp_rows_contribute_no_listener(self, full_scan, port):
        assert port not in [s["port"] for s in full_scan]

    def test_netstat_banner_and_column_headers_contribute_no_listener(
            self, monkeypatch, mod):
        wire(monkeypatch, mod, netstat_tcp=NETSTAT_HEADER, netstat_udp=NETSTAT_HEADER)
        assert mod.check_listening_services() == []

    @pytest.mark.parametrize("stream,truncated", [
        ("netstat_tcp", "tcp4 0 LISTEN\n"),
        ("netstat_udp", "udp4       0      0\n"),
    ], ids=["short-listen-row", "short-udp-row"])
    def test_truncated_netstat_row_is_skipped_without_raising(
            self, monkeypatch, mod, stream, truncated):
        keeper = {
            "netstat_tcp": "tcp4       0      0  *.548                  *.*                    LISTEN\n",
            "netstat_udp": "udp4       0      0  *.5353                 *.*\n",
        }[stream]
        wire(monkeypatch, mod, **{stream: NETSTAT_HEADER + truncated + keeper})
        expected = [("TCP", 548)] if stream == "netstat_tcp" else [("UDP", 5353)]
        assert pairs(mod.check_listening_services()) == expected

    def test_unbound_netstat_udp_row_is_not_a_listener(self, monkeypatch, mod):
        wire(monkeypatch, mod,
             netstat_udp=NETSTAT_HEADER + "udp4       0      0  *.*                    *.*\n")
        assert mod.check_listening_services() == []

    @pytest.mark.parametrize("proto,port", [("TCP", 548), ("UDP", 49152)],
                             ids=["afp-tcp-548", "udp-49152"])
    def test_port_only_netstat_knows_about_has_unknown_pid_and_process(
            self, full_scan, proto, port):
        entry = by_key(full_scan)[(proto, port)]
        assert (entry["pid"], entry["process"]) == ("?", "?")


class TestLsofWinsOverNetstat:
    @pytest.mark.parametrize("proto,port,process", [
        ("TCP", 22, "launchd"),
        ("TCP", 7000, "ControlCe"),
        ("UDP", 5353, "mDNSRespo"),
        ("UDP", 137, "netbiosd"),
    ], ids=["ssh", "airplay", "mdns", "netbios"])
    def test_process_name_from_lsof_survives_the_netstat_pass(
            self, full_scan, proto, port, process):
        # Every one of these ports appears in BOTH the lsof and the netstat
        # capture. lsof runs first precisely so the netstat row cannot
        # overwrite a real name with the "?" placeholder.
        entry = by_key(full_scan)[(proto, port)]
        assert entry["process"] == process
        assert entry["pid"] != "?"

    def test_netstat_does_not_downgrade_an_lsof_entry(self, monkeypatch, mod):
        lsof = LSOF_HEADER + (
            "launchd        1           root   28u  IPv6 0x9e0a1b2c3d4e5f60"
            "      0t0  TCP [::1]:22 (LISTEN)\n"
        )
        netstat = NETSTAT_HEADER + (
            "tcp4       0      0  *.22                   *.*                    LISTEN\n"
        )
        wire(monkeypatch, mod, lsof_tcp=lsof, netstat_tcp=netstat)
        services = mod.check_listening_services()
        assert len(services) == 1
        assert services[0] == {"proto": "TCP", "port": 22,
                               "pid": "1", "process": "launchd"}

    def test_same_port_on_tcp_and_udp_yields_two_separate_entries(self, full_scan):
        # rapportd listens on 52310 over both protocols; the dedup key is the
        # (proto, port) pair, so collapsing them would hide one listener.
        assert [s["proto"] for s in full_scan if s["port"] == 52310] == ["TCP", "UDP"]


class TestResultShape:
    def test_results_are_sorted_by_port_ascending(self, full_scan):
        ports = [s["port"] for s in full_scan]
        assert ports == sorted(ports)
        assert ports[0] == 22 and ports[-1] == 59882

    def test_full_capture_produces_the_expected_listener_table(self, full_scan):
        assert pairs(full_scan) == [
            ("TCP", 22),        # lsof, bracketed IPv6 [::1]:22
            ("UDP", 137),       # lsof UDP, *:137
            ("TCP", 548),       # netstat only (tcp6 *.548)
            ("TCP", 631),       # lsof, 127.0.0.1:631
            ("TCP", 3000),      # lsof, 127.0.0.1:3000
            ("UDP", 5353),      # lsof UDP, *:5353 (deduped across v4/v6)
            ("TCP", 7000),      # lsof, *:7000
            ("TCP", 8000),      # lsof, bracketed IPv6 [::1]:8000
            ("TCP", 8080),      # netstat only, dot form 127.0.0.1.8080
            ("UDP", 49152),     # netstat only, dot form 127.0.0.1.49152
            ("UDP", 49281),     # lsof UDP, bracketed IPv6 with %en0 zone id
            ("TCP", 52310),     # lsof TCP
            ("UDP", 52310),     # lsof UDP, same port different proto
            ("UDP", 59882),     # netstat only, dot form *.59882
        ]

    def test_every_entry_exposes_the_keys_action_listening_services_reads(
            self, full_scan):
        # The docstring at line 1297 advertises a `local_addr` key as well, but
        # neither branch ever sets one. Nothing consumes it (action_listening_
        # services reads only port/proto/process), so this pins the real shape
        # rather than the stale docstring - see the summary.
        for entry in full_scan:
            assert set(entry) == {"proto", "port", "pid", "process"}
            assert isinstance(entry["port"], int)
            assert entry["proto"] in {"TCP", "UDP"}


class TestKnownBugs:
    def test_connected_udp_socket_is_not_re_added_as_a_listener_by_netstat(
            self, monkeypatch, mod):
        # Fixed regression: the netstat pass accepted every UDP row regardless
        # of its foreign address, so a connected/outbound socket that
        # _add_from_lsof deliberately skipped ("established connection, not a
        # listener") was re-added with pid/process '?', and
        # action_listening_services then flagged the ephemeral source port of an
        # ordinary web request as an unrecognised non-system listener. UDP has
        # no state column; the foreign address is what distinguishes a listener
        # ("*.*") from a socket this Mac dialled out on.
        lsof_udp = LSOF_HEADER + (
            "firefox     3312          alice   77u  IPv4 0x9e0a1b2c3d4e5fa6"
            "      0t0  UDP 192.168.87.24:61234->142.250.70.238:443\n"
        )
        netstat_udp = NETSTAT_HEADER + (
            "udp4       0      0  192.168.87.24.61234    142.250.70.238.443\n"
        )
        wire(monkeypatch, mod, lsof_udp=lsof_udp, netstat_udp=netstat_udp)
        assert mod.check_listening_services() == []


class TestListenerClassification:
    """Three groups needing opposite advice, from one list.

    lsof reports only processes owned by the invoking user, so on a normal run
    most listeners arrive from netstat with no name: four rows named against
    twenty-one netstat sees, on the machine this was written for. The report
    used to mark all of them "*" and say "verify you recognise them" — advice
    nobody can follow for a bare port number, and which buried the two entries
    that could genuinely have been checked under twenty that could not.
    """

    SYSTEM = {53: "DNS", 137: "NetBIOS", 5353: "mDNS", 631: "CUPS"}

    def _svc(self, port, process="?", proto="TCP"):
        return {"port": port, "proto": proto, "pid": "?", "process": process}

    def test_a_named_non_system_listener_is_checkable(self, mod):
        got = mod.classify_listeners([self._svc(19292, "AdobeReso")], self.SYSTEM)
        assert got["named"] and not got["unattributed"]

    def test_an_unnamed_non_system_listener_is_not_checkable(self, mod):
        got = mod.classify_listeners([self._svc(49154)], self.SYSTEM)
        assert got["unattributed"] and not got["named"]

    @pytest.mark.parametrize("port", [53, 137, 631, 5353])
    def test_well_known_ports_are_system_whether_named_or_not(self, mod, port):
        got = mod.classify_listeners([self._svc(port)], self.SYSTEM)
        assert got["system"] and not got["named"] and not got["unattributed"]

    def test_a_privileged_port_is_system_even_when_unlisted(self, mod):
        # Anything below 1024 needs privilege to bind, so it is not the kind of
        # thing a stray user process opened.
        got = mod.classify_listeners([self._svc(22, "sshd")], self.SYSTEM)
        assert got["system"]

    def test_the_two_groups_are_kept_apart(self, mod):
        services = ([self._svc(p) for p in (49154, 49155, 49156)]
                    + [self._svc(19292, "AdobeReso"), self._svc(7679, "Google")])
        got = mod.classify_listeners(services, self.SYSTEM)
        assert len(got["unattributed"]) == 3
        assert len(got["named"]) == 2
        assert not (set(map(id, got["named"])) & set(map(id, got["unattributed"])))

    @pytest.mark.parametrize("missing", ["?", "", "   ", None])
    def test_every_shape_of_missing_name_counts_as_unattributed(self, mod, missing):
        got = mod.classify_listeners([self._svc(49154, missing)], self.SYSTEM)
        assert got["unattributed"], f"{missing!r} was treated as a process name"

    def test_a_malformed_entry_does_not_raise(self, mod):
        # netstat output is parsed defensively elsewhere; this must not be the
        # place a corrupt row takes the whole audit down.
        got = mod.classify_listeners([{"proto": "TCP"}, {"port": None}], self.SYSTEM)
        assert len(got["system"]) == 2

    def test_every_listener_lands_in_exactly_one_group(self, mod):
        services = [self._svc(53), self._svc(49154), self._svc(19292, "Adobe")]
        got = mod.classify_listeners(services, self.SYSTEM)
        assert sum(len(v) for v in got.values()) == len(services)


class TestListenerReportWording:
    SYSTEM = {5353: "mDNS"}

    def _run(self, mod, monkeypatch, services):
        monkeypatch.setattr(mod, "check_listening_services", lambda: services)
        mod.action_listening_services()

    def test_unnamed_listeners_are_not_offered_for_recognition(self, mod, monkeypatch, capsys):
        self._run(mod, monkeypatch,
                  [{"port": p, "proto": "TCP", "pid": "?", "process": "?"}
                   for p in (49154, 49155)])
        out = capsys.readouterr().out
        assert "could not be attributed" in out
        assert "Verify you recognise" not in out, \
            "asked the reader to recognise a bare port number"

    def test_the_remedy_is_stated_because_here_it_works(self, mod, monkeypatch, capsys):
        # Distinct from the Local Network denials, where sudo is the wrong
        # advice; for process attribution it is the right advice.
        self._run(mod, monkeypatch,
                  [{"port": 49154, "proto": "TCP", "pid": "?", "process": "?"}])
        assert "sudo" in capsys.readouterr().out

    def test_named_listeners_are_still_offered_for_recognition(self, mod, monkeypatch, capsys):
        self._run(mod, monkeypatch,
                  [{"port": 19292, "proto": "TCP", "pid": "697", "process": "AdobeReso"}])
        out = capsys.readouterr().out
        assert "Verify you recognise" in out
        assert "could not be attributed" not in out

    def test_a_clean_machine_still_says_so(self, mod, monkeypatch, capsys):
        self._run(mod, monkeypatch,
                  [{"port": 5353, "proto": "UDP", "pid": "?", "process": "?"}])
        assert "No unexpected listeners found" in capsys.readouterr().out
