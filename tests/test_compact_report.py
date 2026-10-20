"""--compact: a shorter report that may drop only what has not changed."""

import pytest

BASE = [{"proto": "UDP", "port": 5353, "pid": "?", "process": "?"},
        {"proto": "TCP", "port": 19292, "pid": "1", "process": "AdobeReso"},
        {"proto": "UDP", "port": 51017, "pid": "2", "process": "homed"}]


@pytest.fixture
def listeners(mod, monkeypatch, capsys):
    def run(now, known, compact=True):
        monkeypatch.setattr(mod, "check_listening_services", lambda: now)
        result = mod.action_listening_services(compact=compact, known=known)
        return result, capsys.readouterr().out
    return run


class TestListeners:
    def test_an_unchanged_set_collapses_to_a_line(self, listeners):
        _, out = listeners(BASE, BASE)
        assert "none of them new since the baseline" in out and "19292" not in out

    def test_the_full_list_is_still_returned_for_the_baseline(self, listeners):
        result, _ = listeners(BASE, BASE)
        assert result == BASE

    def test_a_dynamic_port_moving_is_not_a_change(self, mod, listeners):
        moved = [dict(s, port=61675) if s["process"] == "homed" else s for s in BASE]
        _, out = listeners(moved, BASE)
        assert "none of them new" in out

    def test_a_new_fixed_port_prints_the_whole_table_and_names_the_newcomer(self, listeners):
        _, out = listeners(BASE + [{"proto": "TCP", "port": 4444, "pid": "9", "process": "nc"}], BASE)
        assert "4444" in out and "none of them new" not in out
        assert "+ not in the baseline: nc on TCP port 4444" in out

    def test_a_listener_that_went_away_is_named_but_does_not_hold_the_table_open(self, listeners):
        # Short-lived system sockets come and go all day; a closed port is not
        # what this section watches for. It is still said, never silently dropped.
        _, out = listeners(BASE[:2], BASE)
        assert "none of them new" in out and "19292" not in out
        assert "- in the baseline, gone now: homed on UDP a dynamic port" in out

    def test_gone_and_new_together_still_prints_everything(self, listeners):
        _, out = listeners(BASE[:2] + [{"proto": "TCP", "port": 4444, "pid": "9", "process": "nc"}], BASE)
        assert "4444" in out and "+ not in the baseline" in out and "- in the baseline, gone now" in out

    def test_an_unnamed_listener_on_a_dynamic_port_is_counted_not_compared(self, listeners):
        # No process name, no fixed port: nothing to tell one from the next, and
        # they come and go by the minute. Measured: this reopened the table on
        # consecutive runs of an unchanged Mac.
        anon = {"proto": "UDP", "port": 64506, "pid": "?", "process": "?"}
        _, out = listeners(BASE + [anon], BASE)
        assert "none of them new" in out and "64506" not in out
        assert "1 unnamed listener(s) on dynamic ports (baseline: 0)" in out

    def test_an_unnamed_listener_on_a_fixed_port_is_still_new(self, listeners):
        # A fixed port is a choice somebody made, named process or not.
        _, out = listeners(BASE + [{"proto": "TCP", "port": 8021, "pid": "?", "process": "?"}], BASE)
        assert "+ not in the baseline: unattributed on TCP port 8021" in out

    def test_a_named_listener_on_a_dynamic_port_is_still_new(self, listeners):
        _, out = listeners(BASE + [{"proto": "TCP", "port": 50000, "pid": "7", "process": "nc"}], BASE)
        assert "+ not in the baseline: nc on TCP a dynamic port" in out

    def test_with_no_baseline_the_table_is_always_printed(self, listeners):
        _, out = listeners(BASE, None)
        assert "19292" in out

    def test_without_compact_nothing_changes(self, listeners):
        _, out = listeners(BASE, BASE, compact=False)
        assert "19292" in out and "none of them new" not in out

    @pytest.mark.parametrize("junk", [[None, 3, {"port": "x"}], "nope", [{"proto": "TCP"}]])
    def test_a_malformed_baseline_cannot_crash_or_collapse_it(self, mod, junk):
        assert mod.listener_fingerprint(junk) == set()


class TestIpv6:
    def test_compact_keeps_the_router_rows_and_counts_the_rest(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "check_ipv6_routers", lambda known=None: {"risk": "OK", "note": "fine", "routers": []})
        monkeypatch.setattr(mod, "get_ipv6_neighbours", lambda: {
            "fe80::1%en0": {"mac": "aa:aa:aa:aa:aa:aa", "router": True},
            "fe80::2%en0": {"mac": "bb:bb:bb:bb:bb:bb", "router": False},
            "fe80::3%en0": {"mac": "cc:cc:cc:cc:cc:cc", "router": False}})
        mod.action_ipv6_routers(compact=True)
        out = capsys.readouterr().out
        assert "aa:aa:aa:aa:aa:aa" in out and "bb:bb:bb:bb:bb:bb" not in out
        assert "neighbours seen : 3" in out and "2 ordinary neighbour(s) not listed" in out


class TestProvenance:
    STATE = {"upnp": {"mappings": []}, "gateway": "10.0.0.1"}

    def test_compact_keeps_the_list_and_folds_the_lecture(self, mod):
        full = mod.describe_evidence_basis(self.STATE)
        short = mod.describe_evidence_basis(self.STATE, compact=True)
        assert "UPnP port mappings" in short
        assert len(short.splitlines()) < len(full.splitlines())
        assert "weak evidence" in short
