"""Gateway-MAC stability polling (`check_arp_spoofing`).

The detector pings the gateway `polls` times and records the MAC the ARP cache
reports each round. Its verdict is pure set logic over those readings — one MAC
means stable, more than one means the gateway's hardware address moved under us,
the classic ARP-poisoning tell. Two decisions carry the weight and are what
these tests pin: the broadcast address ff:ff:ff:ff:ff:ff must never count as a
"seen" MAC, and `spoofing_suspected` must key off the *distinct* MAC count, not
the number of polls.

The real function sleeps `interval` seconds between polls and shells out to
`ping`; both are neutralised so the suite stays instant and hermetic.
"""

import subprocess


def _poller(monkeypatch, mod, macs_per_poll):
    """Drive check_arp_spoofing: yield one arp table per successive poll.

    `macs_per_poll` is a list — its i-th entry is the MAC read_arp_table should
    report for the gateway on poll i (None = no entry that round). ping and the
    inter-poll sleep are stubbed out.
    """
    gw = "192.168.1.1"
    seq = iter(macs_per_poll)

    def fake_arp():
        mac = next(seq)
        return {gw: mac} if mac is not None else {}

    # ping is a real subprocess in production; the sandbox already forbids it,
    # but stub it explicitly so the intent (we don't care about the ping) reads.
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    monkeypatch.setattr(mod, "read_arp_table", fake_arp)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    return gw


class TestStableGateway:
    def test_one_mac_across_all_polls_is_not_suspicious(self, mod, monkeypatch):
        gw = _poller(monkeypatch, mod, ["3c:22:fb:aa:bb:cc"] * 5)
        r = mod.check_arp_spoofing(gw, polls=5, interval=0)
        assert r["spoofing_suspected"] is False
        assert r["macs_seen"] == ["3c:22:fb:aa:bb:cc"]

    def test_the_same_mac_is_not_double_counted(self, mod, monkeypatch):
        # macs_seen is a set rendered sorted; five identical readings collapse
        # to one entry. Guards against a regression to a list-with-duplicates.
        gw = _poller(monkeypatch, mod, ["3c:22:fb:aa:bb:cc"] * 5)
        assert len(mod.check_arp_spoofing(gw, polls=5, interval=0)["macs_seen"]) == 1


class TestSpoofingDetected:
    def test_two_different_macs_trip_the_alarm(self, mod, monkeypatch):
        gw = _poller(monkeypatch, mod,
                     ["3c:22:fb:aa:bb:cc", "3c:22:fb:aa:bb:cc",
                      "de:ad:be:ef:00:01", "de:ad:be:ef:00:01", "de:ad:be:ef:00:01"])
        r = mod.check_arp_spoofing(gw, polls=5, interval=0)
        assert r["spoofing_suspected"] is True
        assert len(r["macs_seen"]) == 2

    def test_macs_seen_is_returned_sorted(self, mod, monkeypatch):
        # Deterministic ordering makes the note reproducible and the test stable.
        gw = _poller(monkeypatch, mod,
                     ["ff:00:00:00:00:02", "00:00:00:00:00:01"] + ["00:00:00:00:00:01"] * 3)
        r = mod.check_arp_spoofing(gw, polls=5, interval=0)
        assert r["macs_seen"] == sorted(r["macs_seen"])


class TestBroadcastAndMissing:
    def test_broadcast_mac_is_never_counted_as_the_gateway(self, mod, monkeypatch):
        # An incomplete ARP entry can read as the all-ff broadcast address. If
        # that counted, a stable gateway that momentarily failed to resolve
        # would look like it had "two" MACs and cry spoofing.
        gw = _poller(monkeypatch, mod,
                     ["3c:22:fb:aa:bb:cc", "ff:ff:ff:ff:ff:ff",
                      "3c:22:fb:aa:bb:cc", "3c:22:fb:aa:bb:cc", "3c:22:fb:aa:bb:cc"])
        r = mod.check_arp_spoofing(gw, polls=5, interval=0)
        assert r["macs_seen"] == ["3c:22:fb:aa:bb:cc"]
        assert r["spoofing_suspected"] is False

    def test_a_gateway_that_never_resolves_yields_no_macs(self, mod, monkeypatch):
        # Off-subnet gateway: no ARP entry ever. Empty set, no alarm — the
        # caller renders a distinct "could not resolve" message for this.
        gw = _poller(monkeypatch, mod, [None] * 5)
        r = mod.check_arp_spoofing(gw, polls=5, interval=0)
        assert r["macs_seen"] == []
        assert r["spoofing_suspected"] is False
