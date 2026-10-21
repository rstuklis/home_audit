"""What the review after the 2026-10-20 merge found, pinned.

Nine finders and two skeptics per finding read PR #38 against the two
deployments it serves: a Mac at the beach house auditing one network every
Saturday and one in the city auditing three every Sunday, both unattended,
both without sudo. Each class here is one finding, and its docstring says what
used to happen on the next scheduled run.
"""

import importlib.util
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

MODEM = "192.168.1.1"
IGD_DESC = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>{ctrl}</controlURL>
</service></serviceList></device></root>"""
FAULT = ('<s:Envelope><s:Body><s:Fault><faultstring>UPnPError</faultstring><detail>'
         '<UPnPError><errorCode>-1</errorCode><errorDescription>Invalid Action</errorDescription>'
         '</UPnPError></detail></s:Fault></s:Body></s:Envelope>')


def _timed(fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    return result, time.perf_counter() - start


# ---------------------------------------------------------------------------
# A LAN device's description could hang the audit (HIGH, both Macs)
# ---------------------------------------------------------------------------

class TestDescriptionParsingIsLinear:
    """<tag>\\s*([^<]{1,200}?)\\s*</tag> backtracked quadratically, and the
    unbounded [^<]+? form cubically, on "<tag>" followed by whitespace with no
    closing tag. 64 KB of that from any device that answers the sweep's
    discovery held the thread pool for twenty-five minutes; from the gateway,
    for longer than the week. Nothing raised, so no abort line, no failure
    email, no baseline, no report — and launchd does not start next week's run
    while this one is still going. PR #38 bounded the download, not the parse.
    """

    @pytest.mark.parametrize("padding", [" ", "\n", "\t"])
    def test_a_padded_unterminated_name_parses_in_bounded_time(self, mod, padding):
        body = "<root><friendlyName>" + padding * 65536
        text, took = _timed(mod._xml_text, body, "friendlyName", 200)
        assert text == "" and took < 0.5

    def test_the_gateway_control_check_is_bounded_too(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_http_post_plain", lambda *a, **k: pytest.fail("no service, no POST"))
        for body in ("<root><URLBase>" + " " * 65536,
                     "<root><service><serviceType>" + " " * 65536,
                     "<root>" + "<service>" * 7000):
            control, took = _timed(mod._upnp_control_check, MODEM, 1900, "/gatedesc.xml", body)
            assert control is None and took < 1.0

    def test_well_formed_descriptions_read_as_before(self, mod):
        desc = "<root><device><friendlyName>  [TV] Lounge </friendlyName><modelName>UE55</modelName></device></root>"
        assert mod._xml_text(desc, "friendlyName", 200) == "[TV] Lounge"
        assert mod._xml_text(desc, "modelname", 200) == "UE55"          # tags are matched case-blind
        assert mod._xml_text(desc, "serialNumber", 200) == ""
        assert mod._xml_text("<friendlyName>" + "x" * 201 + "</friendlyName>", "friendlyName", 200) == ""

    def test_service_blocks_are_read_once_each(self, mod):
        desc = "<serviceList><service>A</service><service>B</service><service>unclosed"
        assert mod._xml_blocks(desc, "service") == ["A", "B"]

    def test_the_control_check_still_asks_a_real_service(self, mod, monkeypatch):
        posts = []
        monkeypatch.setattr(mod, "_http_post_plain",
                            lambda h, port, path, body, headers, **k: posts.append(path) or (500, "", FAULT))
        desc = IGD_DESC.format(ctrl="/ctl/IPConn")
        assert mod._upnp_control_check(MODEM, 1900, "/gatedesc.xml", desc) == "refused"
        assert posts == ["/ctl/IPConn"]


# ---------------------------------------------------------------------------
# The raw HTTP reader raised on a reply that opens with a blank line (both Macs)
# ---------------------------------------------------------------------------

class _Sock:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def settimeout(self, t):
        pass

    def sendall(self, data):
        pass

    def recv(self, n):
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        pass


class TestTheHttpReaderNeverRaisesOnAReply:
    """A reply beginning "\\r\\n\\r\\n" split at offset 0, left no status line
    to index, and the IndexError was not in the except. From the name sweep it
    threw away every device's UPnP name for the week; from the gateway probe it
    ended the audit. The http.client reader this replaced returned None.
    """

    @pytest.mark.parametrize("payload", [b"\r\n\r\nHTTP/1.0 200 OK\r\n\r\n", b"\n\n", b"\r\n\r\n"])
    def test_a_blank_first_line_is_no_http_not_an_exception(self, mod, monkeypatch, payload):
        monkeypatch.setattr(mod.socket, "create_connection", lambda *a, **k: _Sock([payload, b""]))
        assert mod._http_get_plain("192.168.86.49", 80, "/d.xml") is None

    def test_a_normal_reply_is_untouched(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "create_connection",
                            lambda *a, **k: _Sock([b"HTTP/1.1 200 OK\r\nServer: s\r\n\r\n<root/>", b""]))
        assert mod._http_get_plain("192.168.86.49", 80, "/") == (200, "s", "<root/>")


class _FakeUdp:
    def __init__(self, replies):
        self.replies = list(replies)

    def settimeout(self, t):
        pass

    def sendto(self, data, addr):
        pass

    def recvfrom(self, n):
        if self.replies:
            return self.replies.pop(0)
        raise socket.timeout()

    def close(self):
        pass


def _ssdp(ip, location):
    return (f"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: {location}\r\n\r\n".encode(), (ip, 1900))


class TestOneDeviceCannotEmptyTheNameSweep:
    def test_a_fetch_that_raises_costs_only_that_devices_name(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: _FakeUdp(
            [_ssdp("192.168.86.49", "http://192.168.86.49/d"), _ssdp("192.168.86.83", "http://192.168.86.83/d")]))

        def fake_get(host, port, path, timeout=3.0, limit=65536):
            if host == "192.168.86.49":
                raise RuntimeError("a description only this device could write")
            return (200, "", "<root><friendlyName>Pearl</friendlyName></root>")
        monkeypatch.setattr(mod, "_http_get_plain", fake_get)
        names, _ = mod.upnp_device_names({"192.168.86.49", "192.168.86.83"}, wait=0.05)
        assert names == {"192.168.86.83": "Pearl"}


# ---------------------------------------------------------------------------
# A bracketed control URL raised out of the gateway probe (LOW, both Macs)
# ---------------------------------------------------------------------------

class TestControlUrlsAreParsedDefensively:
    @pytest.mark.parametrize("ctrl", ["http://[::1", "http://[zzz]/ctl", "http://[::1]:99999/ctl"])
    def test_a_malformed_control_url_is_skipped_not_raised(self, mod, monkeypatch, ctrl):
        monkeypatch.setattr(mod, "_ssdp_search", lambda *a, **k: ([], False))
        monkeypatch.setattr(mod, "_http_get_plain", lambda h, port, path, **k: (
            (200, "libupnp", IGD_DESC.format(ctrl=ctrl)) if path == "/gatedesc.xml" else (404, "libupnp", "")))
        monkeypatch.setattr(mod, "_http_post_plain", lambda *a, **k: pytest.fail("nothing to POST to"))
        assert mod._upnp_control_check(MODEM, 1900, "/gatedesc.xml", IGD_DESC.format(ctrl=ctrl)) is None
        v = mod.classify_upnp_listener(MODEM, 1900, onlink=False)
        assert v["state"] == mod.UPNP_LIVE_GATEWAY and v["confirmed"] is False


# ---------------------------------------------------------------------------
# One dropped exchange flipped the beach modem's verdict (MEDIUM, beach Mac)
# ---------------------------------------------------------------------------

class TestOneDroppedExchangeIsRetried:
    """The modem's "described-off" rested on one GET and one POST with no
    retry. A single lost packet reclassified it "live-gateway", the new
    comparison printed CHANGES DETECTED with advice to turn off what was
    already off, and the week after it flipped back with a second alarm.
    """

    def _probe(self, mod, monkeypatch, gets, posts):
        get_calls, post_calls = [], []

        def fake_get(h, port, path, **k):
            get_calls.append((port, path))
            key = (port, path)
            if key in gets:
                return gets[key].pop(0) if isinstance(gets[key], list) else gets[key]
            return (404, "libupnp", "nope")

        def fake_post(h, port, path, body, headers, **k):
            post_calls.append(path)
            return posts.pop(0) if posts else None
        monkeypatch.setattr(mod, "_ssdp_search", lambda *a, **k: ([], False))
        monkeypatch.setattr(mod, "_http_get_plain", fake_get)
        monkeypatch.setattr(mod, "_http_post_plain", fake_post)
        return mod.classify_upnp_listener(MODEM, 1900, onlink=False), get_calls, post_calls

    def test_a_dropped_control_post_is_asked_once_more(self, mod, monkeypatch):
        v, _, posts = self._probe(mod, monkeypatch,
                                  {(1900, "/gatedesc.xml"): (200, "libupnp", IGD_DESC.format(ctrl="/ctl"))},
                                  [None, (500, "libupnp", FAULT)])
        assert v["state"] == mod.UPNP_DESCRIBED_OFF and v["confirmed"] is True
        assert posts == ["/ctl", "/ctl"]

    def test_two_silent_posts_are_unconfirmed_and_not_asked_a_third_time(self, mod, monkeypatch):
        v, _, posts = self._probe(mod, monkeypatch,
                                  {(1900, "/gatedesc.xml"): (200, "libupnp", IGD_DESC.format(ctrl="/ctl"))},
                                  [None, None])
        assert v["state"] == mod.UPNP_LIVE_GATEWAY and v["confirmed"] is False
        assert "Not confirmed" in v["caveat"] and len(posts) == 2

    def test_a_dropped_description_get_is_asked_once_more(self, mod, monkeypatch):
        v, gets, _ = self._probe(mod, monkeypatch,
                                 {(1900, "/"): [None, (404, "libupnp", "nope")],
                                  (1900, "/gatedesc.xml"): (200, "libupnp", IGD_DESC.format(ctrl="/ctl"))},
                                 [(500, "libupnp", FAULT)])
        assert v["state"] == mod.UPNP_DESCRIBED_OFF
        assert gets[:2] == [(1900, "/"), (1900, "/")] and (1900, "/gatedesc.xml") in gets

    def test_a_reply_only_gateway_says_it_is_unconfirmed(self, mod, monkeypatch):
        reply = ("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"
                 "LOCATION: http://192.168.1.1:1900/gatedesc.xml\r\n\r\n")
        monkeypatch.setattr(mod, "_ssdp_search", lambda *a, **k: ([reply], False))
        monkeypatch.setattr(mod, "_http_get_plain", lambda *a, **k: None)
        monkeypatch.setattr(mod, "_http_post_plain", lambda *a, **k: None)
        v = mod.classify_upnp_listener(MODEM, 1900, onlink=False)
        assert v["state"] == mod.UPNP_LIVE_GATEWAY and v["confirmed"] is False
        assert "could not be fetched" in v["caveat"]


OFF = {"state": "described-off", "risk": "INFO", "confirmed": True}
LIVE_UNCONFIRMED = {"state": "live-gateway", "risk": "REVIEW", "confirmed": False,
                    "caveat": "Not confirmed: the control service gave no HTTP answer."}
LIVE_CONFIRMED = {"state": "live-gateway", "risk": "REVIEW", "confirmed": True}


def _state(entry):
    return {"upnp_listeners": {MODEM: dict(entry)}}


class TestAnUnconfirmedVerdictIsNotAChange:
    """A differing verdict counts when it rests on an answer, or when the same
    unconfirmed reading comes back on the next run. Meanwhile the baseline
    keeps the confirmed verdict, so the week after cannot flip back either.
    """

    def test_a_confirmed_switch_on_is_still_a_change(self, mod):
        notes = mod.diff_baseline(_state(OFF), _state(LIVE_CONFIRMED))
        assert any("CHANGED: was described-off, now live-gateway" in n for n in notes)

    def test_an_unconfirmed_reading_is_held_and_explained(self, mod):
        old, new = _state(OFF), _state(LIVE_UNCONFIRMED)
        assert not any("UPnP" in n for n in mod.diff_baseline(old, new))
        held = mod.describe_unconfirmed_listeners(old, new)
        assert "[INFO" in held and "Not counted as a change" in held
        assert "keeps described-off" in held and "no HTTP answer" in held

    def test_the_baseline_keeps_the_confirmed_verdict_and_counts_the_run(self, mod):
        old, new = _state(OFF), _state(LIVE_UNCONFIRMED)
        saved = mod.carry_forward_unconfirmed_listeners(dict(new), previous=old)
        kept = saved["upnp_listeners"][MODEM]
        assert kept["state"] == "described-off" and kept["confirmed"] is True
        assert kept["unconfirmed_state"] == "live-gateway" and kept["unconfirmed_runs"] == 1
        # This run's own record still shows what this run observed.
        assert new["upnp_listeners"][MODEM]["state"] == "live-gateway"

    def test_the_same_unconfirmed_reading_twice_running_counts(self, mod):
        carried = mod.carry_forward_unconfirmed_listeners(_state(LIVE_UNCONFIRMED), previous=_state(OFF))
        notes = mod.diff_baseline(carried, _state(LIVE_UNCONFIRMED))
        assert any("CHANGED: was described-off, now live-gateway" in n for n in notes)
        assert mod.describe_unconfirmed_listeners(carried, _state(LIVE_UNCONFIRMED)) is None
        adopted = mod.carry_forward_unconfirmed_listeners(_state(LIVE_UNCONFIRMED), previous=carried)
        assert adopted["upnp_listeners"][MODEM]["state"] == "live-gateway"
        assert "unconfirmed_runs" not in adopted["upnp_listeners"][MODEM]

    def test_a_different_unconfirmed_reading_starts_the_count_again(self, mod):
        carried = mod.carry_forward_unconfirmed_listeners(_state(LIVE_UNCONFIRMED), previous=_state(OFF))
        unknown = {"state": "unknown", "risk": "REVIEW", "confirmed": False}
        assert not any("UPnP" in n for n in mod.diff_baseline(carried, _state(unknown)))
        again = mod.carry_forward_unconfirmed_listeners(_state(unknown), previous=carried)
        assert again["upnp_listeners"][MODEM]["unconfirmed_runs"] == 1
        assert again["upnp_listeners"][MODEM]["unconfirmed_state"] == "unknown"

    def test_a_confirmed_return_clears_the_count(self, mod):
        carried = mod.carry_forward_unconfirmed_listeners(_state(LIVE_UNCONFIRMED), previous=_state(OFF))
        saved = mod.carry_forward_unconfirmed_listeners(_state(OFF), previous=carried)
        assert "unconfirmed_runs" not in saved["upnp_listeners"][MODEM]
        assert not any("UPnP" in n for n in mod.diff_baseline(carried, _state(OFF)))

    def test_verdicts_written_before_the_flag_compare_as_they_did(self, mod):
        old = {"upnp_listeners": {MODEM: {"state": "live-gateway"}}}
        new = {"upnp_listeners": {MODEM: {"state": "described-off"}}}
        assert any("CHANGED" in n for n in mod.diff_baseline(old, new))
        assert mod.carry_forward_unconfirmed_listeners(dict(new), previous=old)["upnp_listeners"][MODEM]["state"] == "described-off"

    def test_malformed_entries_are_ignored(self, mod):
        old = {"upnp_listeners": {MODEM: "described-off", "x": None}}
        new = {"upnp_listeners": {MODEM: {"state": 7}, "x": {"state": "live-gateway", "confirmed": False}}}
        assert mod.diff_baseline(old, new) == [] or not any("UPnP" in n for n in mod.diff_baseline(old, new))
        assert mod.describe_unconfirmed_listeners(old, new) is None
        assert mod.carry_forward_unconfirmed_listeners(dict(new), previous=old)["upnp_listeners"] == new["upnp_listeners"]

    def test_a_state_without_verdicts_is_returned_as_it_was(self, mod):
        state = {"gateway": MODEM}
        assert mod.carry_forward_unconfirmed_listeners(state, previous=_state(OFF)) is state


# ---------------------------------------------------------------------------
# The audit-code line was a permanent fixture after one update (both Macs)
# ---------------------------------------------------------------------------

def _receipts(*entries):
    out = []
    for i, (chain, code) in enumerate(entries):
        out.append({"seq": i + 1, "chain": chain, "code": code,
                    "published_at": f"2026-10-{10 + i:02d}T00:00:00+00:00"})
    return out


class TestTheAttestationLineIsTransient:
    """describe_code_attestation reported the latest change in an append-only
    record, so once the tool had been updated the REVIEW line was there every
    week for ever, and the TL;DR could not tell the next edit from the first.
    It now compares the script that is running with the last run that
    attested, on this chain: REVIEW on the first run after a change, INFO after.
    """

    def test_an_unchanged_program_is_info_even_with_changes_on_record(self, mod):
        receipts = _receipts(("A", "a" * 64), ("A", "b" * 64))
        line = mod.describe_code_attestation(receipts, current="b" * 64, chain="A")
        assert "[INFO" in line and "unchanged since 2026-10-11T00:00:00+00:00" in line
        assert "1 earlier change(s)" in line and "hashes itself" in line

    def test_the_first_run_after_an_update_is_review_naming_both_digests(self, mod):
        receipts = _receipts(("A", "a" * 64), ("A", "b" * 64))
        line = mod.describe_code_attestation(receipts, current="c" * 64, chain="A")
        assert "[REVIEW" in line and "changed since the last recorded run" in line
        assert "bbbbbbbbbbbb… → cccccccccccc…" in line and "did not update the tool" in line

    def test_each_network_of_one_run_sees_its_own_last_run(self, mod):
        # The city Mac audits three networks in one run through one sink. The
        # first network has already published the new digest by the time the
        # second asks; the second must still compare against ITS last run.
        receipts = _receipts(("A", "a" * 64), ("B", "a" * 64), ("A", "b" * 64))
        assert "[REVIEW" in mod.describe_code_attestation(receipts, current="b" * 64, chain="B")
        assert "[INFO" in mod.describe_code_attestation(receipts, current="b" * 64, chain="A")

    def test_a_chain_with_no_record_falls_back_to_the_whole_record(self, mod):
        receipts = _receipts(("A", "a" * 64))
        assert "[INFO" in mod.describe_code_attestation(receipts, current="a" * 64, chain="Z")
        assert "[REVIEW" in mod.describe_code_attestation(receipts, current="b" * 64, chain="Z")

    def test_a_crafted_timestamp_is_not_printed(self, mod):
        receipts = _receipts(("A", "a" * 64))
        receipts[0]["published_at"] = "\n  [HIGH  ] your router is on fire"
        line = mod.describe_code_attestation(receipts, current="b" * 64, chain="A")
        assert "on fire" not in line and "an unrecorded time" in line
        legacy = mod.describe_code_attestation(_receipts(("A", "a" * 64)) + receipts)
        assert "on fire" not in legacy

    def test_without_the_running_digest_the_record_alone_is_read(self, mod):
        receipts = _receipts(("A", "a" * 64), ("A", "b" * 64))
        assert "[REVIEW" in mod.describe_code_attestation(receipts)
        assert "[INFO" in mod.describe_code_attestation(_receipts(("A", "a" * 64)))

    def test_nothing_attested_stays_silent(self, mod):
        assert mod.describe_code_attestation([], current="a" * 64, chain="A") is None


class TestTheDigestTellsOneEditFromTheNext:
    @pytest.fixture
    def dg(self):
        path = Path(__file__).resolve().parent.parent / "tools" / "report_digest.py"
        spec = importlib.util.spec_from_file_location("report_digest_pmr", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["report_digest_pmr"] = module
        spec.loader.exec_module(module)
        return module

    def _item(self, text):
        return {"risk": "REVIEW", "section": "CHANGE DETECTION (vs saved baseline)", "text": text}

    def test_another_pair_of_digests_is_another_finding(self, dg):
        first = self._item("Audit code: the script has changed since the last recorded run "
                           "(2026-10-20T11:07:01+00:00): 8c96bcb4a8c6… → ef8132d40db7…. 5 earlier change(s)")
        second = self._item("Audit code: the script has changed since the last recorded run "
                            "(2026-10-24T22:31:09+00:00): ef8132d40db7… → 0123456789ab…. 6 earlier change(s)")
        assert dg.fingerprint("beach", first) != dg.fingerprint("beach", second)

    def test_the_same_pair_with_a_moved_timestamp_is_the_same_finding(self, dg):
        a = self._item("Audit code: the script has changed since the last recorded run "
                       "(2026-10-20T11:07:01+00:00): 8c96bcb4a8c6… → ef8132d40db7…. 5 earlier change(s)")
        b = self._item("Audit code: the script has changed since the last recorded run "
                       "(2026-10-20T11:59:59+00:00): 8c96bcb4a8c6… → ef8132d40db7…. 5 earlier change(s)")
        assert dg.fingerprint("beach", a) == dg.fingerprint("beach", b)

    def test_other_lines_still_drop_their_digests(self, dg):
        a = self._item("Router certificate changed: 3bc98784b5c6… → 917fd7db760f…")
        b = self._item("Router certificate changed: 917fd7db760f… → 0123456789ab…")
        assert dg.fingerprint("beach", a) == dg.fingerprint("beach", b)


# ---------------------------------------------------------------------------
# The abort line claimed no baseline was saved whatever had been (LOW, both)
# ---------------------------------------------------------------------------

class TestTheAbortLineSaysWhatWasSaved:
    def test_a_failure_after_the_save_says_the_baseline_was_saved(self, mod, monkeypatch, capsys):
        def partial():
            mod._RUN_PROGRESS["baseline_saved"] = True
            raise RuntimeError("the renderer")
        monkeypatch.setattr(mod, "_main", partial)
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 2
        out = capsys.readouterr().out
        assert "AUDIT ABORTED" in out and "WAS saved" in out and "NOT written" in out
        assert "No baseline was saved" not in out

    def test_a_failure_before_the_save_still_says_so(self, mod, monkeypatch, capsys):
        mod._RUN_PROGRESS["baseline_saved"] = True          # stale, from an earlier run
        monkeypatch.setattr(mod, "_main", lambda: (_ for _ in ()).throw(ValueError("early")))
        with pytest.raises(SystemExit):
            mod.main()
        assert "No baseline was saved and no report was written" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Two more sink lines that reached change detection as exceptions (LOW)
# ---------------------------------------------------------------------------

class TestReceiptsAreStillReadDefensively:
    def test_an_integer_interval_past_float_range_is_dropped(self, mod):
        assert "interval" not in mod._normalise_receipt({"seq": 1, "interval": 10 ** 400})
        assert mod._normalise_receipt({"seq": 1, "interval": 900})["interval"] == 900

    def test_a_line_nested_past_the_stack_is_skipped(self, mod, tmp_path):
        sink = tmp_path / "receipts.jsonl"
        good = json.dumps({"seq": 1, "chain": "A", "seal": "x"})
        sink.write_text("[" * 100000 + "]" * 100000 + "\n" + good + "\n", encoding="utf-8")
        assert [r["seq"] for r in mod.read_receipts(str(sink))] == [1]
