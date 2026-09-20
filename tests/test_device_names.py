"""What each device calls itself — and how little that is trusted.

A sweep gives an IP, a MAC and a vendor. That counts devices; it does not
recognise them, and labelling from memory is how a smart plug spent three
months recorded as "Google Nest - Upstairs". Devices announce names over mDNS,
UPnP and (through the gateway) DHCP, so the audit now asks.

Every such name is the device's own claim, free to make. These tests pin the
parser against hostile packets, the rule that nobody names somebody else's
device, and the rule that a name is shown but never counts as identification.
"""

import errno
import socket
import struct

import pytest


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _name(n):
    out = b""
    for label in n.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _ptr_reply(owner, target, qid=1):
    """A DNS reply holding one PTR record, owner compressed against the question."""
    header = struct.pack(">HHHHHH", qid, 0x8400, 1, 1, 0, 0)
    question = _name(owner) + struct.pack(">HH", 12, 1)
    rdata = _name(target)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    return header + question + answer


class _FakeUdp:
    def __init__(self, replies=(), send_error=None):
        self.replies = list(replies)
        self.send_error = send_error
        self.sent = []
    def settimeout(self, t): pass
    def sendto(self, data, addr):
        if self.send_error:
            raise self.send_error
        self.sent.append((data, addr))
    def recvfrom(self, n):
        if not self.replies:
            raise socket.timeout()
        return self.replies.pop(0)
    def close(self): pass


@pytest.fixture
def udp(mod, monkeypatch):
    def install(replies=(), send_error=None):
        fake = _FakeUdp(replies, send_error)
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: fake)
        return fake
    return install


# ---------------------------------------------------------------------------
# The DNS parser, against packets a stranger wrote
# ---------------------------------------------------------------------------

class TestParser:
    def test_a_query_round_trips_through_the_reader(self, mod):
        q = mod._dns_build_ptr_query("25.87.168.192.in-addr.arpa", qid=7, unicast_response=True)
        name, offset = mod._dns_read_name(q, 12)
        assert name == "25.87.168.192.in-addr.arpa"
        assert struct.unpack(">HH", q[offset:offset + 4]) == (12, 0x8001)

    def test_a_compressed_ptr_record_is_read(self, mod):
        pkt = _ptr_reply("25.87.168.192.in-addr.arpa", "living-room-tv.local")
        assert mod._dns_ptr_records(pkt) == [("25.87.168.192.in-addr.arpa", "living-room-tv.local")]

    def test_a_pointer_loop_does_not_hang(self, mod):
        header = struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0)
        assert mod._dns_ptr_records(header + b"\xc0\x0c") == []

    @pytest.mark.parametrize("pkt", [b"", b"\x00" * 5, b"\xff" * 12, b"\x00" * 12 + b"\x3f" + b"a" * 5])
    def test_garbage_yields_nothing_and_never_raises(self, mod, pkt):
        assert mod._dns_ptr_records(pkt) == []

    def test_a_record_claiming_more_data_than_the_packet_has_is_dropped(self, mod):
        pkt = bytearray(_ptr_reply("1.0.0.10.in-addr.arpa", "x.local"))
        rdlen_at = len(pkt) - len(_name("x.local")) - 2
        pkt[rdlen_at:rdlen_at + 2] = struct.pack(">H", 9999)
        assert mod._dns_ptr_records(bytes(pkt)) == []

    def test_an_absurd_label_is_refused_when_building(self, mod):
        with pytest.raises(ValueError):
            mod._dns_encode_name("a" * 64 + ".local")


class TestNameText:
    def test_control_characters_and_newlines_cannot_forge_report_lines(self, mod):
        text = mod._device_name_text("TV\n  [OK    ] everything is fine\x1b[2K")
        assert "\n" not in text and "\x1b" not in text

    def test_it_is_capped(self, mod):
        assert len(mod._device_name_text("x" * 500)) == mod.DEVICE_NAME_LIMIT

    def test_the_trailing_dot_of_a_dns_name_goes(self, mod):
        assert mod._device_name_text("pi.local.") == "pi.local"

    @pytest.mark.parametrize("junk", [None, "", "   ", "\x00\x01"])
    def test_nothing_in_nothing_out(self, mod, junk):
        assert mod._device_name_text(junk) == ""


# ---------------------------------------------------------------------------
# Who is allowed to answer
# ---------------------------------------------------------------------------

class TestMdns:
    def test_a_device_may_name_itself(self, mod, udp):
        udp([(_ptr_reply("52.86.168.192.in-addr.arpa", "raspberrypi.local"), ("192.168.86.52", 5353))])
        names, refused = mod.mdns_device_names(["192.168.86.52"], wait=0.05)
        assert names == {"192.168.86.52": "raspberrypi.local"} and refused is False

    def test_nobody_names_somebody_elses_device(self, mod, udp):
        # .66 answers for .52. On a LAN anyone can, and a name is how a device
        # gets recognised — so this is the forgery the rule exists to stop.
        udp([(_ptr_reply("52.86.168.192.in-addr.arpa", "google-nest.local"), ("192.168.86.66", 5353))])
        assert mod.mdns_device_names(["192.168.86.52"], wait=0.05)[0] == {}

    def test_an_answer_about_an_address_nobody_asked_about_is_ignored(self, mod, udp):
        udp([(_ptr_reply("9.9.9.9.in-addr.arpa", "x.local"), ("9.9.9.9", 5353))])
        assert mod.mdns_device_names(["192.168.86.52"], wait=0.05)[0] == {}

    def test_the_question_goes_to_the_mdns_group_asking_for_a_unicast_reply(self, mod, udp):
        fake = udp()
        mod.mdns_device_names(["192.168.86.52"], wait=0.01)
        data, dest = fake.sent[0]
        assert dest == ("224.0.0.251", 5353)
        assert data[-2:] == struct.pack(">H", 0x8001)

    def test_a_local_network_denial_is_reported_as_refused(self, mod, udp):
        udp(send_error=OSError(errno.EHOSTUNREACH, "No route to host"))
        assert mod.mdns_device_names(["192.168.86.52"], wait=0.01) == ({}, True)


class TestGatewayDns:
    def test_the_gateways_answer_counts(self, mod, udp):
        udp([(_ptr_reply("49.86.168.192.in-addr.arpa", "samsung.lan"), ("192.168.86.1", 53))])
        names, _ = mod.gateway_device_names(["192.168.86.49"], "192.168.86.1", wait=0.05)
        assert names == {"192.168.86.49": "samsung.lan"}

    def test_an_answer_from_anyone_but_the_gateway_does_not(self, mod, udp):
        udp([(_ptr_reply("49.86.168.192.in-addr.arpa", "samsung.lan"), ("192.168.86.77", 53))])
        assert mod.gateway_device_names(["192.168.86.49"], "192.168.86.1", wait=0.05)[0] == {}

    def test_no_gateway_no_question(self, mod, monkeypatch):
        monkeypatch.setattr(mod.socket, "socket", lambda *a, **k: pytest.fail("opened a socket"))
        assert mod.gateway_device_names(["192.168.86.49"], None) == ({}, False)


def _ssdp(ip, location):
    return (f"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: {location}\r\n\r\n".encode(), (ip, 1900))


DESC = "<root><device><friendlyName>{}</friendlyName><modelName>UE55</modelName></device></root>"


class TestUpnp:
    def _run(self, mod, monkeypatch, udp, replies, pages):
        udp(replies)
        fetched = []

        def fake_get(host, port, path, timeout=3.0, limit=65536):
            fetched.append((host, port, path))
            return pages.get((host, port, path))
        monkeypatch.setattr(mod, "_http_get_plain", fake_get)
        names, _ = mod.upnp_device_names({"192.168.86.49", "192.168.86.83"}, wait=0.05)
        return names, fetched

    def test_the_friendly_name_is_read_from_the_devices_own_description(self, mod, monkeypatch, udp):
        names, _ = self._run(mod, monkeypatch, udp,
                             [_ssdp("192.168.86.49", "http://192.168.86.49:9197/dmr")],
                             {("192.168.86.49", 9197, "/dmr"): (200, "", DESC.format("[TV] Lounge"))})
        assert names == {"192.168.86.49": "[TV] Lounge"}

    def test_a_location_on_another_host_is_never_fetched(self, mod, monkeypatch, udp):
        names, fetched = self._run(mod, monkeypatch, udp,
                                   [_ssdp("192.168.86.49", "http://203.0.113.9/desc.xml")], {})
        assert fetched == [] and names == {}

    def test_a_non_http_location_is_never_fetched(self, mod, monkeypatch, udp):
        _, fetched = self._run(mod, monkeypatch, udp, [_ssdp("192.168.86.49", "file:///etc/passwd")], {})
        assert fetched == []

    def test_a_responder_that_is_not_one_of_the_swept_devices_is_ignored(self, mod, monkeypatch, udp):
        _, fetched = self._run(mod, monkeypatch, udp, [_ssdp("192.168.86.200", "http://192.168.86.200/d")], {})
        assert fetched == []

    def test_each_device_is_fetched_once_however_often_it_answers(self, mod, monkeypatch, udp):
        _, fetched = self._run(mod, monkeypatch, udp,
                               [_ssdp("192.168.86.49", "http://192.168.86.49/a")] * 5, {})
        assert len(fetched) == 1

    def test_markup_in_a_name_is_decoded_not_trusted(self, mod, monkeypatch, udp):
        names, _ = self._run(mod, monkeypatch, udp,
                             [_ssdp("192.168.86.83", "http://192.168.86.83/d")],
                             {("192.168.86.83", 80, "/d"): (200, "", DESC.format("Rob&apos;s Pearl &amp; Co"))})
        assert names == {"192.168.86.83": "Rob's Pearl & Co"}

    def test_the_model_name_is_the_fallback(self, mod, monkeypatch, udp):
        names, _ = self._run(mod, monkeypatch, udp,
                             [_ssdp("192.168.86.83", "http://192.168.86.83/d")],
                             {("192.168.86.83", 80, "/d"): (200, "", "<root><modelName>Pearl Akoya</modelName></root>")})
        assert names == {"192.168.86.83": "Pearl Akoya"}


# ---------------------------------------------------------------------------
# Putting it on the device list
# ---------------------------------------------------------------------------

@pytest.fixture
def sources(mod, monkeypatch):
    def install(mdns=None, upnp=None, dns=None, refused=False):
        monkeypatch.setattr(mod, "mdns_device_names", lambda ips, wait=2.5: (mdns or {}, refused))
        monkeypatch.setattr(mod, "upnp_device_names", lambda ips, wait=3.0, max_fetches=24: (upnp or {}, refused))
        monkeypatch.setattr(mod, "gateway_device_names", lambda ips, gw, wait=1.5: (dns or {}, refused))
    return install


class TestCollect:
    def test_names_are_attached_by_source(self, mod, sources):
        sources(mdns={"10.0.0.2": "pi.local"}, upnp={"10.0.0.2": "Kitchen Pi"}, dns={"10.0.0.3": "plug.lan"})
        devices = [{"ip": "10.0.0.2", "mac": "aa"}, {"ip": "10.0.0.3", "mac": "bb"}, {"ip": "10.0.0.4", "mac": "cc"}]
        assert mod.collect_device_names(devices, "10.0.0.1") == ""
        assert devices[0]["names"] == {"upnp": "Kitchen Pi", "mdns": "pi.local"}
        assert devices[1]["names"] == {"dns": "plug.lan"}

    def test_a_silent_device_gets_no_key_rather_than_an_empty_name(self, mod, sources):
        sources()
        devices = [{"ip": "10.0.0.4", "mac": "cc"}]
        mod.collect_device_names(devices, "10.0.0.1")
        assert "names" not in devices[0]

    def test_the_friendliest_source_is_the_one_shown(self, mod):
        d = {"names": {"dns": "a.lan", "mdns": "a.local", "upnp": "Lounge TV"}}
        assert mod.announced_name(d) == ("Lounge TV", "upnp")
        assert mod.announced_name({"names": {"dns": "a.lan"}}) == ("a.lan", "dns")

    @pytest.mark.parametrize("junk", [{}, {"names": None}, {"names": "x"}, {"names": {"mdns": ""}}, {"names": {"bogus": "y"}}])
    def test_a_malformed_saved_device_has_no_name(self, mod, junk):
        assert mod.announced_name(junk) == ("", "")

    def test_a_refusal_by_the_os_is_said_once_and_plainly(self, mod, sources):
        sources(refused=True)
        note = mod.collect_device_names([{"ip": "10.0.0.4", "mac": "cc"}], "10.0.0.1")
        assert "refused by the OS" in note

    def test_no_devices_no_questions(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "mdns_device_names", lambda *a, **k: pytest.fail("asked anyway"))
        assert mod.collect_device_names([], "10.0.0.1") == ""


class TestDisplay:
    def _print(self, mod, capsys, device, labels=None):
        mod._print_devices_grouped([dict(device, subnet="192.168.86.0/24")], labels or {}, {})
        return capsys.readouterr().out

    def test_the_name_is_shown_quoted_with_its_source(self, mod, capsys):
        out = self._print(mod, capsys, {"ip": "192.168.86.49", "mac": "8c:79:f5:8c:48:a7",
                                        "vendor": "Samsung", "names": {"upnp": "[TV] Lounge"}})
        assert 'announces "[TV] Lounge" [upnp]' in out

    def test_a_name_alone_does_not_make_a_device_identified(self, mod, capsys):
        # The whole point. A private-MAC device that calls itself "Google Nest"
        # is still one the owner has to account for.
        out = self._print(mod, capsys, {"ip": "192.168.86.34", "mac": "02:4b:43:1d:eb:b5",
                                        "vendor": mod.PRIVATE_MAC_VENDOR, "names": {"mdns": "google-nest.local"}})
        assert "<-- unlabelled" in out and "1 unidentified device(s)" in out

    def test_the_owners_label_still_comes_first(self, mod, capsys):
        out = self._print(mod, capsys, {"ip": "192.168.86.49", "mac": "8c:79:f5:8c:48:a7",
                                        "vendor": "Samsung", "names": {"upnp": "[TV] Lounge"}},
                          labels={"8c:79:f5:8c:48:a7": "Lounge TV"})
        line = next(l for l in out.splitlines() if "192.168.86.49" in l)
        assert line.index("Lounge TV") < line.index("announces")


class TestReports:
    def test_announced_names_are_self_reported_evidence(self, mod):
        assert mod.EVIDENCE["device_names"][0] == mod.SELF_REPORTED

    def test_the_provenance_block_lists_them_only_when_a_device_spoke(self, mod):
        spoke = {"devices": [{"ip": "1", "mac": "a", "names": {"mdns": "x.local"}}]}
        silent = {"devices": [{"ip": "1", "mac": "a"}]}
        assert "device_names" in mod.findings_by_evidence(spoke).get(mod.SELF_REPORTED, [])
        assert "device_names" not in mod.findings_by_evidence(silent).get(mod.SELF_REPORTED, [])

    def test_a_hostile_name_is_escaped_in_the_html_report(self, mod, tmp_path):
        out = tmp_path / "r.html"
        mod.generate_html_report({"devices": [{"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "",
                                               "subnet": "10.0.0.0/24",
                                               "names": {"upnp": "<script>alert(1)</script>"}}]}, str(out))
        page = out.read_text()
        assert "<script>alert(1)</script>" not in page
        assert "Announces itself as" in page

    def test_a_name_change_is_not_reported_as_a_network_change(self, mod):
        old = {"devices": [{"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff", "subnet": "10.0.0.0/24"}],
               "scanned_subnets": ["10.0.0.0/24"]}
        new = {"devices": [{"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff", "subnet": "10.0.0.0/24",
                            "names": {"mdns": "pi.local"}}], "scanned_subnets": ["10.0.0.0/24"]}
        assert mod.diff_baseline(old, new) == []
