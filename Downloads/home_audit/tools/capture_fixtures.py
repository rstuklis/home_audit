#!/usr/bin/env python3
"""Capture real command output on this Mac and redact it into test fixtures.

Run this on a Mac that is on a real network. The CI runner is a virtualised
instance in a datacenter with no Wi-Fi hardware and no LAN neighbours, so the
wireless and neighbour fixtures still come from documentation rather than from
reality — and the last capture proved how much that matters, turning up two
parser bugs that neither testing nor review had found.

    python3 tools/capture_fixtures.py            # capture and redact
    python3 tools/capture_fixtures.py --raw      # keep real values (do NOT commit)

Everything lands in captured/ for review; nothing overwrites tests/fixtures/
automatically. Diff, read, then copy across what you want.

REDACTION. A capture holds your SSID, your access points' BSSIDs, every MAC on
your LAN, your account name and your addressing. This repository is public, and
the tool exists for people who are targeted, so redaction is the default and
--raw is opt-in. Substitutions are consistent within a run — one real MAC
becomes one fake MAC everywhere it appears — so the fixtures stay internally
coherent and still exercise the parsers honestly.

Read the output before committing it. Redaction here is careful, not perfect,
and only you can recognise something identifying that it missed. The summary
printed at the end lists every substitution made, so you can check the mapping
rather than trusting it.
"""

import argparse
import ipaddress
import os
import re
import subprocess
import sys

# The commands the parsers read, named after the fixture each one feeds.
COMMANDS = {
    "route_get_default":        ["route", "-n", "get", "default"],
    "netstat_rn":               ["netstat", "-rn"],
    "ifconfig_a":               ["ifconfig", "-a"],
    "scutil_dns":               ["scutil", "--dns"],
    # `arp -a`, not `-an`: the audit resolves names here, so a capture with -n
    # would document a command nothing runs. It costs a redaction step — the
    # name column is then full of the LAN's device names.
    "arp_a_typical":            ["arp", "-a"],
    "ndp_a":                    ["ndp", "-an"],
    "ndp_r":                    ["ndp", "-rn"],
    "lsof_tcp_listen":          ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
    "lsof_udp":                 ["lsof", "-nP", "-iUDP"],
    "netstat_anp_tcp":          ["netstat", "-anp", "tcp"],
    "netstat_anp_udp":          ["netstat", "-anp", "udp"],
    "firewall_globalstate_on":  ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
    "firewall_stealth_on":      ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
    "firewall_blockall_off":    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"],
    "launchctl_print_disabled": ["launchctl", "print-disabled", "system"],
    "launchctl_print_sshd":     ["launchctl", "print", "system/com.openssh.sshd"],
    "launchctl_print_smbd":     ["launchctl", "print", "system/com.apple.smbd"],
    "launchctl_print_screensharing": ["launchctl", "print", "system/com.apple.screensharing"],
    "systemsetup_rae":          ["systemsetup", "-getremoteappleevents"],
    "security_trust":           ["security", "dump-trust-settings", "-d"],
    "wifi_sp_airport":          ["system_profiler", "SPAirPortDataType"],
}

# Only the commands the audit itself reads with merge_stderr=True. Everywhere
# else run() returns stdout alone, so the fixture must be stdout alone —
# capturing a merged stream here would paper over exactly the bug this script
# exists to find. Output that lands only on stderr is reported, not merged.
MERGE_STDERR = {"security_trust"}

# Commands the audit does not read through run() at all. _launchd_running
# calls subprocess directly and decides on the exit status, so a label that is
# not loaded answering on stderr is read correctly as absent — the generic
# "answers on stderr" note is a false alarm for these three, and a tool that
# reports a finding where there is none teaches people to skip its output.
# What they cannot do is produce a fixture: there is nothing on stdout to keep
# unless the service is switched on.
EXIT_STATUS_ONLY = {"launchctl_print_sshd", "launchctl_print_smbd",
                    "launchctl_print_screensharing"}

# Ordered alternation, matched in one pass. Order is the whole point: a MAC
# also satisfies the IPv6 pattern, so substituting separately turned
# "at a4:83:e7:01:01:01" into "at 2001:db8::1" — the MAC replacement was itself
# re-matched as an address. One pass with re.sub never rescans what it wrote.
TOKEN_RE = re.compile(
    r"(?P<mac>\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b)"
    r"|(?P<v6>\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:%\w+)?\b)"
    r"|(?P<v4>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<host>\b[\w-]+\.(?:local|lan|home|internal)\b)"
)

# The field labels that appear inside a Wi-Fi network block. Used only to
# document intent; the SSID rule below is structural, not a name lookup.
WIFI_SECTIONS = ("Current Network Information", "Other Local Wi-Fi Networks")

# Accounts that name the machine's role rather than its owner.
SYSTEM_USERS = {"root", "nobody", "daemon", "unknown"}

# Public resolvers used by so many people that they identify nobody. They are
# kept because the audit's DNS check is built on recognising them: redact
# 8.8.8.8 into an arbitrary address and the fixture stops describing "a known
# provider" and starts describing "an unfamiliar resolver", which is the thing
# the check warns about. Deliberately NOT including the ISP resolvers that
# KNOWN_DNS also lists — an ISP names a provider and a region, so those are
# redacted like any other public address, and the resulting fixture exercises
# the unfamiliar-resolver path honestly. test_capture_redaction pins both
# halves of that against the audit's own table.
PRESERVED_DNS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2620:fe::fe", "2620:fe::9", "2620:119:35::35", "2620:119:53::53",
}


# Apple assigns these to the secure-enclave bridge interface with the same
# literal values on every Mac that has one, which is why they arrive as a
# 00:11:22 / 33:44:55 pair rather than anything a vendor would allocate. They
# name a model of Mac, not a machine, so redacting them protects nobody — and
# it costs something, because the two are indistinguishable once truncated to
# their shared fe80::aede:48ff prefix, and the tool then has to ask a person
# to adjudicate an ambiguity that only exists because it substituted them.
# tests/fixtures/lsof_udp.out already carried one of these in the clear.
APPLE_BRIDGE_MACS = {"ac:de:48:00:11:22", "ac:de:48:33:44:55"}
APPLE_BRIDGE_V6 = {"fe80::aede:48ff:fe00:1122", "fe80::aede:48ff:fe33:4455"}


class Redactor:
    """Consistent substitutions: one real value maps to one fake value.

    Consistency is what keeps a redacted capture usable as a fixture. If the
    router's MAC in `arp -an` and the same MAC in `ndp -an` became two
    different fake values, the cross-table checks would have nothing to find.
    """

    def __init__(self):
        self.macs = {}
        self.v6 = {}
        self.v4 = {}
        self.hosts = {}
        self.ssids = {}
        self.users = {}
        self.domains = {}
        self.collapsed = {}      # truncated spelling -> full spelling
        self.ambiguous = set()   # truncated-looking, but no unique full form

    # netstat pads its Destination and Gateway columns to a fixed width and
    # cuts anything longer, so a link-local that ifconfig prints in full comes
    # back from the routing table with its tail missing. Below this many
    # characters a token is far more likely to be a genuinely short address
    # than a cut one, and guessing there would collapse real distinct hosts.
    TRUNCATION_FLOOR = 12

    def _full_form_of(self, real):
        """The one known address `real` looks like a truncation of, or None.

        Ambiguity is not resolved by picking: 'fe80::1' is a string prefix of
        'fe80::1465:426a:443:4ac2%en0' without being a truncation of it, and
        collapsing those would merge two hosts into one. A unique match is
        treated as truncation; anything else is left alone and reported.
        """
        addr, _, zone = real.partition("%")
        if zone or len(addr) < self.TRUNCATION_FLOOR:
            return None
        hits = [k for k in self.v6
                if k.partition("%")[0].startswith(addr)
                and len(k.partition("%")[0]) > len(addr)]
        if len(hits) == 1:
            return hits[0]
        if hits:
            self.ambiguous.add(real)
        return None

    def prime(self, texts):
        """Learn every address's longest spelling before substituting any.

        Order decides correlation. Met in file order, the full spelling and the
        truncated one are two unrelated strings and become two unrelated fake
        hosts, so the routing table can no longer be lined up against the
        interface list — and cross-table agreement is most of what these
        fixtures are for. Registering longest-first means the truncated form
        arrives to find its own full form already known.
        """
        seen = set()
        for text in texts:
            for m in TOKEN_RE.finditer(text):
                if m.lastgroup == "v6":
                    seen.add(m.group(0))
        for token in sorted(seen, key=len, reverse=True):
            self._v6(token)

    # -- address-shaped tokens ------------------------------------------

    def _mac(self, real):
        real = real.lower()
        # Broadcast and multicast MACs are protocol constants, not identities,
        # and parsers key off them (arp lists ff:ff:... for the broadcast row).
        if real.startswith(("ff:ff", "01:00:5e", "1:0:5e", "33:33")):
            return real
        # The all-zeros link-layer address is a sentinel, not a device: arp and
        # ndp print it for a neighbour that never answered. Substituting it
        # invents a resolved host where the machine reported an unresolved one,
        # and the parsers' "skip the incomplete rows" arms stop being reached.
        if set(real.split(":")) == {"0"} or set(real.split(":")) == {"00"}:
            return real
        # arp and ndp print an octet under 0x10 unpadded ("ac:de:48:0:11:22")
        # where ifconfig pads it ("ac:de:48:00:11:22"). Same NIC, two spellings
        # — and keying on the spelling gave one interface two fake identities,
        # which is the exact cross-table incoherence this class promises not to
        # produce. The audit has _normalise_mac for this; key on the same shape.
        key = ":".join(o.zfill(2) for o in real.split(":"))
        if key in APPLE_BRIDGE_MACS:
            return real          # keep the spelling the tool printed
        real = key
        if real not in self.macs:
            n = len(self.macs) + 1
            # Keep the locally-administered bit: a randomised MAC looks
            # different from a vendor MAC, and that difference is a signal.
            try:
                local = bool(int(real.split(":")[0], 16) & 0x02)
            except ValueError:
                local = False
            oui = "02:00:00" if local else "a4:83:e7"
            self.macs[real] = "%s:%02x:%02x:%02x" % (oui, n, n, n)
        return self.macs[real]

    def _v6(self, real):
        addr, sep, zone = real.partition("%")
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            # Not an address at all. A firmware string's "21:44:11" matches the
            # pattern and must be left exactly as it was.
            return real
        if parsed.version != 6:
            return real
        if parsed.is_multicast or parsed.is_loopback or parsed.is_unspecified:
            return real          # ff02::1, ::1, :: are constants the checks read
        # fe80:: with an all-zeros interface identifier is RFC 4291's
        # Subnet-Router anycast placeholder — no host holds it. It is how ndp
        # reports "a default route exists on this tunnel" and how netstat
        # prints an on-link prefix route, and parse_ndp_routers drops exactly
        # these so a VPN's utun entries are not read as phantom routers.
        # Giving it a host part converts every placeholder into a router the
        # parser is then obliged to keep, so a fixture redacted this way
        # asserts the precise opposite of the behaviour that was shipped.
        if parsed.is_link_local and parsed.packed[8:] == b"\x00" * 8:
            return real
        # Every Mac's loopback carries fe80::1%lo0, the same on all of them.
        # Substituting it costs the fixture a line of realism and buys no
        # privacy, and ifconfig_a.out is meant to read like a real ifconfig.
        if zone == "lo0" and parsed.compressed == "fe80::1":
            return real
        if parsed.compressed in PRESERVED_DNS or parsed.compressed in APPLE_BRIDGE_V6:
            return real
        if real not in self.v6:
            # A cut-off spelling of an address that was never substituted must
            # not be substituted either, or the routing table gains a host the
            # interface list has never heard of.
            if (len(addr) >= self.TRUNCATION_FLOOR
                    and any(k.startswith(addr) for k in APPLE_BRIDGE_V6)):
                return real
            full = self._full_form_of(real)
            if full is not None:
                # Same interface, spelled short by a narrow column. One
                # identity, so the tables still agree with each other.
                self.collapsed[real] = full
                self.v6[real] = self.v6[full]
                return self.v6[real]
            n = len(self.v6) + 1
            # A link-local interface ID is derived from the MAC, so it names
            # the hardware — but the fe80:: prefix is what marks it as a
            # link-local, and check_ipv6_routers reads exactly that.
            base = "fe80::" if parsed.is_link_local else "2001:db8::"
            self.v6[real] = "%s%x%s%s" % (base, n, sep, zone)
        return self.v6[real]

    def _v4(self, real):
        try:
            parsed = ipaddress.ip_address(real)
        except ValueError:
            return real          # a version string like 22.10.375.6
        if parsed.version != 4:
            return real
        if real in PRESERVED_DNS:
            return real
        # RFC1918 and friends are not identifying, and keeping them keeps the
        # fixture realistic: the subnet arithmetic in the parsers is real work.
        if (parsed.is_private or parsed.is_loopback or parsed.is_multicast
                or parsed.is_link_local or parsed.is_unspecified
                or parsed.is_reserved or str(parsed) == "255.255.255.255"):
            return real
        if real not in self.v4:
            # TEST-NET-2. Deliberately not TEST-NET-1: the audit probes
            # 192.0.2.1 to detect DNS interception, and a fixture that reused
            # it would read as that probe.
            self.v4[real] = "198.51.100.%d" % (len(self.v4) + 1)
        return self.v4[real]

    def _host(self, real):
        if real not in self.hosts:
            self.hosts[real] = "host-%d.local" % (len(self.hosts) + 1)
        return self.hosts[real]

    def _token(self, m):
        kind = m.lastgroup
        text = m.group(0)
        return {"mac": self._mac, "v6": self._v6,
                "v4": self._v4, "host": self._host}[kind](text)

    def addresses(self, text):
        return TOKEN_RE.sub(self._token, text)

    # -- per-command redaction ------------------------------------------

    def _ssid(self, real):
        if real not in self.ssids:
            # The connected network is listed first and keeps a stable name, so
            # an evil-twin fixture still reads as "two BSSIDs, one SSID".
            self.ssids[real] = ("HomeNet" if not self.ssids
                                else "Neighbour-%d" % len(self.ssids))
        return self.ssids[real]

    def wifi(self, text):
        """Rename SSIDs in system_profiler SPAirPortDataType output.

        An SSID is a bare ``Name:`` line, inside a network section, whose
        following line is indented deeper. That last clause is what separates a
        network from an empty-valued field: `Country Code:` sits at the same
        depth as an SSID and is followed by a sibling, while `HomeNet:` is
        followed by its own `PHY Mode:`. Matching on "bare Name: line" alone
        renames `Locale`, `Country Code` and `en0` as networks.
        """
        lines = text.splitlines()
        indents = [len(ln) - len(ln.lstrip()) for ln in lines]

        def next_indent(i):
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    return indents[j]
            return -1

        out = []
        section = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                out.append(line)
                continue
            if section is not None and indents[i] <= section:
                section = None
            if stripped.endswith(":") and ":" not in stripped[:-1]:
                label = stripped[:-1].strip()
                if label in WIFI_SECTIONS:
                    section = indents[i]
                    out.append(line)
                    continue
                if (section is not None and indents[i] > section
                        and next_indent(i) > indents[i]):
                    out.append(line[:indents[i]] + self._ssid(label) + ":")
                    continue
            out.append(line)
        return "\n".join(out) + ("\n" if text.endswith("\n") else "")

    def lsof(self, text):
        """Replace the USER column. On a personal Mac the account name is
        usually the owner's real name, which is about as identifying as the
        capture gets. Process names stay: which daemons listen is the point."""
        def sub(m):
            user = m.group("user")
            if user in SYSTEM_USERS or user.startswith("_"):
                return m.group(0)
            if user not in self.users:
                names = ("alice", "bob", "carol", "dave")
                n = len(self.users)
                self.users[user] = names[n] if n < len(names) else "user%d" % n
            return m.group("pre") + self.users[user]
        return re.sub(r"^(?P<pre>\S+\s+\d+\s+)(?P<user>\S+)", sub,
                      text, flags=re.MULTILINE)

    def arp(self, text):
        """Replace the name column of `arp -a`.

        "living-room-tv.lan" and "rebeccas-iphone" name the household's
        devices, and the second has no suffix for the generic hostname pattern
        to key off. The parser reads the address from the parentheses and
        ignores this column entirely, so nothing is lost.
        """
        def sub(m):
            name = m.group("name")
            # `?` is an unresolved entry; the mcast names are protocol
            # constants that appear on every Mac and identify nobody.
            if name == "?" or name == "broadcasthost" or name.endswith(".mcast.net"):
                return name
            if name in self.hosts.values():
                return name          # already replaced by the address pass
            if name not in self.hosts:
                _, dot, suffix = name.partition(".")
                self.hosts[name] = "host-%d%s%s" % (len(self.hosts) + 1, dot, suffix)
            return self.hosts[name]
        return re.sub(r"^(?P<name>\S+)(?= \()", sub, text, flags=re.MULTILINE)

    def dns_domains(self, text):
        """Replace search domains in `scutil --dns`. A home Mac's search domain
        is frequently the ISP's, which narrows the owner to a provider and a
        region. `local` and the reverse-DNS zones are structural and stay."""
        def sub(m):
            domain = m.group("domain")
            if domain == "local" or domain.endswith(".arpa"):
                return m.group(0)
            if domain not in self.domains:
                self.domains[domain] = ("lan" if not self.domains
                                        else "home-%d.example" % len(self.domains))
            return m.group("pre") + self.domains[domain]
        return re.sub(
            r"^(?P<pre>\s*(?:search domain\[\d+\]|domain)\s*:\s*)(?P<domain>\S+)$",
            sub, text, flags=re.MULTILINE)

    def apply(self, name, text):
        text = self.addresses(text)
        if name.startswith("wifi_"):
            text = self.wifi(text)
        elif name.startswith("lsof_"):
            text = self.lsof(text)
        elif name.startswith("arp_"):
            text = self.arp(text)
        elif name == "scutil_dns":
            text = self.dns_domains(text)
        return text

    def report(self):
        """Every substitution made, so the mapping can be checked rather than
        trusted. Printed to the terminal only — never written to a file."""
        groups = [("MAC", self.macs), ("IPv6", self.v6), ("public IPv4", self.v4),
                  ("hostname", self.hosts), ("SSID", self.ssids),
                  ("user", self.users), ("search domain", self.domains)]
        lines = []
        for label, mapping in groups:
            for real, fake in mapping.items():
                if real == fake:
                    continue     # a value mapped to itself was not substituted
                lines.append("  %-14s %s -> %s" % (label, real, fake))
        return lines

    def warnings(self):
        """Things the reader has to adjudicate, because the tool cannot.

        Kept apart from the substitution list: that list is checked for wrong
        entries, this one is where the tool says which entries it is unsure of.
        """
        lines = []
        for short, full in self.collapsed.items():
            lines.append("  column-truncated %s treated as %s (now one host)"
                         % (short, full))
        for short in sorted(self.ambiguous):
            lines.append("  %s looks truncated but matches several addresses "
                         "— left as its own host, check it is not a duplicate"
                         % short)
        return lines


def capture(name, cmd):
    """Run one command; return (text_for_fixture, note_or_None)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, "skipped: %s" % exc

    text = proc.stdout
    if name in MERGE_STDERR:
        text += proc.stderr
        return (text, None) if text.strip() else (None, "no output")

    if not text.strip():
        if name in EXIT_STATUS_ONLY:
            return None, ("service is not loaded, so there is no output to "
                          "capture — the audit reads the exit status here and "
                          "gets this right. Needs a Mac with it switched on.")
        if proc.stderr.strip():
            # Worth saying out loud: run() returns stdout, so a command that
            # answers on stderr is read by the audit as the empty string.
            return None, ("answers on stderr, which the audit reads as empty — "
                          "that is a finding, not a capture problem")
        return None, "no output"
    return text, None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", action="store_true",
                    help="Skip redaction. Real MACs, SSIDs, users and addresses. Do not commit.")
    ap.add_argument("--out", default="captured", help="Output directory (default: captured)")
    args = ap.parse_args(argv)

    if sys.platform != "darwin":
        print("This captures macOS command output; run it on a Mac.", file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    redactor = None if args.raw else Redactor()
    written, notes = 0, []

    captured = []
    for name, cmd in COMMANDS.items():
        text, note = capture(name, cmd)
        if text is None:
            notes.append("  %-28s %s" % (name, note))
            continue
        captured.append((name, text))

    if redactor:
        # Read every file before rewriting any of them. An address's full
        # spelling can live in a file captured after the one that truncates
        # it, and whichever spelling is met first is the one that gets an
        # identity — so substituting as we go makes correlation depend on the
        # order this dict happens to be written in.
        redactor.prime(t for _, t in captured)

    for name, text in captured:
        if redactor:
            text = redactor.apply(name, text)
        path = os.path.join(args.out, name + ".out")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        written += 1
        print("  wrote %-40s (%d lines)" % (path, len(text.splitlines())))

    if notes:
        print("\nnot captured:")
        print("\n".join(notes))

    print("\n%d files in %s/" % (written, args.out))
    if redactor:
        mapping = redactor.report()
        if mapping:
            print("\nsubstitutions made (check these — a wrong one means a "
                  "corrupted fixture, a missing one means a leak):")
            print("\n".join(mapping))
        flags = redactor.warnings()
        if flags:
            print("\njudgement calls (the tool could not decide these alone):")
            print("\n".join(flags))
        print("\nStill real, on purpose: RFC1918 addresses, process names, "
              "hardware models, country codes.")
    else:
        print("\nNOT REDACTED — this contains real identifying values.")

    print("\nRead the files before committing. Then compare with the current set:")
    print("  diff -ru tests/fixtures %s | head -60" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
