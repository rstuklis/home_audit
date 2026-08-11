"""Meta-tests for the scaffolding itself.

If these fail, no other result in the suite can be trusted: they prove the
module imported, the sandbox actually blocks real system access, and the
command-dispatching fakes route commands the way every other test assumes.
"""

import importlib.util
import re
import socket
import subprocess

import pytest

from conftest import (
    PROJECT_DIR,
    EscapedSandbox,
    make_check_port,
    make_run,
    make_subprocess_run,
)


class TestModuleImport:
    def test_module_under_test_is_importable(self, mod):
        assert mod.__name__ == "home_net_audit"
        assert callable(mod.run)

    def test_importing_the_module_runs_nothing(self):
        """Re-execute the source and assert the import itself scans nothing.

        Checking `mod.__name__ != "__main__"` would prove nothing: conftest
        assigns that name via spec_from_file_location, so it can never be
        "__main__" no matter what the source says. Execute the module instead —
        the autouse sandbox turns any subprocess or socket call into
        EscapedSandbox, and a missing `if __name__ == "__main__"` guard would
        run main() and raise (argparse would SystemExit on pytest's argv).
        """
        spec = importlib.util.spec_from_file_location(
            "home_net_audit_import_probe", PROJECT_DIR / "home_net_audit.py")
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        assert callable(probe.main), "module executed but exposed no main()"

    def test_the_main_guard_is_present_in_the_source(self):
        # Belt-and-braces companion to the test above, and the one that names
        # the actual mechanism so a reader knows what protects them.
        src = (PROJECT_DIR / "home_net_audit.py").read_text(encoding="utf-8")
        assert re.search(
            r'^if __name__ == ["\']__main__["\']:\s*\n\s+main\(\)\s*$',
            src, re.MULTILINE), "the __main__ guard around main() is gone"


class TestSandboxBlocksRealAccess:
    def test_subprocess_is_blocked(self):
        with pytest.raises(EscapedSandbox):
            subprocess.run(["echo", "hi"])

    def test_outbound_socket_connect_is_blocked(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(EscapedSandbox):
                s.connect(("example.com", 80))
        finally:
            s.close()

    def test_create_connection_is_blocked(self):
        with pytest.raises(EscapedSandbox):
            socket.create_connection(("example.com", 80), timeout=1)

    def test_dns_resolution_is_blocked(self):
        with pytest.raises(EscapedSandbox):
            socket.gethostbyaddr("8.8.8.8")

    def test_guard_survives_a_bare_except_exception(self):
        # The code under test wraps most system calls in `except Exception`.
        # The guard must escape those handlers, or a leak would look like a pass.
        with pytest.raises(EscapedSandbox):
            try:
                subprocess.run(["echo", "hi"])
            except Exception:  # noqa: BLE001 - deliberately over-broad
                pytest.fail("guard was swallowed by `except Exception`")

    def test_pure_socket_conversions_still_work(self):
        # get_all_interfaces() converts a hex netmask via inet_ntoa; blocking
        # the whole socket module would break the parsers under test.
        assert socket.inet_ntoa((0xFFFFFF00).to_bytes(4, "big")) == "255.255.255.0"


class TestSandboxRedirectsUserData:
    def test_baseline_paths_point_into_tmp(self, mod, tmp_path):
        assert str(tmp_path) in mod.BASELINE_FILE
        assert str(tmp_path) in mod.LABELS_FILE
        assert str(tmp_path) in mod.NETWORKS_FILE

    def test_save_and_load_roundtrip_stays_in_tmp(self, mod, tmp_path):
        mod.save_baseline({"timestamp": "t0", "dns": ["1.1.1.1"]})
        assert mod.load_baseline() == {"timestamp": "t0", "dns": ["1.1.1.1"]}
        written = list(tmp_path.rglob("baseline.json"))
        assert len(written) == 1, "baseline escaped the tmp sandbox"

    def test_missing_baseline_reads_as_none(self, mod):
        assert mod.load_baseline() is None

    def test_labels_and_networks_default_cleanly(self, mod):
        assert mod.load_labels() == {}
        assert mod.load_networks() == dict(mod.DEFAULT_NETWORKS)


class TestCommandDispatch:
    def test_exact_match_beats_substring(self):
        # 'ifconfig' is a substring of 'ifconfig -a'; the exact key must win
        # regardless of insertion order, or interface tests silently misroute.
        fake = make_run({"ifconfig": "SHORT", "ifconfig -a": "LONG"})
        assert fake(["ifconfig", "-a"]) == "LONG"
        assert fake(["ifconfig"]) == "SHORT"

    def test_substring_match_in_insertion_order(self):
        fake = make_run({"socketfilterfw --getglobalstate": "GLOBAL"})
        assert fake(["/usr/libexec/ApplicationFirewall/socketfilterfw",
                     "--getglobalstate"]) == "GLOBAL"

    def test_unmatched_command_returns_empty_like_the_real_run(self):
        # The real run() returns "" when a command is missing or times out.
        assert make_run({})(["no", "such", "command"]) == ""

    def test_calls_are_recorded(self):
        fake = make_run({})
        fake(["arp", "-a"])
        assert fake.calls == ["arp -a"]

    def test_subprocess_fake_defaults_to_failure(self):
        result = make_subprocess_run({})(["launchctl", "print", "system/nope"])
        assert result.returncode == 1
        assert result.stdout == ""

    def test_subprocess_fake_supports_returncode_tuples(self):
        fake = make_subprocess_run({"launchctl print system/ok": (0, "state = running")})
        result = fake(["launchctl", "print", "system/ok"])
        assert (result.returncode, result.stdout) == (0, "state = running")

    def test_subprocess_fake_plain_string_means_success(self):
        fake = make_subprocess_run({"launchctl print-disabled": '"com.apple.smbd" => false'})
        result = fake(["launchctl", "print-disabled", "system"])
        assert result.returncode == 0

    def test_check_port_fake_reports_only_listed_ports(self):
        fake = make_check_port([22, 445])
        assert fake("127.0.0.1", 22) is True
        assert fake("127.0.0.1", 5900) is False


class TestFixtureLoading:
    def test_missing_fixture_error_names_the_directory(self, fixture):
        with pytest.raises(FileNotFoundError) as excinfo:
            fixture("definitely_not_here.out")
        assert "definitely_not_here.out" in str(excinfo.value)
