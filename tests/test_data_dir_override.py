"""HOME_NET_AUDIT_DIR — one switch that moves everything the tool remembers.

This exists because of a real incident rather than a hypothetical. Ad-hoc
verification — a `python -c` snippet importing the module to check one function
— writes to the real ~/.home_net_audit unless every path is redirected
individually, and missing one is silent: the writes succeed. It surfaced later
as a live baseline carrying invented devices and a seal chain with entries no
audit had produced, which then propagated into a real run through
carry-forward. One variable is something a careless one-liner will actually set;
four separate module attributes are not.

The module reads it once at import, so these tests re-import under a patched
environment rather than poking the constant.
"""

import importlib.util
import os
import sys

import pytest

MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "home_net_audit.py")


def load_with_env(monkeypatch, value):
    """Import a FRESH copy of the module with HOME_NET_AUDIT_DIR set to `value`.

    A fresh copy, not the shared `mod` fixture: the paths are computed at import
    and the point of the test is what import does with the environment.
    """
    if value is None:
        monkeypatch.delenv("HOME_NET_AUDIT_DIR", raising=False)
    else:
        monkeypatch.setenv("HOME_NET_AUDIT_DIR", str(value))
    spec = importlib.util.spec_from_file_location("hna_env_probe", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestEverythingFollowsTheOverride:
    @pytest.mark.parametrize("attr", ["BASELINE_FILE", "HISTORY_FILE",
                                      "LABELS_FILE", "NETWORKS_FILE"])
    def test_each_remembered_path_moves(self, monkeypatch, tmp_path, attr):
        m = load_with_env(monkeypatch, tmp_path)
        assert os.path.dirname(getattr(m, attr)) == str(tmp_path)

    def test_the_directory_itself_moves(self, monkeypatch, tmp_path):
        assert load_with_env(monkeypatch, tmp_path).BASELINE_DIR == str(tmp_path)

    def test_per_network_selection_stays_inside_it(self, monkeypatch, tmp_path):
        # Selection derives from BASELINE_FILE, so it must inherit the override
        # rather than reaching back to a default root.
        m = load_with_env(monkeypatch, tmp_path)
        m.select_network_baseline("192.168.87.0/24")
        assert str(tmp_path) in m.BASELINE_FILE
        assert str(tmp_path) in m.HISTORY_FILE

    def test_nothing_resolves_into_the_real_directory(self, monkeypatch, tmp_path):
        real = os.path.expanduser("~/.home_net_audit")
        m = load_with_env(monkeypatch, tmp_path)
        m.select_network_baseline("192.168.86.0/24")
        for attr in ("BASELINE_DIR", "BASELINE_FILE", "HISTORY_FILE",
                     "LABELS_FILE", "NETWORKS_FILE"):
            assert not getattr(m, attr).startswith(real), attr

    def test_a_full_save_and_load_round_trip_lands_in_it(self, monkeypatch, tmp_path):
        # The end-to-end property the variable is for: a run that writes goes
        # entirely to the disposable directory.
        m = load_with_env(monkeypatch, tmp_path)
        m.select_network_baseline("192.168.87.0/24")
        m.save_baseline({"timestamp": "t", "gateway": "192.168.87.1",
                         "devices": [], "scanned_subnets": ["192.168.87.0/24"]})
        assert m.load_baseline() is not None
        written = sorted(p.name for p in tmp_path.iterdir())
        assert any(n.startswith("baseline-") for n in written), written


class TestTheDefaultIsUnchanged:
    def test_an_unset_variable_uses_the_home_directory(self, monkeypatch):
        m = load_with_env(monkeypatch, None)
        assert m.BASELINE_DIR == os.path.expanduser("~/.home_net_audit")

    def test_an_empty_variable_is_treated_as_unset(self, monkeypatch):
        # An exported-but-empty variable is a common shell accident and must not
        # silently redirect everything to the current working directory.
        m = load_with_env(monkeypatch, "")
        assert m.BASELINE_DIR == os.path.expanduser("~/.home_net_audit")

    def test_a_tilde_path_is_expanded(self, monkeypatch):
        m = load_with_env(monkeypatch, "~/audit_elsewhere")
        assert m.BASELINE_DIR == os.path.expanduser("~/audit_elsewhere")
        assert "~" not in m.BASELINE_DIR
