"""Tests for the auto-uplink decision (pure) and the plugin's act-when-offline."""

import importlib.util
import os
import types

from kestrel_pi import uplink
from kestrel_pi.capture import CaptureInterface
from kestrel_pi.context import PluginContext, ServiceRegistry

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "..", "plugins")


# -- pure decision ----------------------------------------------------------
def test_online_does_nothing():
    assert uplink.decide(True, ["Home"], {"Home"}) is None


def test_offline_brings_up_an_in_range_saved_network():
    assert uplink.decide(False, ["Home", "Cafe"], {"Cafe"}) == "Cafe"


def test_priority_order_wins():
    assert uplink.decide(False, ["Home", "Cafe"], {"Home", "Cafe"}) == "Home"


def test_nothing_when_no_saved_network_is_in_range():
    assert uplink.decide(False, ["Home"], {"Other"}) is None


def test_nothing_when_the_best_is_already_connected():
    assert uplink.decide(False, ["Home"], {"Home"}, current="Home") is None


def test_status_summarizes_uplink():
    st = uplink.status(False, ["bnep0"], ["Home", "Cafe"], {"Cafe"},
                       current=None)
    assert st["online"] is False and st["fallbacks_in_range"] == 1
    assert st["next_fallback"] == "Cafe" and st["paths"] == "bnep0"


# -- the plugin -------------------------------------------------------------
def _load():
    path = os.path.join(PLUGIN_DIR, "auto-uplink.py")
    spec = importlib.util.spec_from_file_location("auto_uplink_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plugin(tmp_path, online, saved, visible, current=None):
    mod = _load()
    p = mod.AutoUplink()
    p.options = {}
    sent = []
    p.context = PluginContext(
        name="auto-uplink", options={}, capture=CaptureInterface(str(tmp_path)),
        connectivity=types.SimpleNamespace(online=online,
                                           active_paths=lambda: ["bnep0"]),
        services=ServiceRegistry(), capabilities=("ui",),
        apply=lambda c: sent.append(c) or {"ok": True})
    p.on_loaded()
    p._saved_wifi = lambda: saved
    p._visible_ssids = lambda: set(visible)
    p._connected_ssid = lambda: current
    p._rescan = lambda: None
    return p, sent


def test_plugin_brings_up_fallback_when_offline(tmp_path):
    p, sent = _plugin(tmp_path, online=False, saved=["Home"], visible={"Home"})
    p.on_epoch(1, {})
    assert sent == [{"target": "wifi-up", "name": "Home"}]


def test_plugin_does_nothing_when_online(tmp_path):
    p, sent = _plugin(tmp_path, online=True, saved=["Home"], visible={"Home"})
    p.on_epoch(1, {})
    assert sent == []


def test_plugin_does_nothing_when_no_fallback_in_range(tmp_path):
    p, sent = _plugin(tmp_path, online=False, saved=["Home"], visible={"Other"})
    p.on_epoch(1, {})
    assert sent == []


def test_plugin_readout_reflects_state(tmp_path):
    from kestrel_pi.ui import StubUI
    p, _ = _plugin(tmp_path, online=False, saved=["Home", "Cafe"],
                   visible={"Cafe"})
    p.on_epoch(1, {})
    ui = StubUI().for_plugin("auto-uplink")
    p.on_ui_setup(ui)
    p.on_ui_update(ui, None)
    assert ui.get("online") == "no" and ui.get("fallbacks") == "1"
