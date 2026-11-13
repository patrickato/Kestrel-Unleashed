"""Tests for the auto-whitelist plugin: confirm -> whitelist, once, local-only."""

import importlib.util
import os
import types

from kestrel_pi.capture import CaptureInterface
from kestrel_pi.context import PluginContext, ServiceRegistry

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "..", "plugins")


def _load():
    path = os.path.join(PLUGIN_DIR, "auto-whitelist.py")
    spec = importlib.util.spec_from_file_location("auto_whitelist_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pmkid(ap="aabbccddee01", essid="Net"):
    return "WPA*01*%s*%s*112233445566*%s" % ("a" * 32, ap, essid.encode().hex())


def _eapol(ap="aabbccddee01", essid="Net", pair="02"):
    return "WPA*02*%s*%s*112233445566*%s*%s*%s*%s" % (
        "b" * 32, ap, essid.encode().hex(), "c" * 64, "d" * 10, pair)


def _plugin(tmp_path, options=None):
    mod = _load()
    plugin = mod.AutoWhitelist()
    opts = options or {}
    plugin.options = opts
    sent = []

    def fake_apply(change):
        sent.append(change)
        return {"ok": True, "whitelist": change.get("action"), "restart": False}

    plugin.context = PluginContext(
        name="auto-whitelist", options=opts,
        capture=CaptureInterface(str(tmp_path)),
        connectivity=types.SimpleNamespace(online=True),
        services=ServiceRegistry(),
        capabilities=("capture-read", "ui"),
        apply=fake_apply)
    plugin.on_loaded()
    return plugin, sent


def _event(raw, bssid, essid="Net"):
    return types.SimpleNamespace(raw=raw, bssid=bssid, essid=essid, type="")


# --- the confirm -> whitelist decision --------------------------------------
def test_pmkid_confirms_and_whitelists(tmp_path):
    p, sent = _plugin(tmp_path)
    p.on_handshake(_event(_pmkid("aabbccddee01"), "AA:BB:CC:DD:EE:01"))
    assert sent == [{"target": "capture-whitelist", "action": "add",
                     "entry": "AA:BB:CC:DD:EE:01"}]


def test_ap_confirmed_handshake_whitelists(tmp_path):
    p, sent = _plugin(tmp_path)
    p.on_handshake(_event(_eapol("aabbccddee02", pair="03"),  # M2+M3 from M3
                          "AA:BB:CC:DD:EE:02"))
    assert len(sent) == 1 and sent[0]["entry"] == "AA:BB:CC:DD:EE:02"


def test_client_side_handshake_is_not_whitelisted_by_default(tmp_path):
    # An M1+M2 the AP never answered: keep trying for a real one.
    p, sent = _plugin(tmp_path)
    p.on_handshake(_event(_eapol("aabbccddee03", pair="00"), "AA:BB:CC:DD:EE:03"))
    assert sent == []


def test_require_ap_confirmed_off_accepts_any_handshake(tmp_path):
    p, sent = _plugin(tmp_path, {"require_ap_confirmed": False})
    p.on_handshake(_event(_eapol("aabbccddee04", pair="00"), "AA:BB:CC:DD:EE:04"))
    assert len(sent) == 1 and sent[0]["entry"] == "AA:BB:CC:DD:EE:04"


def test_count_pmkid_off_ignores_pmkid(tmp_path):
    p, sent = _plugin(tmp_path, {"count_pmkid": False})
    p.on_handshake(_event(_pmkid("aabbccddee05"), "AA:BB:CC:DD:EE:05"))
    assert sent == []


# --- once, and resilient ----------------------------------------------------
def test_each_ap_is_whitelisted_only_once_per_session(tmp_path):
    p, sent = _plugin(tmp_path)
    ev = _event(_pmkid("aabbccddee06"), "AA:BB:CC:DD:EE:06")
    p.on_handshake(ev)
    p.on_handshake(ev)
    p.on_handshake(_event(_eapol("aabbccddee06", pair="03"), "AA:BB:CC:DD:EE:06"))
    assert len(sent) == 1


def test_a_failed_apply_is_retried_on_the_next_handshake(tmp_path):
    mod = _load()
    plugin = mod.AutoWhitelist()
    plugin.options = {}
    replies = [{"ok": False, "error": "settings channel unavailable"},
               {"ok": True}]
    sent = []

    def fake_apply(change):
        sent.append(change)
        return replies.pop(0)

    plugin.context = PluginContext(
        name="auto-whitelist", options={},
        capture=CaptureInterface(str(tmp_path)),
        connectivity=types.SimpleNamespace(online=True),
        services=ServiceRegistry(), capabilities=("capture-read", "ui"),
        apply=fake_apply)
    plugin.on_loaded()
    ev = _event(_pmkid("aabbccddee07"), "AA:BB:CC:DD:EE:07")
    plugin.on_handshake(ev)          # first apply fails -> not marked done
    plugin.on_handshake(ev)          # retried, succeeds
    assert len(sent) == 2


def test_no_bssid_is_ignored(tmp_path):
    p, sent = _plugin(tmp_path)
    p.on_handshake(_event(_pmkid(), ""))
    assert sent == []


# --- readout ----------------------------------------------------------------
def test_readout_counts_session_whitelists(tmp_path):
    from kestrel_pi.ui import StubUI
    p, _ = _plugin(tmp_path)
    p.on_handshake(_event(_pmkid("aabbccddee08"), "AA:BB:CC:DD:EE:08"))
    ui = StubUI().for_plugin("auto-whitelist")
    p.on_ui_setup(ui)
    p.on_ui_update(ui, None)
    assert ui.get("whitelisted") == "1"
