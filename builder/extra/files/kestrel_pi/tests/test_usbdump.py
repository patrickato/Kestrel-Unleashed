"""Tests for the USB auto-dump detection (pure) and the plugin's edge trigger."""

import importlib.util
import os
import types

from kestrel_pi import usbdump
from kestrel_pi.capture import CaptureInterface
from kestrel_pi.context import PluginContext, ServiceRegistry

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "..", "plugins")


# -- pure detection ---------------------------------------------------------
def test_valid_label():
    assert usbdump.valid_label("KESTREL") and usbdump.valid_label("loot-01")
    assert not usbdump.valid_label("") and not usbdump.valid_label("bad label")
    assert not usbdump.valid_label("x" * 33)


def test_device_for_present_and_absent():
    assert usbdump.device_for("KESTREL", exists=lambda p: True) \
        == "/dev/disk/by-label/KESTREL"
    assert usbdump.device_for("KESTREL", exists=lambda p: False) is None
    assert usbdump.device_for("bad label", exists=lambda p: True) is None


# -- the plugin edge trigger ------------------------------------------------
def _load():
    path = os.path.join(PLUGIN_DIR, "usb-dump.py")
    spec = importlib.util.spec_from_file_location("usb_dump_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plugin(tmp_path):
    mod = _load()
    p = mod.UsbDump()
    p.options = {"label": "KESTREL"}
    sent = []
    p.context = PluginContext(
        name="usb-dump", options=p.options, capture=CaptureInterface(str(tmp_path)),
        connectivity=types.SimpleNamespace(online=False),
        services=ServiceRegistry(), capabilities=("ui",),
        apply=lambda c: sent.append(c) or {"ok": True, "usb_dump": "kestrel-x",
                                            "copied": 2})
    p.on_loaded()
    return mod, p, sent


def test_dump_fires_once_per_insertion(tmp_path, monkeypatch):
    from kestrel_pi import usbdump as usbdump_mod
    mod, p, sent = _plugin(tmp_path)
    present = {"v": False}
    monkeypatch.setattr(usbdump_mod, "device_for",
                        lambda label: "/dev/x" if present["v"] else None)

    p.on_epoch(1, {})                 # no stick -> nothing
    assert sent == []
    present["v"] = True
    p.on_epoch(2, {})                 # inserted -> one dump
    p.on_epoch(3, {})                 # still in -> no repeat
    assert len(sent) == 1 and sent[0] == {"target": "usb-dump", "label": "KESTREL"}
    present["v"] = False
    p.on_epoch(4, {})                 # removed
    present["v"] = True
    p.on_epoch(5, {})                 # reinserted -> dumps again
    assert len(sent) == 2


def test_readout(tmp_path, monkeypatch):
    from kestrel_pi import usbdump as usbdump_mod
    from kestrel_pi.ui import StubUI
    mod, p, _ = _plugin(tmp_path)
    monkeypatch.setattr(usbdump_mod, "device_for", lambda label: "/dev/x")
    p.on_epoch(1, {})
    ui = StubUI().for_plugin("usb-dump")
    p.on_ui_setup(ui)
    p.on_ui_update(ui, None)
    assert ui.get("stick") == "present" and "kestrel-x" in ui.get("last")
