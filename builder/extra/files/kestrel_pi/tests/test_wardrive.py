"""Tests for the wardrive scoreboard: the pure aggregation and the plugin."""

import importlib.util
import json
import os
import types

from kestrel_pi import capture_quality as cq
from kestrel_pi import wardrive as wd
from kestrel_pi.capture import CaptureInterface
from kestrel_pi.context import PluginContext, ServiceRegistry

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "..", "plugins")


# --- the pure scoreboard ----------------------------------------------------
def _ap(essid, bssid):
    return {"essid": essid, "bssid": bssid, "handshakes": 1}


def test_scoreboard_counts_networks_aps_located_and_cracked():
    aps = [_ap("Home", "AA:BB:CC:00:00:01"),
           _ap("Home", "AA:BB:CC:00:00:02"),   # same ESSID, 2nd BSSID
           _ap("Cafe", "AA:BB:CC:00:00:03"),
           _ap("", "")]                         # unknown-BSSID fold: ignored
    b = wd.scoreboard(
        aps,
        quality={"AA:BB:CC:00:00:01": cq.from_signals(1, 1, True),
                 "AA:BB:CC:00:00:02": cq.from_signals(0, 1, False),
                 "AA:BB:CC:00:00:03": cq.from_signals(1, 0, False)},
        located_bssids={"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:03"},
        recovered_bssids={"AA:BB:CC:00:00:01"},
        track_points=4, distance_m=1234.0)
    assert b["networks"] == 2            # Home, Cafe
    assert b["access_points"] == 3       # three real BSSIDs
    assert b["located"] == 2 and b["unlocated"] == 1
    assert b["recovered"] == 1
    assert b["crack_pct"] == round(100 / 3, 1)
    assert b["quality"] == {"pmkid+handshake": 1, "pmkid": 1,
                            "handshake": 1, "strong": 2}  # both + pmkid are strong
    assert b["distance_text"] == "1.2 km" and b["track_points"] == 4


def test_scoreboard_distance_text_units():
    assert wd.scoreboard([], distance_m=0)["distance_text"] == "-"
    assert wd.scoreboard([], distance_m=850)["distance_text"] == "850 m"
    assert wd.scoreboard([], distance_m=5400)["distance_text"] == "5.4 km"


def test_scoreboard_empty_is_all_zero():
    b = wd.scoreboard([])
    assert b["networks"] == 0 and b["access_points"] == 0
    assert b["crack_pct"] == 0.0 and b["located_pct"] == 0.0
    assert b["quality"]["strong"] == 0 and b["bbox"] is None


def test_scoreboard_passes_bbox_through():
    bb = {"min_lat": 1.0, "max_lat": 2.0, "min_lon": 3.0, "max_lon": 4.0}
    assert wd.scoreboard([], bbox=bb)["bbox"] == bb


# --- the plugin -------------------------------------------------------------
def _load():
    path = os.path.join(PLUGIN_DIR, "wardrive.py")
    spec = importlib.util.spec_from_file_location("wardrive_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _pmkid_line(ap_hex, essid):
    return "WPA*01*%s*%s*112233445566*%s" % ("a" * 32, ap_hex, essid.encode().hex())


def _eapol_line(ap_hex, essid, pair="03"):
    return "WPA*02*%s*%s*112233445566*%s*%s*%s*%s" % (
        "b" * 32, ap_hex, essid.encode().hex(), "c" * 64, "d" * 10, pair)


def _seed(store, bssid_hex, essid, lat, lon, line=None):
    bssid = ":".join(bssid_hex[i:i + 2] for i in range(0, 12, 2)).upper()
    base = os.path.join(str(store), essid + ".hc22000")
    with open(base, "w", encoding="utf-8") as fh:
        fh.write((line or _eapol_line(bssid_hex, essid)) + "\n")
    with open(base + ".gps.json", "w", encoding="utf-8") as fh:
        json.dump({bssid: {"lat": lat, "lon": lon, "fix": 3, "sats": 9, "cn0": 40}},
                  fh)
    return bssid


def _plugin(tmp_path):
    p = MOD.Wardrive()
    p.options = {}
    p.context = PluginContext(
        name="wardrive", options={}, capture=CaptureInterface(str(tmp_path)),
        connectivity=types.SimpleNamespace(online=False),
        services=ServiceRegistry(), capabilities=("location", "capture-read", "ui"))
    p.on_loaded()
    return p


def test_plugin_declarations_local_only():
    assert MOD.Wardrive.__target_api__ == 2
    assert "network" not in MOD.Wardrive.__capabilities__   # no ack
    assert MOD.Wardrive.__actions__[0]["path"] == "view"


def test_plugin_collect_scoreboard(tmp_path, monkeypatch):
    b1 = _seed(tmp_path, "aabbccddee01", "HomeNet", 40.0, -74.0,
               line=_eapol_line("aabbccddee01", "HomeNet", pair="03"))  # confirmed
    _seed(tmp_path, "aabbccddee02", "Cafe", 40.01, -74.01,
          line=_pmkid_line("aabbccddee02", "Cafe"))                     # pmkid
    import kestrel_pi.crack as crackmod
    monkeypatch.setattr(crackmod, "CRACK_DIR", str(tmp_path))
    with open(os.path.join(str(tmp_path), "loot.json"), "w", encoding="utf-8") as fh:
        json.dump({"aps": {b1: {"bssid": b1, "password": "letmein12345",
                                "status": "cracked"}}}, fh)

    b = _plugin(tmp_path)._collect()
    assert b["networks"] == 2 and b["access_points"] == 2
    assert b["located"] == 2
    assert b["recovered"] == 1
    assert b["quality"]["strong"] == 2       # a confirmed 4-way + a PMKID


def test_plugin_collect_is_ttl_cached(tmp_path):
    _seed(tmp_path, "aabbccddee01", "One", 40.0, -74.0)
    p = _plugin(tmp_path)
    assert p._collect()["access_points"] == 1
    _seed(tmp_path, "aabbccddee02", "Two", 41.0, -75.0)
    assert p._collect()["access_points"] == 1            # served from cache
    assert p._collect(force=True)["access_points"] == 2  # re-walk


def test_plugin_page_renders_stats(tmp_path):
    _seed(tmp_path, "aabbccddee01", "HomeNet", 40.0, -74.0)
    p = _plugin(tmp_path)
    page = p.on_webhook("view", types.SimpleNamespace(
        args=types.SimpleNamespace(get=lambda k, d=None: "")))
    body = page.body
    assert "Wardrive scoreboard" in body and "Capture quality" in body
    assert "Access points" in body


def test_plugin_readout_card(tmp_path):
    from kestrel_pi.ui import StubUI
    _seed(tmp_path, "aabbccddee01", "HomeNet", 40.0, -74.0)
    p = _plugin(tmp_path)
    ui = StubUI().for_plugin("wardrive")
    p.on_ui_setup(ui)
    p.on_ui_update(ui, None)
    assert ui.get("aps") == "1"
    assert ui.get("mapped").startswith("1")
