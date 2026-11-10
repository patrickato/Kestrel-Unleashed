"""Tests for the wardriving `map` plugin.

Exercises the plugin with an injected context and real files in a tmp capture
store -- no GPS, no radio, no daemon. The heavy geo logic is covered in
test_geo; here we check the plugin's assembly: the TTL-cached collect, the live
cursor from the position service, the data.json endpoint, the rendered page,
and the dashboard readout card.
"""

import importlib.util
import json
import os
import types

from kestrel_pi.capture import CaptureInterface
from kestrel_pi.context import PluginContext, ServiceRegistry
from kestrel_pi.plugins import PluginPage
from kestrel_pi.ui import StubUI

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "..", "plugins")


def _mod():
    path = os.path.join(PLUGIN_DIR, "map.py")
    spec = importlib.util.spec_from_file_location("map_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MAP = _mod()


def _plugin(store, options=None):
    p = MAP.Map()
    opts = options or {}
    p.options = opts
    p.context = PluginContext(
        name="map", options=opts,
        capture=CaptureInterface(str(store)),
        connectivity=types.SimpleNamespace(online=False),
        services=ServiceRegistry(),
        capabilities=("location", "capture-read", "ui"),
    )
    p.on_loaded()
    return p


def _hashline(ap_hex, essid):
    return "WPA*02*%s*%s*112233445566*%s*0*0*00" % (
        "a" * 32, ap_hex, essid.encode().hex())


def _seed(store, bssid_hex, essid, lat, lon, recovered=False):
    """Write one .hc22000 + its gps sidecar for a located network."""
    bssid = ":".join(bssid_hex[i:i + 2] for i in range(0, 12, 2)).upper()
    base = os.path.join(str(store), essid + ".hc22000")
    with open(base, "w", encoding="utf-8") as fh:
        fh.write(_hashline(bssid_hex, essid) + "\n")
    with open(base + ".gps.json", "w", encoding="utf-8") as fh:
        json.dump({bssid: {"lat": lat, "lon": lon, "fix": 3, "sats": 9, "cn0": 40}}, fh)
    return bssid


def _track(store, points):
    with open(os.path.join(str(store), MAP.geo.TRACK_NAME), "w", encoding="utf-8") as fh:
        for i, (lat, lon) in enumerate(points):
            fh.write(json.dumps({"ts": i, "lat": lat, "lon": lon}) + "\n")


# --- declarations ----------------------------------------------------------
def test_declarations_are_plain_and_local_only():
    assert MAP.Map.__target_api__ == 2
    assert "network" not in MAP.Map.__capabilities__   # local-only: no ack
    assert MAP.Map.__optional_requires__ == ("position",)
    assert MAP.Map.__actions__[0]["path"] == "view"


# --- collect ---------------------------------------------------------------
def test_collect_aggregates_networks_track_and_stats(tmp_path, monkeypatch):
    b1 = _seed(tmp_path, "aabbccddee01", "HomeNet", 40.000, -74.000)
    _seed(tmp_path, "aabbccddee02", "Cafe", 40.010, -74.010)
    _track(tmp_path, [(40.0, -74.0), (40.001, -74.0), (40.002, -74.0)])
    # a loot store marking HomeNet recovered, read via the real crack path
    import kestrel_pi.crack as crackmod
    monkeypatch.setattr(crackmod, "CRACK_DIR", str(tmp_path))
    with open(os.path.join(str(tmp_path), "loot.json"), "w", encoding="utf-8") as fh:
        json.dump({"aps": {b1: {"bssid": b1, "password": "letmein12345",
                                "status": "cracked"}}}, fh)

    p = _plugin(tmp_path)
    data = p._collect()
    assert data["stats"]["located"] == 2
    assert data["stats"]["recovered"] == 1
    assert data["stats"]["track_points"] == 3
    assert data["stats"]["track_m"] > 0
    assert data["bounds"] is not None
    rec = [n for n in data["networks"] if n["recovered"]]
    assert len(rec) == 1 and rec[0]["essid"] == "HomeNet"


def test_collect_is_ttl_cached(tmp_path):
    _seed(tmp_path, "aabbccddee01", "One", 40.0, -74.0)
    p = _plugin(tmp_path)
    first = p._collect()
    assert first["stats"]["located"] == 1
    # add a second network; the cache should still return the first result
    _seed(tmp_path, "aabbccddee02", "Two", 41.0, -75.0)
    assert p._collect()["stats"]["located"] == 1
    # force re-walks
    assert p._collect(force=True)["stats"]["located"] == 2


def test_empty_store_is_an_empty_map_not_a_crash(tmp_path):
    p = _plugin(tmp_path)
    data = p._collect()
    assert data["networks"] == [] and data["track"] == []
    assert data["bounds"] is None
    assert data["stats"]["located"] == 0


def test_recovered_degrades_when_no_loot(tmp_path, monkeypatch):
    _seed(tmp_path, "aabbccddee01", "One", 40.0, -74.0)
    import kestrel_pi.crack as crackmod
    monkeypatch.setattr(crackmod, "CRACK_DIR", str(tmp_path / "no-crack-here"))
    p = _plugin(tmp_path)
    assert p._collect()["stats"]["recovered"] == 0


# --- data.json endpoint ----------------------------------------------------
def test_data_endpoint_returns_json_with_live_position(tmp_path):
    _seed(tmp_path, "aabbccddee01", "One", 40.0, -74.0)
    p = _plugin(tmp_path)
    p.context.services.provide(
        "position", lambda: {"lat": 40.5, "lon": -74.5, "fix": 3, "sats": 8, "cn0": 41})
    body, status, headers = p.on_webhook("data.json", None)
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    doc = json.loads(body.decode("utf-8"))
    assert doc["position"]["lat"] == 40.5
    assert doc["stats"]["located"] == 1
    assert "generated" in doc


def test_data_endpoint_position_null_without_a_fix(tmp_path):
    p = _plugin(tmp_path)
    body, _s, _h = p.on_webhook("data.json", None)
    assert json.loads(body.decode("utf-8"))["position"] is None


# --- page ------------------------------------------------------------------
def test_view_renders_a_self_contained_page(tmp_path):
    p = _plugin(tmp_path, {"tiles": True, "refresh_seconds": 7})
    page = p.on_webhook("view", None)
    assert isinstance(page, PluginPage)
    body = page.body
    assert "mapcanvas" in body and "data.json" in body
    assert "REFRESH_MS=7000" in body
    assert "TILES_DEFAULT=true" in body
    # no external script/style tags -- everything inline (web-ui-conventions)
    assert "<script src=" not in body and "<link" not in body


def test_unknown_subpath_redirects(tmp_path):
    p = _plugin(tmp_path)
    result = p.on_webhook("nope", None)
    assert result.__class__.__name__ == "PluginRedirect"


def test_refresh_seconds_is_clamped(tmp_path):
    assert _plugin(tmp_path, {"refresh_seconds": 999})._refresh_seconds() == MAP.MAX_REFRESH_S
    assert _plugin(tmp_path, {"refresh_seconds": 0})._refresh_seconds() == MAP.MIN_REFRESH_S


# --- dashboard readout card ------------------------------------------------
def test_ui_card_reports_counts_and_live_position(tmp_path):
    _seed(tmp_path, "aabbccddee01", "One", 40.0, -74.0)
    _track(tmp_path, [(40.0, -74.0), (40.02, -74.0)])
    p = _plugin(tmp_path)
    ui = StubUI().for_plugin("map")
    p.on_ui_setup(ui)
    p.context.services.provide("position", lambda: {"lat": 40.1, "lon": -74.1})
    p.on_ui_update(ui, None)
    assert ui.get("located") == "1"
    assert ui.get("live") == "40.10000, -74.10000"
    assert ui.get("distance").endswith("km") or ui.get("distance").endswith("m")


def test_ui_card_live_is_no_fix_without_position(tmp_path):
    p = _plugin(tmp_path)
    ui = StubUI().for_plugin("map")
    p.on_ui_setup(ui)
    p.on_ui_update(ui, None)
    assert ui.get("live") == "no fix"
    assert ui.get("located") == "0"
