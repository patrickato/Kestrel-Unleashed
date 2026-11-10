"""Tests for kestrel_pi.geo -- the wardriving map's location core.

All pure logic over files in a tmp dir and injected dicts, so the whole module
runs with no GPS, no radio and no daemon.
"""

import json
import os
import types

from kestrel_pi import geo


def _write_sidecar(store, name, mapping):
    with open(os.path.join(store, name), "w", encoding="utf-8") as fh:
        json.dump(mapping, fh)


# --- read_sidecars ---------------------------------------------------------
def test_read_sidecars_merges_and_uppercases(tmp_path):
    store = str(tmp_path)
    _write_sidecar(store, "a.hc22000.gps.json",
                   {"aa:bb:cc:dd:ee:ff": {"lat": 40.1, "lon": -74.2, "fix": 3, "sats": 9}})
    _write_sidecar(store, "b.hc22000.gps.json",
                   {"11:22:33:44:55:66": {"lat": 40.2, "lon": -74.3, "fix": 2, "sats": 5}})
    out = geo.read_sidecars(store)
    assert set(out) == {"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"}
    assert out["AA:BB:CC:DD:EE:FF"]["lat"] == 40.1


def test_read_sidecars_best_fix_wins_for_a_repeated_bssid(tmp_path):
    store = str(tmp_path)
    bssid = "AA:BB:CC:DD:EE:FF"
    # same AP captured twice: a 2D fix early, a 3D fix later -> the 3D wins
    _write_sidecar(store, "early.hc22000.gps.json",
                   {bssid: {"lat": 1.0, "lon": 1.0, "fix": 2, "sats": 4,
                            "fix_time": "2026-01-01T00:00:00Z"}})
    _write_sidecar(store, "late.hc22000.gps.json",
                   {bssid: {"lat": 2.0, "lon": 2.0, "fix": 3, "sats": 8,
                            "fix_time": "2026-01-01T01:00:00Z"}})
    out = geo.read_sidecars(store)
    assert out[bssid]["lat"] == 2.0 and out[bssid]["fix"] == 3


def test_read_sidecars_skips_junk_null_island_and_unknown(tmp_path):
    store = str(tmp_path)
    _write_sidecar(store, "ok.hc22000.gps.json",
                   {"AA:BB:CC:DD:EE:01": {"lat": 51.5, "lon": -0.1}})
    _write_sidecar(store, "nullisland.hc22000.gps.json",
                   {"AA:BB:CC:DD:EE:02": {"lat": 0.0, "lon": 0.0}})
    _write_sidecar(store, "unknown.hc22000.gps.json",
                   {"unknown": {"lat": 51.5, "lon": -0.1}})
    _write_sidecar(store, "outofrange.hc22000.gps.json",
                   {"AA:BB:CC:DD:EE:03": {"lat": 999, "lon": 0}})
    # a corrupt file must not abort the scan
    with open(os.path.join(store, "bad.hc22000.gps.json"), "w") as fh:
        fh.write("{ this is not json")
    out = geo.read_sidecars(store)
    assert set(out) == {"AA:BB:CC:DD:EE:01"}


def test_read_sidecars_missing_dir_is_empty(tmp_path):
    assert geo.read_sidecars(str(tmp_path / "nope")) == {}


# --- read_track ------------------------------------------------------------
def test_read_track_parses_order_and_skips_bad_lines(tmp_path):
    store = str(tmp_path)
    path = os.path.join(store, geo.TRACK_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": 1, "lat": 40.0, "lon": -74.0}) + "\n")
        fh.write("not json\n")
        fh.write("\n")
        fh.write(json.dumps({"ts": 2, "lat": 0.0, "lon": 0.0}) + "\n")  # null island
        fh.write(json.dumps({"ts": 3, "lat": 40.1, "lon": -74.1}) + "\n")
    pts = geo.read_track(store)
    assert [p["ts"] for p in pts] == [1, 3]
    assert pts[0]["lat"] == 40.0


def test_read_track_limit_keeps_the_most_recent(tmp_path):
    store = str(tmp_path)
    path = os.path.join(store, geo.TRACK_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(10):
            fh.write(json.dumps({"ts": i, "lat": 40 + i * 0.001, "lon": -74.0}) + "\n")
    pts = geo.read_track(store, limit=3)
    assert [p["ts"] for p in pts] == [7, 8, 9]


def test_read_track_missing_file_is_empty(tmp_path):
    assert geo.read_track(str(tmp_path)) == []


# --- recovered_from_loot ---------------------------------------------------
def test_recovered_from_loot_only_counts_records_with_a_password():
    records = {
        "AA:BB:CC:DD:EE:01": {"password": "hunter2hunter2", "status": "cracked"},
        "aa:bb:cc:dd:ee:02": {"password": "", "status": "pending"},
        "AA:BB:CC:DD:EE:03": {"status": "no-handshake"},
    }
    assert geo.recovered_from_loot(records) == {"AA:BB:CC:DD:EE:01"}
    assert geo.recovered_from_loot(None) == set()
    assert geo.recovered_from_loot("garbage") == set()


# --- essids_from_capture ---------------------------------------------------
def _fake_capture(by_file):
    """by_file: {path: [(bssid, essid), ...]} -> a duck-typed capture view."""
    def read_events(path):
        return [types.SimpleNamespace(bssid=b, essid=e) for b, e in by_file[path]]
    return types.SimpleNamespace(
        hashline_files=lambda: list(by_file),
        read_events=read_events,
    )


def test_essids_from_capture_first_named_essid_wins():
    cap = _fake_capture({
        "/x/a.hc22000": [("AA:BB:CC:DD:EE:01", ""),
                         ("AA:BB:CC:DD:EE:01", "HomeNet")],
        "/x/b.hc22000": [("AA:BB:CC:DD:EE:02", "Cafe")],
    })
    out = geo.essids_from_capture(cap)
    assert out["AA:BB:CC:DD:EE:01"] == "HomeNet"
    assert out["AA:BB:CC:DD:EE:02"] == "Cafe"


def test_essids_from_capture_tolerates_a_broken_store():
    bad = types.SimpleNamespace(
        hashline_files=lambda: ["/x/a"],
        read_events=lambda p: (_ for _ in ()).throw(OSError("boom")),
    )
    assert geo.essids_from_capture(bad) == {}


# --- located_networks ------------------------------------------------------
def test_located_networks_joins_and_sorts_recovered_first():
    sidecars = {
        "AA:BB:CC:DD:EE:01": {"lat": 40.0, "lon": -74.0, "fix": 3, "sats": 9, "cn0": 42},
        "AA:BB:CC:DD:EE:02": {"lat": 40.1, "lon": -74.1},
    }
    essids = {"AA:BB:CC:DD:EE:01": "Zed", "AA:BB:CC:DD:EE:02": "Alpha"}
    recovered = {"AA:BB:CC:DD:EE:02"}
    out = geo.located_networks(sidecars, essids, recovered)
    # recovered first, regardless of name
    assert out[0]["bssid"] == "AA:BB:CC:DD:EE:02" and out[0]["recovered"] is True
    assert out[1]["bssid"] == "AA:BB:CC:DD:EE:01" and out[1]["recovered"] is False
    assert out[1]["essid"] == "Zed" and out[1]["cn0"] == 42


def test_located_networks_without_essids_or_recovered():
    out = geo.located_networks({"AA:BB:CC:DD:EE:01": {"lat": 1.5, "lon": 2.5}})
    assert out[0]["essid"] == "" and out[0]["recovered"] is False


# --- bounds + track_distance ----------------------------------------------
def test_bounds_over_dicts_and_tuples():
    b = geo.bounds([{"lat": 10, "lon": 20}, (12, 24), {"lat": 11, "lon": 22}])
    assert b["min_lat"] == 10 and b["max_lat"] == 12
    assert b["min_lon"] == 20 and b["max_lon"] == 24
    assert b["center_lat"] == 11 and b["center_lon"] == 22


def test_bounds_none_when_no_valid_points():
    assert geo.bounds([]) is None
    assert geo.bounds([{"lat": 0, "lon": 0}, (None, None)]) is None


def test_track_distance_is_sane_and_handles_gaps():
    # ~0.001 deg of latitude ~= 111 m
    pts = [{"lat": 40.0, "lon": -74.0}, {"lat": 40.001, "lon": -74.0}]
    d = geo.track_distance_m(pts)
    assert 100 < d < 125
    # a gap (invalid point) splits the run rather than drawing a line across it
    pts2 = [{"lat": 40.0, "lon": -74.0}, {"lat": 0.0, "lon": 0.0},
            {"lat": 40.001, "lon": -74.0}]
    assert geo.track_distance_m(pts2) == 0.0
    assert geo.track_distance_m([{"lat": 40.0, "lon": -74.0}]) == 0.0
