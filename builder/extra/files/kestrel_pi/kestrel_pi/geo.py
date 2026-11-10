"""geo - aggregate the device's GPS data into the wardriving map's model.

The ``gps`` plugin writes two things this module reads back:

* per-handshake **sidecars** (``<capture>.hc22000.gps.json``) next to every
  hashline in the capture store -- a BSSID-keyed map of the fix at capture time
  (schema ``lat/lon/alt/fix_time/source/fix/sats/cn0/strong``); and
* a continuous **track** (``gps-track.jsonl``) in the same store dir -- one
  ``{"ts","lat","lon"}`` sample per line, the device's path (the route a
  wardrive actually drove, captures or not).

From those, plus the capture store's ESSIDs and the crack loot's recovered set,
it builds the two things the ``map`` plugin draws: the list of **located
networks** (every AP we hold a handshake from *and* a position for, tagged with
whether its passphrase was recovered) and the **route** polyline.

Pure stdlib; reads only, writes nothing. Every reader tolerates a missing or
half-written file: a field device must never blank the dashboard because one
sidecar lost a race with a power cut. Callers inject the capture view and loot
records, so the whole module is exercised with plain dicts and no hardware.
"""

from __future__ import annotations

import glob
import json
import os

# A sidecar file sits next to each hashline: "<name>.hc22000.gps.json".
SIDECAR_GLOB = "*.gps.json"
# One continuous breadcrumb per device, written by the gps plugin in the store.
TRACK_NAME = "gps-track.jsonl"
# Safety rail on the route: a very long drive should not hand the browser an
# unbounded polyline. The track file is itself size-capped by the writer; this
# caps what a single map build returns (most recent points win).
DEFAULT_TRACK_LIMIT = 20000


def _valid_latlon(lat, lon):
    """True only for a real, usable WGS-84 coordinate. Rejects the null island
    (0,0) -- a receiver with no fix often reports exactly 0/0, and plotting it
    would drag the whole map to the Gulf of Guinea."""
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return False
    if lat != lat or lon != lon:  # NaN
        return False
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return False
    if abs(lat) < 1e-7 and abs(lon) < 1e-7:
        return False
    return True


def _fix_quality(fix):
    """Sort key for picking the best of several fixes for one BSSID: a 3D fix
    beats a 2D one, more satellites beats fewer, then the most recent wins. A
    higher tuple is better."""
    try:
        mode = int(fix.get("fix") or 0)
    except (TypeError, ValueError):
        mode = 0
    try:
        sats = int(fix.get("sats") or 0)
    except (TypeError, ValueError):
        sats = 0
    stamp = str(fix.get("fix_time") or "")
    return (mode, sats, stamp)


def read_sidecars(store_dir):
    """Scan ``store_dir`` for every ``*.gps.json`` sidecar and return one merged
    ``{BSSID: fix}`` map (BSSID upper-cased).

    A BSSID can be captured at more than one place/time; the **best** fix wins
    (:func:`_fix_quality` -- 3D over 2D, more sats, then most recent), so each
    network pins at its most trustworthy position. Unreadable or non-dict
    sidecars, entries with no usable coordinate, and the ``"unknown"`` bucket
    the gps plugin uses for a handshake with no BSSID are all skipped."""
    best = {}
    try:
        paths = sorted(glob.glob(os.path.join(store_dir, SIDECAR_GLOB)))
    except OSError:
        return {}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for bssid, fix in data.items():
            if not isinstance(fix, dict):
                continue
            key = str(bssid).upper()
            if key == "UNKNOWN" or not key:
                continue
            if not _valid_latlon(fix.get("lat"), fix.get("lon")):
                continue
            current = best.get(key)
            if current is None or _fix_quality(fix) >= _fix_quality(current):
                best[key] = fix
    return best


def read_track(store_dir, limit=DEFAULT_TRACK_LIMIT):
    """Return the device's route as a list of ``{"ts","lat","lon"}`` points, in
    the order written (chronological). Reads the ``gps-track.jsonl`` breadcrumb
    in ``store_dir``; a missing file yields ``[]``. Bad lines are skipped and
    points off the globe (incl. 0,0) dropped. At most ``limit`` points are
    returned -- the **most recent** ``limit``, so a long drive keeps its tail."""
    path = os.path.join(store_dir, TRACK_NAME)
    points = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if not _valid_latlon(rec.get("lat"), rec.get("lon")):
                    continue
                points.append({
                    "ts": rec.get("ts"),
                    "lat": float(rec["lat"]),
                    "lon": float(rec["lon"]),
                })
    except OSError:
        return []
    if limit and len(points) > limit:
        points = points[-limit:]
    return points


def recovered_from_loot(records):
    """The set of BSSIDs (upper-cased) whose passphrase the cracker recovered,
    from a loot store's ``{bssid: record}`` map. A record counts as recovered
    when it holds a cleartext ``password`` (the same test the loot page uses).
    Tolerant of a missing/garbled store (returns an empty set)."""
    out = set()
    if not isinstance(records, dict):
        return out
    for bssid, rec in records.items():
        if isinstance(rec, dict) and rec.get("password"):
            out.add(str(bssid).upper())
    return out


def essids_from_capture(capture):
    """Build ``{BSSID: essid}`` from the capture store by reading every hashline
    (duck-typed: ``capture.hashline_files()`` + ``capture.read_events(path)``).
    The first non-empty ESSID seen for a BSSID wins. Any read error yields an
    empty map rather than raising -- the map still draws, just without names."""
    out = {}
    try:
        files = capture.hashline_files()
    except Exception:  # noqa: BLE001 - a store read must not break the map
        return out
    for path in files:
        try:
            events = capture.read_events(path)
        except Exception:  # noqa: BLE001
            continue
        for event in events:
            bssid = (getattr(event, "bssid", "") or "").upper()
            if not bssid:
                continue
            essid = getattr(event, "essid", "") or ""
            if essid and not out.get(bssid):
                out[bssid] = essid
            elif bssid not in out:
                out[bssid] = essid
    return out


def located_networks(sidecars, essids=None, recovered=None):
    """Join positioned BSSIDs with their ESSID and recovered status into the
    list the map draws.

    ``sidecars`` is :func:`read_sidecars` output (``{BSSID: fix}``); ``essids``
    is ``{BSSID: essid}`` (:func:`essids_from_capture`); ``recovered`` is a set
    of recovered BSSIDs (:func:`recovered_from_loot`). Returns a list of dicts
    ``{bssid, essid, lat, lon, alt, fix, sats, cn0, recovered, fix_time}``,
    sorted recovered-first then by ESSID, so the networks that matter draw on
    top. Everything is plain JSON-ready scalars for the data endpoint."""
    essids = essids or {}
    recovered = recovered or set()
    out = []
    for bssid, fix in sidecars.items():
        try:
            lat = float(fix["lat"])
            lon = float(fix["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        alt = fix.get("alt")
        try:
            alt = float(alt) if alt is not None else None
        except (TypeError, ValueError):
            alt = None
        out.append({
            "bssid": bssid,
            "essid": essids.get(bssid, ""),
            "lat": lat,
            "lon": lon,
            "alt": alt,
            "fix": fix.get("fix"),
            "sats": fix.get("sats"),
            "cn0": fix.get("cn0"),
            "recovered": bssid in recovered,
            "fix_time": fix.get("fix_time", ""),
        })
    out.sort(key=lambda n: (not n["recovered"], n["essid"].lower(), n["bssid"]))
    return out


def _haversine_m(lat1, lon1, lat2, lon2):
    """Great-circle distance in metres between two WGS-84 points (stdlib math)."""
    import math
    radius = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * radius * math.asin(min(1.0, math.sqrt(a)))


def track_distance_m(points):
    """Total length in metres of a route (list of ``{"lat","lon"}`` points, in
    order), summing the great-circle hop between each consecutive pair. ``0.0``
    for fewer than two points. Used for the map's "distance travelled" stat."""
    total = 0.0
    prev = None
    for pt in points:
        lat, lon = pt.get("lat"), pt.get("lon")
        if not _valid_latlon(lat, lon):
            prev = None
            continue
        if prev is not None:
            total += _haversine_m(prev[0], prev[1], float(lat), float(lon))
        prev = (float(lat), float(lon))
    return total


def bounds(points):
    """Bounding box + centre over an iterable of points, or ``None`` when there
    are none. Each point is either ``(lat, lon)`` or a dict with ``lat``/``lon``.
    Returns ``{min_lat, min_lon, max_lat, max_lon, center_lat, center_lon}`` --
    what the map needs to frame and centre the view with no library."""
    lats, lons = [], []
    for pt in points:
        if isinstance(pt, dict):
            lat, lon = pt.get("lat"), pt.get("lon")
        else:
            try:
                lat, lon = pt[0], pt[1]
            except (TypeError, IndexError):
                continue
        if _valid_latlon(lat, lon):
            lats.append(float(lat))
            lons.append(float(lon))
    if not lats:
        return None
    return {
        "min_lat": min(lats), "max_lat": max(lats),
        "min_lon": min(lons), "max_lon": max(lons),
        "center_lat": (min(lats) + max(lats)) / 2.0,
        "center_lon": (min(lons) + max(lons)) / 2.0,
    }
