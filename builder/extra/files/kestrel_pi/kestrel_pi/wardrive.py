"""Turn a wardrive's capture + GPS + loot into a scoreboard.

A wardriving run produces a pile of captures, GPS sidecars and (later) cracked
keys; this adds them up into the numbers an operator actually wants after a
drive: how many networks and APs, how many got a location, how good the captured
material is (PMKID / 4-way / both), how many cracked, and how far the route ran.

Pure/stdlib: :func:`scoreboard` is a function of already-collected inputs (the
plugin does the store/GPS/loot reads and the geo distance, which are tested on
their own), so the arithmetic here is unit-tested with no hardware. Python 3.11.
"""
from __future__ import annotations

from typing import Dict, Iterable, Mapping, Optional, Sequence


def _distance_text(metres: float) -> str:
    if not metres:
        return "-"
    if metres < 1000:
        return "%d m" % int(round(metres))
    return "%.1f km" % (metres / 1000.0)


def scoreboard(access_points: Sequence[Mapping],
               quality: Optional[Mapping] = None,
               located_bssids: Optional[Iterable[str]] = None,
               recovered_bssids: Optional[Iterable[str]] = None,
               track_points: int = 0,
               distance_m: float = 0.0,
               bbox: Optional[Mapping] = None) -> Dict:
    """Aggregate a wardrive into a scoreboard dict.

    ``access_points`` is :meth:`CaptureInterface.captured_access_points` output
    (one entry per ESSID+BSSID, with a possibly-empty ``bssid``). ``quality`` is
    :meth:`CaptureInterface.access_point_quality` (``{bssid: Quality}``).
    ``located_bssids`` are the BSSIDs with a GPS fix, ``recovered_bssids`` the
    ones the cracker has a key for. ``track_points`` / ``distance_m`` / ``bbox``
    are the pre-computed route facts (the plugin gets them from :mod:`geo`).
    """
    located = {b.upper() for b in (located_bssids or ()) if b}
    recovered = {b.upper() for b in (recovered_bssids or ()) if b}
    quality = quality or {}

    essids = set()
    bssids = set()
    located_count = 0
    recovered_count = 0
    for ap in access_points or ():
        essid = (ap.get("essid") or "").strip()
        bssid = (ap.get("bssid") or "").strip().upper()
        if essid:
            essids.add(essid.lower())
        if not bssid:
            continue
        bssids.add(bssid)
        if bssid in located:
            located_count += 1
        if bssid in recovered:
            recovered_count += 1

    # Capture-quality breakdown over the APs we have material for.
    both = pmkid_only = handshake_only = strong = 0
    for q in quality.values():
        grade = getattr(q, "grade", None)
        if grade == "pmkid+handshake":
            both += 1
        elif grade == "pmkid":
            pmkid_only += 1
        elif grade == "handshake":
            handshake_only += 1
        else:
            continue
        # "strong" = confirmed, crackable-for-sure material: a PMKID, or a 4-way
        # the AP itself completed (same bar the auto-whitelist plugin uses).
        if getattr(q, "pmkid", 0) or getattr(q, "ap_confirmed", False):
            strong += 1

    ap_total = len(bssids)
    crack_pct = round(100.0 * recovered_count / ap_total, 1) if ap_total else 0.0
    located_pct = round(100.0 * located_count / ap_total, 1) if ap_total else 0.0

    return {
        "networks": len(essids),            # distinct named ESSIDs
        "access_points": ap_total,          # distinct BSSIDs
        "located": located_count,
        "unlocated": max(0, ap_total - located_count),
        "located_pct": located_pct,
        "recovered": recovered_count,
        "crack_pct": crack_pct,
        "quality": {
            "pmkid+handshake": both,
            "pmkid": pmkid_only,
            "handshake": handshake_only,
            "strong": strong,
        },
        "track_points": int(track_points or 0),
        "distance_m": float(distance_m or 0.0),
        "distance_text": _distance_text(distance_m or 0.0),
        "bbox": dict(bbox) if bbox else None,
    }
