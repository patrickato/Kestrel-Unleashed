"""Decide when to fall back to a saved Wi-Fi network for an uplink.

In the field the device's internet usually comes from a phone tether (Bluetooth
PAN). When that drops -- the phone dies, you walk out of range -- it should fall
back to a known Wi-Fi network for an uplink (to keep uploading, or to reach the
dashboard). NetworkManager already autoconnects saved networks, so this is the
*decision* half: given whether a link is online, which saved Wi-Fi profiles
exist (in priority order), which are in range, and what is connected now, pick
the one to bring up -- or nothing.

Pure/stdlib, unit-tested; the plugin does the scan and the bring-up.
"""
from __future__ import annotations

from typing import Iterable, Optional, Sequence


def decide(online: bool, saved: Sequence[str], in_range: Iterable[str],
           current: Optional[str] = None) -> Optional[str]:
    """The SSID to bring up for an uplink, or ``None``.

    Nothing to do while already online, or when the best in-range saved network
    is the one already connected. Otherwise the first saved network (``saved`` is
    in priority order) that is currently in range."""
    if online:
        return None
    visible = {s for s in (in_range or ()) if s}
    for ssid in (saved or ()):
        if ssid and ssid in visible:
            return None if ssid == current else ssid
    return None


def status(online: bool, active_paths: Sequence[str], saved: Sequence[str],
           in_range: Iterable[str], current: Optional[str] = None) -> dict:
    """A small readout dict for the dashboard: whether there's internet, the
    active path summary, the current Wi-Fi uplink, and how many saved fallbacks
    are in range right now."""
    visible = {s for s in (in_range or ()) if s}
    fallbacks = [s for s in (saved or ()) if s and s in visible and s != current]
    return {
        "online": bool(online),
        "paths": ", ".join(p for p in (active_paths or ()) if p) or "none",
        "uplink": current or "—",
        "fallbacks_in_range": len(fallbacks),
        "next_fallback": fallbacks[0] if fallbacks else "",
    }
