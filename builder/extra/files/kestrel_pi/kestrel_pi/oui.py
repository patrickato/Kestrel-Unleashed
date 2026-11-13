"""OUI → vendor lookup: the maker of a device from its MAC address.

The first three bytes of a MAC are the OUI, assigned by the IEEE to a
manufacturer. ``vendor("3C:52:A1:..")`` returns the assignee's name ("TP-Link
Systems Inc"), which tells you *who makes* an AP regardless of what its SSID is
named. The table is the public IEEE OUI registry, shipped gzipped as package
data (``data/oui.txt.gz``, ``OUIHEX:vendor`` per line) and loaded once, lazily,
on first use — so importing this module is cheap and off-Pi tests touch no file
until they ask for a lookup.

A locally-administered address (the 2nd-least-significant bit of the first byte
is set) is randomized/private and has no real OUI owner, so ``vendor`` returns
"" for it (phones randomize their MAC per network; some APs do too). Stdlib only.
"""
from __future__ import annotations

import gzip
import os
import re
import threading

_LOCK = threading.Lock()
_TABLE = None  # {oui_hex_upper: vendor}; loaded on first lookup
_DATA = os.path.join(os.path.dirname(__file__), "data", "oui.txt.gz")
_HEX12 = re.compile(r"[0-9A-Fa-f]")


def _normalize(mac):
    """A MAC's first 6 hex digits (the OUI), upper-cased, or "" when the input
    has fewer than 6 hex digits."""
    hexdigits = "".join(_HEX12.findall(mac or ""))
    return hexdigits[:6].upper() if len(hexdigits) >= 6 else ""


def is_locally_administered(mac):
    """True when the MAC is a locally-administered (randomized/private) address,
    which has no IEEE vendor owner. The flag is bit 1 of the first octet."""
    oui = _normalize(mac)
    if not oui:
        return False
    try:
        return bool(int(oui[:2], 16) & 0x02)
    except ValueError:
        return False


def _load():
    global _TABLE
    if _TABLE is not None:
        return _TABLE
    with _LOCK:
        if _TABLE is not None:
            return _TABLE
        table = {}
        try:
            with gzip.open(_DATA, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    oui, _, name = line.partition(":")
                    name = name.strip()
                    if len(oui) == 6 and name:
                        table[oui.upper()] = name
        except OSError:
            table = {}
        _TABLE = table
        return _TABLE


def vendor(mac):
    """The IEEE-registered maker for ``mac``'s OUI, or "" when the address is
    randomized/locally-administered or the OUI is unknown/too short."""
    oui = _normalize(mac)
    if not oui or is_locally_administered(mac):
        return ""
    return _load().get(oui, "")
