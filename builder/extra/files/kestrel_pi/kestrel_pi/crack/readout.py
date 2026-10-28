"""Read the crack worker's ``status.json`` for the daemon's dashboard card and
the e-ink face.

Mirrors :mod:`..agent.readout`: stdlib-only, so the always-on daemon imports it
with no hashcat present. The worker runs in its own process and writes the small
status file this reads; the daemon renders a "Quick-crack" card through the same
shared ``{name,label,value,kind}`` UI element model it uses for every readout,
and the e-ink plugin renders it with no crack code of its own.
"""

from __future__ import annotations

import json
import os
import time

from . import CRACK_DIR, STATUS_NAME

# The dashboard card title (its widget-group key / drag-reorder id).
CARD_NAME = "Quick-crack"


def status_path(crack_dir=CRACK_DIR):
    return os.path.join(crack_dir, STATUS_NAME)


def read_status(crack_dir=CRACK_DIR):
    """The worker's status dict, or ``None`` if it never wrote one. A malformed
    file reads as ``None`` rather than raising."""
    try:
        with open(status_path(crack_dir), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ago(ts, now=None):
    now = time.time() if now is None else now
    delta = max(0.0, now - ts)
    if delta < 60:
        return "just now"
    if delta < 3600:
        return "%dm ago" % int(delta // 60)
    if delta < 86400:
        return "%dh ago" % int(delta // 3600)
    return "%dd ago" % int(delta // 86400)


_STATE_LABEL = {
    "cracking": "cracking",
    "idle": "idle",
    "paused-thermal": "paused (hot)",
    "disabled": "disabled",
    "no-aircrack": "aircrack-ng missing",
    "no-capture": "waiting for a capture",
    "no-wordlists": "no wordlists",
    "error": "error",
}


def widget_elements(status, now=None):
    """The ``[{name,label,value,kind}, ...]`` for the Quick-crack card. Empty for
    a missing status, so the card simply doesn't show before the worker runs."""
    if not status:
        return []
    elements = [
        {"name": "state", "label": "State",
         "value": _STATE_LABEL.get(status.get("state"), status.get("state") or "-"),
         "kind": "text"},
    ]
    if status.get("error"):
        elements.append({"name": "error", "label": "Last error",
                         "value": str(status.get("error")), "kind": "text"})
    total = int(status.get("targets") or 0)
    cracked = int(status.get("cracked") or 0)
    elements.append({"name": "cracked", "label": "Cracked",
                     "value": "%d / %d" % (cracked, total), "kind": "text"})
    if total:
        elements.append({"name": "cracked_pct", "label": "Cracked share",
                         "value": "%.0f%%" % (100.0 * cracked / total),
                         "kind": "percent"})
    elements.append({"name": "pending", "label": "Still trying",
                     "value": str(int(status.get("pending") or 0)), "kind": "number"})
    if status.get("no_handshake"):
        elements.append({"name": "no_handshake", "label": "No handshake yet",
                         "value": str(int(status.get("no_handshake") or 0)),
                         "kind": "number"})
    if status.get("exhausted"):
        elements.append({"name": "exhausted", "label": "Exhausted",
                         "value": str(int(status.get("exhausted") or 0)),
                         "kind": "number"})
    elements.append({"name": "wordlists", "label": "Wordlists",
                     "value": str(int(status.get("wordlists") or 0)), "kind": "number"})
    if status.get("masks"):
        elements.append({"name": "masks", "label": "Masks",
                         "value": str(int(status.get("masks") or 0)), "kind": "number"})
    if status.get("queue"):
        elements.append({"name": "queue", "label": "Queued jobs",
                         "value": str(int(status.get("queue") or 0)), "kind": "number"})
    temp = _num(status.get("temp_c"))
    if temp is not None:
        elements.append({"name": "temp", "label": "CPU temp",
                         "value": "%.0f°C" % temp, "kind": "text"})
    current = status.get("current") or {}
    if current:
        who = current.get("essid") or current.get("bssid") or "?"
        wl = current.get("wordlist") or ""
        shown = who + (" · " + wl if wl else "")
        elements.append({"name": "current", "label": "Now cracking",
                         "value": shown, "kind": "text"})
    last = status.get("last_crack") or {}
    if last:
        who = last.get("essid") or last.get("bssid") or "?"
        at = _num(last.get("at"))
        shown = who + (" (" + _ago(at, now) + ")" if at else "")
        elements.append({"name": "last_crack", "label": "Last cracked",
                         "value": shown, "kind": "text"})
    return elements


def face_summary(status):
    """A compact snapshot for the e-ink face: ``{"cracked", "targets", "state",
    "latest"}``. ``latest`` is the ESSID of the most recent crack, or ``""``.
    Returns ``None`` when the worker has not run, so the face shows nothing."""
    if not status:
        return None
    last = status.get("last_crack") or {}
    return {
        "cracked": int(status.get("cracked") or 0),
        "targets": int(status.get("targets") or 0),
        "state": status.get("state") or "idle",
        "latest": last.get("essid") or last.get("bssid") or "",
    }
