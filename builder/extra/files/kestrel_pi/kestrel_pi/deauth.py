"""Plan a targeted deauthentication of one access point.

Deauth is an active RF transmission at a specific AP (optionally one client), to
knock a client off so it reconnects and a capturing radio sees the 4-way. The RF
itself runs on the device via aireplay-ng; this module is the brain that decides
*whether* and *where*, so the dangerous part is a small, tested decision rather
than buried in shell:

- it refuses a whitelisted target (the capture whitelist is the never-attack
  list -- deauth must honour it exactly like capture does), by BSSID or ESSID;
- it picks the radio that owns the ``attack`` role from the radio assignment;
- it says whether capture must pause (when the only monitor adapter is shared
  between capture and attack).

Authorized use only, and the CLI still requires the authorized-use acknowledgment
before it transmits. Pure/stdlib, Python 3.11, unit-tested with no radio.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Sequence, Tuple

_MAC_RE = re.compile(r"\A([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")


def _norm_mac(mac: str) -> str:
    return (mac or "").strip().upper()


@dataclass(frozen=True)
class DeauthPlan:
    """The outcome of :func:`plan_deauth`. When ``ok``, ``iface`` is the radio to
    transmit on and ``pause_capture`` says whether capture must stop first;
    otherwise ``error`` says why it was refused. ``notices`` are glass-box notes
    (e.g. that capture will pause)."""
    ok: bool
    iface: str = ""
    pause_capture: bool = False
    bssid: str = ""
    client: str = ""
    error: str = ""
    notices: Tuple[str, ...] = field(default_factory=tuple)


def is_whitelisted(bssid: str, essid: str, whitelist: Sequence[str]) -> bool:
    """True when the target is on the capture whitelist, by BSSID (case-
    insensitive) or exact ESSID -- matching how AngryOxide reads the list."""
    wl = list(whitelist or ())
    bset = {_norm_mac(w) for w in wl}
    if _norm_mac(bssid) in bset:
        return True
    return bool(essid) and essid in set(wl)


def plan_deauth(bssid: str, assignment, whitelist: Sequence[str] = (),
                essid: str = "", client: str = "",
                allow_shared: bool = True) -> DeauthPlan:
    """Decide the deauth plan. ``assignment`` is a
    :class:`kestrel_pi.radios.Assignment`; ``whitelist`` the capture whitelist."""
    bssid = _norm_mac(bssid)
    if not _MAC_RE.match(bssid):
        return DeauthPlan(False, error="not a valid BSSID")
    client = _norm_mac(client)
    if client and not _MAC_RE.match(client):
        return DeauthPlan(False, error="not a valid client MAC")
    if is_whitelisted(bssid, essid, whitelist):
        return DeauthPlan(False, bssid=bssid,
                          error="%s is whitelisted (never attacked); remove it "
                          "from the capture whitelist first" % bssid)
    attack = assignment.owner("attack")
    capture = assignment.owner("capture")
    if not attack:
        return DeauthPlan(False, bssid=bssid,
                          error="no radio can transmit deauth: add a monitor-"
                          "capable USB adapter")
    pause = assignment.is_shared("attack") or (attack == capture)
    notices = []
    if pause:
        if not allow_shared:
            return DeauthPlan(False, bssid=bssid,
                              error="deauth would share the capture radio and "
                              "sharing is disabled (allow_shared_attack=false)")
        notices.append("only one monitor adapter: capture pauses for the deauth "
                       "and resumes after (add a second adapter to avoid this)")
    return DeauthPlan(True, iface=attack, pause_capture=pause, bssid=bssid,
                      client=client, notices=tuple(notices))
