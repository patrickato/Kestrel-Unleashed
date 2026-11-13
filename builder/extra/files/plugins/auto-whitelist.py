"""auto-whitelist - stop attacking an AP once its handshake is confirmed.

Once Kestrel has verified, crackable material for an access point there is
nothing more to gain by attacking it, so this adds that AP to the capture
whitelist and AngryOxide stops deauthing it on the next (re)start. "Confirmed"
means a true 4-way handshake the AP itself completed -- an M2+M3 / M3+M4 message
pair -- or a clientless PMKID. An AP with only a partial, client-side handshake
(an M1+M2 the AP never answered) is left alone, so Kestrel keeps trying for a
real one and the device keeps getting smarter about the hard targets.

It reads the message-pair signal straight off each ``.hc22000`` line via
``kestrel_pi.capture_quality`` (each line self-encodes its pair, so one confirmed
line confirms the AP -- no cross-line bookkeeping), and adds the AP once through
the same root-validated ``capture-whitelist`` apply the web whitelist page uses,
so the plugin gains no privilege the operator doesn't already have there.

Opt-in, ships disabled, **local-only**: it does not transmit anything and only
*reduces* attacking, so it needs no ``network`` capability and no authorized-use
acknowledgment. It acts on handshakes seen while it is enabled (an AP already
confirmed in the backlog is whitelisted the next time it produces a handshake,
which, in range, is soon). Target Python 3.11.
"""

from __future__ import annotations

import threading

from kestrel_pi import Plugin
from kestrel_pi import capture_quality


class AutoWhitelist(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = ("Auto-whitelist an AP after a confirmed 4-way (or PMKID) "
                       "so it is no longer actively attacked.")

    __target_api__ = 2
    # capture-read to see handshake events; ui for the dashboard readout. No
    # network capability: whitelisting only reduces attacking, nothing leaves
    # the device, so no authorized-use ack is required to enable it.
    __capabilities__ = ("capture-read", "ui")
    __options__ = {
        # Treat a clientless PMKID as confirmed material (nothing more to gain by
        # attacking). On by default; set false to whitelist only on a 4-way.
        "count_pmkid": {"type": "bool", "default": True},
        # Require the 4-way to be AP-confirmed (an M2+M3 / M3+M4 message pair the
        # AP itself completed). On by default -- a lone client-side M1+M2 does not
        # count, so Kestrel keeps trying for a real handshake. Set false to accept
        # any captured 4-way.
        "require_ap_confirmed": {"type": "bool", "default": True},
    }

    def on_loaded(self):
        self.log = self.context.logger
        self._lock = threading.Lock()
        # BSSIDs already whitelisted this session, so a repeat handshake for the
        # same AP doesn't re-apply. The apply itself is idempotent (the CLI dedups
        # the whitelist), so a confirmed AP from a prior session is re-added at
        # most once when it next produces a handshake.
        self._done = set()
        self._session = 0
        self.log.info("auto-whitelist loaded; confirmed APs will be whitelisted")

    # -- the trigger -----------------------------------------------------
    def on_handshake(self, event):
        bssid = (getattr(event, "bssid", "") or "").upper()
        if not bssid:
            return
        with self._lock:
            if bssid in self._done:
                return
        if not self._confirmed(capture_quality.signal(getattr(event, "raw", ""))):
            return
        self._whitelist(bssid, getattr(event, "essid", "") or "")

    def _confirmed(self, sig):
        """Does this one hashline confirm the AP enough to stop attacking it?"""
        if sig.kind == "pmkid":
            return bool(self.options.get("count_pmkid", True))
        if sig.kind == "eapol":
            if self.options.get("require_ap_confirmed", True):
                return sig.ap_confirmed
            return True
        return False

    def _whitelist(self, bssid, essid):
        reply = self.context.apply(
            {"target": "capture-whitelist", "action": "add", "entry": bssid})
        if reply.get("ok"):
            with self._lock:
                self._done.add(bssid)
                self._session += 1
            self.log.info("auto-whitelisted %s (%s) after a confirmed handshake; "
                          "it won't be actively attacked after capture restarts",
                          bssid, essid or "unnamed")
        else:
            # Don't mark done: a later handshake retries. A failed apply is the
            # settings channel being unavailable, not a reason to give up.
            self.log.warning("auto-whitelist of %s failed: %s",
                             bssid, reply.get("error") or "unknown error")

    # -- dashboard readout ----------------------------------------------
    def on_ui_setup(self, ui):
        ui.add_element("whitelisted", "0", label="Auto-whitelisted",
                       kind="number")

    def on_ui_update(self, ui, state):
        with self._lock:
            ui.set("whitelisted", str(self._session))
