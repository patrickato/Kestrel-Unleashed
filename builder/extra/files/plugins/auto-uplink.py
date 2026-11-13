"""auto-uplink - fall back to a saved Wi-Fi network when the tether drops.

In the field the uplink is usually a phone tether; when it dies, this brings up
a saved Wi-Fi network so uploads and the dashboard keep working. NetworkManager
already autoconnects saved profiles, so this is a prompt nudge on top: while the
device is offline it rescans and, if a saved network (one you added with
``kestrel network wifi``) is in range, activates it. It only ever brings up
*operator-saved* profiles -- it adds no network and handles no key -- so it
needs no authorized-use acknowledgment. The dashboard card shows the uplink
state and how many saved fallbacks are in range. Opt-in, ships disabled.

The decision is the pure, tested ``kestrel_pi.uplink`` module; this does the
scan and the bring-up. Target Python 3.11.
"""

from __future__ import annotations

import subprocess
import threading

from kestrel_pi import Plugin
from kestrel_pi import uplink as uplink_mod


class AutoUplink(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = ("Fall back to a saved Wi-Fi network for an uplink when "
                       "the phone tether drops.")

    __target_api__ = 2
    __capabilities__ = ("ui",)

    def on_loaded(self):
        self.log = self.context.logger
        self._lock = threading.Lock()
        self._last = {}            # last status readout, for the card
        self.log.info("auto-uplink loaded")

    # -- the offline-fallback check (each epoch) ------------------------
    def on_epoch(self, epoch, info):
        online = bool(getattr(self.context.connectivity, "online", False))
        saved = self._saved_wifi()
        current = self._connected_ssid()
        if not online and saved:
            self._rescan()                 # prompt NM to see nearby networks
        in_range = self._visible_ssids()
        paths = self._active_paths()
        with self._lock:
            self._last = uplink_mod.status(online, paths, saved, in_range, current)
        if online:
            return
        target = uplink_mod.decide(online, saved, in_range, current)
        if not target:
            return
        reply = self.context.apply({"target": "wifi-up", "name": target})
        if reply.get("ok"):
            self.log.info("auto-uplink: brought up saved network %r", target)
        else:
            self.log.debug("auto-uplink: wifi-up %r failed: %s",
                           target, reply.get("error"))

    # -- nmcli reads (pi; empty + harmless on any error) ----------------
    @staticmethod
    def _nmcli(args):
        try:
            out = subprocess.run(["nmcli", "-t"] + args, capture_output=True,
                                 text=True, timeout=15, check=False)
            return out.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def _unescape(value):
        return value.replace("\\:", ":").replace("\\\\", "\\")

    def _saved_wifi(self):
        """Saved Wi-Fi profile names (= SSIDs for kestrel-added networks), in
        NetworkManager's listed order."""
        names = []
        for line in self._nmcli(["-f", "NAME,TYPE", "connection", "show"]).splitlines():
            name, _sep, typ = line.rpartition(":")
            if _sep and ("wifi" in typ or "wireless" in typ):
                nm = self._unescape(name).strip()
                if nm and nm not in names:
                    names.append(nm)
        return names

    def _visible_ssids(self):
        out = set()
        for line in self._nmcli(["-f", "SSID", "device", "wifi", "list",
                                 "--rescan", "no"]).splitlines():
            ssid = self._unescape(line).strip()
            if ssid:
                out.add(ssid)
        return out

    def _connected_ssid(self):
        for line in self._nmcli(["-f", "ACTIVE,SSID", "device", "wifi"]).splitlines():
            active, _sep, ssid = line.partition(":")
            if active == "yes":
                ssid = self._unescape(ssid).strip()
                if ssid:
                    return ssid
        return None

    def _active_paths(self):
        try:
            return list(self.context.connectivity.active_paths())
        except Exception:  # noqa: BLE001
            return []

    def _rescan(self):
        self._nmcli(["device", "wifi", "rescan"])

    # -- dashboard readout ----------------------------------------------
    def on_ui_setup(self, ui):
        ui.add_element("online", "?", label="Internet")
        ui.add_element("uplink", "—", label="Uplink")
        ui.add_element("fallbacks", "0", label="Fallbacks in range", kind="number")

    def on_ui_update(self, ui, state):
        with self._lock:
            last = dict(self._last)
        ui.set("online", "yes" if last.get("online") else "no")
        ui.set("uplink", str(last.get("uplink") or "—"))
        ui.set("fallbacks", str(last.get("fallbacks_in_range") or 0))
