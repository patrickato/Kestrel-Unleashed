"""locator - find an access point on foot with a warmer/colder meter.

Pick a nearby AP and this shows a big warmer/colder reading that updates as you
walk, so you can home in on where it physically is. It scans the station Wi-Fi
for the target's signal, smooths it (``kestrel_pi.locator``), and renders a meter
that auto-refreshes. Local-only -- it only scans and reads, transmits nothing, so
no authorized-use acknowledgment. Ships disabled. Target Python 3.11.
"""

from __future__ import annotations

import re
import subprocess
import threading

from kestrel_pi import Plugin
from kestrel_pi import locator as loc_mod

_BSSID_RE = re.compile(r"\A([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")
# How often the meter page reloads itself (seconds) while locating.
_REFRESH_S = 2


class Locator(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = "Find an AP on foot with a warmer/colder signal meter."

    __target_api__ = 2
    __capabilities__ = ("ui",)
    __actions__ = ({"label": "Locate", "path": "view", "method": "get"},)

    def on_loaded(self):
        self.log = self.context.logger
        self._lock = threading.Lock()
        self._locators = {}        # bssid -> SignalLocator (per-target smoothing)
        self.log.info("locator loaded")

    # -- scan ------------------------------------------------------------
    @staticmethod
    def _unescape(value):
        return value.replace("\\:", ":").replace("\\\\", "\\")

    def _scan_signals(self):
        """``{BSSID: signal 0..100}`` for the APs the station Wi-Fi sees now.
        Empty + harmless on any error (no nmcli, no managed Wi-Fi)."""
        out = {}
        try:
            proc = subprocess.run(
                ["nmcli", "-t", "-f", "BSSID,SIGNAL", "device", "wifi", "list",
                 "--rescan", "yes"],
                capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            return out
        for line in (proc.stdout or "").splitlines():
            # terse row: "<bssid-with-\:>:<signal>"; the BSSID's own colons are
            # escaped, so the last ':' splits off the signal.
            raw, sep, sig = line.rpartition(":")
            if not sep:
                continue
            bssid = self._unescape(raw).strip().upper()
            if not _BSSID_RE.match(bssid):
                continue
            try:
                out[bssid] = int(sig)
            except ValueError:
                continue
        return out

    # -- page ------------------------------------------------------------
    def on_webhook(self, path, request):
        if path != "view":
            return self.context.page("Not found - kestrel",
                                     "<h1>Not found</h1>", status=404)
        try:
            token = request.args.get("token") or ""
            target = (request.args.get("bssid") or "").strip().upper()
        except Exception:  # noqa: BLE001
            token, target = "", ""
        signals = self._scan_signals()
        if target and _BSSID_RE.match(target):
            body = self._meter_page(target, signals, token)
        else:
            body = self._picker_page(signals, token)
        return self.context.page("AP locator", body)

    def _meter_page(self, bssid, signals, token):
        esc = self.context.esc
        with self._lock:
            loc = self._locators.setdefault(bssid, loc_mod.SignalLocator())
            reading = loc.update(signals.get(bssid))   # None when not seen
        trend = reading["trend"]
        label = loc_mod.TREND_LABEL.get(trend, trend)
        arrow = loc_mod.TREND_ARROW.get(trend, "")
        bars = reading["bars"]
        level = reading["level"]
        meter = ("█" * bars) + ("░" * (5 - bars))   # full / empty blocks
        level_txt = "%g%%" % level if level is not None else "—"
        qs = "?bssid=" + bssid + (("&token=" + token) if token else "")
        back_qs = ("?token=" + token) if token else ""
        # A plain auto-reloading page: each load re-scans and updates the trend.
        # Status is spelled out (label + arrow + bars), never colour alone.
        return (
            '<p><a href="/plugins/locator/view' + esc(back_qs)
            + '">&larr; Pick another</a></p>'
            + "<h1>Locating " + esc(bssid) + "</h1>"
            + '<p class="count">Walk slowly; watch the reading.</p>'
            + '<div class="wrap"><table><tbody>'
            + '<tr><td data-label="trend"><strong style="font-size:1.6rem">'
            + esc(arrow + " " + label) + "</strong></td></tr>"
            + '<tr><td data-label="signal"><span style="font-size:1.4rem;'
            + 'letter-spacing:.2em">' + meter + "</span> " + esc(level_txt)
            + (reading["seen"] and "" or " <span class=\"smeta\">(not seen this "
               "scan)</span>") + "</td></tr>"
            + "</tbody></table></div>"
            + '<script>setTimeout(function(){location.reload();},'
            + str(_REFRESH_S * 1000) + ");</script>")

    def _picker_page(self, signals, token):
        esc = self.context.esc
        rows = []
        for bssid in sorted(signals, key=lambda b: -signals[b]):
            qs = "?bssid=" + bssid + (("&token=" + token) if token else "")
            bars = loc_mod.bars_for(signals[bssid])
            meter = ("█" * bars) + ("░" * (5 - bars))
            rows.append(
                '<tr><td data-label="ap"><a href="/plugins/locator/view'
                + esc(qs) + '">' + esc(bssid) + "</a></td>"
                + '<td data-label="signal">' + meter + " "
                + esc("%d%%" % signals[bssid]) + "</td></tr>")
        body = "".join(rows) or ("<tr><td colspan='2'>no APs in range "
                                 "(is the station Wi-Fi up?)</td></tr>")
        return ("<h1>AP locator</h1>"
                + '<p class="count">Pick an AP to home in on. The meter updates '
                + "as you walk.</p>"
                + '<div class="wrap"><table><thead><tr><th>access point</th>'
                + "<th>signal</th></tr></thead><tbody>" + body
                + "</tbody></table></div>")
