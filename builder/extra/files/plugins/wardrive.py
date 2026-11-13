"""wardrive - a scoreboard for a wardriving run.

After a drive you want the numbers, not another map: how many networks and
access points you caught, how many got a GPS location, how good the captured
material is (PMKID / 4-way / both -- the same grade the by-access-point view
badges), how many you've cracked, and how far the route ran. This plugin adds
them up into a dashboard card and a page.

It reads only local data -- the capture store, the GPS sidecars next to each
capture, and the loot store -- so it transmits nothing and needs no
authorized-use acknowledgment. The arithmetic lives in the pure
``kestrel_pi.wardrive`` module; this plugin just collects the inputs (TTL-cached,
like the map) and renders. Ships disabled. Target Python 3.11.
"""

from __future__ import annotations

import threading
import time

from kestrel_pi import Plugin
from kestrel_pi import geo
from kestrel_pi import wardrive as wd

# Re-aggregating the whole store + sidecars is cheap but not free; serve a recent
# scan within this window so the dashboard poll and the page don't rescan on
# every hit.
COLLECT_TTL_S = 10.0


class Wardrive(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = ("Wardrive scoreboard: networks, APs, capture quality, "
                       "cracked and route for the run.")

    __target_api__ = 2
    # location + capture-read: it reads the GPS sidecars and the capture store;
    # ui for the card and its page. Local-only, so no authorized-use ack.
    __capabilities__ = ("location", "capture-read", "ui")
    __actions__ = ({"label": "Scoreboard", "path": "view", "method": "get"},)

    def on_loaded(self):
        self.log = self.context.logger
        cap = getattr(self.context, "capture", None)
        self._capture = cap
        self._store_dir = getattr(cap, "store_dir", None)
        self._lock = threading.Lock()
        self._cache = None          # (expires_monotonic, scoreboard_dict)
        self.log.info("wardrive loaded (store=%s)", self._store_dir)

    # -- data (TTL-cached, never raises) ---------------------------------
    def _collect(self, force=False):
        now = time.monotonic()
        with self._lock:
            if not force and self._cache and self._cache[0] > now:
                return self._cache[1]
        board = self._scoreboard()
        with self._lock:
            self._cache = (now + COLLECT_TTL_S, board)
        return board

    def _scoreboard(self):
        cap = self._capture
        store = self._store_dir
        try:
            access_points = cap.captured_access_points() if cap else []
            quality = cap.access_point_quality() if cap else {}
            sidecars = geo.read_sidecars(store) if store else {}
            located = set(sidecars)
            track = geo.read_track(store) if store else []
            distance_m = geo.track_distance_m(track) if track else 0.0
            located_pts = [(f["lat"], f["lon"]) for f in sidecars.values()
                           if f.get("lat") is not None and f.get("lon") is not None]
            bbox = geo.bounds(located_pts + track) if (located_pts or track) else None
            recovered = self._recovered()
        except Exception:  # noqa: BLE001 -- the scoreboard must never crash the daemon
            self.log.exception("wardrive: collect failed; serving empty scoreboard")
            return wd.scoreboard([])
        return wd.scoreboard(
            access_points, quality=quality, located_bssids=located,
            recovered_bssids=recovered, track_points=len(track),
            distance_m=distance_m, bbox=bbox)

    def _recovered(self):
        try:
            from kestrel_pi.crack import CRACK_DIR
            from kestrel_pi.crack.store import LootStore
            return geo.recovered_from_loot(LootStore(CRACK_DIR).load())
        except Exception:  # noqa: BLE001
            return set()

    # -- dashboard readout card -----------------------------------------
    def on_ui_setup(self, ui):
        ui.add_element("networks", "0", label="Networks", kind="number")
        ui.add_element("aps", "0", label="Access points", kind="number")
        ui.add_element("strong", "0", label="Strong material", kind="number")
        ui.add_element("cracked", "0", label="Cracked")
        ui.add_element("mapped", "0", label="Mapped")
        ui.add_element("route", "-", label="Route")

    def on_ui_update(self, ui, state):
        b = self._collect()
        ui.set("networks", str(b["networks"]))
        ui.set("aps", str(b["access_points"]))
        ui.set("strong", str(b["quality"]["strong"]))
        ui.set("cracked", "%d (%g%%)" % (b["recovered"], b["crack_pct"]))
        ui.set("mapped", "%d (%g%%)" % (b["located"], b["located_pct"]))
        ui.set("route", b["distance_text"])

    # -- page ------------------------------------------------------------
    def on_webhook(self, path, request):
        if path == "view":
            token = ""
            try:
                token = request.args.get("token") or ""
            except Exception:  # noqa: BLE001 -- token is optional
                token = ""
            return self.context.page("Wardrive scoreboard",
                                     self._render_page(token))
        return self.context.redirect("No such view.", error=True)

    def _render_page(self, token=""):
        esc = self.context.esc
        b = self._collect(force=True)
        q = b["quality"]

        def row(label, value):
            return ("<tr><td data-label=\"stat\">" + esc(label)
                    + "</td><td data-label=\"value\">" + esc(str(value))
                    + "</td></tr>")

        rows = [
            row("Networks (named ESSIDs)", b["networks"]),
            row("Access points (BSSIDs)", b["access_points"]),
            row("Mapped (with a GPS fix)", "%d of %d (%g%%)"
                % (b["located"], b["access_points"], b["located_pct"])),
            row("Cracked", "%d of %d (%g%%)"
                % (b["recovered"], b["access_points"], b["crack_pct"])),
            row("Route", b["distance_text"]
                + (" over %d points" % b["track_points"] if b["track_points"]
                   else "")),
        ]
        qrows = [
            row("PMKID + 4-way (best)", q["pmkid+handshake"]),
            row("PMKID only", q["pmkid"]),
            row("4-way only", q["handshake"]),
            row("Strong (confirmed, crackable)", q["strong"]),
        ]
        dash = "/?token=" + token if token else "/"
        back = '<p><a href="' + esc(dash) + '">&larr; Dashboard</a></p>'
        return (back + "<h1>Wardrive scoreboard</h1>"
                + '<p class="count">What this run has caught so far.</p>'
                + "<div class='wrap'><table><thead><tr><th>stat</th><th>value</th>"
                + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
                + "<h2>Capture quality</h2>"
                + '<p class="count">How crackable the captured material is.</p>'
                + "<div class='wrap'><table><thead><tr><th>grade</th><th>count</th>"
                + "</tr></thead><tbody>" + "".join(qrows) + "</tbody></table></div>")
