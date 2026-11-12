"""map - the wardriving map: every network you've captured, where you captured
it, your route, and a live cursor, on one self-contained page.

This is the view upstream does not have. It reads what the ``gps`` plugin
already records -- the per-handshake location sidecars and the continuous track
-- aggregates them through :mod:`kestrel_pi.geo`, tags each network with whether
the cracker recovered its key, and draws it all on a dependency-free canvas:

* a **heatmap** of where the air is thick with networks (the hero);
* every located network as a marker, recovered ones lit apart from the rest;
* your **route** as a breadcrumb polyline; and
* a **live cursor** at the current fix, so the map moves with you.

Offline-first by design: it renders a proper Web-Mercator map with a graticule
and scale with no internet at all (the Faraday-cage case), and *progressively
enhances* to real OpenStreetMap tiles when the viewing browser can reach them.
Nothing leaves the device -- tiles, if used, are fetched by the operator's own
browser, not the Kestrel. Local only: no ``network`` capability, no ack.

The page polls a small JSON endpoint (``data.json``) on the same route, so the
map is live without a websocket or any client build step. The heavy scan of the
capture store is TTL-cached and shared with the dashboard readout card, so a
busy store does not get re-walked on every poll or UI tick.
"""

from __future__ import annotations

import json
import time

from kestrel_pi import Plugin
from kestrel_pi import geo
from kestrel_pi import geoexport

# How long a store scan (sidecars + track) is reused before re-walking. The live
# cursor is read fresh each poll (cheap, via the position service); only the
# expensive aggregate is cached.
COLLECT_TTL_S = 20.0
# Clamp the page's live poll cadence to something sane.
MIN_REFRESH_S = 2
MAX_REFRESH_S = 60


class Map(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = "Wardriving map: located networks, your route, and a live cursor."

    __target_api__ = 2
    # Reads where the device has been (location) and the capture store
    # (capture-read); contributes a dashboard card (ui). No network: the device
    # transmits nothing; map tiles, when on, load in the operator's browser.
    __capabilities__ = ("location", "capture-read", "ui")
    # The live cursor is a bonus, not a requirement: the map is complete from the
    # recorded sidecars and track with no live fix at all.
    __optional_requires__ = ("position",)
    __options__ = {
        # Progressive enhancement: let the viewing browser pull street tiles when
        # it can reach the internet. Off = always the offline graticule view. The
        # device itself never fetches tiles either way.
        "tiles": {"type": "bool", "default": True},
        # The tile source, as a {z}/{x}/{y} URL template (an optional {s} expands
        # to a/b/c). The default is OpenStreetMap's canonical host, but OSM's
        # tile policy blocks embedded/kiosk use and may serve an "Access blocked"
        # tile; point this at your own tile server or a provider you are entitled
        # to use (and update the attribution) when that happens, or turn tiles
        # off for the offline grid. Not hardcoding the server is also what OSM's
        # policy asks of apps.
        "tile_url": {"type": "str",
                     "default": "https://tile.openstreetmap.org/{z}/{x}/{y}.png"},
        # Live poll cadence for the page, in seconds (clamped MIN..MAX).
        "refresh_seconds": {"type": "int", "default": 5},
        # Cap on how many of the most recent track points the route draws.
        "max_track_points": {"type": "int", "default": 20000},
    }
    __actions__ = ({"label": "Map", "path": "view", "method": "get", "order": 1},)

    # -- lifecycle -------------------------------------------------------
    def on_loaded(self):
        self.log = self.context.logger
        cap = getattr(self.context, "capture", None)
        self._store_dir = getattr(cap, "store_dir", None)
        self._capture = cap
        self._cache = None        # (expires_monotonic, collected_dict)
        self.log.info("map loaded (store=%s)", self._store_dir)

    # -- dashboard readout card -----------------------------------------
    def on_ui_setup(self, ui):
        ui.add_element("located", "0", label="Networks mapped", kind="number")
        ui.add_element("recovered", "0", label="Recovered here", kind="number")
        ui.add_element("distance", "-", label="Route")
        ui.add_element("live", "no fix", label="Live position")

    def on_ui_update(self, ui, state):
        data = self._collect()
        stats = data["stats"]
        ui.set("located", str(stats["located"]))
        ui.set("recovered", str(stats["recovered"]))
        ui.set("distance", self._distance_text(stats["track_m"]))
        pos = self.context.services.get("position")
        if pos and pos.get("lat") is not None:
            ui.set("live", "%.5f, %.5f" % (pos["lat"], pos["lon"]))
        else:
            ui.set("live", "no fix")

    @staticmethod
    def _distance_text(metres):
        if not metres:
            return "-"
        if metres < 1000:
            return "%d m" % int(round(metres))
        return "%.1f km" % (metres / 1000.0)

    # -- data collection (TTL-cached) -----------------------------------
    def _collect(self, force=False):
        """Aggregate the store into the map model, reusing a recent scan within
        :data:`COLLECT_TTL_S`. Returns ``{networks, track, stats, bounds}`` with
        plain JSON-ready values. Never raises: a store with nothing in it yields
        empty lists and zero stats."""
        now = time.monotonic()
        if not force and self._cache and self._cache[0] > now:
            return self._cache[1]
        store = self._store_dir
        networks, track = [], []
        if store:
            try:
                sidecars = geo.read_sidecars(store)
                essids = geo.essids_from_capture(self._capture) if self._capture else {}
                recovered = self._recovered()
                networks = geo.located_networks(sidecars, essids, recovered)
                limit = self._opt_int("max_track_points", 20000)
                track = geo.read_track(store, limit=limit)
            except Exception:  # noqa: BLE001 - the map must never crash the daemon
                self.log.exception("map: collect failed; serving an empty map")
                networks, track = [], []
        all_points = [(n["lat"], n["lon"]) for n in networks] + track
        data = {
            "networks": networks,
            "track": track,
            "bounds": geo.bounds(all_points),
            "stats": {
                "located": len(networks),
                "recovered": sum(1 for n in networks if n["recovered"]),
                "track_points": len(track),
                "track_m": geo.track_distance_m(track),
            },
        }
        self._cache = (now + COLLECT_TTL_S, data)
        return data

    def _recovered(self):
        """The set of BSSIDs the cracker has recovered a key for, read from the
        loot store. Imported lazily and guarded: a build without the crack stack,
        or an unreadable store, just means no network is lit as recovered."""
        try:
            from kestrel_pi.crack import CRACK_DIR
            from kestrel_pi.crack.store import LootStore
            return geo.recovered_from_loot(LootStore(CRACK_DIR).load())
        except Exception:  # noqa: BLE001
            return set()

    def _opt_int(self, name, default):
        try:
            return int(self.options.get(name, default))
        except (TypeError, ValueError):
            return default

    def _refresh_seconds(self):
        secs = self._opt_int("refresh_seconds", 5)
        return max(MIN_REFRESH_S, min(MAX_REFRESH_S, secs))

    # -- web -------------------------------------------------------------
    def on_webhook(self, path, request):
        if path == "data.json":
            return self._data_response()
        if path.startswith("export."):
            return self._export_response(path[len("export."):])
        if path == "view":
            return self.context.page("Wardriving map", self._render_page())
        return self.context.redirect("No such view.", error=True)

    def _export_response(self, fmt):
        """Serve the located networks + route as a downloadable KML/GPX/WiGLE-CSV
        file. An unknown format redirects back with a note rather than erroring."""
        try:
            data = self._collect()
            content_type, ext, text = geoexport.export(
                fmt, data["networks"], data["track"])
        except KeyError:
            return self.context.redirect("Unknown export format.", error=True)
        body = text.encode("utf-8")
        headers = {
            "Content-Type": content_type,
            "Content-Disposition": 'attachment; filename="kestrel-wardrive.%s"' % ext,
            "Cache-Control": "no-store",
        }
        return (body, 200, headers)

    def _data_response(self):
        data = dict(self._collect())
        pos = self.context.services.get("position")
        if pos and pos.get("lat") is not None and pos.get("lon") is not None:
            data["position"] = {
                "lat": pos.get("lat"), "lon": pos.get("lon"),
                "fix": pos.get("fix"), "sats": pos.get("sats"),
                "cn0": pos.get("cn0"),
            }
        else:
            data["position"] = None
        data["generated"] = time.time()
        body = json.dumps(data).encode("utf-8")
        headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}
        return (body, 200, headers)

    def _render_page(self):
        tiles_default = "true" if self.options.get("tiles", True) else "false"
        tile_url = self.options.get(
            "tile_url", "https://tile.openstreetmap.org/{z}/{x}/{y}.png")
        refresh_ms = str(self._refresh_seconds() * 1000)
        # The page is one self-contained document: a full-bleed canvas, a control
        # bar, a legend and a tooltip, with all behaviour in the inline script
        # below. No framework, no build step, no external library (OSM tiles are
        # the one optional network fetch, done by the browser, not the device).
        return (
            _MAP_STYLE
            + '<p><a href="/plugins">&larr; Plugins</a></p>'
            '<h1>Wardriving map</h1>'
            '<p class="muted" id="mapsummary">Loading the capture store&hellip;</p>'
            + _MAP_BODY
            + '<script>(function(){'
            + 'var TILES_DEFAULT=' + tiles_default + ';'
            + 'var TILE_URL=' + json.dumps(tile_url) + ';'
            + 'var REFRESH_MS=' + refresh_ms + ';'
            + _MAP_SCRIPT
            + '})();</script>'
        )


# --- the page's CSS, markup and script, kept as module constants so the Python
# above stays readable. None of this is run through str.format, so the literal
# braces in the CSS and JS are safe.

_MAP_STYLE = (
    "<style>"
    # Break the canvas out of the shared 60em column to the full viewport width,
    # the classic full-bleed trick, so the map gets real space on any screen.
    ".map-bleed{width:100vw;position:relative;left:50%;right:50%;"
    "margin-left:-50vw;margin-right:-50vw;}"
    ".map-wrap{position:relative;width:100%;height:72vh;min-height:360px;"
    "background:#0b0f14;overflow:hidden;border-top:1px solid var(--border);"
    "border-bottom:1px solid var(--border);touch-action:none;cursor:grab;}"
    ".map-wrap.drag{cursor:grabbing;}"
    "#mapcanvas{display:block;width:100%;height:100%;}"
    # control bar: wraps on small screens, sits over the map top-left
    ".map-ctl{position:absolute;top:.5em;left:.5em;right:.5em;display:flex;"
    "flex-wrap:wrap;gap:.35em;z-index:3;}"
    ".map-ctl button{font:inherit;font-size:.82rem;padding:.3em .6em;border-radius:8px;"
    "border:1px solid rgba(255,255,255,.25);background:rgba(12,16,22,.78);"
    "color:#e7e7ea;cursor:pointer;backdrop-filter:blur(3px);}"
    ".map-ctl button.on{background:#1565c0;border-color:#1565c0;color:#fff;}"
    ".map-ctl button:active{transform:translateY(1px);}"
    # download links styled as buttons; a leading rule mark separates them
    ".map-ctl a.exp{font-size:.82rem;padding:.3em .6em;border-radius:8px;"
    "border:1px solid rgba(255,255,255,.25);background:rgba(12,16,22,.78);"
    "color:#9fd0ff;text-decoration:none;backdrop-filter:blur(3px);}"
    ".map-ctl a.exp:first-of-type{margin-left:.5em;border-left-width:2px;}"
    ".map-zoom{position:absolute;right:.5em;bottom:1.6em;display:flex;"
    "flex-direction:column;gap:.3em;z-index:3;}"
    ".map-zoom button{width:2.1em;height:2.1em;font-size:1.1rem;line-height:1;"
    "border-radius:8px;border:1px solid rgba(255,255,255,.25);"
    "background:rgba(12,16,22,.78);color:#e7e7ea;cursor:pointer;}"
    # legend + scale over the map, bottom-left
    ".map-legend{position:absolute;left:.5em;bottom:1.6em;z-index:3;"
    "font-size:.76rem;color:#dfe3e8;background:rgba(12,16,22,.7);"
    "padding:.4em .55em;border-radius:8px;line-height:1.7;backdrop-filter:blur(3px);}"
    ".map-legend .sw{display:inline-block;width:.8em;height:.8em;border-radius:50%;"
    "margin-right:.35em;vertical-align:-1px;}"
    ".map-scale{position:absolute;left:.5em;bottom:.5em;z-index:3;height:.9em;"
    "border:1px solid #dfe3e8;border-top:none;color:#dfe3e8;font-size:.7rem;"
    "padding:0 .3em;line-height:.9em;background:rgba(12,16,22,.4);}"
    ".map-attrib{position:absolute;right:.4em;bottom:.3em;z-index:3;font-size:.64rem;"
    "color:#9fb0c0;background:rgba(12,16,22,.5);padding:0 .3em;border-radius:4px;}"
    ".map-attrib a{color:#9fb0c0;}"
    # tooltip for a tapped/hovered marker
    "#maptip{position:absolute;z-index:4;max-width:16em;display:none;"
    "font-size:.76rem;color:#eef3f8;background:rgba(10,14,20,.92);"
    "border:1px solid rgba(255,255,255,.25);border-radius:8px;padding:.45em .6em;"
    "pointer-events:none;box-shadow:0 2px 10px rgba(0,0,0,.5);}"
    "#maptip .ssid{font-weight:600;}#maptip .mono{font-family:ui-monospace,monospace;}"
    "#maptip .rec{color:#ffd54a;}"
    ".map-empty{position:absolute;inset:0;display:flex;align-items:center;"
    "justify-content:center;text-align:center;color:#8fa3b5;padding:2em;z-index:2;}"
    "</style>"
)

_MAP_BODY = (
    '<div class="map-bleed"><div class="map-wrap" id="mapwrap">'
    '<canvas id="mapcanvas"></canvas>'
    '<div class="map-ctl" id="mapctl">'
    '<button data-k="fit">Fit</button>'
    '<button data-k="follow">Follow</button>'
    '<button data-k="heat" class="on">Heatmap</button>'
    '<button data-k="markers" class="on">Markers</button>'
    '<button data-k="route" class="on">Route</button>'
    '<button data-k="tiles">Map tiles</button>'
    '<button data-k="recov">Recovered only</button>'
    '<a class="exp" href="export.kml" download>KML</a>'
    '<a class="exp" href="export.gpx" download>GPX</a>'
    '<a class="exp" href="export.csv" download>CSV</a>'
    '</div>'
    '<div class="map-zoom"><button data-z="1">+</button>'
    '<button data-z="-1">&minus;</button></div>'
    '<div class="map-legend" id="maplegend">'
    '<span class="sw" style="background:#ffd54a"></span>recovered<br>'
    '<span class="sw" style="background:#39b0ff"></span>captured<br>'
    '<span class="sw" style="background:#00e3a0"></span>route'
    '</div>'
    '<div class="map-scale" id="mapscale">&nbsp;</div>'
    '<div class="map-attrib" id="mapattrib" style="display:none">'
    '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" '
    'rel="noopener">OpenStreetMap</a></div>'
    '<div id="maptip"></div>'
    '<div class="map-empty" id="mapempty" style="display:none">'
    'No located networks yet. Capture with the GPS plugin enabled and a fix, '
    'then this map lights up.</div>'
    '</div></div>'
)

# The whole map engine: Web-Mercator projection, pointer pan/zoom, an optional
# OSM tile layer that degrades to a graticule offline, an additive heatmap,
# markers, the route polyline, a live cursor, and the live poll loop.
_MAP_SCRIPT = r"""
var TILE=256, R=6378137.0;
var cv=document.getElementById('mapcanvas'), ctx=cv.getContext('2d');
var wrap=document.getElementById('mapwrap');
var tip=document.getElementById('maptip');
var summary=document.getElementById('mapsummary');
var emptyEl=document.getElementById('mapempty');
var attribEl=document.getElementById('mapattrib');
var dpr=Math.max(1, Math.min(3, window.devicePixelRatio||1));
var W=0, H=0;
var view={lat:0, lon:0, z:16};           // center + fractional zoom
var data={networks:[], track:[], position:null, bounds:null, stats:{}};
var opt={heat:true, markers:true, route:true, tiles:TILES_DEFAULT, recov:false, follow:false};
var firstFit=true, tiles={}, heatCache=null, heatKey='';

// --- Web-Mercator: lat/lon <-> world pixels at an integer zoom ---------
function lon2x(lon, z){ return (lon+180)/360 * TILE * Math.pow(2,z); }
function lat2y(lat, z){
  var s=Math.sin(lat*Math.PI/180); s=Math.max(-0.9999,Math.min(0.9999,s));
  return (0.5 - Math.log((1+s)/(1-s))/(4*Math.PI)) * TILE * Math.pow(2,z);
}
function x2lon(x, z){ return x/(TILE*Math.pow(2,z))*360 - 180; }
function y2lat(y, z){
  var n=Math.PI - 2*Math.PI*y/(TILE*Math.pow(2,z));
  return 180/Math.PI*Math.atan(0.5*(Math.exp(n)-Math.exp(-n)));
}
// screen pixel for a lat/lon at the current view (center-anchored)
function project(lat, lon){
  var z=view.z;
  return [ (lon2x(lon,z)-lon2x(view.lon,z)) + W/2,
           (lat2y(lat,z)-lat2y(view.lat,z)) + H/2 ];
}
function unproject(px, py){
  var z=view.z;
  return [ y2lat(lat2y(view.lat,z)+(py-H/2), z),
           x2lon(lon2x(view.lon,z)+(px-W/2), z) ];
}

function resize(){
  var r=wrap.getBoundingClientRect();
  W=Math.max(1,Math.round(r.width)); H=Math.max(1,Math.round(r.height));
  cv.width=Math.round(W*dpr); cv.height=Math.round(H*dpr);
  ctx.setTransform(dpr,0,0,dpr,0,0);
  heatCache=null; draw();
}
window.addEventListener('resize', resize);

// --- control bar -------------------------------------------------------
document.getElementById('mapctl').addEventListener('click', function(e){
  var b=e.target.closest('button'); if(!b) return;
  var k=b.getAttribute('data-k');
  if(k==='fit'){ fit(); return; }
  if(k==='follow'){ opt.follow=!opt.follow; b.classList.toggle('on',opt.follow);
    if(opt.follow && data.position){ view.lat=data.position.lat; view.lon=data.position.lon; } draw(); return; }
  opt[k]=!opt[k]; b.classList.toggle('on',opt[k]);
  if(k==='tiles'){ attribEl.style.display=opt.tiles?'block':'none'; }
  if(k==='heat'){ heatCache=null; }
  draw();
});
document.querySelector('.map-zoom').addEventListener('click', function(e){
  var b=e.target.closest('button'); if(!b) return;
  zoomBy(parseInt(b.getAttribute('data-z'),10), W/2, H/2);
});
// reflect initial tile state on its button + attribution
(function(){ var tb=document.querySelector('[data-k=tiles]');
  if(opt.tiles){ tb.classList.add('on'); attribEl.style.display='block'; } })();

// --- pointer pan/zoom (mouse + touch) ----------------------------------
var ptrs={}, lastDist=0, moved=false;
wrap.addEventListener('pointerdown', function(e){
  wrap.setPointerCapture(e.pointerId);
  ptrs[e.pointerId]={x:e.clientX,y:e.clientY}; moved=false;
  wrap.classList.add('drag'); tip.style.display='none';
});
wrap.addEventListener('pointermove', function(e){
  if(!ptrs[e.pointerId]) return;
  var ids=Object.keys(ptrs);
  if(ids.length===1){
    var p=ptrs[e.pointerId], dx=e.clientX-p.x, dy=e.clientY-p.y;
    if(Math.abs(dx)+Math.abs(dy)>2){ moved=true; opt.follow=false;
      document.querySelector('[data-k=follow]').classList.remove('on'); }
    panPixels(dx,dy); ptrs[e.pointerId]={x:e.clientX,y:e.clientY};
  } else if(ids.length>=2){
    ptrs[e.pointerId]={x:e.clientX,y:e.clientY};
    var a=ptrs[ids[0]], b=ptrs[ids[1]];
    var d=Math.hypot(a.x-b.x, a.y-b.y);
    var r=wrap.getBoundingClientRect();
    var cx=(a.x+b.x)/2-r.left, cy=(a.y+b.y)/2-r.top;
    if(lastDist){ zoomContinuous(Math.log2(d/lastDist), cx, cy); }
    lastDist=d; moved=true;
  }
});
function endPtr(e){ delete ptrs[e.pointerId];
  if(Object.keys(ptrs).length<2) lastDist=0;
  if(Object.keys(ptrs).length===0) wrap.classList.remove('drag'); }
wrap.addEventListener('pointerup', function(e){ if(!moved) showTipAt(e); endPtr(e); });
wrap.addEventListener('pointercancel', endPtr);
wrap.addEventListener('wheel', function(e){
  e.preventDefault();
  var r=wrap.getBoundingClientRect();
  zoomContinuous(-e.deltaY*0.0016, e.clientX-r.left, e.clientY-r.top);
}, {passive:false});

function panPixels(dx,dy){
  var z=view.z;
  var cx=lon2x(view.lon,z)-dx, cy=lat2y(view.lat,z)-dy;
  view.lon=x2lon(cx,z); view.lat=y2lat(cy,z); draw();
}
function zoomContinuous(dz, px, py){
  var before=unproject(px,py);
  view.z=Math.max(2, Math.min(21, view.z+dz));
  var after=unproject(px,py);
  view.lon+=before[1]-after[1]; view.lat+=before[0]-after[0];
  draw();
}
function zoomBy(dz, px, py){ zoomContinuous(dz, px, py); }

// --- fit the view to the data -----------------------------------------
function fit(){
  var b=data.bounds; opt.follow=false;
  document.querySelector('[data-k=follow]').classList.remove('on');
  if(!b){ if(data.position){ view.lat=data.position.lat; view.lon=data.position.lon; view.z=16; } draw(); return; }
  view.lat=b.center_lat; view.lon=b.center_lon;
  if(b.min_lat===b.max_lat && b.min_lon===b.max_lon){ view.z=16; draw(); return; }
  var z=20;
  for(; z>2; z--){
    var x0=lon2x(b.min_lon,z), x1=lon2x(b.max_lon,z);
    var y0=lat2y(b.max_lat,z), y1=lat2y(b.min_lat,z);
    if((x1-x0)<=W*0.86 && (y1-y0)<=H*0.86) break;
  }
  view.z=z; draw();
}

// --- drawing -----------------------------------------------------------
function draw(){
  ctx.clearRect(0,0,W,H);
  ctx.fillStyle='#0b0f14'; ctx.fillRect(0,0,W,H);
  if(opt.tiles) drawTiles(); else drawGraticule();
  if(opt.heat) drawHeat();
  if(opt.route) drawRoute();
  if(opt.markers) drawMarkers();
  drawLive();
  drawScale();
}

function drawGraticule(){
  ctx.strokeStyle='rgba(120,150,180,.14)'; ctx.lineWidth=1;
  ctx.fillStyle='rgba(150,175,200,.5)'; ctx.font='10px system-ui';
  var z=Math.floor(view.z);
  var step=360/Math.pow(2,z)*(TILE/ (TILE));  // degrees per tile
  // choose a graticule step that gives a handful of lines across the view
  var spanLon=x2lon(lon2x(view.lon,view.z)+W/2,view.z)-x2lon(lon2x(view.lon,view.z)-W/2,view.z);
  var g=niceStep(Math.abs(spanLon)/6);
  var west=Math.floor((view.lon-Math.abs(spanLon)/2)/g)*g;
  for(var lo=west; lo< view.lon+Math.abs(spanLon); lo+=g){
    var p=project(view.lat,lo); ctx.beginPath(); ctx.moveTo(p[0],0); ctx.lineTo(p[0],H); ctx.stroke();
    ctx.fillText(lo.toFixed(g<0.01?4:2), p[0]+2, H-4);
  }
  var spanLat=y2lat(lat2y(view.lat,view.z)-H/2,view.z)-y2lat(lat2y(view.lat,view.z)+H/2,view.z);
  var gl=niceStep(Math.abs(spanLat)/6);
  var south=Math.floor((view.lat-Math.abs(spanLat)/2)/gl)*gl;
  for(var la=south; la< view.lat+Math.abs(spanLat); la+=gl){
    var q=project(la,view.lon); ctx.beginPath(); ctx.moveTo(0,q[1]); ctx.lineTo(W,q[1]); ctx.stroke();
    ctx.fillText(la.toFixed(gl<0.01?4:2), 3, q[1]-2);
  }
}
function niceStep(v){
  var p=Math.pow(10,Math.floor(Math.log10(v)));
  var n=v/p; var m=(n>=5)?5:(n>=2)?2:1; return m*p;
}

// optional OSM raster tiles (browser-fetched); fall back to graticule where a
// tile hasn't loaded yet, so the view is never blank
function drawTiles(){
  drawGraticule();
  var z=Math.floor(view.z);
  var scale=Math.pow(2,view.z-z);
  var n=Math.pow(2,z);
  var cxp=lon2x(view.lon,z), cyp=lat2y(view.lat,z);
  var ts=TILE*scale;
  var x0=Math.floor((cxp - W/2/scale)/TILE);
  var x1=Math.floor((cxp + W/2/scale)/TILE);
  var y0=Math.floor((cyp - H/2/scale)/TILE);
  var y1=Math.floor((cyp + H/2/scale)/TILE);
  for(var tx=x0; tx<=x1; tx++){
    for(var ty=y0; ty<=y1; ty++){
      if(ty<0||ty>=n) continue;
      var wx=((tx%n)+n)%n;
      var sx=(tx*TILE - cxp)*scale + W/2;
      var sy=(ty*TILE - cyp)*scale + H/2;
      var img=tileImg(z,wx,ty);
      if(img && img.complete && img.naturalWidth>0){
        ctx.globalAlpha=0.92; ctx.drawImage(img, sx, sy, ts, ts); ctx.globalAlpha=1;
      }
    }
  }
}
function tileImg(z,x,y){
  var key=z+'/'+x+'/'+y; var e=tiles[key];
  if(e!==undefined) return e;
  var img=new Image(); img.crossOrigin='anonymous';
  var sub=['a','b','c'][(x+y)%3];
  img.onload=function(){ draw(); }; img.onerror=function(){ tiles[key]=null; };
  // Build the URL from the configured template ({s} optional). Any provider the
  // operator is entitled to use works; the device never fetches - the browser does.
  img.src=TILE_URL.replace('{s}',sub).replace('{z}',z).replace('{x}',x).replace('{y}',y);
  tiles[key]=img; return img;
}

// additive heatmap of located networks -> colour ramp (the hero layer)
function drawHeat(){
  var pts=visibleNetworks();
  if(!pts.length) return;
  var key=W+'x'+H+':'+view.z.toFixed(2)+':'+view.lat.toFixed(5)+':'+view.lon.toFixed(5)+':'+pts.length+':'+opt.recov;
  if(heatCache && heatKey===key){ ctx.drawImage(heatCache,0,0,W,H); return; }
  var off=document.createElement('canvas'); off.width=W; off.height=H;
  var o=off.getContext('2d');
  var rad=Math.max(16, Math.min(60, 10*Math.pow(2, view.z-15)));
  o.globalCompositeOperation='lighter';
  for(var i=0;i<pts.length;i++){
    var s=project(pts[i].lat, pts[i].lon);
    if(s[0]<-rad||s[0]>W+rad||s[1]<-rad||s[1]>H+rad) continue;
    var g=o.createRadialGradient(s[0],s[1],0, s[0],s[1],rad);
    g.addColorStop(0,'rgba(255,255,255,0.22)');
    g.addColorStop(1,'rgba(255,255,255,0)');
    o.fillStyle=g; o.beginPath(); o.arc(s[0],s[1],rad,0,7); o.fill();
  }
  var img=o.getImageData(0,0,W,H), d=img.data;
  for(var p=0;p<d.length;p+=4){
    var a=d[p+3]/255; if(a<=0.01){ d[p+3]=0; continue; }
    var c=ramp(Math.min(1,a*1.7));
    d[p]=c[0]; d[p+1]=c[1]; d[p+2]=c[2]; d[p+3]=Math.min(235, a*320);
  }
  o.putImageData(img,0,0);
  heatCache=off; heatKey=key;
  ctx.drawImage(off,0,0,W,H);
}
function ramp(t){ // blue -> cyan -> green -> yellow -> red
  var stops=[[20,70,160],[0,190,255],[0,220,120],[255,210,50],[255,70,40]];
  var x=t*(stops.length-1), i=Math.floor(x), f=x-i;
  if(i>=stops.length-1) return stops[stops.length-1];
  var a=stops[i], b=stops[i+1];
  return [a[0]+(b[0]-a[0])*f, a[1]+(b[1]-a[1])*f, a[2]+(b[2]-a[2])*f];
}

function drawRoute(){
  var t=data.track; if(!t||t.length<2) return;
  ctx.strokeStyle='rgba(0,227,160,.85)'; ctx.lineWidth=2.5;
  ctx.lineJoin='round'; ctx.lineCap='round';
  ctx.beginPath();
  for(var i=0;i<t.length;i++){
    var s=project(t[i].lat,t[i].lon);
    if(i===0) ctx.moveTo(s[0],s[1]); else ctx.lineTo(s[0],s[1]);
  }
  ctx.stroke();
}

var screenPts=[];  // cache of on-screen marker positions for hit-testing
function drawMarkers(){
  screenPts=[];
  var pts=visibleNetworks();
  for(var i=0;i<pts.length;i++){
    var n=pts[i], s=project(n.lat,n.lon);
    if(s[0]<-8||s[0]>W+8||s[1]<-8||s[1]>H+8) continue;
    screenPts.push({x:s[0],y:s[1],n:n});
    if(n.recovered){
      ctx.beginPath(); ctx.arc(s[0],s[1],5.5,0,7);
      ctx.fillStyle='#ffd54a'; ctx.fill();
      ctx.lineWidth=1.5; ctx.strokeStyle='rgba(0,0,0,.55)'; ctx.stroke();
    } else {
      ctx.beginPath(); ctx.arc(s[0],s[1],3.2,0,7);
      ctx.fillStyle='rgba(57,176,255,.9)'; ctx.fill();
    }
  }
}
function drawLive(){
  var p=data.position; if(!p) return;
  var s=project(p.lat,p.lon);
  var t=(Date.now()%2000)/2000, pr=6+t*10;
  ctx.beginPath(); ctx.arc(s[0],s[1],pr,0,7);
  ctx.fillStyle='rgba(255,80,80,'+(0.35*(1-t))+')'; ctx.fill();
  ctx.beginPath(); ctx.arc(s[0],s[1],5,0,7);
  ctx.fillStyle='#ff4b4b'; ctx.fill();
  ctx.lineWidth=2; ctx.strokeStyle='#fff'; ctx.stroke();
}
function drawScale(){
  var mPerPx=Math.cos(view.lat*Math.PI/180)*2*Math.PI*R/(TILE*Math.pow(2,view.z));
  var target=90, m=mPerPx*target, nm=niceStep(m);
  var px=Math.round(nm/mPerPx);
  var el=document.getElementById('mapscale');
  el.style.width=px+'px';
  el.textContent=(nm>=1000?(nm/1000)+' km':nm+' m');
}

function visibleNetworks(){
  if(!opt.recov) return data.networks;
  return data.networks.filter(function(n){ return n.recovered; });
}

// --- tooltip on tap/click ---------------------------------------------
function showTipAt(e){
  var r=wrap.getBoundingClientRect();
  var mx=e.clientX-r.left, my=e.clientY-r.top, best=null, bd=18*18;
  for(var i=0;i<screenPts.length;i++){
    var dx=screenPts[i].x-mx, dy=screenPts[i].y-my, d=dx*dx+dy*dy;
    if(d<bd){ bd=d; best=screenPts[i]; }
  }
  if(!best){ tip.style.display='none'; return; }
  var n=best.n;
  var html='<div class="ssid">'+esc(n.essid||'(hidden)')+'</div>'+
    '<div class="mono">'+esc(n.bssid)+'</div>';
  if(n.recovered) html+='<div class="rec">&#9733; key recovered</div>';
  html+='<div class="muted">'+n.lat.toFixed(5)+', '+n.lon.toFixed(5)+'</div>';
  if(n.cn0!=null) html+='<div class="muted">signal '+Math.round(n.cn0)+' dB-Hz</div>';
  tip.innerHTML=html;
  tip.style.display='block';
  var tx=Math.min(W-tip.offsetWidth-6, best.x+10), ty=Math.max(4, best.y-tip.offsetHeight-8);
  tip.style.left=tx+'px'; tip.style.top=(ty<4?best.y+14:ty)+'px';
}
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }

// --- live poll ---------------------------------------------------------
function applyData(d){
  data=d;
  if(!data.networks) data.networks=[];
  if(!data.track) data.track=[];
  heatCache=null;
  var st=data.stats||{};
  var km=(st.track_m||0)>=1000?((st.track_m/1000).toFixed(1)+' km'):((st.track_m||0).toFixed(0)+' m');
  summary.textContent=(st.located||0)+' networks located, '+(st.recovered||0)+
    ' recovered, '+(st.track_points||0)+'-point route ('+km+').';
  emptyEl.style.display=(data.networks.length||data.track.length||data.position)?'none':'flex';
  if(firstFit && (data.bounds||data.position)){ firstFit=false; fit(); }
  if(opt.follow && data.position){ view.lat=data.position.lat; view.lon=data.position.lon; }
  draw();
}
function poll(){
  fetch('data.json',{cache:'no-store'}).then(function(r){return r.json();})
    .then(applyData).catch(function(){ /* keep the last view */ });
}
resize();
poll();
setInterval(poll, REFRESH_MS);
// keep the live cursor pulsing smoothly between polls
setInterval(function(){ if(data.position) draw(); }, 120);
"""
