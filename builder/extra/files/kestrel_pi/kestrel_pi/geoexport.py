"""geoexport - turn the wardriving map's data into the portable formats every
other tool reads, so a Kestrel wardrive is never locked inside the device.

Three standard outputs, built from the same :mod:`kestrel_pi.geo` located-network
list and track:

* **KML** (``to_kml``) -- opens in Google Earth / Maps: a placemark per network
  (recovered ones styled apart) and a line for the route.
* **GPX** (``to_gpx``) -- the GPS interchange format: a waypoint per network and
  a ``<trk>`` for the route, for any mapping/GPS app.
* **WiGLE CSV** (``to_wigle_csv``) -- the de-facto wardriving format, importable
  into WiGLE and the wider ecosystem.

Pure stdlib, string in / string out, no I/O -- the plugin and CLI decide where
the bytes go. Everything user-supplied (ESSIDs especially) is escaped for the
target format. We carry only what the capture store actually knows: a handshake
means WPA/WPA2, and we never invent a channel, RSSI or accuracy we did not
measure (those columns are left empty rather than faked).
"""

from __future__ import annotations

import csv
import io
import time

# A captured 4-way handshake (or PMKID) is by definition a WPA/WPA2-PSK network;
# that is all the store knows, so every exported network carries this auth.
_AUTH = "[WPA2-PSK-CCMP][ESS]"


def _xml_esc(value):
    text = "" if value is None else str(value)
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def _coord(value):
    """A finite lat/lon/alt as a plain decimal string, or ``""`` for None."""
    if value is None:
        return ""
    try:
        return repr(float(value))
    except (TypeError, ValueError):
        return ""


def to_kml(networks, track=None, name="Kestrel wardrive"):
    """A KML document: a styled placemark per network and a route line. Google
    Earth and most GIS tools read KML directly. Coordinates are ``lon,lat,alt``
    (KML order)."""
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>',
           "<name>%s</name>" % _xml_esc(name),
           '<Style id="recovered"><IconStyle><color>ff4ad5ff</color>'
           '<scale>1.1</scale></IconStyle></Style>',
           '<Style id="captured"><IconStyle><color>ffffb039</color>'
           '<scale>0.8</scale></IconStyle></Style>']
    for n in networks or ():
        alt = _coord(n.get("alt"))
        coords = "%s,%s%s" % (_coord(n.get("lon")), _coord(n.get("lat")),
                              ("," + alt) if alt else "")
        if not coords.startswith(",") and _coord(n.get("lat")):
            essid = n.get("essid") or "(hidden)"
            desc = "BSSID %s%s" % (n.get("bssid", ""),
                                   " — key recovered" if n.get("recovered") else "")
            out.append(
                "<Placemark><name>%s</name><description>%s</description>"
                "<styleUrl>#%s</styleUrl><Point><coordinates>%s</coordinates>"
                "</Point></Placemark>" % (
                    _xml_esc(essid), _xml_esc(desc),
                    "recovered" if n.get("recovered") else "captured", coords))
    pts = [p for p in (track or ()) if _coord(p.get("lat")) and _coord(p.get("lon"))]
    if len(pts) >= 2:
        line = " ".join("%s,%s" % (_coord(p["lon"]), _coord(p["lat"])) for p in pts)
        out.append('<Placemark><name>Route</name>'
                   '<Style><LineStyle><color>ffa0e300</color><width>3</width>'
                   "</LineStyle></Style><LineString><tessellate>1</tessellate>"
                   "<coordinates>%s</coordinates></LineString></Placemark>" % line)
    out.append("</Document></kml>")
    return "\n".join(out) + "\n"


def to_gpx(networks, track=None, name="Kestrel wardrive"):
    """A GPX 1.1 document: a ``<wpt>`` per network and a ``<trk>`` for the route.
    The universal GPS exchange format -- any mapping or GPS app imports it."""
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<gpx version="1.1" creator="Kestrel" '
           'xmlns="http://www.topografix.com/GPX/1/1">',
           "<metadata><name>%s</name></metadata>" % _xml_esc(name)]
    for n in networks or ():
        lat, lon = _coord(n.get("lat")), _coord(n.get("lon"))
        if not (lat and lon):
            continue
        essid = n.get("essid") or "(hidden)"
        sym = "Flag, Green" if n.get("recovered") else "Dot"
        ele = _coord(n.get("alt"))
        body = "<name>%s</name><desc>%s</desc><sym>%s</sym>" % (
            _xml_esc(essid), _xml_esc("BSSID " + (n.get("bssid") or "")), _xml_esc(sym))
        if ele:
            body = "<ele>%s</ele>" % ele + body
        out.append('<wpt lat="%s" lon="%s">%s</wpt>' % (lat, lon, body))
    pts = [p for p in (track or ()) if _coord(p.get("lat")) and _coord(p.get("lon"))]
    if len(pts) >= 2:
        out.append("<trk><name>Route</name><trkseg>")
        for p in pts:
            seg = '<trkpt lat="%s" lon="%s">' % (_coord(p["lat"]), _coord(p["lon"]))
            ts = p.get("ts")
            if isinstance(ts, (int, float)):
                seg += "<time>%s</time>" % time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
            out.append(seg + "</trkpt>")
        out.append("</trkseg></trk>")
    out.append("</gpx>")
    return "\n".join(out) + "\n"


def to_wigle_csv(networks, track=None, device="Kestrel"):
    """A WiGLE pre-SQL CSV (``WigleWifi-1.4`` header + column row + one row per
    network). The standard wardriving interchange -- importable into WiGLE and
    read by the wider ecosystem. Columns the store does not measure (channel,
    RSSI, accuracy) are left empty rather than fabricated; ``FirstSeen`` uses the
    GPS fix time when present."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    buf.write("WigleWifi-1.4,appRelease=kestrel,model=%s,release=1,"
              "device=%s,display=,board=,brand=Kestrel\n" % (device, device))
    writer.writerow(["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
                     "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
                     "AccuracyMeters", "Type"])
    for n in networks or ():
        lat, lon = _coord(n.get("lat")), _coord(n.get("lon"))
        if not (lat and lon):
            continue
        writer.writerow([
            n.get("bssid", ""), n.get("essid", ""), _AUTH,
            n.get("fix_time", ""), "", "",
            lat, lon, _coord(n.get("alt")), "", "WIFI",
        ])
    return buf.getvalue()


# Registry the plugin/CLI drive off, so a new format is added in one place.
FORMATS = {
    "kml": ("application/vnd.google-earth.kml+xml", "kml", to_kml),
    "gpx": ("application/gpx+xml", "gpx", to_gpx),
    "csv": ("text/csv", "csv", to_wigle_csv),
}


def export(fmt, networks, track=None):
    """Render ``(content_type, extension, text)`` for a format key in
    :data:`FORMATS`, or raise ``KeyError`` for an unknown one."""
    content_type, ext, fn = FORMATS[fmt]
    return content_type, ext, fn(networks, track)
