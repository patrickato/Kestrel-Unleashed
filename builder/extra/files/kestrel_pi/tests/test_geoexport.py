"""Tests for kestrel_pi.geoexport -- the KML / GPX / WiGLE-CSV exporters.

Pure string in / string out. KML and GPX are parsed back as real XML to prove
they are well-formed; the CSV is parsed back with the csv module.
"""

import csv
import io
import xml.etree.ElementTree as ET

from kestrel_pi import geoexport

NETS = [
    {"bssid": "AA:BB:CC:DD:EE:01", "essid": "Home & Co", "lat": 40.1, "lon": -74.2,
     "alt": 12.0, "recovered": True, "fix_time": "2026-01-02T03:04:05Z"},
    {"bssid": "AA:BB:CC:DD:EE:02", "essid": "Cafe, Downtown", "lat": 40.2, "lon": -74.3,
     "alt": None, "recovered": False, "fix_time": ""},
    {"bssid": "AA:BB:CC:DD:EE:03", "essid": "nocoords", "lat": None, "lon": None},
]
TRACK = [{"ts": 1000, "lat": 40.10, "lon": -74.20},
         {"ts": 1060, "lat": 40.11, "lon": -74.21}]


# --- KML --------------------------------------------------------------------
def test_kml_is_well_formed_and_has_placemarks_and_route():
    kml = geoexport.to_kml(NETS, TRACK)
    root = ET.fromstring(kml)
    ns = "{http://www.opengis.net/kml/2.2}"
    placemarks = root.iter(ns + "Placemark")
    names = [p.find(ns + "name").text for p in placemarks]
    assert "Home & Co" in names            # XML entity decoded back -> escaping ok
    assert "Route" in names                # the route line placemark
    # a network with no coordinates is dropped (only 2 of 3 export)
    pts = [e for e in root.iter(ns + "Point")]
    assert len(pts) == 2
    # KML coordinate order is lon,lat[,alt]
    coord = root.iter(ns + "coordinates").__next__().text
    assert coord.split(",")[0].startswith("-74")


def test_kml_route_omitted_with_fewer_than_two_points():
    kml = geoexport.to_kml(NETS, [{"lat": 40.0, "lon": -74.0}])
    assert "<LineString" not in kml


# --- GPX --------------------------------------------------------------------
def test_gpx_is_well_formed_with_waypoints_and_track():
    gpx = geoexport.to_gpx(NETS, TRACK)
    root = ET.fromstring(gpx)
    ns = "{http://www.topografix.com/GPX/1/1}"
    wpts = list(root.iter(ns + "wpt"))
    assert len(wpts) == 2                   # the no-coords network is skipped
    assert wpts[0].get("lat") == "40.1" and wpts[0].get("lon") == "-74.2"
    trkpts = list(root.iter(ns + "trkpt"))
    assert len(trkpts) == 2
    # the track point time is rendered from the ts
    assert trkpts[0].find(ns + "time").text.endswith("Z")


# --- WiGLE CSV --------------------------------------------------------------
def test_wigle_csv_header_columns_and_rows():
    out = geoexport.to_wigle_csv(NETS)
    lines = out.splitlines()
    assert lines[0].startswith("WigleWifi-1.4")
    rows = list(csv.reader(io.StringIO("\n".join(lines[1:]))))
    assert rows[0] == ["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
                       "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
                       "AccuracyMeters", "Type"]
    data = rows[1:]
    assert len(data) == 2                   # the no-coords network is skipped
    # the comma in "Cafe, Downtown" survives CSV quoting as one field
    cafe = [r for r in data if r[0] == "AA:BB:CC:DD:EE:02"][0]
    assert cafe[1] == "Cafe, Downtown"
    assert cafe[10] == "WIFI"
    home = [r for r in data if r[0] == "AA:BB:CC:DD:EE:01"][0]
    assert home[6] == "40.1" and home[7] == "-74.2"
    assert "WPA2" in home[2]


# --- registry ---------------------------------------------------------------
def test_export_dispatch_and_unknown_format():
    ct, ext, text = geoexport.export("kml", NETS, TRACK)
    assert ext == "kml" and "kml" in ct and text.startswith("<?xml")
    ct, ext, text = geoexport.export("csv", NETS, TRACK)
    assert ext == "csv" and ct == "text/csv"
    try:
        geoexport.export("nope", NETS, TRACK)
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_exporters_tolerate_empty_input():
    assert geoexport.to_kml([], []).startswith("<?xml")
    assert geoexport.to_gpx([], []).startswith("<?xml")
    assert geoexport.to_wigle_csv([]).startswith("WigleWifi-1.4")
