"""Identify a captured network/device from the little Kestrel sees: its ESSID and
its BSSID (AP MAC → OUI vendor). Turns a list of captured SSIDs/BSSIDs into "what
is this" — a NETGEAR router, a Ring doorbell, an HP printer, an Amazon device.

Kestrel captures Wi-Fi handshakes, so the signals here are narrower than a full
LAN recon (no mDNS/BLE): the ESSID name and, when a vendor lookup is wired in, the
OUI vendor. SSID patterns are the strong signal and need no data file; the vendor
is an optional input (pass it from an OUI table when one is available) that fills
in a category when the name says nothing.

Pure, offline, no dependencies, Python 3.11. A reduced port of the Augur project's
device identifier, kept to the signals a capture-only device actually has.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple


# ESSID / device-name substring (regex, case-insensitive) → (category, product,
# confidence). A network that names itself is the best signal we get from capture.
_NAME_PATTERNS: Tuple[Tuple[str, str, str, str], ...] = (
    (r"roomba", "vacuum", "iRobot Roomba", "high"),
    (r"braava", "vacuum", "iRobot Braava", "high"),
    (r"\bshark(ninja)?\b|\brobovac\b|\beufy\b", "vacuum", "robot vacuum", "medium"),
    (r"echo|alexa|echodot|echo-dot", "voice-assistant", "Amazon Echo", "high"),
    (r"google-?home|nest-?hub|nest-?mini|nest-?audio|google-?nest", "voice-assistant", "Google Nest", "high"),
    (r"homepod", "speaker", "Apple HomePod", "high"),
    (r"sonos", "speaker", "Sonos", "high"),
    (r"bose", "speaker", "Bose speaker", "medium"),
    (r"chromecast", "streamer", "Google Chromecast", "high"),
    (r"apple-?tv|appletv", "streamer", "Apple TV", "high"),
    (r"fire-?tv|firetv|\baftt\b|\bafts\b", "streamer", "Amazon Fire TV", "high"),
    (r"\broku\b", "streamer", "Roku", "high"),
    (r"iphone", "phone", "Apple iPhone", "high"),
    (r"\bipad\b", "tablet", "Apple iPad", "high"),
    (r"pixel", "phone", "Google Pixel", "high"),
    (r"galaxy|sm-[a-z]\d", "phone", "Samsung Galaxy", "high"),
    (r"oneplus", "phone", "OnePlus", "high"),
    (r"\bring\b", "doorbell", "Ring", "high"),
    (r"wyze", "camera", "Wyze Cam", "high"),
    (r"nest-?cam|nestcam|dropcam", "camera", "Google Nest Cam", "high"),
    (r"arlo", "camera", "Arlo camera", "high"),
    (r"reolink|hikvision|dahua|amcrest", "camera", "IP camera", "high"),
    (r"ecobee", "thermostat", "ecobee", "high"),
    (r"thermostat|t-?stat", "thermostat", "thermostat", "medium"),
    (r"\bhue\b|philips-?hue", "light", "Philips Hue", "high"),
    (r"lifx", "light", "LIFX bulb", "high"),
    (r"nanoleaf", "light", "Nanoleaf", "high"),
    (r"bulb|lightstrip|light-?strip", "light", "smart light", "medium"),
    (r"kasa|\bwemo\b|smart-?plug|smartplug", "plug", "smart plug", "medium"),
    (r"direct-.*(hp|epson|canon|brother)|printer|\bhp-?print|epson|\blexmark\b", "printer", "printer", "high"),
    (r"\bxbox\b", "gaming", "Xbox", "high"),
    (r"playstation|\bps[45]\b", "gaming", "PlayStation", "high"),
    (r"nintendo|\bswitch-[0-9a-f]", "gaming", "Nintendo Switch", "medium"),
    (r"\btesla\b|\bmodel-?[3sxy]\b", "vehicle", "Tesla", "high"),
    (r"raspberry|raspberrypi|\brpi\b", "computer", "Raspberry Pi", "high"),
    (r"esp-?32|esp-?8266|esphome|\besp_", "iot", "ESP microcontroller", "medium"),
    (r"shelly|sonoff|tuya|smartlife", "iot", "smart-home device", "medium"),
    # Router/gateway + ISP SSID conventions — common for a captured AP.
    (r"netgear|orbi", "router", "NETGEAR router", "medium"),
    (r"linksys", "router", "Linksys router", "medium"),
    (r"asus|\brt-ac|\brt-ax", "router", "ASUS router", "medium"),
    (r"d-?link|dlink", "router", "D-Link router", "medium"),
    (r"tp-?link|\barcher\b|\btether\b", "router", "TP-Link router", "medium"),
    (r"unifi|ubiquiti|amplifi", "router", "Ubiquiti", "medium"),
    (r"eero", "router", "eero mesh", "medium"),
    (r"\bxfinity|comcast", "gateway", "Xfinity/Comcast gateway", "medium"),
    (r"\batt\b|att-wifi|\buverse\b", "gateway", "AT&T gateway", "medium"),
    (r"spectrum|charter", "gateway", "Spectrum gateway", "medium"),
    (r"verizon|\bfios\b|cr1000|g3100", "gateway", "Verizon Fios gateway", "medium"),
    # A network broadcasting a setup/provisioning SSID is a device waiting to be
    # configured — often the softest target and a strong hint of the device type.
    (r"setup|_config$|-config$|provision|\bhotspot\b", "setup-ap", "device in setup mode", "medium"),
)

# OUI vendor substring → (category, product) default, used when the ESSID says
# nothing but the BSSID's vendor is known.
_VENDOR_CATEGORY: Tuple[Tuple[str, str, str], ...] = (
    ("irobot", "vacuum", "iRobot Roomba"),
    ("sonos", "speaker", "Sonos"),
    ("roku", "streamer", "Roku"),
    ("ring", "doorbell", "Ring"),
    ("ecobee", "thermostat", "ecobee"),
    ("nest", "iot", "Google Nest device"),
    ("amazon", "iot", "Amazon device"),
    ("google", "iot", "Google device"),
    ("philips", "light", "Philips (Hue?)"),
    ("signify", "light", "Philips Hue"),
    ("lifx", "light", "LIFX"),
    ("wyze", "camera", "Wyze"),
    ("arlo", "camera", "Arlo"),
    ("hikvision", "camera", "Hikvision camera"),
    ("dahua", "camera", "Dahua camera"),
    ("tp-link", "router", "TP-Link"),
    ("tplink", "router", "TP-Link"),
    ("ubiquiti", "router", "Ubiquiti"),
    ("netgear", "router", "NETGEAR"),
    ("asustek", "router", "ASUS"),
    ("d-link", "router", "D-Link"),
    ("arris", "gateway", "ARRIS gateway"),
    ("technicolor", "gateway", "Technicolor gateway"),
    ("sagemcom", "gateway", "Sagemcom gateway"),
    ("espressif", "iot", "ESP device"),
    ("tuya", "iot", "Tuya smart device"),
    ("raspberry", "computer", "Raspberry Pi"),
    ("apple", "phone", "Apple device"),
    ("samsung", "phone", "Samsung device"),
    ("intel", "computer", "PC/laptop"),
    ("realtek", "computer", "PC/laptop"),
    ("nintendo", "gaming", "Nintendo"),
    ("sony interactive", "gaming", "PlayStation"),
    ("garmin", "wearable", "Garmin"),
    ("fitbit", "wearable", "Fitbit"),
)

_CONF = {"high": 0, "medium": 1, "low": 2}


def _match_name(text: str) -> Optional[Tuple[str, str, str]]:
    """Best (category, product, confidence) for an ESSID, or None."""
    if not text:
        return None
    low = text.lower()
    best: Optional[Tuple[str, str, str]] = None
    for pattern, category, product, conf in _NAME_PATTERNS:
        if re.search(pattern, low):
            if best is None or _CONF[conf] < _CONF[best[2]]:
                best = (category, product, conf)
    return best


def _vendor_category(vendor: str) -> Optional[Tuple[str, str]]:
    low = (vendor or "").lower()
    for sub, category, product in _VENDOR_CATEGORY:
        if sub in low:
            return category, product
    return None


def identify(bssid: str = "", essid: str = "", vendor: str = "") -> dict:
    """Identify a captured AP from its ESSID (strongest), falling back to the OUI
    vendor. Returns {category, product, vendor, confidence, reasons}. 'vendor' is
    optional — pass it from an OUI table when one is wired in; without it, the
    ESSID still classifies most named devices."""
    reasons: List[str] = []

    name = _match_name(essid)
    if name is not None:
        category, product, conf = name
        reasons.append(f"ESSID '{essid}' → {product}")
        if vendor:
            reasons.append(f"OUI vendor '{vendor}'")
        return {"category": category, "product": product, "vendor": vendor or "unknown",
                "confidence": conf, "reasons": tuple(reasons)}

    vc = _vendor_category(vendor)
    if vc is not None:
        category, product = vc
        reasons.append(f"OUI vendor '{vendor}' → typically {product}")
        return {"category": category, "product": product, "vendor": vendor or "unknown",
                "confidence": "medium", "reasons": tuple(reasons)}

    if vendor:
        reasons.append(f"OUI vendor '{vendor}'")
        return {"category": "unknown", "product": vendor, "vendor": vendor,
                "confidence": "low", "reasons": tuple(reasons)}

    return {"category": "unknown", "product": "", "vendor": "unknown",
            "confidence": "low", "reasons": ()}


def label(bssid: str = "", essid: str = "", vendor: str = "") -> str:
    """A compact one-line identity for the captured-networks view, e.g.
    'Ring · doorbell' or 'NETGEAR router'. Empty when nothing is known."""
    g = identify(bssid, essid, vendor)
    product, category = g["product"], g["category"]
    if product and category not in ("unknown", ""):
        return f"{product} · {category}"
    if product:
        return product
    if category not in ("unknown", ""):
        return category
    return ""
