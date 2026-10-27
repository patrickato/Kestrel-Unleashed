"""Device-aware crack suggestions: given a captured network, recommend the
attacks most likely to recover a **default** WPA key for that kind of device,
in order — curated default-key lists, brute-force masks, and (when the SSID/OUI
identifies a model) the vendor key-generator to run.

Kestrel's device-ID already classifies each captured AP (camera, router,
printer, ...), and some SSIDs name the model outright (``UPC1234567``,
``ATTabcdefg``, ``NETGEAR42``). This turns that into "what should I throw at it,
and in what order", so the operator isn't guessing. Pure/stdlib: it only decides
*what* to run; the cracking itself is the normal ``-m 22000`` path.

Honest by design (the research bottom line): predictable default PSKs live on
**older ISP routers/gateways** (where per-vendor keygens collapse the search to
a handful of candidates); **cameras, hotspots and IoT hubs** mostly onboard via
BLE / QR / an *open* setup AP and ship **no** crackable default WPA key, so for
those the engine says so and falls back to the generic order rather than
inventing a vendor default. The single highest-value blind attack across
everything is the **8-digit numeric mask**.

Lab / authorized use only -- suggest attacks only against devices you own or are
authorized to assess.
"""
from __future__ import annotations

import re

from .. import device_id

# --- the building-block attacks --------------------------------------------
# Masks use hashcat built-in charsets: ?d = 0-9, ?H = 0-9A-F (uppercase hex).
MASK_8_DIGIT = "?d?d?d?d?d?d?d?d"            # 10^8 -- the universal default-key win
MASK_10_DIGIT = "?d" * 10
MASK_11_DIGIT = "?d" * 11
MASK_8_HEX = "?H?H?H?H?H?H?H?H"             # 8 uppercase hex (sticker-style keys)
MASK_10_HEX = "?H" * 10                      # Thomson/SpeedTouch/BT family

# A tiny curated default-key list shipped as device-defaults.txt; referenced
# only when it is actually present in the wordlists dir.
DEFAULTS_LIST = "device-defaults.txt"


def _mask(value, label, note=""):
    return {"kind": "mask", "value": value, "label": label,
            "runnable": True, "note": note}


def _wordlist(name, label, note=""):
    return {"kind": "wordlist", "value": name, "label": label,
            "runnable": True, "note": note}


def _keygen(tool, label, url, note=""):
    # Advisory: an external generator Kestrel does not bundle. It produces a
    # small candidate list to feed back through `kestrel crack run ... --wordlist`.
    return {"kind": "keygen", "value": tool, "label": label, "url": url,
            "runnable": False, "note": note}


# The generic fallback order (research section 8), for an unidentified AP or a
# device class with no special default. Masks always run; the list is included
# only when present.
def _generic(have_defaults):
    out = []
    if have_defaults:
        out.append(_wordlist(DEFAULTS_LIST, "Curated default keys (12345678, ...)"))
    out += [
        _mask(MASK_8_DIGIT, "8-digit numeric", "the single best default-key sweep"),
        _mask(MASK_10_DIGIT, "10-digit numeric", "slower; some gateways/hotspots"),
        _mask(MASK_8_HEX, "8 uppercase hex", "sticker-style keys"),
    ]
    return out


# --- SSID-pattern rules (model-specific; highest priority) ------------------
# Each: (compiled regex on ESSID, headline, [attacks], caveat). These collapse
# an otherwise-infeasible brute into a vendor keygen or a tight mask.
_SSID_RULES = [
    (re.compile(r"^UPC\d{7}$", re.I),
     "UPC / Ubee gateway — default key is 8 uppercase letters (no I/L/O)",
     [_keygen("upc_keys", "upc_keys generator (→ a few candidates)",
              "https://github.com/cdiv1e12/upc_keys.py",
              "feed its output back via `--wordlist`"),
      _mask("?1?1?1?1?1?1?1?1",
            "blind 8× A-Z no I/L/O  (needs: -1 ABCDEFGHJKMNPQRSTUVWXYZ)",
            "the keygen is far faster when the SSID is UPC#######")],
     "Legacy UPC/Ziggo only; newer units randomized."),
    (re.compile(r"^ATT.{6,8}$", re.I),
     "AT&T Arris/Pace gateway — algorithmic 12-char lowercase-alnum key",
     [_keygen("pskracker", "PSKracker nvg589/nvg599 (→ candidate list)",
              "https://github.com/soxrok2212/PSKracker",
              "blind brute is infeasible; use the keygen")],
     "Older NVG589/599; BGW210/320 are randomized."),
    (re.compile(r"^HOME-[0-9A-F]{4}$", re.I),
     "Comcast/Xfinity gateway — word+4-digit+word, or per-model BSSID keygen",
     [_keygen("pskracker", "PSKracker dpc3939/dpc3941/tg1682g (needs BSSID)",
              "https://github.com/soxrok2212/PSKracker"),
      _keygen("xfinity-gen", "Xfinity combinator wordlist generator",
              "https://github.com/0dayCTF/0day-Xfinity-Wordlist-Generator")],
     "Legacy DPC/Arris models; XB6/7/8 are randomized."),
    (re.compile(r"^NETGEAR", re.I),
     "NETGEAR — default key is a dictionary word + 3 digits",
     [_keygen("hybrid", "hashcat hybrid: a word list + ?d?d?d (-a 6)",
              "https://hashcat.net/wiki/doku.php?id=hybrid_attack",
              "e.g. a Netgear word list with mask ?d?d?d appended")],
     "Older models; many are now random."),
    (re.compile(r"^Belkin\.[0-9a-f]+$", re.I),
     "Belkin — key derived from WAN MAC + serial (CVE-2012-4366)",
     [_keygen("pskracker", "PSKracker belkin -b <bssid> (→ a few candidates)",
              "https://github.com/soxrok2212/PSKracker")],
     "Affected Belkin model range only."),
    (re.compile(r"^(SpeedTouch|Thomson|BTHomeHub|Orange-|BigPond)", re.I),
     "Thomson/SpeedTouch/BT family — 10 uppercase-hex key derived from the serial",
     [_keygen("routerkeygen", "routerkeygen / stkeys (→ candidate list)",
              "https://github.com/routerkeygen/routerkeygenPC"),
      _mask(MASK_10_HEX, "blind 10 uppercase hex", "days-scale; prefer the keygen")],
     "Classic 2007-2013 gear; essentially gone on new kit."),
    (re.compile(r"^EE-(BrightBox-)?[0-9A-Za-z]{6}$", re.I),
     "EE BrightBox — default key is word-word with a '-' separator",
     [_keygen("combinator", "hashcat combinator (-a 1) with -j '$-'",
              "https://github.com/hashcat/hashcat-utils")],
     "BrightBox 1/2 era."),
    (re.compile(r"^DIRECT-.*(HP|EPSON|CANON|BROTHER)", re.I),
     "Printer Wi-Fi Direct — very often the factory default 12345678",
     None,   # filled with the printer order below (keeps it in one place)
     "Newer printers print a random 8-char key on the config page."),
]


def _printer_attacks(have_defaults):
    out = [_mask(MASK_8_DIGIT, "8-digit numeric",
                 "HP Wi-Fi Direct default is 12345678 — this sweeps it + the rest")]
    if have_defaults:
        out.insert(0, _wordlist(DEFAULTS_LIST, "Curated default keys (incl. 12345678)"))
    return out


# --- category rules (when no SSID pattern matched) --------------------------
def _category_suggestion(category, product, have_defaults):
    if category in ("router", "gateway"):
        return (product + " — no model match; try the generic default-key order"
                + " (ID the model from the SSID/OUI for a vendor keygen)",
                _generic(have_defaults),
                "Predictable defaults are mostly pre-2015 gear.")
    if category == "printer":
        return (product + " — Wi-Fi Direct default is usually 12345678",
                _printer_attacks(have_defaults),
                "Newer models randomize the key.")
    if category in ("hotspot",):
        return (product + " — default is on the label; modern units are random",
                [_mask(MASK_8_DIGIT, "8-digit numeric"),
                 _mask(MASK_10_DIGIT, "10-digit numeric"),
                 _mask(MASK_11_DIGIT, "11-digit numeric")],
                "No reliable keygen; blind masks then probable-WPA lists.")
    if category in ("camera", "doorbell", "iot", "light", "speaker", "tv",
                    "gaming", "hub"):
        return (product + " — these usually onboard via BLE/QR/open-AP and ship"
                + " no crackable default WPA key; using the generic order",
                _generic(have_defaults),
                "Don't expect a vendor default here; this is a blind fallback.")
    return None


def suggest(essid="", bssid="", vendor="", have_defaults=False):
    """Return an ordered attack suggestion for one AP.

    ``{category, product, match, headline, attacks:[...], caveat}``. ``match`` is
    ``ssid-pattern`` (model identified), ``category`` (device class), or
    ``generic``. ``have_defaults`` says whether the curated default-key list is
    present, so it is suggested only when runnable. Each attack carries
    ``runnable`` (a mask or present wordlist Kestrel can run now) or is advisory
    (an external keygen, with a ``url``)."""
    essid = essid or ""
    ident = device_id.identify(bssid=bssid, essid=essid, vendor=vendor)
    category = ident.get("category", "")
    product = ident.get("product") or (category or "network")

    for rx, headline, attacks, caveat in _SSID_RULES:
        if rx.search(essid.strip()):
            if attacks is None:                    # the printer Wi-Fi Direct rule
                attacks = _printer_attacks(have_defaults)
            return {"category": category or "router", "product": product,
                    "match": "ssid-pattern", "headline": headline,
                    "attacks": attacks, "caveat": caveat}

    cat = _category_suggestion(category, product, have_defaults)
    if cat is not None:
        headline, attacks, caveat = cat
        return {"category": category, "product": product, "match": "category",
                "headline": headline, "attacks": attacks, "caveat": caveat}

    return {"category": category, "product": product, "match": "generic",
            "headline": (product + " — no device-specific default known; "
                         "generic default-key order"),
            "attacks": _generic(have_defaults),
            "caveat": "Blind fallback; a strong human-chosen key needs the wordlists."}


def render_text(sug, essid=""):
    """A plain-text block for the CLI: the headline, the ordered attacks with a
    ready `kestrel crack run` line for the runnable ones, and the caveat."""
    lines = []
    who = essid or sug.get("product") or "this network"
    lines.append("Suggested for %s (%s):" % (who, sug.get("product", "")))
    lines.append("  " + sug.get("headline", ""))
    lines.append("")
    for i, a in enumerate(sug.get("attacks", []), 1):
        tag = {"mask": "mask", "wordlist": "list", "keygen": "tool",
               "hybrid": "hybrid"}.get(a["kind"], a["kind"])
        lines.append("  %d. [%s] %s" % (i, tag, a.get("label", a.get("value", ""))))
        if a["kind"] == "mask":
            lines.append("       kestrel crack run <FILE> --mask '%s'" % a["value"])
        elif a["kind"] == "wordlist" and a.get("runnable"):
            lines.append("       kestrel crack run <FILE> --wordlist %s" % a["value"])
        if a.get("url"):
            lines.append("       %s" % a["url"])
        if a.get("note"):
            lines.append("       (%s)" % a["note"])
    if sug.get("caveat"):
        lines.append("")
        lines.append("  Note: " + sug["caveat"])
    return "\n".join(lines)
