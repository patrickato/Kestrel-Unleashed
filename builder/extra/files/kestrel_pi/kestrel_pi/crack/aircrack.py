"""aircrack-ng crack backend (the Pi's working CPU WPA cracker).

hashcat needs an OpenCL device; the Pi's only CPU OpenCL is pocl, which caps a
single allocation at 256 MB -- too small for the ``-m 22000`` kernel at any
settings -- so hashcat can't run WPA here at all. aircrack-ng cracks WPA on the
CPU natively (no OpenCL, no cap), so this is the engine the worker uses.

aircrack reads packet captures, not hashcat's ``.hc22000`` hashlines, and it
won't parse AngryOxide's pcapng directly, so the worker first converts the
rolling capture to a classic ``.pcap`` with ``tcpdump``. A dictionary attack is
``aircrack-ng -w <list> -b <bssid> <pcap>``; a mask is run by streaming
``crunch`` candidates into aircrack's stdin (``-w -``). The runner is injected,
so the logic tests with no tools and no radio. Stdlib only.
"""
from __future__ import annotations

import re
import shutil

AIRCRACK = "aircrack-ng"
TCPDUMP = "tcpdump"
CRUNCH = "crunch"


def have_aircrack():
    return shutil.which(AIRCRACK) is not None


def have_tcpdump():
    return shutil.which(TCPDUMP) is not None


def have_crunch():
    return shutil.which(CRUNCH) is not None


def convert_cmd(pcapng, out_pcap):
    """argv to rewrite a pcapng as a classic pcap aircrack can read."""
    return [TCPDUMP, "-r", str(pcapng), "-w", str(out_pcap)]


def build_dict_cmd(pcap, bssid, wordlist):
    """argv for a dictionary crack of one AP (``bssid``) in ``pcap``. ``pcap``
    may be one path or a list of paths (aircrack accepts several captures)."""
    caps = [str(p) for p in (pcap if isinstance(pcap, (list, tuple)) else [pcap])]
    return [AIRCRACK, "-w", str(wordlist), "-b", str(bssid), "-q"] + caps


def build_stdin_cmd(pcap, bssid):
    """argv for aircrack reading candidate keys from **stdin** (``-w -``), used
    when a generator (crunch) streams a mask's keyspace into it."""
    caps = [str(p) for p in (pcap if isinstance(pcap, (list, tuple)) else [pcap])]
    return [AIRCRACK, "-w", "-", "-b", str(bssid), "-q"] + caps


# hashcat built-in mask charsets -> crunch character sets.
_CHARSETS = {
    "d": "0123456789",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
}


def mask_to_crunch(mask):
    """A hashcat mask made of a single repeated built-in class (``?d?d?d?d`` ...)
    -> ``[crunch, N, N, charset]``. Returns ``None`` for anything crunch can't
    express simply (mixed classes, custom ``?1`` sets, or literal characters) --
    the caller then skips it rather than running the wrong keyspace."""
    tokens = re.findall(r"\?.", mask or "")
    if not tokens or "".join(tokens) != (mask or ""):
        return None                       # literals or stray characters present
    classes = {t[1] for t in tokens}
    if len(classes) != 1:
        return None                       # mixed classes -- crunch -t is needed
    cls = classes.pop()
    charset = _CHARSETS.get(cls)
    if charset is None:
        return None                       # custom/unsupported class
    n = len(tokens)
    return [CRUNCH, str(n), str(n), charset]


_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")


def parse_key(text):
    """The recovered passphrase from aircrack output, or ``None``."""
    m = _KEY_RE.search(text or "")
    return m.group(1) if m else None


def classify(text):
    """How an aircrack run ended, from its output (exit codes don't distinguish
    'not found' from an error): ``"cracked"`` (key recovered), ``"exhausted"``
    (ran, no match), or ``"error"`` (bad capture / no handshake / didn't run)."""
    t = text or ""
    if "KEY FOUND" in t:
        return "cracked"
    if "KEY NOT FOUND" in t or "Passphrase not in dictionary" in t:
        return "exhausted"
    return "error"


def error_detail(text):
    """A short reason from a failed run, for the status 'error' field."""
    t = (text or "").strip()
    for needle in ("Unsupported file format", "No valid WPA handshakes",
                   "No matching network", "Please specify", "Read 0 packets"):
        if needle in t:
            return needle
    last = [ln.strip() for ln in t.splitlines() if ln.strip()]
    return (last[-1] if last else "aircrack-ng failed")[:200]
