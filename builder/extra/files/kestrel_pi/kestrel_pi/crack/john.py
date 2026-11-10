"""On-device cracking of the ``.hc22000`` store with John the Ripper (jumbo).

The Pi's other CPU engine, aircrack-ng, needs a packet capture and can read
neither the ``.hc22000`` hashline store nor a PMKID; hashcat can't run on the
Pi's pocl at all. John the Ripper **jumbo** cracks both **EAPOL** handshakes and
**PMKID** on the CPU, with a rule engine, reading only the hashline store -- so
it is the preferred on-device cracker when present, and the only on-device way to
chew the *stored backlog* (whose raw captures housekeeping deleted long ago).

John reads its own ``$WPAPSK$`` format, not hashcat's ``.hc22000``, so this
module converts (both verified end to end -- John recovers the known passphrase):

- **PMKID** (``WPA*01*…``) -> John's wpapsk PMKID line directly, a field
  reshuffle matching ``wpapcap2john``'s output.
- **EAPOL** (``WPA*02*…``) -> a hashcat ``hccapx`` record, which John's shipped
  ``hccapx2john.py`` turns into a wpapsk line (robust + maintained; it also emits
  the nonce-fuzz variants that cover unknown nonce endianness).

Pure helpers (the conversions, the command lines, the ``--show`` and progress
parsers) are unit-tested here; the controller does the temp files + subprocess.
Stdlib only.
"""

from __future__ import annotations

import re
import shutil
import struct

JOHN = "john"
HCCAPX2JOHN = "hccapx2john.py"
HCCAPX_SIZE = 393          # one hccapx v4 record (packed)
_SOURCE_TAG = "kestrel"    # the trailing "source" field on a John wpapsk line


def have_john(john=JOHN):
    """True only when a usable **jumbo** John is present: the ``john`` binary is
    on PATH *and* its ``hccapx2john.py`` helper is found beside it. Debian's stock
    ``john`` is the core build -- no wpapsk format, no ``*2john`` tools -- so we
    must not let ``engine = auto`` pick it and then fail on ``--format=wpapsk``."""
    return shutil.which(john) is not None and find_hccapx2john(john) is not None


def find_hccapx2john(john=JOHN):
    """Locate ``hccapx2john.py`` -- on PATH, or next to the ``john`` binary (john
    jumbo ships it in the same ``run/`` dir). ``None`` if not found."""
    hit = shutil.which(HCCAPX2JOHN)
    if hit:
        return hit
    jbin = shutil.which(john)
    if jbin:
        import os
        cand = os.path.join(os.path.dirname(os.path.realpath(jbin)), HCCAPX2JOHN)
        if os.path.exists(cand):
            return cand
    return None


def colonize(mac_hex):
    """``aabbccddeeff`` -> ``AA:BB:CC:DD:EE:FF``."""
    h = (mac_hex or "").strip()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper()


def _essid_text(essid_hex):
    try:
        return bytes.fromhex(essid_hex).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return essid_hex        # keep hex for a hidden/odd ESSID rather than fail


def _fields(line):
    """Split a hc22000 line on ``*`` and return the fields, or ``None`` if it is
    not a WPA line with enough of them."""
    line = (line or "").strip()
    if not line.startswith("WPA*"):
        return None
    f = line.split("*")
    return f if len(f) >= 6 else None


def pmkid_to_john(line):
    """A hc22000 **PMKID** line -> a John wpapsk line, or ``None`` if ``line`` is
    not a PMKID. Mirrors ``wpapcap2john``:
    ``essid:pmkid*ap*sta*essid_hex:sta:ap:ap::PMKID:source``."""
    f = _fields(line)
    if not f or f[1] != "01":
        return None
    pmkid, ap, sta, essid_hex = f[2], f[3], f[4], f[5]
    if not (pmkid and ap and sta and essid_hex):
        return None
    essid = _essid_text(essid_hex)
    return "%s:%s*%s*%s*%s:%s:%s:%s::PMKID:%s" % (
        essid, pmkid, ap, sta, essid_hex, sta, ap, ap, _SOURCE_TAG)


def eapol_to_hccapx(line):
    """A hc22000 **EAPOL** line -> one packed 393-byte ``hccapx`` v4 record, or
    ``None`` if ``line`` is not a crackable EAPOL line. The STA nonce is read from
    the EAPOL frame's Key Nonce field; the key version from its key-info bits."""
    f = _fields(line)
    if not f or f[1] != "02":
        return None
    try:
        mic = bytes.fromhex(f[2]); ap = bytes.fromhex(f[3]); sta = bytes.fromhex(f[4])
        essid = bytes.fromhex(f[5]); anonce = bytes.fromhex(f[6]); eapol = bytes.fromhex(f[7])
        mp = int(f[8], 16) & 0xFF if len(f) > 8 and f[8] else 0
    except (ValueError, IndexError):
        return None
    if len(mic) != 16 or len(ap) != 6 or len(sta) != 6 or len(anonce) != 32:
        return None
    if len(eapol) < 49 or len(eapol) > 256 or len(essid) > 32:
        return None
    snonce = eapol[17:49]                                   # Key Nonce in the frame
    keyver = (int.from_bytes(eapol[5:7], "big") & 0x07) or 2  # key-info descriptor ver
    rec = b"HCPX" + struct.pack("<I", 4)
    rec += struct.pack("<B", mp)
    rec += struct.pack("<B", len(essid)) + essid.ljust(32, b"\x00")
    rec += struct.pack("<B", keyver)
    rec += mic.ljust(16, b"\x00")
    rec += ap + anonce
    rec += sta + snonce
    rec += struct.pack("<H", len(eapol)) + eapol.ljust(256, b"\x00")
    return rec if len(rec) == HCCAPX_SIZE else None


def split_sources(lines):
    """Split hc22000 ``lines`` into ``(pmkid_john_lines, eapol_hccapx_blob)``:
    the PMKID lines already converted to John text, and the EAPOL records packed
    into one concatenated hccapx blob for ``hccapx2john`` to convert. Lines that
    are neither (or malformed) are dropped."""
    pmkid, blob = [], b""
    for line in lines:
        jl = pmkid_to_john(line)
        if jl is not None:
            pmkid.append(jl)
            continue
        rec = eapol_to_hccapx(line)
        if rec is not None:
            blob += rec
    return pmkid, blob


def build_crack_cmd(hashfile, wordlist, pot, rules=None, session=None,
                    progress_every=2, john=JOHN):
    """argv for a dictionary crack of ``hashfile`` with ``wordlist`` (+ optional
    ``rules``), writing cracks to ``pot``. ``--progress-every`` makes John print a
    periodic status line the live view parses; ``--format=wpapsk`` pins the format
    so it never prompts."""
    cmd = [john, "--format=wpapsk", "--wordlist=%s" % wordlist,
           "--pot=%s" % pot]
    if rules:
        cmd.append("--rules=%s" % rules)
    if session:
        cmd.append("--session=%s" % session)
    if progress_every:
        cmd.append("--progress-every=%d" % int(progress_every))
    cmd.append(hashfile)
    return cmd


def build_show_cmd(hashfile, pot, john=JOHN):
    """argv to list the cracks John found for ``hashfile`` (reads ``pot``)."""
    return [john, "--show", "--format=wpapsk", "--pot=%s" % pot, hashfile]


_MASK_OK = {"?d", "?l", "?u", "?s", "?a"}


def mask_to_john(mask):
    """A hashcat mask that uses only built-in classes John shares (``?d ?l ?u ?s
    ?a``) -> the same string for ``john --mask``; ``None`` for anything else
    (custom ``?1`` sets, ``?h``/``?H``, or literals), so the caller skips it rather
    than run the wrong keyspace. The device-default numeric masks pass straight
    through."""
    tokens = re.findall(r"\?.", mask or "")
    if not tokens or "".join(tokens) != (mask or ""):
        return None
    return mask if all(t in _MASK_OK for t in tokens) else None


def build_mask_cmd(hashfile, mask, pot, session=None, progress_every=2, john=JOHN):
    """argv for a mask (brute-force) crack of ``hashfile`` with John's own
    ``--mask`` (same ``?d?l?u?s?a`` tokens), writing cracks to ``pot``."""
    cmd = [john, "--format=wpapsk", "--mask=%s" % mask, "--pot=%s" % pot]
    if session:
        cmd.append("--session=%s" % session)
    if progress_every:
        cmd.append("--progress-every=%d" % int(progress_every))
    cmd.append(hashfile)
    return cmd


_HEX12 = re.compile(r"^[0-9a-fA-F]{12}$")


def parse_show(text):
    """Parse ``john --show`` wpapsk output into ``[(bssid, essid, password), …]``.

    A line is ``essid:password:sta:ap:ap::TYPE[:…]:source`` -- the BSSID is the
    AP MAC, which appears as the repeated 12-hex pair. We locate that pair so a
    password containing ``:`` still parses, and derive everything from it."""
    out = []
    for raw in (text or "").splitlines():
        raw = raw.strip()
        if not raw or ":" not in raw:
            continue
        parts = raw.split(":")
        ap_idx = None
        for i in range(1, len(parts) - 1):
            if parts[i] and parts[i] == parts[i + 1] and _HEX12.match(parts[i]):
                ap_idx = i
                break
        if ap_idx is None or ap_idx < 2:
            continue
        essid = parts[0]
        password = ":".join(parts[1:ap_idx - 1])   # between essid and the STA mac
        if not password:
            continue
        out.append((colonize(parts[ap_idx]), essid, password))
    return out


_RE_PCT = re.compile(r"([\d.]+)\s*%")
_RE_RATE = re.compile(r"([\d.]+)\s*([kMG]?)p/s")
_RE_ETA = re.compile(r"\(ETA:\s*([^)]+)\)")
_RE_CAND = re.compile(r"(\S+)\.\.(\S+)\s*$")
_RE_GUESS = re.compile(r"(\d+)g\s")
_MULT = {"": 1.0, "k": 1e3, "M": 1e6, "G": 1e9}


def parse_progress(text):
    """Latest John status line -> the same shape the live view uses for aircrack
    (``percent``/``rate_kps``/``eta``/``passphrase``), or ``{}``. John prints, with
    ``--progress-every``:
    ``0g 0:00:00:02 0.03% (ETA: 20:10:43) 0g/s 13359p/s 13359c/s 13359C/s a..b``."""
    text = text or ""
    # Work from the last status line present (John repaints line by line).
    line = ""
    for ln in text.splitlines():
        if _RE_RATE.search(ln) or _RE_GUESS.search(ln):
            line = ln
    if not line:
        return {}
    out = {}
    m = _RE_PCT.search(line)
    if m:
        out["percent"] = float(m.group(1))
    m = _RE_RATE.search(line)          # p/s -> k/s, to match aircrack's unit
    if m:
        out["rate_kps"] = float(m.group(1)) * _MULT.get(m.group(2), 1.0) / 1000.0
    m = _RE_ETA.search(line)
    if m:
        out["eta"] = m.group(1).strip()
    m = _RE_CAND.search(line)
    if m and m.group(2).upper() != "DONE":
        out["passphrase"] = m.group(2)
    return out
