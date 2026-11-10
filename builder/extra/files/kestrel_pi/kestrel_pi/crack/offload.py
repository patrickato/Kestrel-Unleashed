"""crack/offload - bridge the Pi's captures to a real GPU, and the results back.

The Pi cracks on its CPU with aircrack-ng, which is slow (~1-1.5k guesses/s) and
**cannot crack PMKID at all**. A desktop GPU running hashcat is ~1000x faster and
cracks PMKID too (hashcat mode 22000 covers both the EAPOL handshake and PMKID).
This module is the transport-independent core of offloading to one:

* :func:`build_kit` bundles the still-uncracked hashlines plus a ready-to-run
  hashcat script (Windows ``.bat`` and Linux/macOS ``.sh``) and a README into a
  folder you copy to the GPU box. This is the **zero-config, air-gap-friendly**
  path: no SSH, no keys, works across the Faraday cage on a USB stick. You run
  one script on the GPU box; it writes ``recovered.txt``.
* :func:`parse_recovered` reads that ``recovered.txt`` (hashcat ``--show`` output,
  ``<hashline>:<password>`` per line) back into ``(bssid, essid, password)``, and
  :func:`reconcile` applies it to the loot store.

Why a reconcile file instead of writing loot directly: the crack **worker** owns
every write to the loot store (it loads at the top of a pass and saves at the
end, and a pass can run for minutes). So ``kestrel crack ingest`` only *appends*
the recovered lines to a pi-owned file here; the worker applies them on its next
pass through :func:`reconcile`, with no lost-update race. The same ingest path
serves any transport (manual kit today, an automated SSH offload later).

Pure stdlib; no subprocess in this module."""

from __future__ import annotations

import os

from ..capture import parse_hashline
from .hashcat import parse_show
from .store import LootStore

# Where `kestrel crack ingest` accumulates recovered lines (hashline:password),
# deduped, for the worker to reconcile into the loot store. Pi-owned, in the
# crack dir alongside loot.json.
RECOVERED_NAME = "offload-recovered.txt"
# What a built kit is named, and the file the GPU box produces for the trip back.
KIT_TARGETS = "targets.hc22000"
KIT_RECOVERED = "recovered.txt"


def parse_recovered(text):
    """Parse hashcat ``--show`` output (or any ``<hashline>:<password>`` text)
    into ``[(bssid, essid, password), ...]``. The hc22000 hashline uses ``*`` as
    its separator and holds no ``:``, so splitting on the first colon is exact
    (:func:`~kestrel_pi.crack.hashcat.parse_show`); each hashline is then parsed
    for its BSSID/ESSID. Lines that are not a valid hashline (a raw potfile whose
    hash form we can't key to an AP) are skipped, so a stray file never raises."""
    out = []
    text = (text or "").lstrip("﻿")        # drop a stray BOM
    for hashline, password in parse_show(text):
        event = parse_hashline(hashline)
        if event is None or not event.bssid or not password:
            continue
        out.append((event.bssid.upper(), event.essid or "", password))
    return out


def decode_recovered(raw):
    """Decode recovered.txt bytes to text, tolerating the encodings the common
    hashcat front-ends produce. Windows PowerShell's ``>`` redirect writes
    **UTF-16** (with a BOM), which decoded as UTF-8 is unparseable garbage and
    silently ingests nothing; this detects a UTF-16 or UTF-8 BOM and decodes
    accordingly, else UTF-8. A ``str`` is returned unchanged."""
    if isinstance(raw, str):
        return raw
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig", errors="replace")
    return raw.decode("utf-8", errors="replace")


def append_recovered_path(crack_dir, path):
    """Read a recovered.txt from ``path`` (tolerating UTF-16/BOM via
    :func:`decode_recovered`) and append it with :func:`append_recovered`.
    Returns the number of newly-added recovered keys."""
    with open(path, "rb") as fh:
        raw = fh.read()
    return append_recovered(crack_dir, decode_recovered(raw))


def append_recovered(crack_dir, text):
    """Append the recovered ``<hashline>:<password>`` lines in ``text`` to the
    pi-owned reconcile file, de-duplicated against what's already there. Returns
    the number of valid, newly-added recovered keys (0 if none parsed). The file
    is what the worker reads in :func:`reconcile`; writing it needs no lock
    because only ``kestrel crack ingest`` appends and only the worker reads."""
    pairs = parse_recovered(text)
    if not pairs:
        return 0
    path = os.path.join(crack_dir, RECOVERED_NAME)
    existing = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            existing = fh.read()
    except OSError:
        existing = ""
    have = {ln.split(":", 1)[0] for ln in existing.splitlines() if ":" in ln}
    added, lines = 0, []
    for hashline, password in parse_show(text):
        event = parse_hashline(hashline)
        if event is None or not event.bssid or not password:
            continue
        if hashline in have:
            continue
        have.add(hashline)
        lines.append(hashline + ":" + password)
        added += 1
    if added:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return added


def reconcile(aps, crack_dir, now=None, wordlist_name="GPU offload"):
    """Apply the recovered reconcile file to ``aps`` (the loaded loot store),
    marking each still-uncracked AP cracked with its recovered key. Called by the
    worker at the top of a pass, so loot writes stay single-owner. Returns the
    number of records newly marked cracked (0 when the file is absent/empty or
    everything was already cracked). Never raises on a missing/garbled file."""
    path = os.path.join(crack_dir, RECOVERED_NAME)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return 0
    marked = 0
    for bssid, essid, password in parse_recovered(text):
        rec = aps.get(bssid)
        if rec is None:
            # A recovered AP we have no capture record for: create a minimal one
            # so the key is not lost (it still shows on /loot and the map).
            rec = aps[bssid] = {"bssid": bssid, "essid": essid, "status": "pending",
                                "password": "", "tried": [], "first_seen": now or 0}
        if rec.get("password"):
            continue                       # already cracked (locally or earlier)
        rec["no_handshake"] = False
        if essid and not rec.get("essid"):
            rec["essid"] = essid
        LootStore.mark_cracked(rec, password, wordlist_name, now=now)
        marked += 1
    return marked


def uncracked_hashlines(hashline_files, aps, read_events):
    """Every raw hashline whose BSSID is not already cracked in ``aps`` -- the
    targets worth sending to the GPU (PMKID included, which the Pi can't crack).
    ``read_events`` is the capture view's reader (``capture.read_events``).
    De-duplicated, order preserved."""
    cracked = {b for b, rec in (aps or {}).items()
               if isinstance(rec, dict) and rec.get("password")}
    out, seen = [], set()
    for path in hashline_files:
        try:
            events = read_events(path)
        except Exception:  # noqa: BLE001 - one unreadable file must not stop the kit
            continue
        for event in events:
            bssid = (getattr(event, "bssid", "") or "").upper()
            raw = (getattr(event, "raw", "") or "").strip()
            if not raw or not bssid or bssid in cracked or raw in seen:
                continue
            seen.add(raw)
            out.append(raw)
    return out


def build_kit(out_dir, hashline_files, aps, read_events):
    """Write a GPU crack kit into ``out_dir``: ``targets.hc22000`` (the uncracked
    hashlines), ``crack.bat`` + ``crack.sh`` (run hashcat and emit
    ``recovered.txt``) and ``README.txt``. Returns
    ``{"dir", "targets", "files"}``; ``targets`` is 0 when nothing is left to
    crack (the kit is still written, with an empty target file and a note)."""
    os.makedirs(out_dir, exist_ok=True)
    lines = uncracked_hashlines(hashline_files, aps, read_events)
    targets_path = os.path.join(out_dir, KIT_TARGETS)
    with open(targets_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    files = {KIT_TARGETS: targets_path}
    for name, body in (("crack.bat", _CRACK_BAT), ("crack.sh", _CRACK_SH),
                       ("README.txt", _README)):
        p = os.path.join(out_dir, name)
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        if name == "crack.sh":
            try:
                os.chmod(p, 0o755)
            except OSError:
                pass
        files[name] = p
    return {"dir": out_dir, "targets": len(lines), "files": files}


# -- the files written into a kit (not shell files in THIS repo, so not linted;
#    they run on the operator's GPU box, which has hashcat) ---------------------

_CRACK_BAT = (
    "@echo off\r\n"
    "REM  Kestrel GPU crack kit (Windows). Run on a machine with a GPU + hashcat.\r\n"
    "REM  Usage:  crack.bat  [path-to-wordlist.txt]\r\n"
    "setlocal\r\n"
    "set WL=%~1\r\n"
    "if \"%WL%\"==\"\" set WL=wordlist.txt\r\n"
    "if not exist \"%WL%\" (\r\n"
    "  echo No wordlist found. Put one next to this file as wordlist.txt, or pass it:\r\n"
    "  echo     crack.bat C:\\path\\to\\rockyou.txt\r\n"
    "  exit /b 1\r\n"
    ")\r\n"
    "where hashcat >nul 2>nul || (echo hashcat not found on PATH - install it first. & exit /b 1)\r\n"
    "echo Cracking targets.hc22000 with %WL% ...\r\n"
    "hashcat -m 22000 -a 0 targets.hc22000 \"%WL%\" --potfile-path kestrel.potfile\r\n"
    "echo Writing recovered.txt ...\r\n"
    "REM  --outfile (not a > redirect): PowerShell's > writes UTF-16, which the\r\n"
    "REM  Kestrel can't parse; hashcat's --outfile is plain UTF-8.\r\n"
    "hashcat -m 22000 --show targets.hc22000 --potfile-path kestrel.potfile --outfile recovered.txt\r\n"
    "echo.\r\n"
    "echo Done. Copy recovered.txt back to the Kestrel and run:\r\n"
    "echo     kestrel crack ingest recovered.txt\r\n"
    "endlocal\r\n"
)

_CRACK_SH = (
    "#!/usr/bin/env bash\n"
    "#  Kestrel GPU crack kit (Linux/macOS). Run on a machine with a GPU + hashcat.\n"
    "#  Usage:  ./crack.sh  [path-to-wordlist.txt]\n"
    "set -eu\n"
    'WL="${1:-wordlist.txt}"\n'
    'if [ ! -f "$WL" ]; then\n'
    '  echo "No wordlist found. Put one next to this file as wordlist.txt, or pass it:"\n'
    '  echo "    ./crack.sh /path/to/rockyou.txt"\n'
    "  exit 1\n"
    "fi\n"
    'command -v hashcat >/dev/null 2>&1 || { echo "hashcat not found on PATH - install it first."; exit 1; }\n'
    'echo "Cracking targets.hc22000 with $WL ..."\n'
    'hashcat -m 22000 -a 0 targets.hc22000 "$WL" --potfile-path kestrel.potfile || true\n'
    'echo "Writing recovered.txt ..."\n'
    "hashcat -m 22000 --show targets.hc22000 "
    "--potfile-path kestrel.potfile --outfile recovered.txt\n"
    'echo\n'
    'echo "Done. Copy recovered.txt back to the Kestrel and run:"\n'
    'echo "    kestrel crack ingest recovered.txt"\n'
)

_README = (
    "Kestrel - GPU crack kit\n"
    "=======================\n\n"
    "Your Kestrel captures Wi-Fi handshakes and PMKIDs but cracks them slowly on\n"
    "its little CPU (and it can't crack PMKID at all). This kit lets a real GPU do\n"
    "the heavy lifting - about a thousand times faster - and send the answers back.\n"
    "Nothing here phones home: you move the files, so it works even with the\n"
    "Kestrel fully offline.\n\n"
    "WHAT'S IN HERE\n"
    "  targets.hc22000   the networks still waiting to be cracked (PMKID included)\n"
    "  crack.bat         run this on Windows\n"
    "  crack.sh          run this on Linux or macOS\n"
    "  README.txt        this file\n\n"
    "ON THE GPU MACHINE (a desktop/laptop with a decent GPU)\n"
    "  1. Install hashcat (https://hashcat.net/hashcat/) so `hashcat` runs in a\n"
    "     terminal. On Windows, unzip it and add it to PATH (or drop these files in\n"
    "     the hashcat folder).\n"
    "  2. Put a wordlist next to these files named wordlist.txt (rockyou.txt is a\n"
    "     fine start), or pass your own path to the script.\n"
    "  3. Run it:\n"
    "       Windows:  crack.bat               (or: crack.bat C:\\path\\to\\rockyou.txt)\n"
    "       Linux/Mac: ./crack.sh             (or: ./crack.sh /path/to/rockyou.txt)\n"
    "     For the random all-digit router keys no wordlist holds, run a brute force\n"
    "     instead, e.g. (8 digits):\n"
    "       hashcat -m 22000 -a 3 targets.hc22000 ?d?d?d?d?d?d?d?d --potfile-path kestrel.potfile\n"
    "     then re-run the --show line to refresh recovered.txt (the script's last step).\n\n"
    "BACK ON THE KESTREL\n"
    "  Copy recovered.txt back and run:\n"
    "       kestrel crack ingest recovered.txt\n"
    "  The recovered keys then show up on the Loot page and light up on the map,\n"
    "  and each one is also tried against your other networks automatically.\n\n"
    "TIP: the same recovered.txt can be ingested more than once safely - already-\n"
    "known keys are ignored.\n"
)
