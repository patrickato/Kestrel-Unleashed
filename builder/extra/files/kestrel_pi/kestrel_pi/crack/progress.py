"""Live crack progress: parse aircrack-ng's running status, and read/write the
small ``crack-progress.json`` the live view renders.

The worker normally runs aircrack-ng with ``-q`` (quiet) and reads its output in
one shot at the end, so there is nothing to watch while a wordlist grinds -- and
on the Pi one AP against a big list is *hours*. For a live view the worker runs
aircrack **without** ``-q`` and streams its repainting status block through
:func:`parse_progress` here, writing the latest numbers to ``crack-progress.json``
a few times a second. The daemon's Quick-crack card (auto-refreshing) and
``kestrel crack watch`` both read that file and overlay it on ``status.json``.

Pure and stdlib-only: the fiddly, testable part (parsing aircrack's text) lives
here; the streaming plumbing lives in :mod:`.controller`. A future engine (e.g.
John the Ripper for the ``.hc22000`` store) adds its own parser beside
:func:`parse_progress`; the file shape and the readers stay the same.
"""

from __future__ import annotations

import json
import os
import re
import time

from . import CRACK_DIR, PROGRESS_NAME

# How recent ``crack-progress.json`` must be to count as "live". The worker
# flushes every couple of seconds while cracking; if the file is older than this
# the worker has moved on (or died), so the readers ignore it rather than show a
# frozen passphrase forever.
STALE_SECONDS = 30

# aircrack-ng repaints a status block as it works, e.g.:
#       [00:00:08] 10464/10303727 keys tested (1308.00 k/s)
#       Time left: 2 hours, 11 minutes, 23 seconds              0.10%
#                            Current passphrase: superman
_RE_ELAPSED = re.compile(r"\[(\d{1,2}):(\d{2}):(\d{2})\]")
_RE_KEYS = re.compile(r"(\d[\d,]*)\s*/\s*(\d[\d,]*)\s+keys tested")
_RE_RATE = re.compile(r"\(\s*([\d.]+)\s*k/s\s*\)")
_RE_PASS = re.compile(r"Current passphrase:\s*(.+)")
_RE_ETA = re.compile(r"Time left:\s*(.+?)(?:\s{2,}|\s*[\d.]+\s*%|$)")
_RE_PCT = re.compile(r"([\d.]+)\s*%")


def _last(rx, text, group=1):
    """The last match of ``rx`` in ``text`` (aircrack repaints, so the latest
    block wins), or ``None``."""
    found = None
    for found in rx.finditer(text):
        pass
    return found.group(group) if found else None


def _int(digits):
    return int(digits.replace(",", ""))


def parse_progress(text):
    """Latest progress from a tail of aircrack-ng output. Returns a dict with
    whatever it could read -- ``tested``/``total`` (int), ``rate_kps`` (float),
    ``percent`` (float), ``eta`` (str), ``passphrase`` (str), ``elapsed`` (str)
    -- or ``{}`` when nothing parseable is present yet (banner only)."""
    text = text or ""
    out = {}
    keys = None
    for keys in _RE_KEYS.finditer(text):
        pass
    if keys:
        out["tested"] = _int(keys.group(1))
        out["total"] = _int(keys.group(2))
    rate = _last(_RE_RATE, text)
    if rate is not None:
        out["rate_kps"] = float(rate)
    eta = _last(_RE_ETA, text)
    if eta and eta.strip():
        out["eta"] = eta.strip()
    passphrase = _last(_RE_PASS, text)
    if passphrase is not None:
        pw = passphrase.rstrip()
        if pw:
            out["passphrase"] = pw
    elapsed = None
    for elapsed in _RE_ELAPSED.finditer(text):
        pass
    if elapsed:
        out["elapsed"] = "%s:%s:%s" % elapsed.groups()
    pct = _last(_RE_PCT, text)
    if pct is not None:
        out["percent"] = float(pct)
    elif out.get("total"):
        out["percent"] = round(100.0 * out["tested"] / out["total"], 2)
    return out


def progress_path(crack_dir=CRACK_DIR):
    return os.path.join(crack_dir, PROGRESS_NAME)


def write_progress(crack_dir, data, now=None):
    """Write ``crack-progress.json`` atomically and world-readable (the daemon,
    running as ``pi`` like the worker, and ``kestrel crack watch`` read it).
    Stamps ``updated_at`` so the readers can tell live from stale."""
    record = dict(data or {})
    record["updated_at"] = time.time() if now is None else now
    path = progress_path(crack_dir)
    tmp = path + ".tmp"
    try:
        os.makedirs(crack_dir, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(record, handle)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return record


def read_progress(crack_dir=CRACK_DIR):
    """The last-written progress dict, or ``None`` if absent/malformed."""
    try:
        with open(progress_path(crack_dir), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def clear_progress(crack_dir=CRACK_DIR):
    """Remove ``crack-progress.json`` (the worker is no longer cracking). Missing
    file is fine."""
    try:
        os.unlink(progress_path(crack_dir))
    except OSError:
        pass


def is_fresh(progress, now=None, max_age=STALE_SECONDS):
    """True when ``progress`` is a live 'cracking' record written within
    ``max_age`` seconds -- so a reader shows it as happening *now* rather than a
    frozen leftover."""
    if not isinstance(progress, dict):
        return False
    if progress.get("state") and progress.get("state") != "cracking":
        return False
    ts = progress.get("updated_at")
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return False
    now = time.time() if now is None else now
    return 0 <= (now - ts) <= max_age
