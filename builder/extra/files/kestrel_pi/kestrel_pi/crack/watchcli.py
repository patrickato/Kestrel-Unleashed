"""``kestrel crack watch`` -- a live, redrawing view of the crack worker.

Reads the worker's ``status.json`` and the live ``crack-progress.json`` a few
times a second and redraws a compact panel until Ctrl-C, so an operator SSH'd in
from a laptop can watch a crack move (which wordlist, how far, keys/s, the
passphrase it is on) instead of re-running ``crack status`` by hand. Pure render
(:func:`render_frame`) is unit-tested; only the loop (clear screen, sleep) is not.
"""

from __future__ import annotations

import argparse
import sys
import time

from . import CRACK_DIR
from . import progress as progress_mod
from . import readout


def _bar(pct, width=24):
    """A text progress bar for ``pct`` (0-100), e.g. ``[########········]``."""
    try:
        frac = max(0.0, min(1.0, float(pct) / 100.0))
    except (TypeError, ValueError):
        frac = 0.0
    filled = int(round(frac * width))
    return "[" + "#" * filled + "·" * (width - filled) + "]"


def render_frame(status, progress, now=None):
    """The watch panel as a string, for ``status`` + ``progress`` (either may be
    ``None``). No I/O and no real-clock dependence (``now`` is injected), so it is
    unit-testable."""
    now = time.time() if now is None else now
    if not status:
        return "Kestrel quick-crack\n  the worker has not reported yet.\n"
    state = status.get("state") or "?"
    label = readout._STATE_LABEL.get(state, state)
    lines = []
    temp = status.get("temp_c")
    head = "Kestrel quick-crack — %s" % label
    if isinstance(temp, (int, float)):
        head += "   CPU %.0f°C" % temp
    lines.append(head)

    counts = "  cracked %d / %d   trying %d   exhausted %d" % (
        int(status.get("cracked") or 0), int(status.get("targets") or 0),
        int(status.get("pending") or 0), int(status.get("exhausted") or 0))
    if status.get("no_handshake"):
        counts += "   no-handshake %d" % int(status.get("no_handshake"))
    lines.append(counts)
    if status.get("queue"):
        lines.append("  queued manual jobs: %d" % int(status.get("queue")))

    live = progress if progress_mod.is_fresh(progress, now) else None
    current = status.get("current") or {}
    if live:
        who = (live.get("essid") or live.get("bssid")
               or current.get("essid") or current.get("bssid") or "?")
        wl = live.get("wordlist") or current.get("wordlist") or ""
        lines.append("  now  %s%s" % (who, " · " + wl if wl else ""))
        bits = []
        pct = live.get("percent")
        if isinstance(pct, (int, float)):
            bits.append("%s  %.1f%%" % (_bar(pct), pct))
        if isinstance(live.get("rate_kps"), (int, float)):
            bits.append("%.2f k/s" % live["rate_kps"])
        if live.get("eta"):
            bits.append("left " + str(live["eta"]))
        if bits:
            lines.append("       " + "   ".join(bits))
        if live.get("passphrase"):
            lines.append("       trying: %s" % live["passphrase"])
    elif state == "cracking" and current:
        who = current.get("essid") or current.get("bssid") or "?"
        wl = current.get("wordlist") or ""
        lines.append("  now  %s%s" % (who, " · " + wl if wl else ""))
    else:
        lines.append("  (nothing cracking right now)")
    if status.get("error"):
        lines.append("  error: %s" % status.get("error"))

    last = status.get("last_crack") or {}
    if last:
        who = last.get("essid") or last.get("bssid") or "?"
        at = last.get("at")
        when = "  (%s)" % readout._ago(float(at), now) if isinstance(at, (int, float)) else ""
        lines.append("  last %s%s" % (who, when))
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="kestrel crack watch",
        description="Live view of the on-device crack worker (Ctrl-C to quit).")
    ap.add_argument("--crack-dir", default=CRACK_DIR)
    ap.add_argument("--interval", type=float, default=2.0,
                    help="seconds between redraws (default 2)")
    ap.add_argument("--once", action="store_true",
                    help="print one frame and exit (no clear, no loop)")
    args = ap.parse_args(argv)
    interval = max(0.5, args.interval)

    def frame():
        return render_frame(readout.read_status(args.crack_dir),
                            progress_mod.read_progress(args.crack_dir))

    if args.once:
        sys.stdout.write(frame())
        return 0
    try:
        while True:
            # Home + clear-to-end, so the panel redraws in place without the
            # scrollback churn a full clear-screen causes over SSH.
            sys.stdout.write("\x1b[H\x1b[J" + frame())
            sys.stdout.write("\n(updating every %gs — Ctrl-C to quit)\n" % interval)
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
