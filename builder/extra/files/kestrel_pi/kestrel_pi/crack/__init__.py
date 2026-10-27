"""Kestrel-Unleashed on-device quick-crack.

This subpackage auto-cracks the handshakes Kestrel captures, on the Pi itself.
The worker (:mod:`.controller`, run by ``kestrel-crack.service``) reads the
Phase 2 capture store (the append-only ``.hc22000`` hashlines,
``docs/developer/capture-interface.md``), runs ``hashcat -m 22000`` against the
operator's wordlists on the CPU, and writes any recovered passphrase -- in
cleartext -- to the loot store, which the dashboard ``/loot`` page, the e-ink
face and ``kestrel crack`` all read.

Design, from ``docs/developer/crack-interface.md``:

- **Local-only.** It reads data already captured; it never touches the radio,
  the network, or root. It runs as ``pi`` and writes only pi-owned files under
  :data:`CRACK_DIR`.
- **CPU-only, bounded.** The Pi has no usable cracking GPU (the VideoCore has no
  hashcat OpenCL path), so cracking runs on the CPU via pocl. It is niced and
  thermal-gated so capture always keeps priority and the board never cooks.
- **"Leave it alone."** Once an AP yields a crackable hashline, capture is done
  with it (AngryOxide de-dupes per AP). The cracker keeps that hashline in play
  until it cracks or every wordlist is exhausted, then stops -- but a newly
  added wordlist re-arms the exhausted targets.

Layout:

- :mod:`.store` - the loot store, the manual-job queue, the wordlist-signature
  bookkeeping and the work derivation. Pure stdlib (+ :mod:`..device_id`); no
  subprocess, no hardware, so it is the unit-test seam.
- :mod:`.wordlists` - discover and order the wordlists on the device.
- :mod:`.hashcat` - build the hashcat command line and parse ``--show`` output.
  The only module that knows hashcat's CLI; still subprocess-free (the caller
  runs the command, so tests drive it with canned output).
- :mod:`.readout` - stdlib-only reader of the worker's ``status.json`` + loot
  for the daemon's dashboard card and the e-ink face (mirrors
  :mod:`..agent.readout`; the daemon imports it with no hashcat present).
- :mod:`.controller` - the worker process: the crack loop, the thermal gate, the
  status file. ``kestrel-crack.service`` runs :func:`.controller.main`.
"""

from __future__ import annotations

# The worker's runtime directory (owned by pi, created by the build). The loot
# store, the manual-job queue, the shared potfile and the status file live here.
CRACK_DIR = "/var/lib/kestrel/crack"
# The Phase 2 capture store the worker sources hashlines from (read-only).
DEFAULT_CAPTURE_STORE = "/var/lib/kestrel/capture"
# Where wordlists live; the [crack] wordlists_dir default (also in config.toml).
DEFAULT_WORDLISTS_DIR = "/var/lib/kestrel/wordlists"

LOOT_NAME = "loot.json"        # per-AP loot records (keyed by BSSID)
QUEUE_DIR = "queue"            # manual crack jobs: pi-written, worker-consumed
STATUS_NAME = "status.json"    # the worker's live status, for the UI (world-readable)
POTFILE_NAME = "kestrel.potfile"   # hashcat's shared potfile (accumulates cracks)

# Bumped only on a breaking change to the loot/status JSON shape; the daemon
# readout and the CLI tolerate a missing or newer version by showing what they
# understand. Distinct from the capture contract_version and HOOK_API_VERSION.
CRACK_CONTRACT = 1

# Absolute ceiling on the thermal gate: however the operator sets
# [crack] max_temp_c, the worker never runs hashcat at/above this CPU temp.
HARD_MAX_TEMP_C = 85

# The [crack] table defaults; mirror config.toml so a missing key falls back to
# code (an in-place update does not rewrite config.toml, so new keys default here).
CRACK_DEFAULTS = {
    "enabled": True,
    "wordlists_dir": DEFAULT_WORDLISTS_DIR,
    "order": "size",
    "rules": [],
    "masks": [],
    "nice": 15,
    "workload": 1,
    "kernel_accel": 1,          # hashcat -n: cap the per-batch size so a WPA
                                # attack fits the Pi's 256 MB single-alloc OpenCL
                                # limit (0 = let hashcat autotune -- too big here)
    "max_temp_c": 75,
    "resume_temp_c": 68,
    "max_job_seconds": 0,
    "recrack_on_new_wordlist": True,
}

__all__ = [
    "CRACK_DIR", "DEFAULT_CAPTURE_STORE", "DEFAULT_WORDLISTS_DIR",
    "LOOT_NAME", "QUEUE_DIR", "STATUS_NAME", "POTFILE_NAME",
    "CRACK_CONTRACT", "HARD_MAX_TEMP_C", "CRACK_DEFAULTS",
]
