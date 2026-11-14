"""The loot store, the manual-job queue and the work derivation.

Pure stdlib (+ :mod:`..device_id`): no subprocess, no hardware, so this is the
unit-test seam for the whole feature.

The **loot store** (``loot.json``) holds one record per access point, keyed by
BSSID. A record remembers the recovered passphrase (cleartext) once cracked, and
the set of wordlist *signatures* already tried without success, from which its
status is derived:

- ``cracked``   - a passphrase was recovered.
- ``pending``   - at least one available wordlist has not been tried yet.
- ``exhausted`` - every available wordlist was tried, none cracked. A newly
  added or grown wordlist has a new signature, so it is not in ``tried`` and the
  target returns to ``pending`` on its own (``recrack_on_new_wordlist``).

The **queue** is a directory of job files written by the web ``/loot`` page and
``kestrel crack`` (as ``pi``, no root) and consumed by the worker. A manual job
names capture files + a wordlist (+ optional rules) and runs even against a
cracked/exhausted target, because the operator asked for it explicitly -- that
is how "re-run what didn't crack against another wordlist/ruleset" works.
"""

from __future__ import annotations

import json
import os
import re
import time

from .. import device_id

_MAC12_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def normalize_bssid(bssid):
    """Accept ``AA:BB:CC:DD:EE:FF`` or a bare 12-hex MAC and return the
    colon-separated upper form, or ``""`` when it is neither (so a bad value is
    never keyed into loot). wpa-sec's download format uses bare-hex MACs; loot
    keys on the colon form."""
    b = (bssid or "").strip()
    if ":" in b:
        return b.upper() if _MAC_RE.match(b) else ""
    if _MAC12_RE.match(b):
        b = b.upper()
        return ":".join(b[i:i + 2] for i in range(0, 12, 2))
    return ""
from . import CRACK_CONTRACT, CRACK_DIR, LOOT_NAME, QUEUE_DIR


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return default
    return data


def _write_json_atomic(path, data, world_readable=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    # The loot store holds recovered passwords in cleartext, so it is owner-only
    # (the pi daemon and crack worker both run as pi; root-run CLIs still read
    # it). open()+umask would otherwise leave it world-readable at 0644, so set
    # the mode explicitly either way. world_readable is kept for callers that
    # genuinely need a 0644 file (none currently write secrets through it).
    try:
        os.chmod(path, 0o644 if world_readable else 0o600)
    except OSError:
        pass


def _tried_has(record, wl, recrack_on_new=True):
    """True if ``record`` has already tried wordlist ``wl``. With
    ``recrack_on_new`` (the default) a grown/replaced list (new signature) is a
    fresh try; without it, any earlier try of the same *name* counts as done."""
    tried = record.get("tried") or []
    if recrack_on_new:
        return wl["sig"] in tried
    name = wl["name"]
    return any(isinstance(t, str) and t.split(":", 1)[0] == name for t in tried)


class LootStore:
    """Read/modify/write the per-AP loot records. Callers mutate the dict
    returned by :meth:`load` and persist it with :meth:`save`; the helpers keep
    the record shape consistent."""

    def __init__(self, crack_dir=CRACK_DIR):
        self.crack_dir = crack_dir
        self.path = os.path.join(crack_dir, LOOT_NAME)

    def load(self):
        """``{bssid: record}``; ``{}`` on a missing/corrupt store."""
        data = _read_json(self.path, None)
        if not isinstance(data, dict):
            return {}
        aps = data.get("aps")
        return aps if isinstance(aps, dict) else {}

    def save(self, aps):
        # Owner-only: this store carries recovered cleartext keys. Both readers
        # (the daemon and the crack worker) run as pi, so 0600 is enough and a
        # world-readable loot file is not worth the leak.
        _write_json_atomic(
            self.path,
            {"contract_version": CRACK_CONTRACT, "updated_at": time.time(),
             "aps": aps},
        )

    @staticmethod
    def upsert(aps, target, now=None):
        """Ensure a record exists for ``target`` (``{bssid, essid, type,
        hashline, hashlines, files}``) and refresh its capture-derived fields,
        keeping any crack result and tried-set. Returns the record, or ``None``
        when the target has no BSSID to key on (it can't be tracked per-AP)."""
        bssid = (target.get("bssid") or "").upper()
        if not bssid:
            return None
        now = time.time() if now is None else now
        rec = aps.get(bssid)
        if rec is None:
            rec = aps[bssid] = {"bssid": bssid, "first_seen": now,
                                "status": "pending", "password": "",
                                "cracked_wordlist": "", "cracked_at": 0,
                                "tried": []}
        essid = target.get("essid") or rec.get("essid") or ""
        rec["essid"] = essid
        rec["type"] = target.get("type") or rec.get("type") or "unknown"
        rec["hashline"] = target.get("hashline") or rec.get("hashline") or ""
        rec["hashlines"] = int(target.get("hashlines") or rec.get("hashlines") or 0)
        rec["files"] = sorted(set(target.get("files") or rec.get("files") or []))
        ident = device_id.identify(bssid=bssid, essid=essid)
        rec["device"] = device_id.label(bssid=bssid, essid=essid)
        rec["category"] = ident["category"]
        rec["product"] = ident["product"]
        rec["vendor"] = ident.get("vendor", "")
        return rec

    @staticmethod
    def mark_cracked(rec, password, wordlist_name, now=None):
        rec["status"] = "cracked"
        rec["password"] = password
        rec["cracked_wordlist"] = wordlist_name
        rec["cracked_at"] = time.time() if now is None else now

    @staticmethod
    def mark_tried(rec, sig):
        tried = rec.setdefault("tried", [])
        if sig and sig not in tried:
            tried.append(sig)

    @staticmethod
    def derive_status(rec, all_sigs):
        """``cracked`` / ``no-handshake`` / ``pending`` / ``exhausted`` for ``rec``
        given the set of currently available wordlist signatures. Recomputed and
        cached onto the record by the worker each pass, so the CLI/web can show it
        without the wordlist set in hand. ``no-handshake`` means the capture holds
        no crackable 4-way handshake for this AP yet (a PMKID-only capture); it
        takes precedence over pending/exhausted but not over a recovered key."""
        if rec.get("password"):
            return "cracked"
        if rec.get("no_handshake"):
            return "no-handshake"
        tried = set(rec.get("tried") or [])
        if all_sigs and all_sigs.issubset(tried):
            return "exhausted"
        return "pending"

    @classmethod
    def refresh_statuses(cls, aps, all_sigs):
        """Recompute every record's cached ``status`` field in place."""
        for rec in aps.values():
            rec["status"] = cls.derive_status(rec, all_sigs)

    @staticmethod
    def counts(aps):
        """``{cracked, pending, exhausted, no_handshake, total}`` from the cached
        statuses (the hyphenated ``no-handshake`` status maps to the
        ``no_handshake`` key so callers can read it as an identifier)."""
        out = {"cracked": 0, "pending": 0, "exhausted": 0, "no_handshake": 0,
               "total": len(aps)}
        for rec in aps.values():
            st = rec.get("status", "pending")
            key = "no_handshake" if st == "no-handshake" else st
            out[key] = out.get(key, 0) + 1
        return out


def import_key(crack_dir, bssid, essid, psk, source, label=None, extra=None,
               now=None):
    """Record an externally-recovered key (WPS, wpa-sec, onlinehashcrack, ...)
    into the loot store so it shows on ``/loot`` beside on-device cracks. Keyed
    by BSSID (bare-hex or colon form both accepted). ``label`` is the
    ``cracked_wordlist`` shown as the origin (defaults to ``source``); ``source``
    tags the record; ``extra`` merges any source-specific fields. Returns True
    when a new crack was recorded, False when the BSSID/psk is unusable or the AP
    was already cracked (an existing key is never overwritten). The store's other
    writer is the crack worker; both run as pi and each write is a short
    load/modify/atomic-save, as the WPS path already does."""
    bssid = normalize_bssid(bssid)
    if not bssid or not psk:
        return False
    store = LootStore(crack_dir)
    aps = store.load()
    rec = LootStore.upsert(aps, {"bssid": bssid, "essid": essid or "",
                                 "type": source, "hashlines": 0, "files": []},
                           now=now)
    if rec is None or rec.get("password"):
        return False
    rec["no_handshake"] = False
    LootStore.mark_cracked(rec, psk, label or source, now=now)
    rec["source"] = source
    if extra:
        rec.update(extra)
    store.save(aps)
    return True


# -- device grouping (batch "crack all cameras / all TP-Link") ---------------
# Each loot record caches a device ``category`` (camera, router, gateway,
# printer, hotspot, iot, ...) and a ``vendor`` (from device_id), so uncracked
# APs can be cracked a whole class at a time instead of one Run button each.
GROUP_BYS = ("category", "vendor")

# Friendly plurals/synonyms the CLI accepts for a category group.
_GROUP_ALIASES = {
    "cameras": "camera", "routers": "router", "gateways": "gateway",
    "printers": "printer", "hotspots": "hotspot", "iots": "iot",
    "doorbells": "doorbell", "speakers": "speaker", "tvs": "tv",
}


def _canon_group(value):
    v = (value or "").strip().lower()
    return _GROUP_ALIASES.get(v, v)


def is_crackable(rec):
    """True when an AP is worth a crack job: not already cracked and it holds a
    real handshake (a PMKID-only / ``no-handshake`` AP can't crack on-device)."""
    return rec.get("status") not in ("cracked", "no-handshake")


def match_group(rec, by, value):
    """Whether ``rec`` is in the device group ``(by, value)``. ``category`` is an
    exact (alias-folded) match; ``vendor`` is a case-insensitive substring, so
    ``tp-link`` matches ``TP-Link``."""
    val = (value or "").strip().lower()
    if not val:
        return False
    if by == "category":
        return (rec.get("category") or "").strip().lower() == _canon_group(val)
    if by == "vendor":
        return val in (rec.get("vendor") or "").strip().lower()
    return False


def group_members(aps, by, value, crackable_only=True):
    """Records in the device group ``(by, value)`` -- by default only the ones
    still worth cracking (uncracked, with a handshake)."""
    out = [r for r in aps.values() if match_group(r, by, value)]
    if crackable_only:
        out = [r for r in out if is_crackable(r)]
    return out


def group_summary(aps):
    """The device groups present that have at least one crackable AP, as
    ``[{by, value, total, crackable}]`` sorted most-crackable first. Drives the
    batch "crack all <group>" picker on /loot and ``kestrel crack groups``. An AP
    counts under both its category and its vendor (both are valid groups)."""
    buckets = {}
    for rec in aps.values():
        for by in GROUP_BYS:
            val = (rec.get(by) or "").strip()
            if not val or val.lower() == "unknown":   # device-ID's not-ID'd sentinel
                continue
            bucket = buckets.setdefault((by, val.lower()),
                                        {"by": by, "value": val,
                                         "total": 0, "crackable": 0})
            bucket["total"] += 1
            if is_crackable(rec):
                bucket["crackable"] += 1
    out = [b for b in buckets.values() if b["crackable"] > 0]
    out.sort(key=lambda b: (-b["crackable"], b["by"], b["value"].lower()))
    return out


def group_files(aps, by, value, files_for_bssid):
    """The crackable APs in group ``(by, value)`` and the de-duplicated union of
    their capture files, resolved through the ``files_for_bssid`` callable (the
    capture interface's resolver). Returns ``(members, files)``; the caller
    enqueues the chosen wordlist(s)/mask over ``files``."""
    members = group_members(aps, by, value)
    files = []
    for rec in members:
        for path in files_for_bssid(rec.get("bssid") or ""):
            if path not in files:
                files.append(path)
    return members, files


def mask_sig(mask):
    """A stable tried-set signature for a brute-force mask (deterministic, so it
    never needs re-running once tried)."""
    return "mask:" + str(mask).strip()


def build_attacks(wordlists, masks=()):
    """The ordered attack list the worker runs: every wordlist (as a ``dict``
    attack, smallest-first) then every mask (as a ``mask`` attack, last — brute
    force is the deepest, slowest tier). Each attack carries ``kind``, ``name``,
    ``sig`` and either ``path`` (dict) or ``mask``."""
    attacks = [dict(w, kind="dict") for w in (wordlists or ())]
    for mask in masks or ():
        mask = str(mask).strip()
        if mask:
            attacks.append({"kind": "mask", "name": mask, "mask": mask,
                            "sig": mask_sig(mask)})
    return attacks


def next_auto_batch(aps, targets, attacks, recrack_on_new=True):
    """The next unit of automatic work: the first attack (in ``attacks`` order)
    that has an uncracked target which has not tried it, paired with **one** such
    target. Returns ``(attack, [target])`` or ``None`` when nothing is left.

    One AP per pass, attack-first. The attack-first order still lands the quick
    wins across every AP before a bigger list is opened (the smallest untried
    attack is always chosen first, for whichever AP still needs it). Doing a
    single AP per pass -- rather than the whole batch in one go -- means the
    worker returns to its loop often, so a handshake caught mid-crack joins
    within one AP-crack instead of waiting out a long batch, and a freshly
    cracked password can be reused against the rest right away. There is no cost:
    aircrack-ng cracks one BSSID per run regardless (the old "load the attack
    once, test every target" batching was a hashcat optimisation that does
    nothing here). ``attacks`` come from :func:`build_attacks`; a target with no
    BSSID is skipped."""
    by_bssid = {}
    for target in targets:
        bssid = (target.get("bssid") or "").upper()
        if bssid:
            by_bssid.setdefault(bssid, target)
    for attack in attacks:
        only = attack.get("only_bssid")       # a per-device attack: its AP only
        for bssid, target in by_bssid.items():
            if only and only != bssid:
                continue
            rec = aps.get(bssid)
            if rec is None or rec.get("password"):
                continue
            if not _tried_has(rec, attack, recrack_on_new):
                return attack, [target]
    return None


def next_auto_batch_multi(aps, targets, attacks, recrack_on_new=True):
    """Like :func:`next_auto_batch`, but for a multi-salt engine (John): the first
    attack (in order) with any untried uncracked target, paired with **every**
    uncracked target that has not tried it -- so one wordlist run covers the whole
    backlog in a single pass instead of one AP at a time. John loads all salts at
    once and identical ESSIDs share the PBKDF2 work, so this is far faster on a
    backlog. A per-device (``only_bssid``) or ``mask`` attack still returns a
    single target -- those are inherently per-AP. Returns ``(attack, [targets])``
    or ``None``. ``attacks`` come from :func:`build_attacks`; the attack-first
    order still opens the smallest list first, now across every AP at once."""
    by_bssid = {}
    for target in targets:
        bssid = (target.get("bssid") or "").upper()
        if bssid:
            by_bssid.setdefault(bssid, target)
    for attack in attacks:
        only = attack.get("only_bssid")
        per_ap = bool(only) or attack.get("kind") == "mask"
        batch = []
        for bssid, target in by_bssid.items():
            if only and only != bssid:
                continue
            rec = aps.get(bssid)
            if rec is None or rec.get("password"):
                continue
            if not _tried_has(rec, attack, recrack_on_new):
                batch.append(target)
                if per_ap:
                    break                      # mask / per-device: one AP per run
        if batch:
            return attack, batch
    return None


# --- the manual-job queue --------------------------------------------------

def queue_path(crack_dir):
    return os.path.join(crack_dir, QUEUE_DIR)


def enqueue_job(crack_dir, files, wordlist="", mask="", rules=(), label="",
                origin="manual", now=None):
    """Write a manual crack job and return its path. ``files`` are the capture
    files to crack; give **either** a ``wordlist`` path (dictionary attack) **or**
    a ``mask`` string (brute force, e.g. ``?d?d?d?d?d?d?d?d``); ``rules`` optional
    rule paths (dictionary only). A monotonic, random-suffixed name keeps jobs
    ordered and unique."""
    now = time.time() if now is None else now
    directory = queue_path(crack_dir)
    os.makedirs(directory, exist_ok=True)
    name = "job-%d-%s.json" % (int(now * 1000), os.urandom(3).hex())
    path = os.path.join(directory, name)
    job = {"files": list(files), "wordlist": wordlist, "mask": mask,
           "rules": list(rules), "label": label, "origin": origin, "created": now}
    _write_json_atomic(path, job)
    return path


def list_jobs(crack_dir):
    """``[(path, job), ...]`` oldest-first (the name encodes the timestamp).
    Malformed job files are skipped."""
    directory = queue_path(crack_dir)
    try:
        names = sorted(n for n in os.listdir(directory)
                       if n.startswith("job-") and n.endswith(".json"))
    except OSError:
        return []
    out = []
    for name in names:
        path = os.path.join(directory, name)
        job = _read_json(path, None)
        if isinstance(job, dict):
            out.append((path, job))
    return out


def queue_len(crack_dir):
    return len(list_jobs(crack_dir))


def remove_job(path):
    try:
        os.remove(path)
    except OSError:
        pass


def clear_queue(crack_dir):
    """Remove every pending manual job. Returns how many were cleared. The job
    currently running (already claimed by the worker) is not in the queue dir, so
    it is unaffected."""
    jobs = list_jobs(crack_dir)
    for path, _job in jobs:
        remove_job(path)
    return len(jobs)


# -- worker control (operator pause) ----------------------------------------
CONTROL_NAME = "control.json"


def control_path(crack_dir):
    return os.path.join(crack_dir, CONTROL_NAME)


def read_control(crack_dir):
    """The operator control state: ``{"paused": bool, "stop_seq": int}``.
    Missing/corrupt = not paused, seq 0. Separate from the ``[crack] enabled``
    config toggle (a hard off): ``paused`` is a soft hold the worker checks each
    loop (the current job still finishes), and ``stop_seq`` is a monotonic
    "abort the job running now" counter -- the worker records it at the start of
    a job and kills the live cracker when it later reads a higher value."""
    data = _read_json(control_path(crack_dir), None)
    if not isinstance(data, dict):
        return {"paused": False, "stop_seq": 0}
    try:
        seq = int(data.get("stop_seq", 0) or 0)
    except (TypeError, ValueError):
        seq = 0
    return {"paused": bool(data.get("paused", False)), "stop_seq": seq}


def _write_control(crack_dir, paused, stop_seq):
    os.makedirs(crack_dir, exist_ok=True)
    _write_json_atomic(control_path(crack_dir),
                       {"paused": bool(paused), "stop_seq": int(stop_seq)},
                       world_readable=True)


def set_paused(crack_dir, paused):
    """Pause or resume the worker. Written by the daemon/CLI (both pi); the
    worker (also pi) reads it. Preserves the stop counter. Returns the new
    paused state."""
    cur = read_control(crack_dir)
    _write_control(crack_dir, bool(paused), cur["stop_seq"])
    return bool(paused)


def request_stop(crack_dir):
    """Ask the worker to abort the job running right now (distinct from pause,
    which lets the current job finish). Bumps the monotonic ``stop_seq`` the
    worker captures per job; it kills the live cracker when the counter has
    advanced past the value it started with, and the next job -- which captures
    the new value -- is unaffected. Preserves the paused state. Returns the new
    counter."""
    cur = read_control(crack_dir)
    new_seq = cur["stop_seq"] + 1
    _write_control(crack_dir, cur["paused"], new_seq)
    return new_seq
