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
import time

from .. import device_id
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
    if world_readable:
        try:
            os.chmod(path, 0o644)
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
        _write_json_atomic(
            self.path,
            {"contract_version": CRACK_CONTRACT, "updated_at": time.time(),
             "aps": aps},
            world_readable=True,
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
        """``cracked`` / ``pending`` / ``exhausted`` for ``rec`` given the set of
        currently available wordlist signatures. Recomputed and cached onto the
        record by the worker each pass, so the CLI/web can show it without the
        wordlist set in hand."""
        if rec.get("password"):
            return "cracked"
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
        """``{cracked, pending, exhausted, total}`` from the cached statuses."""
        out = {"cracked": 0, "pending": 0, "exhausted": 0, "total": len(aps)}
        for rec in aps.values():
            out[rec.get("status", "pending")] = out.get(
                rec.get("status", "pending"), 0) + 1
        return out


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
    that has at least one uncracked target which has not tried it, paired with
    every such target.

    Attack-first, not target-first, on purpose: one hashcat run loads the attack
    once and tests every outstanding target against it, so the quick wins across
    all APs land before the next (bigger) attack is even opened. Returns
    ``(attack, [target, ...])`` or ``None`` when there is nothing left to try.
    ``attacks`` come from :func:`build_attacks` (wordlists then masks); a target
    with no loot record (no BSSID) is skipped."""
    by_bssid = {}
    for target in targets:
        bssid = (target.get("bssid") or "").upper()
        if bssid:
            by_bssid.setdefault(bssid, target)
    for attack in attacks:
        batch = []
        for bssid, target in by_bssid.items():
            rec = aps.get(bssid)
            if rec is None or rec.get("password"):
                continue
            if not _tried_has(rec, attack, recrack_on_new):
                batch.append(target)
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
