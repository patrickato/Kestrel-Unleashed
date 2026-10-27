"""The crack worker process.

``kestrel-crack.service`` runs :func:`main`. Each pass the worker:

1. re-reads ``[crack]`` (so ``kestrel crack enable/disable`` takes effect with no
   restart) and the wordlists on disk;
2. refreshes the loot store from the capture store (new captures become pending
   targets, device-identified);
3. does one unit of work -- a queued **manual** job first, else the next
   **automatic** batch (:func:`.store.next_auto_batch`): the next wordlist that
   still has untried, uncracked targets, run once against all of them;
4. records cracks (cleartext) and tried-wordlists, and writes ``status.json``.

It is **thermal-gated** (pauses at/above ``max_temp_c``, hard-capped at
:data:`.HARD_MAX_TEMP_C`, resumes at ``resume_temp_c``) and **niced**, so capture
always keeps the CPU and the board never cooks. It runs as ``pi`` and writes only
pi-owned files; nothing here needs root, the radio, or the network.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import tempfile
import time

from ..capture import CaptureInterface, parse_hashline
from ..config import DEFAULT_CONFIG_PATH, load_config, section
from . import (CRACK_DEFAULTS, CRACK_DIR, DEFAULT_CAPTURE_STORE, HARD_MAX_TEMP_C,
               POTFILE_NAME, STATUS_NAME)
from . import hashcat as hc
from . import store as store_mod
from . import wordlists as wl_mod
from .store import LootStore

log = logging.getLogger("kestrel-crack")

# Idle poll: how long to wait before re-checking for work when there is none to
# do (new captures arrive on the capture poll cadence, so this needn't be tight).
IDLE_SLEEP = 15
# How long to wait out a thermal pause before re-reading the temperature.
THERMAL_SLEEP = 30
THERMAL_ZONE = "/sys/class/thermal/thermal_zone0/temp"


def read_temp_c(path=THERMAL_ZONE):
    """CPU temperature in °C from the thermal zone, or ``None`` off a Pi (so the
    gate is simply open when it can't be read)."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return int(handle.read().strip()) / 1000.0
    except (OSError, ValueError):
        return None


def _default_runner(cmd, timeout=None):
    """Run ``cmd``; return ``(returncode, stdout, stderr)``. hashcat's exit code
    is advisory here (results are read with ``--show``), so a non-zero never
    raises; a timeout or a missing binary are reported as codes."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                              stdin=subprocess.DEVNULL, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "" if isinstance(exc.stdout, str) else ""), "timeout"
    except FileNotFoundError:
        return 127, "", "hashcat not found"


def targets_from_events(events):
    """Group parsed :class:`HandshakeEvent`s into per-AP crack targets, keyed by
    BSSID. Returns ``[{bssid, essid, type, hashline, hashlines, lines, files}]``;
    events without a BSSID (a corrupt line) are dropped (nothing to key or crack
    reliably)."""
    by_bssid = {}
    for ev in events:
        bssid = (ev.bssid or "").upper()
        if not bssid or not ev.raw:
            continue
        slot = by_bssid.get(bssid)
        if slot is None:
            slot = by_bssid[bssid] = {
                "bssid": bssid, "essid": ev.essid or "", "type": ev.type,
                "hashline": ev.raw, "lines": [], "files": set()}
        if not slot["essid"] and ev.essid:
            slot["essid"] = ev.essid
        # Prefer an EAPOL line as the representative/type over a PMKID.
        if ev.type == "eapol" and slot["type"] != "eapol":
            slot["type"] = "eapol"
            slot["hashline"] = ev.raw
        if ev.raw not in slot["lines"]:
            slot["lines"].append(ev.raw)
        if ev.path:
            slot["files"].add(os.path.basename(ev.path))
    out = []
    for slot in by_bssid.values():
        slot["files"] = sorted(slot["files"])
        slot["hashlines"] = len(slot["lines"])
        out.append(slot)
    return out


class CrackWorker:
    """One crack worker. Subprocess and clock are injected so the whole loop is
    unit-testable without hashcat or real time."""

    def __init__(self, config_path=DEFAULT_CONFIG_PATH, crack_dir=CRACK_DIR,
                 capture_store=DEFAULT_CAPTURE_STORE, runner=_default_runner,
                 temp_reader=read_temp_c, clock=time.time):
        self.config_path = config_path
        self.crack_dir = crack_dir
        self.capture = CaptureInterface(capture_store)
        self.loot = LootStore(crack_dir)
        self.potfile = os.path.join(crack_dir, POTFILE_NAME)
        self._runner = runner
        self._temp = temp_reader
        self._clock = clock
        os.makedirs(crack_dir, exist_ok=True)

    # -- config -----------------------------------------------------------
    def config(self):
        cfg = load_config(self.config_path, logger=log)
        return section(cfg, "crack", CRACK_DEFAULTS)

    # -- thermal ----------------------------------------------------------
    def thermal_ok(self, conf, resuming=False):
        """True if cracking may run now. ``max_temp_c`` is hard-capped at
        :data:`.HARD_MAX_TEMP_C`; once paused, it must fall to ``resume_temp_c``
        before resuming (hysteresis, so it doesn't flap at the threshold)."""
        temp = self._temp()
        if temp is None:
            return True
        ceiling = min(float(conf.get("max_temp_c", 75)), HARD_MAX_TEMP_C)
        floor = min(float(conf.get("resume_temp_c", 68)), ceiling)
        return temp <= floor if resuming else temp < ceiling

    # -- cracking ---------------------------------------------------------
    def _materialize(self, lines):
        """Write hashlines to a temp file hashcat reads; return its path."""
        tmp_dir = os.path.join(self.crack_dir, ".tmp")
        os.makedirs(tmp_dir, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix="hashes-", suffix=".hc22000",
                                    dir=tmp_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line.rstrip("\n") + "\n")
        return path

    def _run_attack(self, lines, attack, conf, rules=()):
        """Run one hashcat pass (``attack`` is a dict- or mask-attack from
        :func:`.store.build_attacks`) over ``lines`` and return ``{bssid:
        password}`` for everything cracked (read back via ``--show`` against the
        shared potfile, not scraped from stdout). ``rules`` apply to a dictionary
        attack only."""
        kind = attack.get("kind", "dict")
        if not lines:
            return {}
        if kind == "dict" and not os.path.isfile(attack.get("path", "")):
            return {}
        if kind == "mask" and not attack.get("mask"):
            return {}
        hashfile = self._materialize(lines)
        try:
            budget = int(conf.get("max_job_seconds") or 0) or None
            if kind == "mask":
                cmd = hc.build_mask_cmd(hashfile, attack["mask"], self.potfile,
                                        nice=conf.get("nice", 15),
                                        workload=conf.get("workload", 1))
            else:
                cmd = hc.build_crack_cmd(hashfile, attack["path"], self.potfile,
                                         rules=rules, nice=conf.get("nice", 15),
                                         workload=conf.get("workload", 1))
            rc, _out, err = self._runner(cmd, timeout=budget)
            if rc not in (0, 1, 124):  # 0 cracked, 1 exhausted, 124 our timeout
                log.warning("hashcat exited %s: %s", rc, (err or "").strip()[:200])
            rc2, show_out, _err2 = self._runner(
                hc.build_show_cmd(hashfile, self.potfile))
            cracked = {}
            for hashline, password in hc.parse_show(show_out):
                ev = parse_hashline(hashline)
                if ev and ev.bssid:
                    cracked[ev.bssid.upper()] = password
            return cracked
        finally:
            try:
                os.remove(hashfile)
            except OSError:
                pass

    # -- one pass ---------------------------------------------------------
    def run_once(self):
        """Do at most one unit of work. Returns ``(state, did_work)``."""
        conf = self.config()
        aps = self.loot.load()
        targets = targets_from_events(self._all_events())
        for target in targets:
            LootStore.upsert(aps, target, now=self._clock())
        wordlists = wl_mod.discover(conf.get("wordlists_dir"),
                                    conf.get("order", "size"))
        masks = [str(m).strip() for m in (conf.get("masks") or []) if str(m).strip()]
        attacks = store_mod.build_attacks(wordlists, masks)
        all_sigs = {a["sig"] for a in attacks}
        rules = wl_mod.resolve_rules(conf.get("rules"), conf.get("wordlists_dir"))
        recrack = bool(conf.get("recrack_on_new_wordlist", True))

        state, did_work, current = "idle", False, None
        if not conf.get("enabled", True):
            state = "disabled"
        elif not hc.have_hashcat():
            state = "no-hashcat"
        else:
            jobs = store_mod.list_jobs(self.crack_dir)
            if jobs:
                state, current = "cracking", self._run_manual(jobs[0], aps, rules, conf)
                did_work = True
            elif not attacks:
                state = "no-wordlists"
            else:
                batch = store_mod.next_auto_batch(aps, targets, attacks, recrack)
                if batch is not None:
                    state, current = "cracking", self._run_auto(batch, aps, rules, conf)
                    did_work = True

        LootStore.refresh_statuses(aps, all_sigs)
        self.loot.save(aps)
        self._write_status(aps, conf, wordlists, masks, state, current)
        return state, did_work

    def _all_events(self):
        events = []
        for path in self.capture.hashline_files():
            events.extend(self.capture.read_events(path))
        return events

    def _run_auto(self, batch, aps, rules, conf):
        attack, tgts = batch
        lines = []
        for target in tgts:
            for line in target["lines"]:
                if line not in lines:
                    lines.append(line)
        cracked = self._run_attack(lines, attack, conf, rules=rules)
        now = self._clock()
        for target in tgts:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            if bssid in cracked:
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            else:
                LootStore.mark_tried(rec, attack["sig"])
        return {"essid": tgts[0].get("essid"), "bssid": tgts[0].get("bssid"),
                "wordlist": attack["name"], "origin": "auto", "started": now}

    def _run_manual(self, job_entry, aps, default_rules, conf):
        path, job = job_entry
        mask = (job.get("mask") or "").strip()
        wordlist = job.get("wordlist") or ""
        if mask:
            attack = {"kind": "mask", "name": mask, "mask": mask,
                      "sig": store_mod.mask_sig(mask)}
        else:
            attack = {"kind": "dict", "name": os.path.basename(wordlist),
                      "path": wordlist, "sig": self._wordlist_sig(wordlist)}
        files = [f for f in (job.get("files") or []) if os.path.isfile(f)]
        rules = wl_mod.resolve_rules(job.get("rules"), conf.get("wordlists_dir")) \
            or default_rules
        events = []
        for f in files:
            events.extend(self.capture.read_events(f))
        targets = targets_from_events(events)
        for target in targets:
            LootStore.upsert(aps, target, now=self._clock())
        lines = []
        for target in targets:
            for line in target["lines"]:
                if line not in lines:
                    lines.append(line)
        cracked = self._run_attack(lines, attack, conf, rules=rules) if lines else {}
        now = self._clock()
        for target in targets:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            if bssid in cracked:
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            elif attack["sig"]:
                LootStore.mark_tried(rec, attack["sig"])
        store_mod.remove_job(path)
        return {"essid": job.get("label") or attack["name"], "bssid": "",
                "wordlist": attack["name"], "origin": "manual", "started": now}

    @staticmethod
    def _wordlist_sig(path):
        try:
            st = os.stat(path)
        except OSError:
            return ""
        return "%s:%d:%d" % (os.path.basename(path), st.st_size, int(st.st_mtime))

    # -- status -----------------------------------------------------------
    def _write_status(self, aps, conf, wordlists, masks, state, current):
        counts = LootStore.counts(aps)
        last = None
        for rec in aps.values():
            if rec.get("password") and rec.get("cracked_at"):
                if last is None or rec["cracked_at"] > last.get("at", 0):
                    last = {"essid": rec.get("essid"), "bssid": rec.get("bssid"),
                            "at": rec.get("cracked_at")}
        status = {
            "contract_version": 1,
            "enabled": bool(conf.get("enabled", True)),
            "state": state,
            "targets": counts["total"],
            "cracked": counts["cracked"],
            "pending": counts["pending"],
            "exhausted": counts["exhausted"],
            "wordlists": len(wordlists),
            "masks": len(masks or []),
            "queue": store_mod.queue_len(self.crack_dir),
            "temp_c": self._temp(),
            "current": current,
            "last_crack": last,
            "updated_at": self._clock(),
        }
        store_mod._write_json_atomic(
            os.path.join(self.crack_dir, STATUS_NAME), status, world_readable=True)

    # -- loop -------------------------------------------------------------
    def run_forever(self, stop=None):
        paused = False
        while stop is None or not stop():
            conf = self.config()
            if conf.get("enabled", True) and hc.have_hashcat():
                if not self.thermal_ok(conf, resuming=paused):
                    paused = True
                    masks = [str(m).strip() for m in (conf.get("masks") or [])
                             if str(m).strip()]
                    self._write_status(self.loot.load(), conf,
                                       wl_mod.discover(conf.get("wordlists_dir"),
                                                       conf.get("order", "size")),
                                       masks, "paused-thermal", None)
                    time.sleep(THERMAL_SLEEP)
                    continue
                paused = False
            _state, did_work = self.run_once()
            if not did_work:
                time.sleep(IDLE_SLEEP)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kestrel on-device quick-crack worker")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--crack-dir", default=CRACK_DIR)
    parser.add_argument("--capture-store", default=DEFAULT_CAPTURE_STORE)
    parser.add_argument("--once", action="store_true",
                        help="do a single pass and exit (debugging)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        stream=sys.stderr)
    worker = CrackWorker(config_path=args.config, crack_dir=args.crack_dir,
                         capture_store=args.capture_store)
    # Nice ourselves too, so even the worker's own bookkeeping yields to capture.
    try:
        conf = worker.config()
        os.nice(max(0, min(19, int(conf.get("nice", 15)))))
    except (OSError, ValueError):
        pass
    if args.once:
        state, _ = worker.run_once()
        log.info("crack pass: %s", state)
        return 0
    try:
        worker.run_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
