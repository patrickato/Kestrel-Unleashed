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
import time

from ..capture import CaptureInterface
from ..config import DEFAULT_CONFIG_PATH, load_config, section
from . import (CRACK_DEFAULTS, CRACK_DIR, DEFAULT_CAPTURE_STORE, HARD_MAX_TEMP_C,
               POTFILE_NAME, STATUS_NAME)
from . import aircrack as ac
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
    """Run ``cmd``; return ``(returncode, stdout, stderr)``. A non-zero exit
    never raises (aircrack 'key not found' is a normal result read from the
    output); a timeout or a missing binary are reported as codes."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                              stdin=subprocess.DEVNULL, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "" if isinstance(exc.stdout, str) else ""), "timeout"
    except FileNotFoundError:
        return 127, "", "command not found"


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
        self._last_error = ""        # last hashcat failure, surfaced in status
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

    # -- cracking (aircrack-ng backend) -----------------------------------
    def _prepare_pcaps(self):
        """Convert each capture pcapng to a classic pcap aircrack reads, cached by
        source mtime under the crack dir. Returns the pcap paths (empty if there
        are none yet or tcpdump is missing)."""
        pcapngs = self.capture.pcapng_files()
        if not pcapngs or not ac.have_tcpdump():
            return []
        out_dir = os.path.join(self.crack_dir, ".pcap")
        os.makedirs(out_dir, exist_ok=True)
        pcaps = []
        for src in pcapngs:
            dst = os.path.join(out_dir, os.path.basename(src) + ".pcap")
            try:
                fresh = (os.path.exists(dst)
                         and os.path.getmtime(dst) >= os.path.getmtime(src))
                if not fresh:
                    rc, _o, _e = self._runner(ac.convert_cmd(src, dst), timeout=180)
                    if rc != 0:
                        continue
                pcaps.append(dst)
            except OSError:
                continue
        return pcaps

    def _run_mask(self, pcaps, bssid, crunch_args, timeout):  # pragma: no cover
        """Stream a mask's keyspace from crunch into aircrack's stdin. Separate
        from the injected runner because it is a pipeline; the pure mask->crunch
        mapping (:func:`aircrack.mask_to_crunch`) is what the tests cover."""
        gen = subprocess.Popen(crunch_args, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
        try:
            proc = subprocess.run(ac.build_stdin_cmd(pcaps, bssid), stdin=gen.stdout,
                                  capture_output=True, text=True, timeout=timeout)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as exc:
            return 124, (exc.stdout or "" if isinstance(exc.stdout, str) else ""), "timeout"
        except FileNotFoundError:
            return 127, "", "crunch/aircrack-ng not found"
        finally:
            try:
                if gen.stdout:
                    gen.stdout.close()
                gen.kill()
            except OSError:
                pass

    def _crack_one(self, pcaps, bssid, attack, conf):
        """Crack one AP (``bssid``) in ``pcaps`` with ``attack``. Returns
        ``(password_or_None, ok)``; ``ok`` is False only when aircrack actually
        **errored** (bad capture / no handshake), so a run that simply didn't find
        the key still counts as tried."""
        timeout = int(conf.get("max_job_seconds") or 0) or None
        kind = attack.get("kind", "dict")
        if kind == "mask":
            crunch_args = ac.mask_to_crunch(attack.get("mask", ""))
            if crunch_args is None:
                return None, True            # mask crunch can't express: skip
            rc, out, err = self._run_mask(pcaps, bssid, crunch_args, timeout)
        else:
            wl = attack.get("path", "")
            if not os.path.isfile(wl):
                return None, True            # missing wordlist: skip, not an error
            rc, out, err = self._runner(ac.build_dict_cmd(pcaps, bssid, wl),
                                        timeout=timeout)
        text = (out or "") + "\n" + (err or "")
        verdict = ac.classify(text)
        if verdict == "cracked":
            return ac.parse_key(out), True
        if verdict == "exhausted":
            return None, True
        msg = ("aircrack-ng: " + ac.error_detail(text))[:200]
        log.warning("%s", msg)
        self._last_error = msg
        return None, False

    def _run_attack(self, targets, attack, conf, pcaps):
        """Run ``attack`` against each target AP. Returns ``(cracked, failed)``:
        ``cracked`` is ``{BSSID: password}`` and ``failed`` is the BSSIDs whose
        run errored (so the caller does not record the wordlist as tried for
        them, and a systematic failure never masquerades as 'exhausted')."""
        cracked, failed = {}, set()
        for target in targets:
            bssid = (target.get("bssid") or "").upper()
            if not bssid:
                continue
            password, ok = self._crack_one(pcaps, bssid, attack, conf)
            if password is not None:
                cracked[bssid] = password
            elif not ok:
                failed.add(bssid)
        return cracked, failed

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
        recrack = bool(conf.get("recrack_on_new_wordlist", True))

        state, did_work, current = "idle", False, None
        self._last_error = ""
        if not conf.get("enabled", True):
            state = "disabled"
        elif not (ac.have_aircrack() and ac.have_tcpdump()):
            state = "no-aircrack"
        else:
            pcaps = self._prepare_pcaps()
            if not pcaps:
                # aircrack cracks from the packet capture; nothing to do until the
                # rolling pcapng has handshakes (the hashline store isn't enough).
                state = "no-capture"
            else:
                jobs = store_mod.list_jobs(self.crack_dir)
                if jobs:
                    state, current = "cracking", self._run_manual(jobs[0], aps, pcaps, conf)
                    did_work = True
                elif not attacks:
                    state = "no-wordlists"
                else:
                    batch = store_mod.next_auto_batch(aps, targets, attacks, recrack)
                    if batch is not None:
                        state, current = "cracking", self._run_auto(batch, aps, pcaps, conf)
                        did_work = True

        LootStore.refresh_statuses(aps, all_sigs)
        self.loot.save(aps)
        # An aircrack failure this pass takes precedence over idle/cracking, so the
        # dashboard shows the real error instead of a silent false "exhausted".
        if self._last_error and state in ("idle", "cracking"):
            state = "error"
        self._write_status(aps, conf, wordlists, masks, state, current)
        return state, did_work

    def _all_events(self):
        events = []
        for path in self.capture.hashline_files():
            events.extend(self.capture.read_events(path))
        return events

    def _run_auto(self, batch, aps, pcaps, conf):
        attack, tgts = batch
        cracked, failed = self._run_attack(tgts, attack, conf, pcaps)
        now = self._clock()
        for target in tgts:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            if bssid in cracked:
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            elif bssid not in failed:
                # Record the wordlist as tried only when aircrack actually ran it;
                # on an error the AP stays pending so it retries once fixed.
                LootStore.mark_tried(rec, attack["sig"])
        return {"essid": tgts[0].get("essid"), "bssid": tgts[0].get("bssid"),
                "wordlist": attack["name"], "origin": "auto", "started": now}

    def _run_manual(self, job_entry, aps, pcaps, conf):
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
        events = []
        for f in files:
            events.extend(self.capture.read_events(f))
        targets = targets_from_events(events)
        for target in targets:
            LootStore.upsert(aps, target, now=self._clock())
        cracked, failed = self._run_attack(targets, attack, conf, pcaps) \
            if targets else ({}, set())
        now = self._clock()
        for target in targets:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            if bssid in cracked:
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            elif attack["sig"] and bssid not in failed:
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
            "error": self._last_error or "",
            "updated_at": self._clock(),
        }
        store_mod._write_json_atomic(
            os.path.join(self.crack_dir, STATUS_NAME), status, world_readable=True)

    # -- loop -------------------------------------------------------------
    def run_forever(self, stop=None):
        paused = False
        while stop is None or not stop():
            conf = self.config()
            if conf.get("enabled", True) and ac.have_aircrack():
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
