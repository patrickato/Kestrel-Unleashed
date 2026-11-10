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
import hashlib
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
from . import john as john_mod
from . import offload as offload_mod
from . import progress as progress_mod
from . import store as store_mod
from . import wordlists as wl_mod
from .store import LootStore

log = logging.getLogger("kestrel-crack")

# Idle poll: how long to wait before re-checking for work when there is none to
# do (new captures arrive on the capture poll cadence, so this needn't be tight).
IDLE_SLEEP = 15
# Cap how often the rolling capture is re-converted to a pcap for aircrack: with
# one AP per crack pass the loop returns often, so without this a growing capture
# would be re-converted every few seconds. A new handshake still lands within it.
PCAP_REFRESH_SECONDS = 20
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
                 temp_reader=read_temp_c, clock=time.time, stream=False):
        self.config_path = config_path
        self.crack_dir = crack_dir
        self.capture = CaptureInterface(capture_store)
        self.loot = LootStore(crack_dir)
        self.potfile = os.path.join(crack_dir, POTFILE_NAME)
        self._runner = runner
        self._temp = temp_reader
        self._clock = clock
        # Stream aircrack's live status into crack-progress.json while a dict
        # crack grinds (the live view). On-device only (main() sets it); off in
        # tests, which drive the injected runner and read output in one shot.
        self._stream = stream
        self._py = "python3"         # interpreter for john's hccapx2john.py helper
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
        now = time.time()
        for src in pcapngs:
            dst = os.path.join(out_dir, os.path.basename(src) + ".pcap")
            try:
                dst_mtime = os.path.getmtime(dst) if os.path.exists(dst) else 0
                # Re-convert when the capture has grown, but at most once every
                # PCAP_REFRESH_SECONDS: with one AP per pass the loop comes back
                # often, and re-running tcpdump on a steadily growing capture
                # every few seconds would be wasteful. A new handshake is still
                # picked up within that window.
                fresh = bool(dst_mtime) and (
                    dst_mtime >= os.path.getmtime(src)
                    or (now - dst_mtime) < PCAP_REFRESH_SECONDS)
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

    def _run_dict_streaming(self, pcaps, bssid, wl, timeout, on_progress):  # pragma: no cover
        """Run a dictionary crack with a live feed: aircrack-ng *without* ``-q``,
        its repainting status read as it comes and handed to ``on_progress`` a few
        times a second. Returns ``(rc, text, "")`` like the injected runner, with
        ``text`` the head+tail of aircrack's output for the final classify (capped
        so a multi-hour run can't grow memory without bound). On-device only --
        the batch path and every test use the injected runner instead."""
        import select
        cmd = ac.build_dict_cmd(pcaps, bssid, wl, quiet=False)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            return 127, "", ""
        head, tail, rc = b"", b"", None
        deadline = (self._clock() + timeout) if timeout else None
        last_flush = 0.0
        flush_every = progress_mod.STALE_SECONDS / 15.0 or 2.0
        try:
            while True:
                if deadline and self._clock() > deadline:
                    proc.kill()
                    rc = 124
                    break
                ready, _, _ = select.select([proc.stdout], [], [], flush_every)
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        rc = proc.wait()
                        break
                    if len(head) < 8192:
                        head += chunk[:8192 - len(head)]
                    tail = (tail + chunk)[-8192:]
                now = self._clock()
                if on_progress and (now - last_flush) >= flush_every:
                    prog = progress_mod.parse_progress(tail.decode("utf-8", "replace"))
                    if prog:
                        on_progress(prog)
                    last_flush = now
                if proc.poll() is not None and not ready:
                    rc = proc.returncode
                    break
        finally:
            try:
                if proc.poll() is None:
                    proc.kill()
                if proc.stdout:
                    proc.stdout.close()
            except OSError:
                pass
        text = (head + b"\n" + tail).decode("utf-8", "replace")
        return (rc if rc is not None else 0), text, ""

    def _crack_one(self, pcaps, bssid, attack, conf, essid="", origin=""):
        """Crack one AP (``bssid``) in ``pcaps`` with ``attack``. Returns
        ``(password_or_None, ok, reason)``: ``ok`` is False only when the run did
        not genuinely try the wordlist; ``reason`` is ``"no-handshake"`` when the
        AP simply has no crackable handshake (benign -- not a worker error),
        ``"error"`` for a real aircrack failure, else ``None``."""
        timeout = int(conf.get("max_job_seconds") or 0) or None
        kind = attack.get("kind", "dict")
        if kind == "mask":
            crunch_args = ac.mask_to_crunch(attack.get("mask", ""))
            if crunch_args is None:
                return None, True, None      # mask crunch can't express: skip
            rc, out, err = self._run_mask(pcaps, bssid, crunch_args, timeout)
        else:
            wl = attack.get("path", "")
            if not os.path.isfile(wl):
                return None, True, None      # missing wordlist: skip, not an error
            # Mark this AP/wordlist as the live crack now, so the dashboard and
            # `kestrel crack watch` show which list is running the instant it
            # starts (not just after the pass). On-device we also stream the
            # keys/rate/passphrase into the same file as aircrack repaints.
            base = {"state": "cracking", "bssid": bssid, "essid": essid,
                    "wordlist": attack.get("name", ""), "origin": origin,
                    "started": self._clock()}
            progress_mod.write_progress(self.crack_dir, base, now=self._clock())
            if self._stream:
                rc, out, err = self._run_dict_streaming(
                    pcaps, bssid, wl, timeout,
                    lambda prog: progress_mod.write_progress(
                        self.crack_dir, dict(base, **prog), now=self._clock()))
            else:
                rc, out, err = self._runner(ac.build_dict_cmd(pcaps, bssid, wl),
                                            timeout=timeout)
        text = (out or "") + "\n" + (err or "")
        verdict = ac.classify(text)
        if verdict == "cracked":
            return ac.parse_key(out), True, None
        if verdict == "exhausted":
            return None, True, None
        if verdict == "no-handshake":
            # Benign: this AP has no crackable 4-way handshake yet (PMKID-only, or
            # no EAPOL captured). Don't set _last_error -- the worker stays healthy
            # and the caller marks just this AP "no handshake".
            return None, False, "no-handshake"
        msg = ("aircrack-ng: " + ac.error_detail(text))[:200]
        log.warning("%s", msg)
        self._last_error = msg
        return None, False, "error"

    def _run_attack(self, targets, attack, conf, pcaps, origin=""):
        """Run ``attack`` against each target AP. Returns
        ``(cracked, failed, no_handshake)``: ``cracked`` is ``{BSSID: password}``,
        ``failed`` the BSSIDs whose run genuinely errored, and ``no_handshake``
        the BSSIDs with no crackable handshake yet (both kept out of 'tried' so
        they retry once a handshake lands, but only ``failed`` marks the worker)."""
        cracked, failed, no_handshake = {}, set(), set()
        for target in targets:
            bssid = (target.get("bssid") or "").upper()
            if not bssid:
                continue
            password, ok, reason = self._crack_one(
                pcaps, bssid, attack, conf,
                essid=target.get("essid") or "", origin=origin)
            if password is not None:
                cracked[bssid] = password
            elif reason == "no-handshake":
                no_handshake.add(bssid)
            elif not ok:
                failed.add(bssid)
        return cracked, failed, no_handshake

    # -- one pass ---------------------------------------------------------
    def run_once(self):
        """Do at most one unit of work. Returns ``(state, did_work)``."""
        conf = self.config()
        aps = self.loot.load()
        targets = targets_from_events(self._all_events())
        for target in targets:
            LootStore.upsert(aps, target, now=self._clock())
        # Apply any GPU-offload results dropped in by `kestrel crack ingest`
        # before this pass. The worker owns every loot write, so ingest only
        # queues to a file and this single-owner step marks the records cracked
        # (race-free). Runs before the enabled/aircrack gates so an offloaded key
        # lands even when local cracking is off.
        offload_mod.reconcile(aps, self.crack_dir, now=self._clock())
        wordlists = wl_mod.discover(conf.get("wordlists_dir"),
                                    conf.get("order", "size"))
        masks = [str(m).strip() for m in (conf.get("masks") or []) if str(m).strip()]
        attacks = store_mod.build_attacks(wordlists, masks)
        reuse = self._reuse_attack(aps, conf)
        if reuse is not None:
            attacks = [reuse] + attacks       # recovered passwords, tried first
        all_sigs = {a["sig"] for a in attacks}
        recrack = bool(conf.get("recrack_on_new_wordlist", True))

        state, did_work, current = "idle", False, None
        self._last_error = ""
        engine = self._engine(conf)
        if not conf.get("enabled", True):
            state = "disabled"
        elif engine == "john":
            # John reads the .hc22000 store directly (EAPOL + PMKID + rules), so it
            # needs no packet capture and cracks the stored backlog too. Isolated
            # from the aircrack path below so that proven path is untouched.
            state, did_work, current = self._crack_pass_john(
                aps, targets, attacks, conf, recrack)
        elif engine == "aircrack":
            if not (ac.have_aircrack() and ac.have_tcpdump()):
                state = "no-aircrack"
            else:
                pcaps = self._prepare_pcaps()
                if not pcaps:
                    # aircrack cracks from the packet capture; nothing to do until
                    # the rolling pcapng has handshakes (hashlines aren't enough).
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
                            current, progressed = self._run_auto(batch, aps, pcaps, conf)
                            if progressed:
                                state, did_work = "cracking", True
                            else:
                                # Only no-handshake (or errored) APs this pass --
                                # nothing to grind, so idle and sleep rather than
                                # hot-loop; a real error still flips to "error".
                                state, current, did_work = "idle", None, False
        else:
            state = "no-cracker"        # neither john nor aircrack is installed

        LootStore.refresh_statuses(aps, all_sigs)
        self.loot.save(aps)
        # An aircrack failure this pass takes precedence over idle/cracking, so the
        # dashboard shows the real error instead of a silent false "exhausted".
        if self._last_error and state in ("idle", "cracking"):
            state = "error"
        # Nothing is grinding now, so retire any live-progress record -- otherwise
        # the dashboard/watch would show a frozen passphrase. (It self-expires via
        # is_fresh() too, but clearing is immediate and tidy.)
        if state != "cracking":
            progress_mod.clear_progress(self.crack_dir)
        self._write_status(aps, conf, wordlists, masks, state, current)
        return state, did_work

    def _all_events(self):
        events = []
        for path in self.capture.hashline_files():
            events.extend(self.capture.read_events(path))
        return events

    def _reuse_attack(self, aps, conf):
        """A synthetic, highest-priority wordlist of the passwords already
        recovered, so every still-uncracked AP tries known passwords first -- PSK
        reuse across APs (one operator, one neighbourhood, one vendor default) is
        common and nearly free to check. Kept as ``recovered-psks.txt`` in the
        crack dir; its signature is the content hash, so recovering a new password
        gives the rest a fresh pass against the updated list. Returns None when
        disabled (``[crack] reuse_passwords = false``) or nothing is recovered."""
        if not bool(conf.get("reuse_passwords", True)):
            return None
        psks = sorted({rec.get("password") for rec in aps.values()
                       if rec.get("password")})
        if not psks:
            return None
        body = "".join(p + "\n" for p in psks)
        path = os.path.join(self.crack_dir, "recovered-psks.txt")
        try:
            current = ""
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    current = fh.read()
            if current != body:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
        except OSError:
            return None
        sig = "reuse:" + hashlib.sha1(body.encode("utf-8")).hexdigest()[:12]
        return {"kind": "dict", "name": "recovered-psks", "path": path,
                "size": len(psks), "sig": sig}

    def _run_auto(self, batch, aps, pcaps, conf):
        """Run one auto batch. Returns ``(current, progressed)``: ``progressed``
        is True when at least one AP cracked or genuinely tried the wordlist, so
        the caller can go idle (and sleep) instead of hot-looping on a batch that
        was all no-handshake/errored APs."""
        attack, tgts = batch
        cracked, failed, no_hs = self._run_attack(tgts, attack, conf, pcaps, "auto")
        now = self._clock()
        progressed = bool(cracked)
        for target in tgts:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            if bssid in cracked:
                rec["no_handshake"] = False
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            elif bssid in no_hs:
                rec["no_handshake"] = True     # waiting for a handshake; not tried
            elif bssid in failed:
                continue                        # real error: stays pending, retries
            else:
                # Record the wordlist as tried only when aircrack actually ran it.
                rec["no_handshake"] = False
                LootStore.mark_tried(rec, attack["sig"])
                progressed = True
        current = {"essid": tgts[0].get("essid"), "bssid": tgts[0].get("bssid"),
                   "wordlist": attack["name"], "origin": "auto", "started": now}
        return current, progressed

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
        cracked, failed, no_hs = self._run_attack(targets, attack, conf, pcaps, "manual") \
            if targets else ({}, set(), set())
        now = self._clock()
        for target in targets:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            if bssid in cracked:
                rec["no_handshake"] = False
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            elif bssid in no_hs:
                rec["no_handshake"] = True
            elif attack["sig"] and bssid not in failed:
                rec["no_handshake"] = False
                LootStore.mark_tried(rec, attack["sig"])
        store_mod.remove_job(path)
        return {"essid": job.get("label") or attack["name"], "bssid": "",
                "wordlist": attack["name"], "origin": "manual", "started": now}

    # -- john engine (cracks the .hc22000 store directly) -----------------
    def _engine(self, conf):
        """Which on-device cracker to use, from ``[crack] engine``: ``auto``
        (John when installed, else aircrack-ng), ``john``, or ``aircrack``.
        Returns ``None`` when the chosen/only engine isn't installed."""
        choice = str(conf.get("engine", "auto") or "auto").lower()
        if choice == "john":
            return "john" if john_mod.have_john() else None
        if choice == "aircrack":
            return "aircrack"
        return "john" if john_mod.have_john() else "aircrack"

    def _crack_pass_john(self, aps, targets, attacks, conf, recrack):
        """One John pass over the ``.hc22000`` store: a queued manual job first,
        else the next auto batch. Returns ``(state, did_work, current)``."""
        jobs = store_mod.list_jobs(self.crack_dir)
        if jobs:
            return "cracking", True, self._run_manual_john(jobs[0], aps, conf)
        if not attacks:
            return "no-wordlists", False, None
        batch = store_mod.next_auto_batch(aps, targets, attacks, recrack)
        if batch is None:
            return "idle", False, None
        current, progressed = self._run_auto_john(batch, aps, conf)
        return ("cracking", True, current) if progressed else ("idle", False, None)

    def _john_attack(self, targets, attack, conf, origin):
        """Run ``attack`` (John) against each target AP; ``{BSSID: password}``."""
        cracked = {}
        for target in targets:
            bssid = (target.get("bssid") or "").upper()
            if not bssid:
                continue
            password = self._crack_one_john(target, attack, conf, origin)
            if password:
                cracked[bssid] = password
        return cracked

    def _run_auto_john(self, batch, aps, conf):
        attack, tgts = batch
        cracked = self._john_attack(tgts, attack, conf, "auto")
        now = self._clock()
        progressed = False
        for target in tgts:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            rec["no_handshake"] = False          # the hashline IS the handshake
            if bssid in cracked:
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            else:
                LootStore.mark_tried(rec, attack["sig"])
            progressed = True
        current = {"essid": tgts[0].get("essid"), "bssid": tgts[0].get("bssid"),
                   "wordlist": attack["name"], "origin": "auto", "started": now}
        return current, progressed

    def _run_manual_john(self, job_entry, aps, conf):
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
        cracked = self._john_attack(targets, attack, conf, "manual") if targets else {}
        now = self._clock()
        for target in targets:
            bssid = target["bssid"].upper()
            rec = aps.get(bssid)
            if rec is None:
                continue
            rec["no_handshake"] = False
            if bssid in cracked:
                LootStore.mark_cracked(rec, cracked[bssid], attack["name"], now=now)
            elif attack["sig"]:
                LootStore.mark_tried(rec, attack["sig"])
        store_mod.remove_job(path)
        return {"essid": job.get("label") or attack["name"], "bssid": "",
                "wordlist": attack["name"], "origin": "manual", "started": now}

    def _build_john_hashfile(self, lines):  # pragma: no cover
        """Convert hc22000 ``lines`` to a John wpapsk hashfile: PMKID lines
        directly, EAPOL via John's ``hccapx2john.py`` on a packed hccapx blob.
        Returns the hashfile path, or ``None`` if nothing converted."""
        work = os.path.join(self.crack_dir, ".john")
        os.makedirs(work, exist_ok=True)
        pmkids, blob = john_mod.split_sources(lines)
        parts = list(pmkids)
        if blob:
            helper = john_mod.find_hccapx2john()
            if helper:
                hcxf = os.path.join(work, "batch.hccapx")
                with open(hcxf, "wb") as fh:
                    fh.write(blob)
                _rc, out, _err = self._runner([self._py, helper, hcxf], timeout=60)
                if out and out.strip():
                    parts.append(out.strip())
        if not parts:
            return None
        hashfile = os.path.join(work, "batch.john")
        with open(hashfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(p for p in parts if p) + "\n")
        return hashfile

    def _crack_one_john(self, target, attack, conf, origin=""):  # pragma: no cover
        """Crack one AP against the John hashfile built from its hashlines.
        Returns the recovered passphrase or ``None``. On-device; tests override
        this (like ``_run_mask``) and the full path is proven end to end."""
        lines = target.get("lines") or (
            [target["hashline"]] if target.get("hashline") else [])
        if not lines:
            return None
        hashfile = self._build_john_hashfile(lines)
        if not hashfile:
            return None
        bssid = (target.get("bssid") or "").upper()
        pot = os.path.join(self.crack_dir, "john.pot")
        timeout = int(conf.get("max_job_seconds") or 0) or None
        base = {"state": "cracking", "bssid": bssid,
                "essid": target.get("essid") or "", "wordlist": attack.get("name", ""),
                "origin": origin, "started": self._clock()}
        progress_mod.write_progress(self.crack_dir, base, now=self._clock())
        if attack.get("kind") == "mask":
            jmask = john_mod.mask_to_john(attack.get("mask", ""))
            if jmask is None:
                return None                       # mask John can't express: skip
            cmd = john_mod.build_mask_cmd(hashfile, jmask, pot)
        else:
            wl = attack.get("path", "")
            if not os.path.isfile(wl):
                return None
            rules = conf.get("rules") or []
            rule = rules[0] if isinstance(rules, (list, tuple)) and rules else None
            cmd = john_mod.build_crack_cmd(hashfile, wl, pot, rules=rule)
        if self._stream:
            self._run_john_streaming(cmd, base, timeout)
        else:
            self._runner(cmd, timeout=timeout)
        _rc, out, _err = self._runner(john_mod.build_show_cmd(hashfile, pot), timeout=60)
        for found_bssid, _essid, password in john_mod.parse_show(out or ""):
            if found_bssid.upper() == bssid:
                return password
        return None

    def _run_john_streaming(self, cmd, base, timeout):  # pragma: no cover
        """Run John, reading its ``--progress-every`` status lines and writing the
        live record. Cracks go to the potfile regardless; this is only the feed."""
        import select
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            return
        deadline = (self._clock() + timeout) if timeout else None
        buf = b""
        try:
            while True:
                if deadline and self._clock() > deadline:
                    proc.kill()
                    break
                ready, _, _ = select.select([proc.stdout], [], [], 2.0)
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    buf = (buf + chunk)[-8192:]
                    prog = john_mod.parse_progress(buf.decode("utf-8", "replace"))
                    if prog:
                        progress_mod.write_progress(
                            self.crack_dir, dict(base, **prog), now=self._clock())
                if proc.poll() is not None and not ready:
                    break
        finally:
            try:
                if proc.poll() is None:
                    proc.kill()
                if proc.stdout:
                    proc.stdout.close()
            except OSError:
                pass

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
            "no_handshake": counts["no_handshake"],
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
                         capture_store=args.capture_store, stream=True)
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
