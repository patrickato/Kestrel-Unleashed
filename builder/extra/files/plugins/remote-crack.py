"""remote-crack - automatically crack captured handshakes on a desktop GPU.

The painless, no-setup path is the GPU crack *kit* (`kestrel crack kit` -- you
move files). This plugin is the turnkey, automatic alternative: once you point it
at a GPU box over SSH, it offloads your still-uncracked networks (PMKID included,
which the Pi can't crack) to hashcat there and brings the recovered keys back on
its own -- no clicking, no file-shuffling.

Design (mirrors the remote-train plugin's SSH job model, simpler):

- **Async, disconnect-tolerant.** A crack run can take a long time, so it is
  launched *detached* on the host (``setsid``) with a ``crack.lock`` marker; a
  dropped tether never kills it. The plugin polls the lock, and when a run
  finishes it pulls the host's ``recovered.txt`` (hashcat ``--show`` output).

- **Shared ingest, race-free.** The pulled ``recovered.txt`` goes through the
  exact same path as the manual kit: :func:`offload.append_recovered` queues it
  to the pi-owned reconcile file and the crack *worker* marks the records cracked
  on its next pass (single-owner loot writes). So a remote crack lands identically
  to a local one -- on Loot, lit on the map, and reused against the other APs.

- **Offload each AP once.** Auto mode launches a run only when there are
  uncracked BSSIDs it hasn't sent yet (new captures), so it doesn't re-grind the
  same targets; the Crack-now button / ``remote-crack now`` forces a full
  re-offload (e.g. after you change the host wordlist).

Opt-in: it ships captured material off-device over SSH, so it declares the
``network`` capability (enabling it takes the authorized-use ack) and copies as
the device's own key over passwordless SSH (``remote-crack setup``), storing no
secret. The GPU host is independent of the backup and training hosts.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading
import time

from kestrel_pi import Plugin
from kestrel_pi.crack import CRACK_DIR, offload

_DEFAULT_KEY = "/home/pi/.ssh/id_ed25519"
# A run lock older than this is a crashed run and may be relaunched. A big
# wordlist/mask on a GPU can run for hours, so this is generous.
_DEFAULT_STALE_HOURS = 12
_RSYNC_TRIES = 3
_RSYNC_BACKOFF = 5
# The CLI (`remote-crack now`) drops this in the crack dir; on_epoch picks it up.
_NOW_TRIGGER = ".remote-crack-now"


class RemoteCrack(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = "Auto-crack captured handshakes on a desktop GPU over SSH (opt-in)."

    __target_api__ = 2
    __capabilities__ = ("capture-read", "network", "ui")
    # One row button: "Crack now" forces an offload of everything uncracked.
    # Offered only once configured and passwordless SSH is set up.
    __actions__ = ({"label": "Crack now", "path": "crack", "method": "post"},)
    __options__ = {
        "crack_host": {"type": "str", "default": ""},
        "crack_user": {"type": "str", "default": ""},
        "crack_path": {"type": "str", "default": ""},
        "crack_port": {"type": "int", "default": 22},
        "ssh_key": {"type": "str", "default": "/home/pi/.ssh/id_ed25519"},
        # The wordlist to crack with, as a path ON THE GPU HOST (e.g. the host's
        # own rockyou.txt). Cracking stays idle until this is set.
        "wordlist": {"type": "str", "default": ""},
        # The hashcat binary on the host (name on PATH or an absolute path).
        "hashcat": {"type": "str", "default": "hashcat"},
        # Optional extra hashcat flags, e.g. "-O -w 3". Space-separated; each is
        # passed as its own argv item (no shell), so it can't inject.
        "extra_args": {"type": "str", "default": ""},
        # Turnkey: offload new uncracked targets on their own. Off = only the
        # Crack-now button / `remote-crack now` launch a run.
        "auto": {"type": "bool", "default": True},
        # How often to run a full cycle (check for new targets / finished runs).
        "interval_seconds": {"type": "int", "default": 900},
        "stale_lock_hours": {"type": "int", "default": 12},
        # Per SSH/rsync op (not the detached crack run itself).
        "timeout": {"type": "int", "default": 600},
    }

    # -- lifecycle -------------------------------------------------------
    def on_loaded(self):
        self.log = self.context.logger
        self._lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._crack_now = threading.Event()
        self._status = "idle"
        self._last_result = None          # (recovered_count, epoch)
        self._offloaded = set()           # BSSIDs sent in a launched run
        self._set_health()
        self._worker = threading.Thread(
            target=self._run, name="remote-crack-worker", daemon=True)
        self._worker.start()

    def on_unload(self):
        self._stop.set()
        self._wake.set()

    def on_internet_available(self):
        self._wake.set()

    def on_epoch(self, epoch, info):
        self._set_health()
        trigger = os.path.join(CRACK_DIR, _NOW_TRIGGER)
        if os.path.exists(trigger):
            try:
                os.remove(trigger)
            except OSError:
                pass
            self._crack_now.set()
            self._wake.set()

    # -- the "Crack now" row button -------------------------------------
    def webhook_actions(self):
        if self._missing_config() or not self._key_ready() or not self._wordlist():
            return ()
        return self.__actions__

    def on_webhook(self, path, request):
        if path != "crack":
            return self.context.redirect("No such action.", error=True)
        if self._missing_config() or not self._key_ready():
            return self.context.redirect(
                "passwordless SSH is not set up -- run "
                "'sudo kestrel remote-crack setup' on the device first", error=True)
        if not self._wordlist():
            return self.context.redirect(
                "set a wordlist on the GPU host first "
                "(plugins ... --set wordlist=/path/on/host/rockyou.txt)", error=True)
        # In-process: the worker thread lives in this same daemon, so just wake it.
        self._crack_now.set()
        self._wake.set()
        return self.context.redirect("GPU crack offload requested.")

    # -- worker ----------------------------------------------------------
    def _run(self):
        self._cycle(force=False)
        while not self._stop.is_set():
            self._wake.wait(timeout=self._interval())
            self._wake.clear()
            if self._stop.is_set():
                return
            self._cycle(force=False)

    def _cycle(self, force=False):
        manual = self._crack_now.is_set()
        self._crack_now.clear()
        if self._missing_config() or not self._key_ready():
            if manual:
                self._set_status("not set up: set a host and run 'remote-crack setup'")
            self._set_health()
            return
        if not self._wordlist():
            self._set_status("idle: set a wordlist path on the GPU host")
            return
        if not self.context.connectivity.online:
            if manual:
                self._set_status("can't offload now: the device is offline")
            return
        if not self._run_lock.acquire(blocking=False):
            return
        try:
            if not self.context.require_capability("network"):
                self._set_status("error: network capability not declared")
                return
            self._run_cycle(manual)
        finally:
            self._run_lock.release()

    def _run_cycle(self, manual):
        """One pass: finish a running job (pull + ingest), or launch a new one."""
        state = self._job_state()
        if state == "running":
            self._set_status("cracking on %s" % self._host())
            return
        if state == "finished":
            self._collect_results()
        # Decide whether to launch. A manual request re-offloads everything;
        # auto launches only when there are uncracked BSSIDs not yet sent.
        aps = self._loot()
        lines, bssids = self._uncracked(aps)
        if not lines:
            self._set_status("idle: nothing left to crack" if not manual
                             else "nothing to crack -- all networks are cracked")
            return
        new = bssids - self._offloaded
        if not manual and not new:
            self._set_status("idle (sent %d network(s); waiting for new captures)"
                             % len(self._offloaded))
            return
        if manual:
            self._offloaded = set()        # force a full re-offload
        if self._launch(lines):
            self._offloaded |= bssids
            self._set_status("cracking %d network(s) on %s"
                             % (len(lines), self._host()))
        else:
            self._set_status("couldn't start the run -- see the log")

    def _collect_results(self):
        """Pull the finished run's recovered.txt and queue it for the worker."""
        local = os.path.join(self._workdir(), "recovered.txt")
        ok, _ = self._rsync_down("%s/recovered.txt" % self._remote_path(), local)
        if not ok:
            return
        try:
            with open(local, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return
        added = offload.append_recovered(CRACK_DIR, text)
        if added:
            with self._lock:
                self._last_result = (added, time.time())
            self.log.info("remote-crack: %d recovered key(s) ingested from %s",
                          added, self._host())

    # -- host operations (SSH/rsync) ------------------------------------
    def _ssh_opts(self):
        return ["-i", self._key(), "-p", str(self._port()),
                "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=20",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]

    def _ssh_e(self):
        return ("ssh -i %s -p %d -o BatchMode=yes "
                "-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 "
                "-o ServerAliveInterval=15 -o ServerAliveCountMax=4"
                % (shlex.quote(self._key()), self._port()))

    def _remote(self, script, timeout=None):
        cmd = (["ssh"] + self._ssh_opts()
               + ["%s@%s" % (self._user(), self._host()), "sh", "-s"])
        try:
            proc = subprocess.run(cmd, input=script, capture_output=True,
                                  text=True, timeout=timeout or self._timeout(),
                                  check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return (False, str(exc))
        out = (proc.stdout or "") + (proc.stderr or "")
        return (proc.returncode == 0, out.strip())

    def _rsync_up_file(self, local_file, remote_path):
        cmd = ["rsync", "-az", "--partial", "--mkpath", "-e", self._ssh_e(),
               local_file, "%s@%s:%s" % (self._user(), self._host(), remote_path)]
        return self._run_rsync(cmd)

    def _rsync_down(self, remote_path, local_path):
        cmd = ["rsync", "-az", "--partial", "-e", self._ssh_e(),
               "%s@%s:%s" % (self._user(), self._host(), remote_path), local_path]
        return self._run_rsync(cmd)

    def _run_rsync(self, cmd):
        last_err = ""
        for attempt in range(_RSYNC_TRIES):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self._timeout(), check=False)
            except FileNotFoundError:
                return (False, "rsync not installed")
            except (OSError, subprocess.SubprocessError) as exc:
                last_err = str(exc)
            else:
                if proc.returncode == 0:
                    return (True, (proc.stderr or proc.stdout or "").strip())
                last_err = (proc.stderr or proc.stdout or "").strip()
            if attempt + 1 < _RSYNC_TRIES:
                time.sleep(_RSYNC_BACKOFF * (attempt + 1))
        return (False, last_err)

    def _job_state(self):
        """``running`` / ``finished`` / ``none`` for the host crack job: a fresh
        ``crack.lock`` means running; a stale one or a ``crack.result`` with no
        lock means finished; otherwise none. One SSH."""
        ok, out = self._remote(
            "cd %s 2>/dev/null || exit 0; "
            "[ -f crack.lock ] && echo \"lock $(cat crack.lock 2>/dev/null)\"; "
            "[ -f crack.result ] && echo \"result $(cat crack.result 2>/dev/null)\""
            % self._q_path(), timeout=90)
        if not ok:
            return "none"
        lock_ts, has_result = None, False
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == "lock" and len(parts) > 1:
                try:
                    lock_ts = float(parts[1])
                except ValueError:
                    lock_ts = None
            elif parts and parts[0] == "result":
                has_result = True
        if lock_ts:
            age_h = (time.time() - lock_ts) / 3600.0
            if age_h < self._stale_hours():
                return "running"
            return "finished"            # stale lock = crashed run, treat as done
        return "finished" if has_result else "none"

    def _launch(self, lines):
        """Upload the uncracked hashlines and launch a detached hashcat run."""
        local = os.path.join(self._workdir(), "targets.hc22000")
        try:
            os.makedirs(self._workdir(), exist_ok=True)
            with open(local, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError as exc:
            self.log.warning("remote-crack: cannot stage targets: %s", exc)
            return False
        up_ok, out = self._rsync_up_file(
            local, "%s/targets.hc22000" % self._remote_path())
        if not up_ok:
            self.log.warning("remote-crack: target upload failed: %s", out)
            return False
        ok, out = self._remote(self._launch_script(), timeout=120)
        if not ok:
            self.log.warning("remote-crack: launch failed: %s", out)
        return ok

    def _launch_script(self):
        path = self._q_path()
        hc = shlex.quote(self._hashcat())
        wl = shlex.quote(self._wordlist())
        extra = " ".join(shlex.quote(a) for a in self._extra_args())
        worker = (
            "set -u\n"
            "cd %(path)s\n"
            "rm -f crack.result\n"
            "date +%%s > crack.lock\n"
            "if %(hc)s -m 22000 -a 0 targets.hc22000 %(wl)s "
            "--potfile-path kestrel.potfile %(extra)s; then r=ok; else r=err; fi\n"
            "%(hc)s -m 22000 --show targets.hc22000 "
            "--potfile-path kestrel.potfile > recovered.txt 2>/dev/null\n"
            "echo \"$r\" > crack.result\n"
            "rm -f crack.lock\n"
        ) % {"path": path, "hc": hc, "wl": wl, "extra": extra}
        return (
            "set -eu\n"
            "mkdir -p %(path)s\n"
            "cd %(path)s\n"
            "if [ -f crack.lock ]; then echo already-running; exit 0; fi\n"
            "cat > run-crack.sh <<'RUN'\n"
            "%(worker)s"
            "RUN\n"
            "setsid sh run-crack.sh >crack.log 2>&1 </dev/null &\n"
            "echo launched\n"
        ) % {"path": path, "worker": worker}

    # -- device-side data -----------------------------------------------
    def _loot(self):
        from kestrel_pi.crack.store import LootStore
        try:
            return LootStore(CRACK_DIR).load()
        except Exception:  # noqa: BLE001
            return {}

    def _uncracked(self, aps):
        """``(hashlines, bssids)`` for the still-uncracked captures."""
        cap = self.context.capture
        try:
            lines = offload.uncracked_hashlines(
                cap.hashline_files(), aps, cap.read_events)
        except Exception:  # noqa: BLE001
            return [], set()
        bssids = set()
        for raw in lines:
            event = _parse(raw)
            if event is not None and event.bssid:
                bssids.add(event.bssid.upper())
        return lines, bssids

    # -- readout ---------------------------------------------------------
    def on_ui_setup(self, ui):
        ui.add_element("target", "-", label="GPU host")
        ui.add_element("state", "idle", label="Offload")
        ui.add_element("recovered", "none", label="Last result")

    def on_ui_update(self, ui, state):
        with self._lock:
            status = self._status
            last = self._last_result
        ui.set("target", self._target() or "-")
        ui.set("state", status)
        if last:
            ui.set("recovered", "%d recovered %s" % (last[0], _ago(last[1])))
        else:
            ui.set("recovered", "none")

    # -- helpers ---------------------------------------------------------
    def _missing_config(self):
        return [k for k in ("crack_host", "crack_user", "crack_path")
                if not str(self.options.get(k) or "").strip()]

    def _key_ready(self):
        return os.path.exists(self._key())

    def _key(self):
        return self.options.get("ssh_key") or _DEFAULT_KEY

    def _host(self):
        return self.options.get("crack_host") or ""

    def _user(self):
        return self.options.get("crack_user") or ""

    def _remote_path(self):
        return (self.options.get("crack_path") or "").rstrip("/") or "."

    def _q_path(self):
        return shlex.quote(self._remote_path())

    def _wordlist(self):
        return str(self.options.get("wordlist") or "").strip()

    def _hashcat(self):
        return str(self.options.get("hashcat") or "hashcat").strip() or "hashcat"

    def _extra_args(self):
        raw = str(self.options.get("extra_args") or "").strip()
        return shlex.split(raw) if raw else []

    def _workdir(self):
        return os.path.join(CRACK_DIR, "remote-crack")

    def _target(self):
        if self._missing_config():
            return ""
        return "%s@%s:%s" % (self._user(), self._host(), self._remote_path())

    def _port(self):
        try:
            return int(self.options.get("crack_port", 22))
        except (TypeError, ValueError):
            return 22

    def _auto(self):
        return bool(self.options.get("auto", True))

    def _interval(self):
        try:
            return max(60, int(self.options.get("interval_seconds", 900)))
        except (TypeError, ValueError):
            return 900

    def _stale_hours(self):
        try:
            return max(1, int(self.options.get("stale_lock_hours", _DEFAULT_STALE_HOURS)))
        except (TypeError, ValueError):
            return _DEFAULT_STALE_HOURS

    def _timeout(self):
        try:
            return max(30, int(self.options.get("timeout", 600)))
        except (TypeError, ValueError):
            return 600

    def _set_status(self, status):
        with self._lock:
            self._status = status

    def _set_health(self):
        missing = self._missing_config()
        if missing:
            self.context.health_note = (
                "not configured: set %s (plugins enable remote-crack --set ...)"
                % ", ".join(missing))
        elif not self._key_ready():
            self.context.health_note = (
                "passwordless SSH not set up -- run 'sudo kestrel remote-crack "
                "setup' to install the device key on %s" % self._host())
        elif not self._wordlist():
            self.context.health_note = (
                "set a wordlist path on the GPU host (--set wordlist=...)")
        else:
            self.context.health_note = ""


def _parse(raw):
    from kestrel_pi.capture import parse_hashline
    return parse_hashline(raw)


def _ago(epoch):
    if not epoch:
        return ""
    delta = int(time.time() - float(epoch))
    if delta < 0:
        delta = 0
    if delta < 60:
        return "just now"
    if delta < 3600:
        return "%dm ago" % (delta // 60)
    if delta < 86400:
        return "%dh ago" % (delta // 3600)
    return "%dd ago" % (delta // 86400)
