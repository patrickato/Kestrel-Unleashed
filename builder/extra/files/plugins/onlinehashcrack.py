"""onlinehashcrack - offload captured handshakes to onlinehashcrack.com.

A connectivity-gated uploader, parallel to the ``wpa-sec`` plugin: it queues new
hc22000 hashlines from the capture store and submits them to OnlineHashCrack's
cracking service (hashcat-as-a-service) whenever a management path is online,
then polls the task list so you can see which networks it cracked.

**Important difference from wpa-sec:** OnlineHashCrack's API v2 never returns the
recovered passphrase -- a cracked task reports status ``FOUND`` and a
``cleartext_location`` (a URL to view the key on the site), not the key itself.
So this plugin tells you *which* networks are cracked and *where* to read the
key; it cannot auto-fill the on-device loot the way wpa-sec's potfile does. The
on-device cracker and the GPU offload remain the paths that put a key back in
your loot.

API v2 (JSON over POST to ``endpoint``): submit with ``action=add_tasks``
(``algo_mode`` + up to 50 ``hashes`` per call), poll with ``action=list_tasks``.
``api_key`` and ``agree_terms:"yes"`` travel in the JSON body. The WPA
``algo_mode`` is the hashcat mode (22000); it is a config option so a service
change is a setting, not a code edit. The exact field/mode contract is confirmed
on hardware (like wpa-sec's Gate 3); the behaviour here is the committed contract.

Because it transmits captured material off-device it is **opt-in**: it declares
the ``network`` capability (so enabling it takes the authorized-use
acknowledgment), ships disabled with no key baked in, and queues rather than
drops when offline. Target Python 3.11.
"""

from __future__ import annotations

import json
import os
import threading
import time
from urllib.parse import urlencode

from kestrel_pi import Plugin
from kestrel_pi.capture import parse_hashline

# The API accepts 1..50 hashes per add_tasks call, each <= 512 chars.
MAX_BATCH = 50
MAX_HASH_LEN = 512


class OnlineHashCrack(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = ("Offload captured handshakes to onlinehashcrack.com; "
                       "track which networks it cracked.")

    __target_api__ = 2
    __capabilities__ = ("capture-read", "network", "ui")
    # One row button on the Plugins page: "Results" opens the task-status page.
    __actions__ = ({"label": "Results", "path": "results", "method": "get"},)
    __options__ = {
        "api_key": {"type": "str", "required": True, "secret": True},
        "endpoint": {"type": "str",
                     "default": "https://api.onlinehashcrack.com/v2"},
        # hashcat mode for WPA-PBKDF2-PMKID+EAPOL. A config option so a service
        # change is a setting, not a code edit.
        "algo_mode": {"type": "int", "default": 22000},
        "poll_results": {"type": "bool", "default": True},
        # How often, at most, to re-poll the task list while online (1h).
        "results_interval_seconds": {"type": "int", "default": 3600},
        "timeout": {"type": "int", "default": 30},
    }

    # -- lifecycle -------------------------------------------------------
    def on_loaded(self):
        self.log = self.context.logger
        self._lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._state_path = os.path.join(
            self.context.capture.store_dir, ".onlinehashcrack-uploaded.json")
        self._uploaded = self._load_state()
        self._uploaded_session = 0
        self._last_results = 0.0
        # Snapshot of the last list_tasks poll: {hash: {"status","location"}},
        # plus a FOUND count for the readout.
        self._tasks = {}
        self._found = 0
        self._queue = []
        for path in self.context.capture.hashline_files():
            for event in self.context.capture.read_events(path):
                self._enqueue(event.raw)
        self.log.info("onlinehashcrack loaded; %d hashline(s) queued",
                      len(self._queue))
        self._worker = threading.Thread(
            target=self._run, name="onlinehashcrack-worker", daemon=True)
        self._worker.start()

    def on_unload(self):
        self._stop.set()
        self._wake.set()

    def _run(self):
        self._tick()
        while not self._stop.is_set():
            self._wake.wait(timeout=self._worker_interval())
            self._wake.clear()
            if self._stop.is_set():
                return
            self._tick()

    def _worker_interval(self):
        try:
            return max(60, int(self.options.get("results_interval_seconds", 3600)))
        except (TypeError, ValueError):
            return 3600

    def _tick(self):
        if not self.context.connectivity.online:
            return
        if not self._run_lock.acquire(blocking=False):
            return
        try:
            self._flush()
            self._maybe_poll_results()
        finally:
            self._run_lock.release()

    def on_handshake(self, event):
        self._enqueue(event.raw)
        self._wake.set()

    def on_internet_available(self):
        self._wake.set()

    def on_epoch(self, epoch, info):
        self._wake.set()

    # -- queueing --------------------------------------------------------
    def _enqueue(self, raw):
        if not raw:
            return
        if len(raw) > MAX_HASH_LEN:
            return      # the API caps a hash at 512 chars; skip oversize lines
        with self._lock:
            if raw in self._uploaded or raw in self._queue:
                return
            self._queue.append(raw)

    # -- submit ----------------------------------------------------------
    def _flush(self):
        if not self.context.require_capability("network"):
            return
        with self._lock:
            batch = self._queue[:MAX_BATCH]
        if not batch:
            return
        if self._submit(batch):
            with self._lock:
                for raw in batch:
                    self._uploaded.add(raw)
                    if raw in self._queue:
                        self._queue.remove(raw)
                self._uploaded_session += len(batch)
            self._save_state()
            self.log.info("onlinehashcrack submitted %d hashline(s)", len(batch))
            # More may be queued than one batch holds; nudge for the next pass.
            with self._lock:
                more = bool(self._queue)
            if more:
                self._wake.set()

    def _submit(self, hashes):
        body = {
            "api_key": self.options.get("api_key") or "",
            "agree_terms": "yes",
            "action": "add_tasks",
            "algo_mode": self._algo_mode(),
            "hashes": list(hashes),
        }
        reply = self._post(body)
        if reply is None:
            return False      # transient: stay queued, retry next pass
        if not reply.get("success", False):
            # A non-transient rejection (bad key, terms, quota): log and treat
            # the batch as attempted so it isn't resent forever.
            self.log.warning("onlinehashcrack add_tasks refused: %s",
                             reply.get("message") or reply.get("error_code")
                             or "unknown")
            return True
        acc = (reply.get("accepted") or {}).get("count", 0)
        skip = (reply.get("skipped") or {}).get("count", 0)
        rej = (reply.get("rejected") or {}).get("count", 0)
        if rej:
            self.log.info("onlinehashcrack: %d accepted, %d skipped, %d rejected",
                          acc, skip, rej)
        return True

    # -- results ---------------------------------------------------------
    def _maybe_poll_results(self):
        if not self.options.get("poll_results", True):
            return
        interval = int(self.options.get("results_interval_seconds", 3600))
        now = time.monotonic()
        if self._last_results and now - self._last_results < max(0, interval):
            return
        self._last_results = now
        self._poll_results()

    def _poll_results(self):
        reply = self._post({
            "api_key": self.options.get("api_key") or "",
            "agree_terms": "yes",
            "action": "list_tasks",
        })
        if reply is None or not reply.get("success", False):
            return
        tasks = {}
        found = 0
        for task in reply.get("tasks") or []:
            h = str(task.get("hash") or "")
            if not h:
                continue
            status = str(task.get("status") or "")
            location = str(task.get("cleartext_location") or "")
            tasks[h] = {"status": status, "location": location}
            if status.upper() == "FOUND":
                found += 1
        with self._lock:
            self._tasks = tasks
            self._found = found

    # -- HTTP ------------------------------------------------------------
    def _post(self, body):
        """POST the JSON body to the API. Returns the parsed reply dict, or
        ``None`` on a transport error (so the caller stays queued and retries)."""
        import requests

        endpoint = self.options.get("endpoint") or \
            "https://api.onlinehashcrack.com/v2"
        try:
            resp = requests.post(
                endpoint, json=body,
                timeout=int(self.options.get("timeout", 30)))
        except Exception as exc:  # noqa: BLE001 - any transport error: retry later
            self.log.warning("onlinehashcrack request failed: %s", exc)
            return None
        try:
            return resp.json()
        except ValueError:
            self.log.warning("onlinehashcrack: non-JSON reply (HTTP %s)",
                             resp.status_code)
            return None

    def _algo_mode(self):
        try:
            return int(self.options.get("algo_mode", 22000))
        except (TypeError, ValueError):
            return 22000

    # -- state -----------------------------------------------------------
    def _load_state(self):
        try:
            with open(self._state_path, "r", encoding="utf-8") as handle:
                return set(json.load(handle))
        except (OSError, ValueError):
            return set()

    def _save_state(self):
        try:
            with open(self._state_path, "w", encoding="utf-8") as handle:
                json.dump(sorted(self._uploaded), handle)
        except OSError as exc:
            self.log.warning("onlinehashcrack: could not save state: %s", exc)

    # -- dashboard readout ----------------------------------------------
    def on_ui_setup(self, ui):
        ui.add_element("submitted", "0", label="Submitted", kind="number")
        ui.add_element("queued", "0", label="Queued", kind="number")
        ui.add_element("found", "0", label="Cracked (on OHC)", kind="number")

    def on_ui_update(self, ui, state):
        with self._lock:
            submitted, queued, found = (
                self._uploaded_session, len(self._queue), self._found)
        ui.set("submitted", str(submitted))
        ui.set("queued", str(queued))
        ui.set("found", str(found))

    # -- results page (the "Results" row button) ------------------------
    def on_webhook(self, path, request):
        if path != "results":
            return self.context.page("Not found - kestrel",
                                     "<h1>Not found</h1>", status=404)
        esc = self.context.esc
        try:
            token = request.args.get("token") or ""
        except Exception:  # noqa: BLE001
            token = ""
        qs = ("?" + urlencode({"token": token})) if token else ""
        back = '<p><a href="/plugins' + qs + '">&larr; Plugins</a></p>'
        # The cleartext_location links lead to the recovered key on the service,
        # so gate the page on the web login like wpa-sec's cracked list.
        if not self.context.web_authed:
            return self.context.page(
                "onlinehashcrack - kestrel",
                back + "<h1>OnlineHashCrack results</h1>"
                + "<p>Turn on the dashboard login to view task results "
                + "(they link to recovered keys on the service).</p>")
        with self._lock:
            tasks = dict(self._tasks)
        rows = []
        for h, info in sorted(tasks.items(),
                              key=lambda kv: kv[1]["status"].upper() != "FOUND"):
            ev = parse_hashline(h)
            who = (ev.essid or ev.bssid or "?") if ev else "?"
            status = info["status"] or "-"
            loc = info["location"]
            cell = (('<a href="' + esc(loc) + '" rel="noopener noreferrer" '
                     'target="_blank">view key &rarr;</a>') if loc else "")
            rows.append("<tr><td data-label=\"network\">" + esc(who)
                        + "</td><td data-label=\"status\">" + esc(status)
                        + "</td><td data-label=\"key\">" + cell + "</td></tr>")
        body = "".join(rows) or ("<tr><td colspan='3'>no tasks yet "
                                 "(submit handshakes and check back)</td></tr>")
        return self.context.page(
            "onlinehashcrack - kestrel",
            back + "<h1>OnlineHashCrack results</h1>"
            + '<p class="count">OnlineHashCrack never returns the key itself; '
            + "a cracked task links to where you can read it on the service.</p>"
            + "<div class='wrap'><table><thead><tr><th>network</th>"
            + "<th>status</th><th>key</th></tr></thead><tbody>" + body
            + "</tbody></table></div>")
