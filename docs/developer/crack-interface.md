# Quick-crack interface contract

`contract_version: 1` (Kestrel-Unleashed)

This is the stable surface the on-device quick-crack subsystem exposes, so the
dashboard, the e-ink face and the CLI can build against it without reading the
worker's implementation. It is versioned: a change that breaks a consumer bumps
`contract_version` (distinct from the capture `contract_version`, the agent
`SPEC_VERSION` and `HOOK_API_VERSION`).

Quick-crack is **local-only**: it reads the Phase 2 capture store (see
[`capture-interface.md`](capture-interface.md)) and cracks on the CPU. It never
touches the radio, the network, or root. Everything it writes is pi-owned under
the crack dir. The Pi has no usable cracking GPU (no hashcat OpenCL path for the
VideoCore), so cracking is CPU-only via pocl, niced and thermal-gated so capture
always keeps priority.

## Components

- **Worker** — `kestrel_pi.crack.controller`, run by `kestrel-crack.service`
  (as `pi`). Each pass it re-reads `[crack]`, refreshes loot from the capture
  store, does one unit of work (a queued manual job first, else the next
  automatic batch), records results, and writes `status.json`.
- **Package** — `kestrel_pi.crack`: `store` (loot + queue + work derivation,
  pure stdlib, the unit-test seam), `wordlists` (discovery + ordering),
  `hashcat` (the one place that knows the hashcat CLI), `readout` (stdlib-only
  reader for the daemon card / e-ink face), `controller` (the worker loop).
- **CLI** — `kestrel crack status|list|show|wordlists|run|enable|disable|clear`.
- **Web** — the daemon's `/loot` page (read-only without web auth; with it, a
  multi-select capture-file + wordlist form that queues a manual job). A **Loot**
  nav card on the dashboard. The daemon exposes a `crack` readout service and
  merges the worker's readout into the `Quick-crack` widget card.

## Files (under `/var/lib/kestrel/crack/`, pi-owned)

- **`loot.json`** (world-readable) — the recovered loot, keyed by BSSID:
  ```jsonc
  {"contract_version": 1, "updated_at": <epoch>, "aps": {
    "AA:BB:CC:DD:EE:FF": {
      "bssid": "AA:BB:CC:DD:EE:FF", "essid": "HomeWiFi",
      "type": "eapol",                 // or "pmkid"
      "status": "cracked",             // cracked | pending | exhausted (derived)
      "password": "hunter2!",          // cleartext, "" until cracked
      "cracked_wordlist": "rockyou.txt", "cracked_at": <epoch>,
      "device": "NETGEAR router · router",   // from kestrel_pi.device_id
      "category": "router", "product": "NETGEAR router",
      "first_seen": <epoch>, "hashlines": 2,
      "files": ["HomeWiFi.hc22000"],
      "tried": ["rockyou.txt:139921497:1700000000"]  // wordlist signatures tried
    }}}
  ```
  `status` is **derived**, not authoritative state: `cracked` if a password is
  set; else `pending` if any available wordlist signature is not in `tried`;
  else `exhausted`. The worker caches it onto each record each pass so a reader
  without the wordlist set can show it.
- **`status.json`** (world-readable) — the worker's live state for the UI:
  ```jsonc
  {"contract_version": 1, "enabled": true,
   "state": "cracking",   // idle | cracking | paused-thermal | disabled | no-hashcat | no-wordlists | error
   "targets": 46, "cracked": 12, "pending": 30, "exhausted": 4,
   "wordlists": 3, "queue": 2, "temp_c": 61.2,
   "current": {"essid": "...", "bssid": "...", "wordlist": "...", "origin": "auto|manual"},
   "last_crack": {"essid": "...", "bssid": "...", "at": <epoch>},
   "error": "",           // last hashcat failure (e.g. a missing OpenCL device); "" when healthy
   "updated_at": <epoch>}
  ```
  `error` is additive (readers that ignore it are unaffected, so `contract_version`
  stays 1). When hashcat exits with an error code (not 0 cracked / 1 exhausted /
  124 the worker's own timeout), the worker records the message here, sets
  `state: "error"`, and does **not** mark the wordlist tried -- so a systematic
  failure (no OpenCL device, etc.) surfaces on the dashboard instead of
  masquerading as `exhausted`.
- **`queue/job-<ms>-<rand>.json`** — manual crack jobs, written by the web `/loot`
  page and `kestrel crack run` (as pi), consumed oldest-first and deleted:
  `{"files": [<abs capture paths>], "wordlist": <abs path>, "mask": <mask|"">,
  "rules": [<abs>], "label": "...", "origin": "manual|web", "created": <epoch>}`.
  A job gives **either** a `wordlist` (dictionary attack) **or** a `mask` (brute
  force); a non-empty `mask` wins.
- **`kestrel.potfile`** — hashcat's shared potfile (accumulates every crack).

## Wordlists

- **Dir:** `[crack] wordlists_dir` (default `/var/lib/kestrel/wordlists/`). Every
  readable, non-empty file is a candidate; `*.rule` files are excluded as
  wordlists (they are hashcat rule files, selectable via `[crack] rules`).
- **Signature:** `basename:size:mtime`. A grown/replaced list has a new
  signature, so it is not in any target's `tried` set and the cracker gives every
  uncracked AP a fresh pass against it — this is `recrack_on_new_wordlist`.
- **Order:** `[crack] order` — `size` (smallest first, the default and fastest to
  a common password), `name`, or an explicit comma-separated filename list.
- **Boot drop-in:** files staged under `/boot/firmware/kestrel-wordlists/` are
  moved into `wordlists_dir` on boot by `kestrel-crack-wordlist-provision.service`
  and the staged dir is cleared.

## Work model

An **attack** (`store.build_attacks`) is a wordlist (`kind: dict`) or a brute-force
mask (`kind: mask`), each with a tried-set `sig` (`name:size:mtime` for a
wordlist, `mask:<mask>` for a mask). The ordered attack list is **wordlists
first** (smallest-first) **then masks** (the deepest, slowest tier). `[crack]
masks` is empty by default, so auto-crack never surprise-runs a multi-hour brute
force; a mask is normally a deliberate deep attack on a chosen target.

- **Automatic** (derived each pass, no persisted queue): attack-first. The next
  unit is the first attack (in order) that still has an uncracked target which
  has not tried it, run once against **every** such target (one hashcat run tests
  all outstanding hashes against the loaded attack). Cracked → password
  recorded; not cracked → the attack's signature is added to that target's
  `tried`. A cracked or fully-tried (`exhausted`) target yields no work — this is
  "leave it alone". Capture is "done" with an AP once it holds a crackable
  hashline (AngryOxide de-dupes per AP); the cracker keeps working the stored
  hashline until cracked or exhausted.
- **Manual** (queue): a job names specific capture files + a wordlist (+ rules)
  and runs even against a cracked/exhausted target — the operator asked for it.
  This is how "re-run what didn't crack against another wordlist/ruleset" works.
  Manual jobs are processed before automatic work.

## Cracking

Kestrel stores `.hc22000`, so cracking is always `hashcat -m 22000` (EAPOL +
PMKID). The worker materializes the target hashlines to a temp file and runs
either a dictionary attack —
`nice -n <nice> hashcat -m 22000 -a 0 --quiet --potfile-path <pot> -w <workload>
[-r <rule>] <hashfile> <wordlist>` — or a brute-force mask —
`nice -n <nice> hashcat -m 22000 -a 3 --quiet --potfile-path <pot> -w <workload>
<hashfile> <mask>` — then reads back what cracked with
`hashcat -m 22000 --show --potfile-path <pot> <hashfile>` (the first `:` splits
hashline from password; the hashline is `*`-separated and carries no `:`).

## Bounds (so capture always wins and the board never cooks)

- **Niced** (`[crack] nice`, default 15) at the process and the hashcat child;
  `CPUWeight=20` in the unit gives capture/daemon/agent the cores under
  contention; `-w` (`[crack] workload`, default 1) keeps it desktop-friendly.
- **Thermal-gated:** pause at/above `[crack] max_temp_c` (default 75, hard cap
  `HARD_MAX_TEMP_C=85`), resume at/below `resume_temp_c` (default 68) — the same
  budget as the agent's training.
- **`max_job_seconds`** optionally caps each `(target × wordlist)` run.

This file is the normative reference. Release impact: adding/removing a key in
the JSON shapes above, or changing the file locations, is a `contract_version`
bump.
