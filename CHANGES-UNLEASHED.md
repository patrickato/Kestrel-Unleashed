# Kestrel-Unleashed — changes from upstream Kestrel

Kestrel-Unleashed is a modified version of Kestrel
([aluminum-ice](https://git.3ntropy.io/aluminum-ice/kestrel), GPL-3.0-or-later).
This file is the "prominent notice" of modifications that the GPL (section 5)
requires: it records what was changed, and when, relative to upstream.

Upstream base: Kestrel `main` at commit `03943c4` (imported with full history).

---

## 2026-10-27 — Fork established, unleashed for authorized lab use

### Fork identity / attribution
- Renamed the project to **Kestrel-Unleashed**; added `NOTICE` and this file.
- `README.md` carries a prominent fork notice at the top.
- `LICENSE` (GPL-3.0-or-later) and the complete upstream commit history and
  authorship are retained unchanged.

### Unleashed: the capture gate (operator's own isolated lab; authorized use only)
Upstream ships capture **disabled** and behind an interactive authorized-use
acknowledgment. This fork assumes the operator runs it against their **own
networks in an isolated lab**, so it removes that gate — the acknowledgment
*mechanism* is unchanged and still resettable; only the shipped default differs.

- `builder/extra/files/config.toml`: `[capture] enabled = true` — capture runs on
  first boot (was `false`). One table only; no other defaults were touched.
- `builder/config.yml`:
  - Pre-seed the authorized-use acknowledgment (`/etc/kestrel/capture-ack`) at
    image build, so capture does not stop to ask on first run.
    `kestrel capture reset-ack` still clears it; `kestrel capture enable` still
    records it — only the lab build ships it already satisfied.
  - Enable `kestrel-capture.service` on boot, so `[capture] enabled = true`
    actually takes effect (upstream leaves the unit disabled until the CLI
    enables it).

The authorized-use warnings in the UI and docs are retained. The default `pi` /
`raspberry` login and the secrets-free policy are unchanged; supply a real
password and any real network details at build time, never in a commit.

### Added: firmware for the common USB capture dongles
`builder/config.yml` adds `firmware-atheros`, `firmware-libertas`,
`firmware-mediatek` and `firmware-realtek` to the image, so the usual external
adapters (e.g. the Alfa AWUS036ACM / MT7612U) work out of the box over their
in-kernel mac80211 drivers — no DKMS. RTL8812AU adapters (AWUS036ACH/AC) still
need an out-of-tree driver Kestrel deliberately omits and are not covered.

### Added: device identification from captured SSIDs/BSSIDs
A reduced port of the Augur project's device identifier
(`kestrel_pi/device_id.py`): it turns a captured network's ESSID (and, when
available, its BSSID vendor) into "what is this" — a router, a Ring doorbell, an
HP printer, an Amazon device. Pure stdlib, offline. The loot store and the web
Loot page show the result next to each network.

### Added: on-device quick-crack (capture → crack → loot)
A new, self-contained attack-and-crack capability (new to Kestrel; a port of the
Augur crack→loot flow): the device cracks its own captured handshakes on the CPU
and shows the recovered password in cleartext.

- `builder/config.yml`: adds `hashcat`, `pocl-opencl-icd` and
  `ocl-icd-libopencl1` (CPU OpenCL — the Pi has no usable cracking GPU); ships a
  starter wordlist, the `[crack]` worker service, the wordlist boot-provisioner,
  and the crack/wordlist directories.
- `builder/extra/files/config.toml`: new `[crack]` table (ships `enabled =
  true`, inert without a wordlist); nice/thermal/workload bounds so capture keeps
  priority. One new table only; no other defaults touched.
- `kestrel_pi/crack/` (new subpackage) + `kestrel-crack.service`: the worker
  reads the capture store, runs `hashcat -m 22000` against the wordlists,
  auto-cracks new handshakes (wordlist-first, "leave an AP alone" once it holds a
  crackable hashline), and writes a pi-owned loot store. Local-only — no radio,
  no network, no root.
- CLI `kestrel crack …`, a daemon `/loot` web page (multi-select batch crack) and
  a dashboard Loot card, plus a `crack` daemon readout service. See
  `docs/developer/crack-interface.md` and the README "Wordlists" section.
- Wordlists are operator-supplied: dropped into `/var/lib/kestrel/wordlists/` or
  staged on the boot partition under `/boot/firmware/kestrel-wordlists/`.

**Release impact: reflash-class** (adds apt packages and a new installed lib
script / service), so it ships on a freshly flashed image, not an app-layer
update.

### Added: brute-force mask attacks
The crack worker now runs hashcat **mask** attacks (`-a 3`) as well as
dictionaries, for the random all-numeric router keys no wordlist holds. A unified
attack model (wordlists then masks) drives both the auto and manual paths;
`[crack] masks` is empty by default (a brute force is a multi-hour commitment),
and a mask is normally aimed at one target with `kestrel crack run <file> --mask
'?d?d?d?d?d?d?d?d'` or the Loot page's mask box.

### Added: on-device kiosk (HDMI touchscreen)
The dashboard can run full-screen and touch-operable on an attached HDMI screen
at boot (chromium under the `cage` kiosk compositor). Ships OFF; `kestrel kiosk
enable` turns it on and sets the new `[web] trust_localhost`, which trusts
dashboard requests arriving over loopback (the on-device screen) without a login
— a management-link client never presents a loopback address, so it never widens
off-device access. Adds `cage`/`seatd`/`chromium-browser` (reflash-class), a
`[kiosk]` table, `kestrel-kiosk.service` (not enabled by default) and the
`kestrel kiosk` CLI. Needs validation on a real screen; see
`docs/user-guide/kiosk-setup.md`.

### Added: WPS PIN / Pixie-Dust attacks (reaver)
A second attack class beside handshake capture: a WPS-enabled AP can leak its
WPA passphrase, and reaver's offline **Pixie-Dust** attack recovers it in
seconds-to-minutes when the AP is vulnerable (with the slow online PIN brute
force as a `--no-pixie` fallback).

- `builder/config.yml`: adds `reaver` (ships `wash`, the WPS scanner) and
  `pixiewps`.
- `builder/extra/files/config.toml`: new `[wps]` table (`pixie_dust`,
  `scan_seconds`) — defaults only; nothing runs until invoked. One new table.
- `kestrel_pi/wps.py` (new, stdlib-only, unit-tested): reaver command building,
  `-vv` output parsing, and writing a recovered key into the **crack loot
  store** so WPS hits show on `/loot` and in `kestrel crack list`, tagged
  `via WPS (pin …)`.
- CLI `kestrel wps {scan,attack,list}`: CLI-driven, **no always-on service**. It
  **transmits**, so it takes the authorized-use acknowledgment; it uses the
  capture dongle in monitor mode and **pauses capture** for the run, restarting
  it afterward. See `docs/user-guide/wps-attacks.md`.

**Release impact: reflash-class** (adds apt packages), so it ships on a freshly
flashed image, not an app-layer update. The radio orchestration is not yet
validated end-to-end on hardware (see `docs/developer/deferred.md`).

### Added: evil-portal (captive-portal rogue AP)
A generic captive-portal **framework** for authorized Wi-Fi assessments — not a
kit of fake-brand pages. It broadcasts an open SSID on the capture dongle,
answers all DNS to itself, redirects web traffic to a portal page (operator
template or a neutral shipped default), and logs what clients submit.

- `builder/config.yml`: adds `hostapd`, `dnsmasq-base` (the binary without the
  stock system service, so it can't grab `:53`) and `iptables`; installs the
  launcher, the neutral default templates, and a pi-owned state dir.
- `builder/extra/files/config.toml`: new `[evil-portal]` table (`ssid`,
  `channel`, `portal_ip`, DHCP range) — defaults only. One new table.
- `kestrel_pi/evilportal.py` (new, stdlib-only, unit-tested): the portal HTTP
  server's request routing, the OS-probe URL table, template loading (with a
  neutral built-in fallback), and the captured-submission store.
- `builder/extra/files/evil-portal/templates/`: neutral `index.html` /
  `done.html` with a README spelling out the **no-impersonation** rule.
- `evil-portal-launch` + `kestrel-evil-portal.service`: the rogue-AP plumbing
  (hostapd + dnsmasq + an iptables :80 redirect; the portal runs as pi on
  :8880). The unit is **start-on-demand only** — it has no `[Install]` section,
  so it never auto-starts at boot. Capture is paused for the run and resumed on
  stop.
- CLI `kestrel evil-portal {start,stop,status,creds}`: CLI-driven, gated by the
  authorized-use acknowledgment (it transmits and takes over the dongle). See
  `docs/user-guide/evil-portal.md`.
- `run_as_pi` moved from the CLI into `common.sh` so the launcher can drop the
  portal server to pi the standard way (enforced by `test_root_python.py`).

**Release impact: reflash-class** (adds apt packages). The AP orchestration is
not yet validated end-to-end on hardware (see `docs/developer/deferred.md`).

### Fixed: on-device cracking never actually ran (hardware)
First hardware test surfaced two bugs that together made every handshake read as
`exhausted` within minutes without a real attempt:
- **hashcat needs `--force` on the Pi.** The only OpenCL device is the CPU via
  pocl, which hashcat treats as unsupported and refuses to use without `--force`
  — so it exited non-zero immediately. `build_crack_cmd`/`build_mask_cmd` now
  pass `--force`.
- **An errored run was recorded as "tried."** The worker marked a wordlist tried
  even when hashcat exited with an error, so a systematic failure masqueraded as
  `exhausted`. `_run_attack` now reports whether hashcat genuinely completed
  (exit 0/1/124); on an error the AP stays `pending`, the message is surfaced in
  `status.json` (`error` field, additive — `contract_version` stays 1) and as a
  new `error` worker state / "Last error" dashboard readout, so the real cause is
  visible instead of a silent false exhaustion.
- **Hashcat ran out of allocatable device memory.** With `--force` in place
  hashcat then exited 252 ("Not enough allocatable device memory") because the
  Pi's CPU OpenCL (pocl) caps a single allocation at 256 MB and a `-m 22000`
  attack's autotuned batch overflows it. New `[crack] kernel_accel` (hashcat
  `-n`, default `1`) pins the per-batch size so it fits; it is operator-tunable
  (raise for speed on big lists until it errors again, then back off).

**Release impact: app-layer-safe** (only the `kestrel_pi` package changed), but
it ships with the next image either way.

### Added: device-aware crack suggestions
The device-ID already classifies each captured AP (camera, ISP router, printer,
...), and some SSIDs name the model outright (`UPC1234567`, `ATTabcdefg`,
`NETGEAR42`). A new suggestion engine turns that into "what should I throw at
this, in order" for recovering a **default** WPA key.

- `kestrel_pi/crack/suggest.py` (new, stdlib-only, unit-tested): maps device
  class + SSID pattern → an ordered attack list — curated default-key list,
  brute-force masks (the 8-digit numeric mask is the universal high-value one),
  and, when the SSID/OUI identifies a legacy model, the vendor key-generator to
  run (UPC `upc_keys`, AT&T/Comcast/Belkin via PSKracker, Thomson/BT via
  routerkeygen). Honest by design: cameras / hotspots / IoT hubs mostly onboard
  via BLE/QR/open-AP and ship no crackable default, so it says so and falls back
  to the generic order rather than inventing a vendor default.
- CLI `kestrel crack suggest <network>` prints the ordered attacks with ready
  `kestrel crack run` lines; the web Loot page gains a **suggested** column.
- `builder/extra/files/wordlists/device-defaults.txt`: a small curated
  default-key list (`12345678`, `password`, ...), installed alongside the
  starter lists; the engine suggests it only when present.

**Release impact: the engine + CLI + Loot column are app-layer-safe; the
`device-defaults.txt` wordlist lands on a reflash** (the in-place engine doesn't
install wordlists). The suggestions work without it (masks + existing lists), so
an app-layer update gets the feature and the curated list rides in on the next
image.

### Changed: the crack engine is now aircrack-ng, not hashcat (the Pi can't run hashcat)
Hardware testing proved hashcat cannot crack WPA on the Pi at all: hashcat needs
an OpenCL device, the Pi's only CPU OpenCL is **pocl**, and pocl caps a single
allocation at **256 MB** — too small for the `-m 22000` kernel at *any* settings
(`-w 1 -n 1 -T 1 --backend-vector-width 1` still fails with "not enough
allocatable device memory"), and pocl won't expose the board's real 16 GB. No
hashcat flag gets under the cap. So the worker now drives **aircrack-ng**, which
cracks WPA on the CPU natively (no OpenCL, no cap) at ~1,200 keys/s on a Pi 5.

- `builder/config.yml`: drop `hashcat`/`pocl-opencl-icd`/`ocl-icd-libopencl1`;
  add `aircrack-ng`, `tcpdump` (aircrack reads packet captures, so the rolling
  pcapng is converted to a classic pcap first) and `crunch` (streams a mask's
  keyspace into aircrack for brute force).
- `kestrel_pi/crack/aircrack.py` (new, stdlib, unit-tested): capture→pcap
  conversion, the dictionary and stdin (mask) command builders, the
  mask→crunch mapping, and output parsing/classification.
- `kestrel_pi/crack/controller.py`: the worker converts the capture to pcap once
  per cycle and runs aircrack **per AP** (by BSSID); dictionaries run directly,
  masks via `crunch | aircrack-ng -w -`. Per-target error handling (an errored
  AP stays pending, never a false "exhausted"); new `no-aircrack`/`no-capture`
  states. Same loot store, wordlist ladder, device-aware suggestions, thermal
  gating and glass-box error surfacing.
- `kestrel_pi/capture.py`: `CaptureInterface.pcapng_files()` exposes the rolling
  capture for the backend.

Trade-offs vs hashcat (noted in `docs/developer/deferred.md`): aircrack has no
rule engine (`[crack] rules` is a no-op), and only **uniform** masks (`?d?d…`,
`?H?H…`) map to crunch — mixed/custom masks are skipped. `hashcat.py` stays as a
dormant, still-tested module for a future GPU host; `[crack] kernel_accel`/
`workload` apply only to that path.

**Release impact: reflash-class** (swaps apt packages), and app-layer-updatable
for the worker code once the packages are on the image.

### Added: point-and-click web controls for WPS, evil-portal and crack suggestions
Everything added above was reachable from the terminal; this wires the three
offensive features into the dashboard so they are point-and-click on a phone or
the device's own kiosk screen, with the same auth + authorized-use gating as the
capture toggle (read-only when `[web] auth` is off).

- **WPS page (`/wps`)**: a *WPS attacks* dashboard card → a page with a **Scan
  for WPS APs** button and, per result, an **Attack** button (reaver /
  Pixie-Dust). Long-running scan/attack launch in the background as a fixed-name
  transient unit (`systemd-run --unit=kestrel-wps-run`, so a second run while one
  is active is refused rather than fighting over the one radio); the page shows
  the live state (idle/scanning/attacking) from a CLI-written state file and
  self-refreshes while busy. The `kestrel wps` CLI now records that state and its
  last scan output under `/var/lib/kestrel/wps/`.
- **Evil-portal page (`/portal`)**: an *Evil-portal* card → a page showing the
  live service state and SSID/channel, **Start**/**Stop** buttons (Start takes
  the ack), and — because they are plaintext — the captured submissions, shown
  **only with web auth on** (like the wpa-sec "Show" view). This closes the
  "show captured submissions on the dashboard" deferred item.
- **One-click crack suggestions on `/loot`**: the suggested-attack column is now
  a **Run** button (web auth on) that queues exactly that attack — the device
  default mask or wordlist — against just that AP (via the new
  `CaptureInterface.files_for_bssid()`), no typing.
- Root side (`plugins-ctl.py`, runs as root): new `apply_wps` / `apply_evil-portal`
  apply targets behind the existing `kestrel-plugins-apply.socket`. They validate
  the BSSID strictly (regex, argv not shell), enforce the shared `capture-ack`,
  and shell only to the trusted root CLI — a web button grants no privilege the
  terminal didn't. `config.yml` creates the root-owned, world-readable
  `/var/lib/kestrel/wps` state dir.

**Release impact:** the *feature code* is app-layer-safe — all of it is
`kestrel_pi` package code, `plugins-ctl.py` and `kestrel.sh`, which the in-place
engine carries into a running device, and the new `/var/lib/kestrel/wps` state
dir is created by the CLI on first use, so an app-layer update gets the feature
with no new lib script or apt package. The only build hunk is a `file:`-created
directory in `config.yml`, which trips `update_kind=auto` to **reflash** — but
this release is already reflash-class for the aircrack apt swap above, so it
rides along at no extra cost (leave `update_kind=auto`, or force `reflash`).

### Fixed: a PMKID-only AP no longer reds-out the whole cracker; WPS scan shows progress
Two glass-box/UX fixes from the first on-hardware run.

- **Per-AP "no handshake" instead of a worker-wide error.** aircrack-ng cracks
  only a captured 4-way EAPOL handshake, not a PMKID (hashcat could, but the Pi
  can't run it). One PMKID-only AP used to set the worker's `error` state and
  paint the Loot page red even while other APs cracked fine. Now
  `aircrack.classify` recognises the no-EAPOL/no-handshake family as a distinct
  **`no-handshake`** verdict; the worker marks just that AP `no-handshake` (a new
  loot status, muted pill, "needs a 4-way handshake" hint, no Run button), keeps
  itself healthy, and goes **idle** (and sleeps) when the only remaining work is
  handshake-less APs instead of hot-looping. A real aircrack failure still flips
  to `error` and surfaces the reason. The AP is never marked "tried", so it
  becomes a normal target the moment a handshake is captured. `status.json` gains
  a `no_handshake` count; the Quick-crack readout shows "No handshake yet: N".
  Touched: `crack/aircrack.py`, `crack/controller.py`, `crack/store.py`,
  `crack/readout.py`, `web.py`.
- **WPS scan progress.** The `/wps` page could sit on "scanning" forever: the
  self-refresh only fired if the page happened to read the state file mid-scan,
  and there was a launch race. It now force-refreshes right after a scan is
  kicked off, shows a countdown ("about N seconds left") from the state file's
  age and the `[wps] scan_seconds` window, treats a long-stale `scanning` state
  as finished (so a crashed scan unit can't wedge the page), and distinguishes
  "no scan yet" from "scanned, found none". Touched: `web.py`.

**Release impact: app-layer-safe** — all `kestrel_pi` package code and `web.py`;
no build inputs, apt/pip, or new scripts.

### Left for later (deliberately not changed yet)
Kept at upstream defaults pending design discussion: the learning **agent**
(`[agent]`) and the display/uploader **plugins** (e-ink face, session-stats, gps,
wpa-sec, wigle, backup). Of the Augur ports under consideration, the device
identifier and the quick-crack→loot flow are now in; the multi-screen touch deck
(for the device's own HDMI screen) is the remaining one.
