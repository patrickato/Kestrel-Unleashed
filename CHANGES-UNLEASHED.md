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

### Added: the dashboard is served over Ethernet
The dashboard bound only to the management radios (`bnep0` BT-PAN, `wlan0`
onboard Wi-Fi), never `eth0`, so a headless Pi 5 on a plain Ethernet cable was
reachable by SSH but not on `:8080`, and read "Internet: Offline" while wired.
`eth0` is now a management interface (first in the list, as the most stable path
when a cable is present), so "plug a Pi 5 into the network and open the
dashboard" just works with no Wi-Fi staging. Ethernet is treated as a trusted
management link: controls still require `[web] auth`, the capture dongle is still
never served, and `[web] bind` can be set to `loopback` or a specific IP to not
serve on a LAN. Touched: `connectivity.py`, `web.py` (app-layer-safe), plus the
README/GUIDE "getting online" docs. 

### Improved: crack responsiveness (one AP per pass) + password reuse
Two changes to the auto-crack worker so it keeps up with live capture and gets
more out of every crack.

- **One AP per pass.** The worker used to run a wordlist against *every*
  uncracked AP in a single pass before looping back and re-scanning, so a
  handshake caught mid-grind waited out the whole batch (hours, on a big list).
  That "batch all targets" design was a hashcat optimisation (load the dictionary
  once, test many); under aircrack-ng, which cracks **one BSSID per run**, it
  bought nothing. `next_auto_batch` now returns one AP per pass, so a new
  handshake joins within one AP-crack and a freshly recovered password can be
  reused immediately — smallest-first ordering unchanged. The pcap conversion is
  now rate-limited (`PCAP_REFRESH_SECONDS`) so the more frequent passes don't
  re-run tcpdump on a growing capture every few seconds.
- **Password reuse across APs.** The moment one AP is cracked, its password is
  tried against every other still-uncracked AP *first*, ahead of the wordlists —
  PSK reuse across APs (one operator, one area, one vendor default) is common and
  nearly free to check. Recovered passwords are kept in the crack dir's
  `recovered-psks.txt` and injected as the highest-priority list; a new recovery
  re-arms the rest for a fresh pass against the updated set. Config:
  `[crack] reuse_passwords` (default `true`).

Touched: `crack/store.py`, `crack/controller.py`, `crack/__init__.py`,
`config.toml`. Release impact: app-layer-safe. Tests: +3 (one-per-pass ordering,
reuse hit, reuse disabled). 967 pass, lint clean.

### Added: wordlist optimizer (`kestrel crack wordlists optimize`)
Merges every installed wordlist into one de-duplicated master list, dropping
anything outside WPA passphrase length (8–63 chars) and keeping the best-ranked
candidates first (first-seen order preserved, so a frequency-ranked source stays
ranked). De-dup keys on an 8-byte hash per candidate, so even a 14M-line list
de-dupes in well under 200 MB of RAM on any Pi. Runs as `pi`, writes
`optimized.txt` to the pi-owned crack dir, and prints the one `sudo cp` to install
it — the "one good list" without losing smallest-first effectiveness or wasting
guesses on duplicates/too-short candidates. Core in `crack/wordlists.py`
(`optimize()`), CLI in `kestrel.sh`. Release impact: app-layer-safe (package +
CLI). Tests: +2.

### Added: wardriving map (located networks + route + live cursor)
A live, self-contained map in the dashboard — the view that makes the device a
wardriving tool, not just a capture box, and the one upstream does not have. It
reads what the `gps` plugin already records and draws it with **no map library,
no build step and no internet required**.

- `kestrel_pi/geo.py` (new, stdlib-only, unit-tested): the location core. Scans
  the per-handshake GPS **sidecars** (`<capture>.hc22000.gps.json`) into a merged
  `{BSSID: best-fix}` map (3D over 2D, more sats, most recent), reads the
  continuous **track**, joins ESSIDs from the capture store and the recovered set
  from the crack loot store into the located-networks list, and computes bounds /
  route distance. Pure functions, dependency-injected, tolerant of half-written
  files.
- `plugins/gps.py`: the position source now also lays a continuous **breadcrumb**
  (`gps-track.jsonl` in the capture store) — one point per fix, throttled by
  distance/interval and self-trimming past a size cap, so a long drive's route is
  bounded. Best-effort, like the existing sidecar/seam writes; off a device it is
  simply skipped.
- `plugins/map.py` (new, unit-tested): a local-only plugin (`location`,
  `capture-read`, `ui`; **no `network`**, so no authorized-use ack). A **Map**
  row button opens a full-screen Web-Mercator canvas: a **heatmap** of network
  density (the hero), markers for every located AP (recovered lit apart from
  uncracked, tap for details), the **route** polyline and a **live cursor** at the
  current fix. Offline it draws a coordinate graticule + scale bar; online the
  *viewing browser* (never the device) overlays OpenStreetMap tiles. The page
  polls a small `data.json` endpoint on the same route (TTL-cached store scan,
  shared with a dashboard readout card). Server-rendered, dependency-free, inline
  JS/CSS — per `web-ui-conventions`.
- `config.toml`: new `[plugins.map]` table (ships **disabled**; `tiles`,
  `refresh_seconds`, `max_track_points`). One new table only.
- `kestrel_pi/geoexport.py` (new, stdlib-only, unit-tested) + map **export**
  links/endpoints: one click (or a `curl` over the management link) downloads the
  whole wardrive as **KML** (Google Earth), **GPX** (the route, for any GPS app)
  or **WiGLE CSV** (the standard wardriving interchange). Columns the store never
  measured (channel/RSSI/accuracy) are left empty, not fabricated.

Touched: `geo.py` (new), `geoexport.py` (new), `plugins/map.py` (new),
`plugins/gps.py`, `config.toml`, user guide + README. Release impact:
**app-layer-safe** (package modules, a new plugin file and a config table — no
apt/pip/boot change, no new lib script). The live data flow is validated headless
(Playwright render, JS parse-checked); an end-to-end drive with a real receiver
is for the hardware pass. Tests: +49 (`test_geo.py`, `test_map.py`,
`test_geoexport.py`).

### Changed: dashboard ships dark by default, with a visual refresh
The web UI (dashboard, plugin pages, loot/map/agent, the kiosk view — every page
through `_page`) now **ships dark by default** rather than following the viewer's
OS setting, so the HDMI kiosk and a phone are both dark out of the box. The look
is refreshed into a cohesive "Kestrel" palette: a deep cool-slate base, an amber
identity accent (`--brand`) as a short rule under every page title and as the
keyboard-focus outline, emerald go-actions, and the existing semantic on/off/err
status tones (status still never colour-alone — every dot/pill carries text).

- `web.py`: the `_STATUS_CSS` token block is now dark-on-`:root` with a
  fully-defined **opt-in** light palette under `:root[data-theme="light"]`
  (reserved for a future settings toggle — no `prefers-color-scheme` auto-switch,
  which would wrongly flip a light-OS kiosk). Added `--brand`/`--accent-ink`, the
  `h1::after` title rule, a visible `:focus-visible` outline and a button hover.
  Pure CSS — **no client script is added to theme a page** (pages stay scriptless
  where they can). Every structural class/selector is unchanged, so no page markup
  moved.
- `docs/developer/web-ui-conventions.md`: theming section updated to the
  dark-by-default model.

Release impact: app-layer-safe (the CLI/package carry `web.py`). Validated by
headless render (kiosk + phone widths) and the suite. Tests: +1 (dark-by-default
+ light palette defined), one theme test updated. 1007 pass, lint clean.

### Added: GPU crack offload (and the only way to crack PMKID here)
The Pi's aircrack-ng is slow and **cannot crack PMKID at all**. This adds a
zero-config bridge to a real GPU running hashcat (~1000x faster, PMKID included)
with **no SSH, no keys** — you move files, so it works with the device fully
offline (a USB stick across the Faraday cage).

- `kestrel_pi/crack/offload.py` (new, stdlib-only, unit-tested): `build_kit`
  bundles the still-uncracked hashlines (PMKID included) + ready-to-run
  `crack.bat`/`crack.sh` (run `hashcat -m 22000` and emit `recovered.txt` via
  `--show`) + a README; `parse_recovered`/`append_recovered`/`reconcile` take the
  returned `recovered.txt` back into the loot store.
- **Race-free ingest:** the crack worker owns every loot write (it loads at the
  top of a pass and saves at the end, and a pass can run minutes), so ingest only
  *appends* recovered lines to a pi-owned reconcile file; the worker applies them
  on its next pass (`controller.run_once` calls `offload.reconcile` before the
  enabled/aircrack gates, so an offloaded key lands even when local cracking is
  off). The same ingest path will serve an automated SSH offload later.
- **CLI:** `kestrel crack kit [DIR]` (builds + zips the kit) and `kestrel crack
  ingest FILE` (applies a GPU box's `recovered.txt`).
- **Web:** a *GPU offload* section on the Loot page (auth on) with a **Download
  GPU crack kit (.zip)** link (`GET /loot/gpu-kit`) and an **Ingest results** file
  upload (`POST /loot/ingest`, CSRF-gated) — point-and-click on every UI.
- Recovered keys land exactly like a local crack: shown on Loot, lit on the map,
  and auto-reused against the other APs (they feed the existing reuse list).

Touched: `crack/offload.py` (new), `crack/controller.py`, `kestrel.sh`, `web.py`,
user guide + README. Release impact: **app-layer-safe** (package module + CLI +
web, no apt/pip/boot/new-lib-script). Validated: the kit builds and its scripts
are syntax- and shellcheck-clean; the round trip (build → recovered.txt → ingest
→ reconcile → cracked) is unit-tested; a real GPU-box run is for the hardware
pass. Tests: +17 (`test_offload.py`, Loot GPU web tests).

### Added: remote-crack — automatic GPU offload over SSH
The turnkey companion to the manual GPU kit: a new opt-in `remote-crack` plugin
that offloads uncracked networks (PMKID included) to hashcat on a desktop GPU
over SSH and brings the recovered keys back on its own — no file-shuffling.

- `plugins/remote-crack.py` (new, unit-tested): mirrors the `remote-train` SSH
  job model, simpler. A crack run is launched **detached** on the host
  (`setsid`) with a `crack.lock` marker, so a dropped tether never kills it; the
  plugin polls the lock and, when a run finishes, pulls the host's
  `recovered.txt` (hashcat `--show` output) and feeds it through the **same**
  `offload.append_recovered` → worker-reconcile path as the manual kit (race-free,
  single-owner loot writes). Auto mode offloads each uncracked BSSID once (new
  captures), and the **Crack now** row button / `remote-crack now` forces a full
  re-offload. The button triggers in-process (same daemon), so it needs no root
  apply target.
- Declares the `network` capability (authorized-use ack) and copies as the
  device's own key over passwordless SSH (`kestrel remote-crack setup`), storing
  no secret. The GPU host is independent of the backup and training hosts.
- `config.toml`: new `[plugins.remote-crack]` table (ships **disabled**:
  host/user/path/wordlist/hashcat/auto/interval/…). CLI `kestrel remote-crack
  {setup,now,status}` in `kestrel.sh` (mirrors `remote-train`). Reuses the ssh/
  rsync already present for backup/remote-train — **no new apt package**.

Touched: `plugins/remote-crack.py` (new), `config.toml`, `kestrel.sh`, user guide
+ README, `test_plugins_apply.py` (roster). Release impact: **app-layer-safe**
(a plugin file + config + CLI; no apt/pip/boot/new-lib-script). Device-side logic
(launch decision, finished-run collection, the shared ingest, launch-script
quoting) is unit-tested with the SSH ops stubbed; a real GPU-box run is for the
hardware pass. Tests: +8 (`test_remote_crack.py`). 1028 pass, lint clean.

### Added: live crack view (`kestrel crack watch` + live dashboard card)
Cracking a big list against one AP is *hours* on the Pi's CPU with no sign of
life — aircrack ran with `-q` and its output was read only at the end. The worker
now marks which wordlist/network it is on the instant a crack starts, and
on-device streams aircrack's running status (keys tested, %, k/s, ETA, the
passphrase it is trying) into a world-readable `crack-progress.json`.

- `kestrel crack watch`: a redrawing terminal panel (state, cracked/total, the
  live wordlist, a progress bar + rate + ETA, the current passphrase), built for
  an SSH session from a laptop; Ctrl-C quits.
- The dashboard **Quick-crack** card overlays the same live fields and refreshes
  on its own (no JS); a stale record self-expires so it never shows a frozen
  passphrase.
- aircrack's progress block is parsed by a new pure `kestrel_pi.crack.progress`;
  the streaming runner drops `-q` only for this path (the batch worker and every
  test still read output in one shot via the injected runner).

Touched: `kestrel_pi/crack/{progress.py,watchcli.py}` (new), `crack/{__init__,
aircrack,controller,readout}.py`, `daemon.py`, `kestrel.sh`, user guide. Release
impact: **app-layer-safe** (package + CLI only; no apt/pip/boot/config/new-lib-
script/unit). Live numbers need a handshake to crack on-device; the parser,
overlay, renderer and the worker's write/clear are unit-tested
(`test_progress.py`), and the aircrack stream itself is for the hardware pass.
Tests: +13. 1042 pass, lint clean.

### Added: John the Ripper on-device engine — crack the hc22000 store on CPU
aircrack-ng (the Pi's CPU engine) needs a packet capture and can read neither the
`.hc22000` hashline store nor a PMKID; hashcat can't run on the Pi's pocl. So the
*stored backlog* (whose raw captures housekeeping deleted) had no on-device
cracker — only the GPU offload. **John the Ripper jumbo** cracks both EAPOL and
PMKID on the CPU, with rules, reading only the hashline store, so it is now the
preferred on-device engine when installed.

- New `kestrel_pi/crack/john.py`: converts a hc22000 **PMKID** line to John's
  wpapsk line (a field reshuffle), and a hc22000 **EAPOL** line to a hashcat
  `hccapx` record that John's shipped `hccapx2john.py` turns into a wpapsk line
  (STA nonce read from the EAPOL frame, key version from its key-info bits).
  **Both were proven end to end against a real john jumbo** — it recovers the
  known passphrase from a synthesized PMKID *and* a synthesized WPA2 handshake,
  and `parse_show` maps each crack back to the right BSSID.
- `[crack] engine` = `auto` (default) | `john` | `aircrack`. `auto` picks John
  only when a *jumbo* build is present (`have_john()` requires the `hccapx2john`
  marker, so a stray Debian **core** `john` — which has no wpapsk — is never
  chosen); otherwise aircrack-ng, unchanged. The worker's John path is isolated
  from the proven aircrack path.
- `kestrel crack watch` understands John's `--progress-every` status line too.

Touched: `kestrel_pi/crack/{john.py (new),__init__.py,controller.py,readout.py}`,
`config.toml`, user guide, `deferred.md`. Release impact: the **code is
app-layer-safe** and inert without John (current devices keep aircrack), but the
capability needs the **jumbo `john` binary on the image**, which is
**reflash-class** and cannot be built/validated from CI or a cloud session
(Debian ships only core `john`; jumbo must be compiled for arm64) — it is written
up in `deferred.md` for the hardware/release pass, alongside a note to let John
crack all APs in one multi-salt run. Tests: +13 (`test_john.py`, plus engine
wiring/selection in `test_crack.py`); 1055 pass, lint clean.

### Added: device-aware auto masks — per-network default-key sweep
`[crack] masks` ships empty, so auto-crack ran no brute force at all — nothing
swept the common all-numeric default keys unless the operator armed a global
mask (which then blasts *every* network). Now the auto loop is device-aware: for
each pending AP it asks `crack/suggest.auto_masks()` whether that device type
plausibly ships a numeric default, and if so appends the 8-digit default-key
mask **tagged to that AP alone** (deepest tier, after the wordlists).

- Fires for printers, hotspots and ISP routers/gateways; returns nothing for
  cameras/IoT (ship no crackable default), unidentified APs, and model-matched
  gear whose real attack is a vendor keygen or a GPU-only hex/custom mask — all
  of which stay one-tap via the Loot suggestion / `kestrel crack suggest`.
- Only the on-device-practical 8-digit (`?d×8`) auto-runs; deeper numeric
  (10/11-digit) and hex/custom masks would take weeks per AP on the Pi CPU, so
  they're left to the GPU offload and the one-tap suggestion.
- `next_auto_batch` honors an attack's `only_bssid` tag so a per-device mask runs
  against its AP and no other; the tag is kept out of the global exhausted-set so
  a camera never needs a mask it will never be offered.

Touched: `crack/{suggest.py,store.py,controller.py}`, `config.toml`, user guide.
Release impact: **app-layer-safe** (pure logic + the worker; no new deps/units).
Tests: +4 (`auto_masks`, `only_bssid`, the per-device attack builder); 1059 pass,
lint clean. On-device mask execution rides the hardware pass with the rest.

### Fixed: kiosk strands on a chromium error page; now self-heals
`kiosk-launch.sh` ran `exec cage chromium` once with no wait and no retry, so if
the dashboard wasn't answering when chromium loaded -- a boot race (the launcher
starts `After=` the daemon *unit*, but its web port binds a moment later) or a
momentary daemon drop (e.g. a USB brown-out from hot-plugging a hub) -- chromium
parked on `ERR_CONNECTION_REFUSED` forever, with no way back on a touchscreen.

The launcher is now a self-healing supervisor: it waits for the dashboard to
answer before starting the browser, and a watchdog relaunches the browser if the
dashboard goes unreachable past `[kiosk] reload_after_seconds` (default 15; 0
disables). Reachability is a dependency-free bash `/dev/tcp` probe of the url's
host:port (no curl), and a `TERM`/`INT` trap tears cage down cleanly on
`systemctl stop`.

Touched: `kiosk-launch.sh`, `config.toml` (new `reload_after_seconds`), changelog.
Release impact: **app-layer-safe** (`kiosk-launch.sh` is in the engine's
`LIB_SCRIPTS`; the new config key falls back to the code default on existing
devices). Lint clean; shell-only, so covered by shellcheck + `bash -n`.

### Fixed: dashboard readouts refreshed only once a minute (GPS looked frozen)
The daemon fired `on_ui_update` (the dashboard refresh) on the **same loop** as
`on_epoch` (the decision tick), so every plugin card -- GPS fix, signal, sats,
the map cursor -- only updated every `epoch_seconds` (default **60s**). On a
live GPS/wardriving device that made the readout feel broken: move the antenna,
wait a minute to see any change.

Split them. A new `_ui_loop` dispatches `on_ui_update` every `[daemon]
ui_refresh_seconds` (default **5s**), decoupled from the 60s decision epoch; the
dashboard page's own auto-reload default dropped 30→10s to match (the map page
was already fast). `_tick_epoch` now drives only `on_epoch`.

Touched: `daemon.py` (`_tick_epoch` split + `_tick_ui`/`_ui_loop`), `config.py`
(`ui_refresh_seconds`), `config.toml`, `config_catalog.py`, changelog. Release
impact: **app-layer-safe** -- existing devices pick up the 5s data refresh from
the code default on an in-place update (operator config is skipped); lower
`[web] refresh_seconds` on the device for a fully live screen. Tests: +1; 1060
pass, lint clean.

### Left for later (deliberately not changed yet)
Kept at upstream defaults pending design discussion: the learning **agent**
(`[agent]`) and the display/uploader **plugins** (e-ink face, session-stats, gps,
wpa-sec, wigle, backup). Of the Augur ports under consideration, the device
identifier and the quick-crack→loot flow are now in; the multi-screen touch deck
(for the device's own HDMI screen) is the remaining one.
