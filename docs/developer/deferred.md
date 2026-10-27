# Deferred improvements

Known improvements that were consciously put off, so they aren't lost. Each
entry says what it is, why it waited, what doing it involves, and what should
trigger picking it up.

How to use this file:

- **Defer something:** add an entry in the same change that decides to defer it,
  under the area it belongs to. Write it impersonally (what and why, not who).
- **Do something:** remove its entry in the same change that does it, and say so
  in the PR description.
- Keep entries short; link to the code or doc that has the detail.

## In-place updates (`updates` plugin and update engine)

### Sign releases and verify the signature before installing

- **What:** release authenticity today rests only on TLS to the configured host
  and the Forgejo account (or `RELEASE_TOKEN`) that publishes releases. Whoever
  controls either can publish a release that runs as root on every device whose
  operator taps Upgrade.
- **Why deferred:** needs a signing key kept off the build host, a key-rotation
  story, and a one-time reflash to ship the public key; the root-side
  verification that now exists (`update-apply --verify`) was the prerequisite.
- **What to do:** sign `update-manifest.json` (for example `ssh-keygen -Y sign`
  or minisign) in the Release workflow, with the private key held outside the
  runner; ship the public key in the image (root-owned); make `--verify` refuse
  a release whose manifest signature doesn't check out. Signed tags plus
  `git verify-tag` are an alternative.
- **Pick up when:** before the device is used beyond the maintainer's own
  hardware, or if the release account or runner is shared.

### Remove systemd units a release drops

- **What:** the engine removes shipped plugins, lib scripts and operator
  scripts that a release no longer carries, but leaves dropped unit files in
  place (`removal_plan` in `builder/extra/files/update-apply.py`).
- **Why deferred:** removing a unit safely means disabling (and stopping) it
  first, and a rollback would then have to re-enable it.
- **What to do:** record units and their enable state in the install list,
  `systemctl disable --now` a dropped unit before removing it, and restore both
  on rollback.
- **Pick up when:** the first release that renames or drops a unit.

### Kill the whole backup process group on a pre-update-backup timeout

- **What:** the bounded pre-update backup (`run_backup` in
  `builder/extra/files/update-apply.py`, `backup_timeout_seconds`) stops *waiting*
  after the timeout and lets the update proceed to cancel/restart, but
  `subprocess` kills only the direct child (`kestrel backup now`), not the
  `rsync`/`ssh` grandchild it spawned. A doomed transfer can keep running in the
  background until it dies on its own (broken pipe / its own timeout).
- **Why deferred:** the operator-visible symptom — the dashboard held down for
  many minutes — is fixed (the daemon restarts at the timeout); the lingering
  rsync is harmless and short-lived, so a clean process-group kill was not worth
  widening the generic `run()` wrapper for right now.
- **What to do:** run the backup in its own session/process group
  (`start_new_session=True`) and, on `TimeoutExpired`, signal the whole group so
  the rsync/ssh child is torn down with its parent.
- **Pick up when:** the lingering transfer is shown to cause real trouble (e.g.
  two overlapping backups contending), or the `run()` wrapper gains process-group
  handling for another reason.

### Don't make beta testers reflash for a stable release after a reflash beta

- **What:** a stable release's manifest is built against the previous stable
  release, so if any beta in the cycle needed a reflash, the stable release is
  reflash too — even for devices that already flashed that beta.
- **Why deferred:** conservative and correct; it only costs beta testers an
  unnecessary flash.
- **What to do:** have the Release workflow also record, per stable release, the
  oldest version it can be applied on in place (`min_update_from`, already
  honoured by the plugin and `--verify`) computed across the betas.
- **Pick up when:** beta cycles with reflash betas become routine.

### One implementation of the update decision

- **What:** the plugin (`plugins/updates.py`, as pi) and the engine's `--verify`
  (`update-apply.py`, as root) each implement version ordering and the
  skipped-reflash check. A parity test covers `version_key` only.
- **Why deferred:** root must not import pi-writable code (the plugin imports
  from the pi venv), so sharing needs a stdlib-only module installed root-owned
  and loaded by both.
- **What to do:** move the shared logic into such a module (installed as a lib
  script), have both sides use it, and drop the duplicate.
- **Pick up when:** either side's decision logic next changes.

## Capture output

### Make `per-ap` the default output mode

- **What:** `[capture.output] mode` ships `per-ssid` but supports `per-ap`, which
  keys each `.hc22000` file on the AP BSSID so unrelated APs that reuse a network
  name (every `AndroidAP`, POS/printer/router default) are never merged into one
  file. `per-ap` is the more correct default; it is only opt-in today to avoid
  forcing a reflash.
- **Why deferred:** the default lives in `builder/extra/files/config.toml`, which
  the in-place update engine skips (operator config), so changing it would reach
  only freshly flashed devices and silently diverge from app-layer-updated ones.
  That makes the default-flip reflash-class on its own — too much to justify for
  this change alone.
- **What to do:** set `mode = "per-ap"` in `config.toml`, bump
  `contract_version` 3→4 in `docs/developer/capture-interface.md` (the filenames
  every consumer sees change), and update the mode's "default" wording in
  `config_catalog.py`, the user guides and `GUIDE_MD`. Force `update_kind=reflash`
  for that release — `auto` does not watch `config.toml`, so it would mislabel it
  app-layer.
- **Pick up when:** the next release that is already reflash-class for a larger
  reason, so this rides along at no extra reflash cost.

## Ghost user-guide publisher (`tools/ghost-guide`)

### Remove superseded screenshots from Ghost

- **What:** each publish uploads any screenshot whose pixels changed, and the
  replaced image stays in Ghost's media library.
- **Why deferred:** Ghost's Admin API has no image delete, so it means working
  on the server's content directory or by hand in Ghost, outside the API key's
  reach.
- **What to do:** periodically delete `content/images/**/<figure key>-N.png`
  files no page references, on the Ghost host.
- **Trigger:** the media library grows enough to matter.

### Run the publisher's tests in CI

- **What:** `python3 -m pytest tools/ghost-guide` (renderer, framing, pixel
  comparison) runs only on a desktop.
- **Why deferred:** the Test workflow installs only what `make test` needs; this
  adds markdown-it-py (the browser isn't needed for these tests).
- **What to do:** add a step to `.forgejo/workflows/test.yml` that installs
  `markdown-it-py` and `Pillow` and runs the tool's tests.
- **Trigger:** the tool's renderer starts changing often.

## Quick-crack (Kestrel-Unleashed on-device crack)

### Show the cracked count on the e-ink face

- **What:** the daemon already publishes a `crack` readout service (the worker's
  cracked/pending counts, last crack), alongside `agent`/`battery`/`position`,
  but the e-ink face (`builder/extra/files/plugins/eink.py`) does not yet render
  it. Loot is fully surfaced on the web `/loot` page (which serves the device's
  own screen in kiosk mode, a phone, and a desktop browser) and the CLI; the
  2.7" e-ink HAT is an optional, ship-disabled accessory.
- **Why deferred:** the 264×176 panel layout is tight and already full (icon
  strip, mascot, status/info/counter rows); adding a cracked counter needs a
  careful layout pass to avoid crowding, which isn't worth the risk for an
  accessory display when the web page already covers "on screen".
- **What to do:** add `"crack"` to the face's `__optional_requires__`, read
  `context.services.get("crack")` (or the shared `MoodInputs`), and show a
  compact `CRK <cracked>` on the counter row (next to `PWND`) or a milestone
  mood on a new crack — reusing `kestrel_pi.crack.readout.face_summary()`.
- **Pick up when:** the e-ink face layout is next revised, or an operator asks
  for the cracked count on the panel.

### aircrack-ng backend: no rules, uniform masks only

- **What:** the crack worker moved from hashcat to aircrack-ng (hashcat can't run
  on the Pi's pocl — see CHANGES). aircrack has no rule engine, so `[crack]
  rules` is a no-op; and only **uniform** masks (`?d?d…`, `?H?H…`) map to a
  `crunch` run — mixed-class or custom (`?1`) masks are skipped. `hashcat.py`
  remains a dormant, still-tested module (for a possible GPU host).
- **Why deferred:** aircrack covers the common cases (wordlists + the device-
  default masks, which are uniform), and the Pi can't run hashcat anyway. Rules
  and complex masks are a smaller slice of value.
- **What to do:** for rules, pre-expand a small list with a rule engine off-box
  or generate candidates and stream them into `aircrack-ng -w -`. For complex
  masks, extend `aircrack.mask_to_crunch` to emit `crunch -t <template>` with
  per-position charsets, or stream a generator. Consider John the Ripper jumbo
  (wordlists + masks + rules, native CPU) if rules become important — it needs a
  from-source build in the image.
- **Pick up when:** an operator needs rules, or a device-default attack needs a
  mask crunch can't express simply.

## WPS attacks (`kestrel wps` / reaver)

### Validate the attack end-to-end on hardware

- **What:** `kestrel_pi/wps.py` (reaver command building, `-vv` output parsing,
  loot write) and the `kestrel wps` CLI (monitor-mode switch, capture
  pause/restore, reaver/wash invocation) are implemented and unit-tested for the
  pure parts, but the full `scan` → `attack` → recovered-key-in-loot path has
  **not** been run against a real WPS AP on a Pi with the capture dongle.
- **Why deferred:** needs real hardware (a Pi, the AWUS036ACM, and a WPS AP the
  operator is authorized to test), which the build/CI environment doesn't have.
- **What to do:** on a device, `sudo kestrel wps scan`, confirm `wash` lists a
  known WPS AP, run `sudo kestrel wps attack <bssid>`, and confirm a Pixie-Dust
  hit lands on `/loot` tagged `via WPS (pin …)`. Check the capture service
  actually stops for the run and restarts after. Confirm the `reaver -vv` field
  labels this build prints still match `_PIN_RE`/`_PSK_RE`/`_SSID_RE` in
  `wps.py`, and tighten the regexes if the Kali/bookworm reaver differs.
- **Pick up when:** a Pi + dongle + an authorized WPS AP are on hand.

## Evil-portal (`kestrel evil-portal`)

### Validate the rogue AP end-to-end on hardware

- **What:** the portal server (`kestrel_pi/evilportal.py` — routing, probe
  table, templates, cred store) is unit-tested, but the AP plumbing in
  `evil-portal-launch` (hostapd + dnsmasq + the iptables `:80` redirect, the
  interface reconfigure, the capture pause/restore) has **not** been run on a Pi
  with the dongle in AP mode.
- **Why deferred:** needs real hardware (a Pi, an AP-mode-capable dongle, a
  client to join) the build/CI environment doesn't have.
- **What to do:** on a device, `sudo kestrel evil-portal start`, join the SSID
  from a phone, confirm the captive-portal sheet appears and a submission lands
  in `kestrel evil-portal creds`; `stop` and confirm capture resumes and the
  interface/iptables rule are cleaned up. Confirm `dnsmasq-base` + `hostapd`
  behave as invoked (conf keys, foreground flags) on the bookworm versions.
- **Pick up when:** a Pi + AP-capable dongle + a test client are on hand.

### Show captured submissions on the dashboard

- **What:** captured portal submissions are shown by `kestrel evil-portal creds`
  (CLI) only; there is no web view, unlike crack loot on `/loot`.
- **Why deferred:** submissions are plaintext credentials, so a web view must be
  strictly auth-gated (like the wpa-sec "Show" page, only rendered when
  `[web] auth` is on), which is more surface than the first cut warranted.
- **What to do:** add an auth-gated `on_webhook`-style page or a dashboard card
  that reads `evilportal.load_creds()` and renders it only when `[web] auth` is
  not `none`, reusing the loot page's escaping and responsive-table conventions.
- **Pick up when:** evil-portal is validated on hardware and an operator wants
  the captures on the phone/kiosk rather than the terminal.

