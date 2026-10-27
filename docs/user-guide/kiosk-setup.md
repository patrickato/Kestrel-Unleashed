# On-device kiosk (HDMI touchscreen)

Show the Kestrel dashboard **full-screen on an attached HDMI touchscreen**, as a
live, touch-operable console — loot, capture, plugins, everything — the moment
the device boots. Kestrel-Unleashed only; local hardware (no radio, no network).

It runs the dashboard in **chromium** under **cage** (a minimal single-app
Wayland kiosk compositor). It ships **off**; turn it on with one command.

## Turn it on

```bash
sudo kestrel kiosk enable
```

That sets `[kiosk] enabled`, turns on `[web] trust_localhost` (so the local
screen can operate controls without a login — see "Security" below), and starts
the kiosk service. Point it somewhere other than the local dashboard with
`--url`:

```bash
sudo kestrel kiosk enable --url http://127.0.0.1:8080/loot
sudo kestrel kiosk status      # config, service state, missing-package warnings
sudo kestrel kiosk disable     # turn it off (and restore the stricter auth)
```

## Security — what `trust_localhost` does

The dashboard normally requires the device login (`[web] auth = system`). A
kiosk browser can't log in, so enabling the kiosk sets `[web] trust_localhost`:
requests that arrive over **loopback** (`127.0.0.1`) are trusted without a
credential. A management-link client (BT-PAN, Wi-Fi) always presents its own
address, never loopback, so this **never** opens the dashboard to the network —
it only trusts something already physically on the device. `kiosk disable`
turns it back off.

## Rotation

If the screen is mounted sideways, rotate it the standard Raspberry Pi way in
`/boot/firmware/config.txt` (not in Kestrel config):

```
# 0=normal, 1=90, 2=180, 3=270
display_hdmi_rotate=2
```

Reboot after changing it. (Touch coordinates follow the display rotation.)

## If the screen stays blank

The kiosk needs a GPU/DRM seat, which depends on your exact board and screen —
it may need a nudge on first run:

1. Check the service: `systemctl status kestrel-kiosk` and
   `journalctl -u kestrel-kiosk -n 40 --no-pager`.
2. Confirm the packages are present: `kestrel kiosk status` warns if `cage` or
   `chromium` is missing.
3. Seat access: cage gets its seat from **seatd**. Make sure it's running
   (`systemctl status seatd`) and that the `pi` user can reach it. The build adds
   `pi` to `video`, `render` and `input`; if the journal shows a seat/`libseat`
   error, add `pi` to seatd's socket group too (check it with
   `ls -l /run/seatd.sock`, then `sudo usermod -aG <that-group> pi` and reboot).
4. HDMI not detected at boot: add `hdmi_force_hotplug=1` to
   `/boot/firmware/config.txt` and reboot with the screen connected.

The kiosk is opt-in and off by default, so none of this affects a normal boot —
turn it on, validate it on your screen, and tweak from the journal if needed.
