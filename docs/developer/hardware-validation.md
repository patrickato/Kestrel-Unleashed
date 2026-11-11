# Hardware validation runbook (the Pi pass)

The unit tests prove the pure logic with no radio; this runbook proves the parts
that only a real Pi, a real dongle, and real RF can exercise. Work through it on
a flashed device, driving from a laptop over SSH. Each check lists the exact
commands and a single **PASS** line.

**Authorized use only.** Run every attack against networks you own or are
explicitly authorized to test. The device fires only where you point it.

## Before you start

- Flash the latest image and put the Pi on your network.
- From the laptop: `ssh pi@kestrel.local` (or `ssh pi@<pi-ip>`). All commands
  below are run in that SSH session unless marked *(on the GPU box)*.
- Capture dongle attached (e.g. an AWUS036ACM in monitor mode).
- Find the dashboard address once — you'll open it in a laptop browser for the
  map check:

  ```
  kestrel web status
  ```

- Per-check extras: a GPS dongle (V1), a WPS AP you own (V3), a phone (V4), the
  TUF with hashcat (V5/V6), an arm64 builder (V7).

---

## V1 — GPS, wardriving map, and exports

```
sudo kestrel plugins enable gps
sudo kestrel plugins enable map
kestrel plugins info gps
```

Take the Pi outdoors or to a window for a fix, then move at least ~10 metres to
lay a track. In a laptop browser open the dashboard (the address from
`kestrel web status`), and open the **Map** page (the GPS/Map card links to it,
or go to **Plugins → Map**).

- Confirm the **GPS card** shows a fix (satellites / "locked"); `kestrel plugins
  info gps` should report it healthy.
- On the **Map** page confirm: captured networks drop **pins**, your **route**
  line draws, and the **live cursor** tracks your position.
- Click **KML**, **GPX**, and **CSV** on the Map page. Open one — e.g. import the
  `.kml` into Google Earth, or open the `.csv` (it's WiGLE format).

**PASS:** a fix is shown, pins + route + cursor render, and all three exports
download and open.

---

## V2 — On-device crack landing

Two engines crack on the Pi. Validate whichever is installed (`kestrel crack
status` prints `engine: john` or `engine: aircrack`).

```
kestrel crack status
kestrel crack wordlists
```

Make sure a wordlist that contains a known test password is present (drop one in
with `scp` to `/var/lib/kestrel/wordlists/`, or stage on the boot partition).
Then queue a capture file you hold the handshake for, and watch it live:

```
kestrel crack run /var/lib/kestrel/capture/<yourfile>.hc22000 --wordlist rockyou.txt
kestrel crack watch
```

- **aircrack path** (live capture): confirm a handshake currently in the rolling
  capture cracks and the key lands.
- **John path** (if `engine: john`): confirm a **stored** `.hc22000` network
  cracks with no packet capture present — including a **PMKID-only** network
  (aircrack can't do those). See V7 to get John installed first.
- `kestrel crack watch` should show the running wordlist, a progress bar, keys/s
  and the current passphrase; `kestrel crack list` shows the recovered key.

**PASS:** a known-password network moves to `cracked` on `kestrel crack list`
and on the dashboard **Loot** page, and `crack watch` showed live progress.

---

## V3 — WPS / Pixie-Dust

```
sudo kestrel wps scan --seconds 30
```

Confirm `wash` lists a WPS AP you own. Then attack it (capture pauses for the
run and resumes after):

```
sudo kestrel wps attack <BSSID> --yes
kestrel wps list
```

- Pixie-Dust (the default) should recover the PIN/PSK in seconds-to-minutes on a
  vulnerable router; `--no-pixie` is the slow online brute-force fallback.
- Confirm capture stopped during the run and restarted after:
  `kestrel capture status`.

**PASS:** a recovered key appears in `kestrel wps list` and on **Loot** tagged
`via WPS`, and capture resumed afterwards.

---

## V4 — Evil-portal (captive-portal rogue AP)

Needs an AP-mode-capable dongle and a phone to join.

```
sudo kestrel evil-portal start --yes
```

From a phone, join the SSID it broadcasts; confirm the captive-portal sheet
appears. Submit the test form, then:

```
kestrel evil-portal creds
sudo kestrel evil-portal stop
kestrel capture status
```

**PASS:** the submission shows in `kestrel evil-portal creds`; after `stop`,
capture resumes and the AP interface + iptables redirect are cleaned up.

---

## V5 — GPU offload (manual kit)

On the Pi, build a kit of everything still uncracked:

```
kestrel crack kit
```

Copy the printed `.zip` to the TUF, unzip it. *(on the GPU box, in that folder):*

```
.\hashcat -m 22000 -a 0 targets.hc22000 rockyou.txt -r rules\best64.rule -w 4 -d 1 --potfile-path kestrel.potfile
```

`-w 4` runs the card flat out; `-d 1` pins it to the RTX 4070 (skip the weak iGPU).
`-O` is a no-op for mode 22000 (no optimized kernel), so it's omitted. rockyou ×
best64 × N salts can run for **hours to days** — that's expected; it's resumable
(`q` to stop, `--restore` to resume; the potfile keeps every crack). Pull results
(live, any time):

```
.\hashcat -m 22000 targets.hc22000 --show --session show --outfile recovered.txt --potfile-path kestrel.potfile
```

Copy `recovered.txt` back to the Pi (use `--outfile`, never `>` — PowerShell's
`>` writes UTF-16 and the ingest can't read it), then:

```
kestrel crack ingest recovered.txt
kestrel crack list
```

**PASS:** recovered keys from the GPU land in `kestrel crack list` / **Loot** and,
for located networks, fill in on the map.

---

## V6 — GPU offload (remote-crack, automatic over SSH)

```
sudo kestrel plugins enable remote-crack --yes --set crack_host=<gpu-host> --set crack_user=<user> --set crack_path=/remote/dir --set wordlist=/path/on/host/rockyou.txt
sudo kestrel remote-crack setup
kestrel remote-crack status
kestrel remote-crack now
```

`setup` installs the device key on the GPU host (asks its password once; stores
no secret). `now` offloads every uncracked network; watch progress:

```
kestrel remote-crack status
```

**PASS:** `remote-crack status` shows the host cracking, and recovered keys flow
back into **Loot** on the next worker pass without touching the Pi by hand.

---

## V7 — Install John the Ripper (jumbo) on the image — the reflash step

The John engine code ships, but Debian's stock `john` is the crippled **core**
build (no WPA). Install a **jumbo** build for arm64 so `engine: john` lights up.
Build it on the Pi (proven on a Pi 5, aarch64 — ~3 min):

```
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
cd /tmp
rm -rf john
git clone --depth 1 https://github.com/openwall/john.git
cd john/src
./configure
make -sj$(nproc)
../run/john --test=0 --format=wpapsk
```

That last line must say `PASS`. Install the whole `run/` tree to a stable
location, then put the three tools on `PATH` — **`john` via a wrapper, not a
symlink** (John finds its `john.conf` relative to how it's invoked; a bare
symlink makes it look in `/usr/local/bin` and fail with "Cannot find John home",
so the wrapper calls the real binary by full path):

```
sudo mkdir -p /opt/kestrel
sudo cp -a /tmp/john/run /opt/kestrel/john
sudo tee /usr/local/bin/john >/dev/null <<'EOF'
#!/bin/sh
exec /opt/kestrel/john/john "$@"
EOF
sudo chmod +x /usr/local/bin/john
sudo ln -sf /opt/kestrel/john/hccapx2john.py /usr/local/bin/hccapx2john.py
sudo ln -sf /opt/kestrel/john/wpapcap2john /usr/local/bin/wpapcap2john
```

Verify and switch the engine on. The crack worker must restart to detect John
and load the engine code (the in-place updater does this for you from the release
that adds the restart; a hand build needs it once):

```
john --test=0 --format=wpapsk
sudo systemctl restart kestrel-crack.service
kestrel crack status
```

Confirm it now reports `engine: john (active)` and `no-handshake` drops toward 0
as John reads the hashline store. Then watch it work: `kestrel crack watch`.
Validate end to end with V2 — a **stored** PMKID network and a **stored** EAPOL
network both cracking on the CPU with no capture present. (Prefer baking the
built binary into the image build; see `docs/developer/deferred.md`. This is
reflash-class, and John grinds hard on four cores — the thermal governor pauses
it at `max_temp_c` and resumes.)

**PASS:** `kestrel crack status` shows `engine: john`, and a stored PMKID and a
stored EAPOL network each crack on-device under V2.
