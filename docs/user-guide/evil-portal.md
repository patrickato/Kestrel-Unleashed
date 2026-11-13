# Evil-portal (captive-portal rogue AP)

> **Lab / authorized use only.** This stands up an **open Wi-Fi network** and a
> page that **captures whatever people type into it**. Run it only against an
> environment you own or are explicitly authorized to assess (your Faraday lab,
> a contracted engagement). `kestrel evil-portal start` asks for the
> authorized-use acknowledgment before it transmits.
>
> **Do not impersonate.** Serve pages that are honestly your own (a generic
> guest-Wi-Fi or lab login). Do **not** build a page that imitates a real
> company, service, or its sign-in — no copied logos, brand names, or look-alike
> login screens.

## What it does

Evil-portal is a generic **captive-portal framework**, not a kit of fake brand
pages. When you start it, the device:

1. broadcasts an **open SSID** (default `Guest WiFi`) on the capture dongle,
2. hands clients a DHCP lease and answers **all DNS** to itself, so every name a
   client looks up resolves to the device,
3. redirects their web traffic to a **portal page** — the one you supply, or a
   neutral built-in — and **logs every field** that gets submitted.

That is enough to demonstrate, in an authorized test, that users will join an
open network and hand credentials to its sign-in page.

## The radio

It uses the **capture dongle** (e.g. the Alfa AWUS036ACM — it must support AP
mode) in access-point mode, not the Pi's built-in Wi-Fi. Starting it **pauses
capture**; stopping it resumes capture. One radio, one job at a time. It is
**start-on-demand only** — it never comes up on its own at boot.

## From the dashboard

With the dashboard login on (`[web] auth`), the **Evil-portal** card opens a page
that shows whether the portal is running and its SSID/channel, has **Start
portal** / **Stop portal** buttons (Start asks the acknowledgment), and lists the
captured submissions right on the page. Because those submissions are plaintext,
the page shows them **only while the dashboard login is on** (like the wpa-sec
"Show" view); with the login off the page is read-only and the submissions are
hidden. The terminal below is the same-strength equivalent.

## Use it

```bash
# Start the portal (asks the authorized-use ack, pauses capture):
sudo kestrel evil-portal start

# See what clients have submitted:
kestrel evil-portal creds
#   2026-10-27 14:05:11  10.0.0.23        password=hunter2 username=alice

# Status (service state, SSID, how many submissions so far):
kestrel evil-portal status

# Stop it and resume capture:
sudo kestrel evil-portal stop
```

## The portal page (templates)

The shipped default is a **neutral** "Guest Wi-Fi" sign-in. To use your own,
copy the templates to `/etc/kestrel/evil-portal/templates/` (that path overrides
the shipped defaults and survives updates) and edit them there:

```bash
sudo mkdir -p /etc/kestrel/evil-portal/templates
sudo cp /usr/local/share/kestrel/evil-portal/templates/* /etc/kestrel/evil-portal/templates/
sudo nano /etc/kestrel/evil-portal/templates/index.html
```

- `index.html` — the portal. Keep the form's `action="/login"`; every field
  `name` you include is captured.
- `done.html` — shown after a submission.

Keep them honestly your own — see the impersonation rule at the top.

## Config

`[evil-portal]` in `/etc/kestrel/config.toml` (the CLI flips `enabled`; the rest
are defaults):

```toml
[evil-portal]
enabled    = false        # the launcher's gate; `start`/`stop` set it
ssid       = "Guest WiFi" # a generic name, not a real network's
channel    = 1
portal_ip  = "10.0.0.1"
dhcp_start = "10.0.0.10"
dhcp_end   = "10.0.0.250"
```

## Release impact

**Reflash-class.** Adds the `hostapd`, `dnsmasq-base` and `iptables` apt
packages, which the in-field app-layer update engine does not install — it ships
on a freshly flashed image, not an in-place update.

## How the captive portal is supposed to work

A captive portal does **not** pop before connecting. The phone joins the open
network and gets an IP first (that's "connecting"); *then* it runs a background
internet check (e.g. `connectivitycheck.gstatic.com/generate_204`). The portal
answers that probe with a **302 redirect** to the sign-in page, which is what
makes the phone show **"Sign in to Wi-Fi network."** So the "Connected without
internet" status is the normal trigger point, not a failure.

The portal serves each request on a fresh connection (`Connection: close`) and
302-redirects every OS probe to the login page — the two things modern phones
need. It logs every request: `journalctl -u kestrel-evil-portal.service -f`.

## Troubleshooting: the sign-in window doesn't appear

1. **Watch the portal log** while you join from the phone. Lines like
   `GET /generate_204 ... -> 302 (captive probe)` mean the probe reached the
   portal and was redirected — the sign-in should appear.
2. **If you see nothing in the log**, the probe isn't reaching the portal —
   almost always **Private DNS** on the phone (modern Android/Samsung defaults
   it to DoT, which bypasses the portal's DNS). Turn it off: **Settings →
   Connections → More connection settings → Private DNS → Off**, then rejoin.
3. **Manual fallback that always works:** open the phone browser to any plain
   `http://` address — it redirects to the Guest WiFi form. Submit it; the
   capture shows in `kestrel evil-portal creds`.
4. **Prove the server + redirect on the Pi itself** while the portal runs:
   ```
   curl -si http://127.0.0.1:8880/generate_204 | head -1
   curl -si http://10.0.0.1/generate_204 | head -1
   ```
   Both should print `HTTP/1.0 302 Found`. The first failing means the portal
   didn't bind; the second failing (when the first works) means the
   `:80 → :8880` iptables REDIRECT isn't in place.
