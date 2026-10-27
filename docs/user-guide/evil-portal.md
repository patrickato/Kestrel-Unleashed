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

## Not yet validated on hardware

The AP/DHCP/DNS/redirect orchestration (`evil-portal-launch`) is implemented and
the portal server's routing, templates and capture store are unit-tested, but
the full path has **not** been run end-to-end on a Pi with the dongle in AP
mode. See `docs/developer/deferred.md`.
