# Grok Ideas & Recommendations for Kestrel-Unleashed

**Author:** Grok (xAI)  
**Date:** 2026-11-12  
**Purpose:** Notes and opinions on the project as a whole, for Claude (and the operator) to review and discuss.  
**Scope:** Additive only. No other files in the repo were touched.

---

## Project understanding (as of this note)

Kestrel-Unleashed is a modified fork of aluminum-ice/Kestrel (GPL-3.0-or-later). It is a clean, reproducible 64-bit Raspberry Pi OS image (Packer + Ansible, bookworm) that turns a Pi 5 (primary) or Zero 2 W into a handheld, battery-powered Wi-Fi capture-and-learning device.

Core strengths already present:
- AngryOxide capture engine on a dedicated USB adapter (in-kernel nl80211/mac80211 only — no DKMS).
- Reinforcement-learning agent (stable-baselines3 / RecurrentPPO) that learns scan posture, with offline training, on-device fine-tuning, model import, and remote training.
- Mobile-first, dependency-free web dashboard + optional e-ink face + offline-capable wardriving map + GPS tagging.
- Plugin host that stays source-compatible with the pwnagotchi plugin API while adding modern safeguards.
- Unleashed-specific additions: capture + learning agent enabled by default for authorized lab use; on-device aircrack-ng quick-crack (wordlists + masks via crunch, thermal-gated); device-ID suggestions; WPS Pixie-Dust/reaver; evil-portal captive framework; on-device kiosk; GPU offload kit + remote-crack plugin; loot store with cleartext recovered keys.
- Consent-first design, secrets-free image, in-field app-layer updates, solid audience-split documentation.

It is deliberately positioned for authorized lab / owned-network use, with clear warnings and gating retained where transmission occurs.

---

## High-value recommendations to make it the best possible version of itself

### 1. Capture & attack surface (core loop)

- **Active deauth / association attacks** (optional, heavily gated). Upstream leans passive; many pwnagotchi users still want controlled client deauth or association to force handshakes/PMKIDs. Recommend adding as a plugin or `kestrel attack` subcommand that pauses passive capture, uses the same authorized-use ack, and has rate/thermal limits + a clear “lab only” UI warning.
- **Better PMKID handling end-to-end**. Surface PMKID-only networks more clearly in the dashboard/loot, auto-prioritize them for the GPU kit, and document the exact hashcat workflow.
- **Multi-adapter / multi-radio support**. Let the agent assign channels or roles across two USB adapters when present (one passive, one active, or dual-band split).
- **Client tracking & “interesting target” heuristics**. Tag clients that repeatedly connect, roam, or use weak crypto; feed that into the RL agent’s state so it prioritizes channels with high-value targets.
- **Probe-request harvesting + client fingerprinting**. Useful for lab mapping of devices that are not currently associated.

### 2. Cracking & loot (biggest current differentiator)

- **Smarter auto-crack orchestration**. Expand the existing device-aware suggestions with a small rules engine or lightweight model that ranks wordlist/mask order per network class (ISP router vs camera vs IoT). Add progress estimation and “estimated time remaining” on the Loot page.
- **Rule-based mutation on-device where possible**. aircrack-ng has no rules engine, so either pre-expand popular rulesets into wordlists at build/install time or ship a tiny hashcat-style rule applicator that feeds aircrack via stdin for the most common mutations.
- **Loot analytics dashboard**. Success rate by wordlist, by device class, by time-of-day, by location (when GPS is present). “These 3 lists cracked 80 % of your ISP routers.”
- **One-click “export everything for external tools”** (unify hc22000 + recovered keys + KML/GPX/WiGLE into a single archive with a README).
- **Optional local hashcat path on Pi 5** (or documented path for people who attach a Coral / Hailo / USB accelerator), even if it only helps with non-WPA work, plus better thermal/memory management notes.

### 3. Learning agent & intelligence

- **Multi-agent / multi-device coordination**. Let nearby Kestrels (or a “Merlin” desktop companion) share anonymized channel occupancy or model weights over Bluetooth PAN or a local mesh so they divide the spectrum instead of overlapping.
- **Online / continual learning improvements**. Better reward shaping (handshake quality, uniqueness, crackability score), curiosity-driven exploration, and safer on-device fine-tuning with catastrophic-forgetting guards.
- **Explainability**. Dashboard card that shows “why the agent chose this channel plan right now” (top features from the policy).
- **Pre-trained models for common environments** (dense urban, suburban, office, rural) that users can drop in.

### 4. Hardware & power / field usability

- **First-class UPS / battery support expansion**. More boards beyond Waveshare, accurate remaining-time estimates, graceful low-battery shutdown that finishes the current capture cycle, and a “field mode” that aggressively throttles the cracker and RL training.
- **Better thermal & power profiles**. Explicit “quiet / cool / performance / field” modes that the agent and cracker respect.
- **Official supported hardware matrix** with tested adapters, e-ink HATs, GPS modules, cases, and power banks (including current draw numbers).
- **Kiosk + e-ink polish**. More faces/moods driven by real state, touch gestures on the HDMI kiosk, and a pure-CLI “status” that is beautiful over SSH.

### 5. Software quality, safety & operations

- **Stronger isolation for attack features**. Keep WPS / evil-portal / future deauth in clearly separated, capability-declared plugins that cannot run unless the operator has explicitly acknowledged risk *and* the capture dongle is in the right mode.
- **Audit / logging mode**. Immutable, signed session logs of every action the device took (useful for authorized pentest reports).
- **Config & state backup/restore** that is one command and works offline (the existing backup plugin is a good base — make it dead-simple and include models + loot).
- **Fuzz / property-based testing** around the plugin host, crack worker, and AngryOxide integration (the places that touch radio or cleartext keys).
- **SBOM + reproducible builds** fully documented so downstream users and auditors can verify the image.

### 6. Ecosystem & UX

- **First-class “Merlin” integration** (the desktop cracking companion mentioned in the community). Let Kestrel push hashlines and pull results automatically when a Merlin instance is reachable, with zero manual kit steps.
- **Plugin marketplace / discovery** inside the dashboard (even if it is just a curated list of community plugins with capability declarations and risk labels).
- **Rich export formats for reports**: PDF/Markdown “session report” with map, cracked networks, device IDs, timeline.
- **Voice / Bluetooth audio status** (optional): short spoken summaries when a new handshake or crack lands — useful when the device is in a bag.
- **Official Docker / QEMU “lab simulator”** so people can try the full stack (including the agent and web UI) without hardware.

### 7. Positioning & documentation

- Keep the strong ethical framing (“authorized lab / own networks only”) front-and-center. Consider a short “threat model & responsible use” page.
- A one-page “vs pwnagotchi” comparison that highlights the modern base, real RL that works, on-device cracking, and the deliberate passive-first design.
- Hardware shopping list + “recommended build for $X” guides (Pi 5 + MT7612U + e-ink + UPS + case).

---

## Suggested priority order

1. Deauth / association as a gated plugin (biggest missing pwnagotchi capability for many users).
2. Smarter crack orchestration + loot analytics (you already own the cracking loop — make it best-in-class).
3. Multi-device coordination + better agent explainability.
4. Power/thermal field modes + expanded UPS support.
5. Merlin integration and polished export/report tooling.

---

## Closing opinion

You already have an excellent foundation: reproducible builds, a clean plugin system, real learning that works, on-device + GPU cracking, and a thoughtful Unleashed posture for lab use. Adding controlled active attacks, smarter cracking intelligence, multi-unit awareness, and first-class field power/ops tooling would make this the clear modern successor that serious authorized testers actually want to run every day.

Happy to expand any of these into architecture sketches, plugin interfaces, reward-design notes, or concrete implementation outlines in follow-up discussion.

— Grok
