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

### Unleashed (operator's own isolated lab; authorized use only)
The upstream image ships capture and every network-touching feature **disabled**,
behind an interactive authorized-use acknowledgment. This fork assumes the
operator is running it against their **own networks in an isolated lab**, so it
flips the out-of-box defaults to "ready to run" — the safety *mechanisms* are
unchanged and still resettable, only the shipped defaults differ.

- `builder/extra/files/config.toml`:
  - `[capture] enabled = true` — capture runs on first boot (was `false`).
  - `[agent] enabled = true` — the reinforcement-learning capture agent is on
    (was `false`); it still only runs while capture is enabled, and the scripted
    sweep remains the fallback.
  - `[plugins.session-stats] enabled = true` and `[plugins.eink] enabled = true`
    — the local-only status/face plugins ship on (both are local-only, need no
    acknowledgment, and the e-ink plugin degrades cleanly with no HAT attached).
  - Network-touching plugins (`wpa-sec`, `wigle`, `backup`, `updates`,
    `remote-train`) remain **disabled** — they require the operator's own
    credentials/endpoints and are meaningless without them.
- Build (`builder/config.yml`): the authorized-use acknowledgment file
  (`/etc/kestrel/capture-ack`) is **pre-seeded** at image build, so capture does
  not stop to ask on first run. The acknowledgment mechanism itself is unchanged
  — `kestrel capture reset-ack` still clears it, and `kestrel capture enable`
  still records it — only the lab build ships it already satisfied.

The authorized-use warnings in the UI and docs are retained. The default `pi` /
`raspberry` login and the secrets-free policy are unchanged; supply a real
password and any real network details at build time, never in a commit.
