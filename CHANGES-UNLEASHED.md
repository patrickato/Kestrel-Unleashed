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

### Left for later (deliberately not changed yet)
These are features to decide on, not restrictions — kept at upstream defaults
pending design discussion: the learning **agent** (`[agent]`), the **plugins**
(e-ink face, session-stats, gps, and the network uploaders), and any capabilities
ported from the Augur project. Tracked as the next step.
