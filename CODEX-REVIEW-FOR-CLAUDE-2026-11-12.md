# Kestrel-Unleashed: independent review and discussion note for Claude

Date: 2026-11-12
Author: ChatGPT / Codex, at the repository owner's request
Review baseline: `adfae318252c0382d598cf257eab35b28b509c69`

## Purpose and limits

The owner requested a special, separate note for Claude to read and discuss with them. This is a set of review findings and proposals, NOT an instruction to implement changes. Discuss priorities with the owner before treating any proposal as an accepted roadmap.

The authorized repository change for this request is creation of this note only. No existing file, configuration, workflow, or implementation was modified. The repository advanced after the review baseline; recheck current code before treating an observation as a current defect.

This was a source review of repository structure, documentation, configuration, and selected implementation files. No image was built, tests executed, or hardware exercised. A missing feature below means a proposed extension not established in the reviewed material, not proof that no partial implementation exists.

## Product direction

Preserve the project's wireless attack/capture/offline-analysis identity. Develop it into a coherent portable wireless assessment appliance with dependable operation, understandable results, and a strong operator experience.

Already represented in the repository: AngryOxide capture; local analysis with aircrack and a John backend; manual GPU kits and automatic remote-crack; WPS and portal workflows; device identification; GPS/map exports; mobile dashboard; HDMI kiosk and e-ink; battery support; plugins; learning-agent/remote training; backup; update rollback/recovery. Do not propose these as entirely new capabilities.

Preserve the service boundaries, unprivileged dashboard, narrow privileged helper, and versioned interfaces.

## Concrete findings to recheck

1. **Fork release identity.** At the baseline, `builder/extra/files/config.toml` configured updates for `aluminum-ice/kestrel` at `https://git.3ntropy.io`. Give this fork an explicit, verified update identity so an operator does not inadvertently replace fork behavior with upstream behavior.
2. **Actual CI and release execution.** Workflows exist under `.forgejo/workflows`. The GitHub Actions and Releases endpoints returned no runs/releases during the review. This does not rule out external Forgejo CI; identify the authoritative build host and expose its evidence.
3. **Documentation drift.** README text says the learning agent is enabled by default; the reviewed config has `[agent] enabled = false`. The testing guide says CI only lints while a Forgejo pytest workflow exists. Architecture documentation retains upstream capture-off descriptions. Generate defaults/capability references from authoritative sources.
4. **Sensitive storage.** `kestrel_pi/crack/store.py` stores plaintext recovered values and calls `_write_json_atomic(..., world_readable=True)`, setting file mode 0644. Parent-directory permissions still determine effective access. Separate sensitive values from general status, use restrictive permissions, and make reveal/export deliberate.
5. **Plugin isolation limits.** `dispatch.py` quarantines a stuck plugin but cannot terminate its running thread. Multiple stuck plugins can consume the shared worker pool. Queues also need bounds/coalescing. Consider process isolation where enforceable cancellation is required.
6. **Implemented versus shipped versus verified.** The deferred list distinguishes the existing John integration from its outstanding image-binary packaging. It also lists hardware verification gaps for WPS and portal orchestration. Present these distinctions explicitly and recheck against newer commits.
7. **Existing deferred work.** Release signatures, dropped systemd-unit cleanup, and per-AP output defaults are already documented proposals. Complete or reconcile those entries instead of inventing competing roadmaps.

Relevant sources:
- `builder/extra/files/config.toml`
- `.forgejo/workflows/test.yml`
- `builder/extra/files/kestrel_pi/kestrel_pi/dispatch.py`
- `builder/extra/files/kestrel_pi/kestrel_pi/crack/store.py`
- `builder/extra/files/update-apply.py`
- `docs/developer/deferred.md`
- `docs/developer/hardware-validation.md`
- `docs/developer/architecture.md`

## Core product recommendations

### 1. Unified network detail

One page joins BSSID identity, SSID, vendor estimates with confidence, first/last seen, channel and signal history, advertised security, artifacts, validation, local/remote analysis status, location observations, notes, and sessions. Group related APs without collapsing unrelated devices that share an SSID.

### 2. Passive inventory independent of handshake collection

Maintain observed AP records even when no handshake is collected. Record advertised WPA2/WPA3/PMF capabilities, channels, signal trends, and changes between visits. Distinguish advertised, observed, inferred, and verified facts. Existing geo code principally joins capture-related sidecars and records; a general observation store would broaden survey usefulness.

### 3. Device health and recovery

Show driver/interface detection, ownership, last fresh observation, dropped-data indicators where available, free storage, undervoltage, throttling, GPS freshness, service restarts, and remote-host availability. Offer targeted recovery and a redacted support bundle. Service-active is not proof of useful output.

### 4. Sessions and reporting

Named sessions hold configuration snapshots, observations, artifacts, notes, and health events. Compare visits: newly observed or missing devices, changed settings, coverage differences, and unresolved findings. Export human-readable HTML/PDF and machine-readable JSON/CSV. Ordinary reports omit recovered secrets.

### 5. Capability-aware controls

Show available, requires setup, unavailable, or unverified based on installed binaries, versions, adapter capabilities, and hardware. Unsupported backend features should have specific reasons, rather than apparently functional controls that silently do nothing.

### 6. Hardware profiles and resource coordination

Define tested Pi 4/Pi 5/Zero 2 W profiles and headless/HDMI/small-display layouts. Coordinate CPU-heavy work, training, backup, temperature, memory, storage and battery usage. Treat SPI TFT support separately from HDMI kiosk support; do not assume the user's earlier 480x320 TFT is this project's current display.

### 7. Better offline maps

Offer local basemaps, session filters, signal observations, repeat-survey comparisons, accuracy indicators, and stale-fix warnings. A point is the receiver's observation location, not a proven physical AP location.

### 8. Durable catalog and event history

Consider a transactional SQLite index for sessions, observations, jobs, artifacts, and health events while retaining raw files. Add checksums, timestamps, source/engine versions, parser versions, and validation outcomes. Recover cleanly from power loss; distinguish completed, interrupted, and resumable work.

### 9. Release and recovery engineering

Extend existing rollback/recovery with signed releases, fork identity checks, configuration migrations, and fault-injection tests: full disk, lost power, unplugged adapter, bad state, unavailable remote host, and interrupted update.

### 10. Explainable agent evaluation

Build on existing baseline/interleaved comparisons. Show active policy, fallback reasons, observation freshness, sample size, uncertainty, and resource cost. Do not claim improvement from a short sample in changing RF conditions.

## Additional directions for its red-team role

These are capability proposals at product level, for controlled assessments and offline evidence analysis; they are not attack execution instructions.

| Proposed capability | What it would add | Important distinction |
| --- | --- | --- |
| Wi-Fi security posture analysis | Summarize advertised cipher/authentication modes, PMF, WPS exposure, open networks, and changes from a baseline. | Advertising a setting or matching a fingerprint does not prove exploitability. |
| Offline packet-analysis workspace | Import PCAP/PCAPNG, inspect protocol summaries and authentication timelines, attach notes, and retain artifact provenance. | Imported data should not require touching a radio. |
| Capture quality inspector | Explain malformed/incomplete artifacts, parsing errors, duplicates, missing prerequisites, and which installed analyzers can consume a file. | Separate file presence, structural validity, and successful analysis. |
| Enterprise Wi-Fi assessment records | Inventory advertised enterprise authentication, summarize observable EAP negotiation from supplied captures, and document managed-client certificate-validation test results. | Certificate trust policy cannot generally be inferred from beacons or ordinary passive observation. |
| Rogue AP / impersonation detection | Compare an organization's AP baseline for unexpected security changes and suspicious SSID/BSSID combinations. | Mesh, roaming, replacement hardware, and legitimate multi-AP deployments require contextual handling. |
| Owned-LAN inventory and segmentation checks | An optional wired/management-side module for host/service inventory and expected-versus-observed reachability across lab segments. | Explicit operator-selected networks; keep management access stable. |
| BLE device inventory | Optional advertisement inventory, service metadata where appropriate, and repeat-session comparison. | Randomized addresses limit durable identity; document Bluetooth PAN coexistence/resource constraints. |
| Controlled lab scenario runner | Reproducible scenarios with setup requirements, expected evidence, cleanup checks, and pass/fail records. | Improve validation and repeatability, not automatic exploitation of arbitrary nearby devices. |
| Assessment evidence export | An export bundle with artifact hashes, timestamps, tool versions, notes, finding confidence, and remediation guidance. | Do not include passwords in ordinary bundles by default. |
| Radio capability and ownership manager | Inventory radios, show which component owns each, detect conflicting requests, and recover state after a task exits. | Establish reliable ownership first; adding adapters alone does not guarantee compatible simultaneous operation. |
| Offline reference and annotation library | Local protocol explanations, finding templates, troubleshooting, and versioned vendor/security references. | Hardware guesses or version matches are leads, not verified vulnerabilities. |
| Finding validation and retest | Track a finding through evidence, operator confirmation, remediation, and a later comparison. | Keep inferred observations separate from verified test outcomes. |

## Scope discipline

Avoid making the core image a blanket installation of unrelated tools. Package optional capability groups with clear dependencies, expected resource use, uninstall behavior, and end-to-end verification. A tool being installed is not the same as it being integrated.

Do not prioritize broad automatic exploit chaining, credential impersonation templates, or stealth/persistence tooling as the project's next expansion. The immediate value lies in reliable wireless assessment, deeper interpretation of collected evidence, controlled lab verification, and clear results.

## Suggested order for discussion

1. Release identity, real CI evidence, documentation accuracy, sensitive storage, plugin resilience, and outstanding hardware validation.
2. Unified network detail, capability inventory, health page, and durable session/catalog model.
3. Passive posture analysis, offline packet workspace, capture-quality explanations, and report exports.
4. Hardware/display profiles, offline mapping, optional wired/BLE modules, and improved agent evaluation.

Suggested first product feature: unified network detail backed by a session-aware data model. Suggested first engineering tasks: verify fork update identity and reconcile implemented/shipped/hardware-verified status.

## Questions for Claude and the owner

- Which proposals already exist in commits after the review baseline?
- Which features have repeatable hardware evidence, and on which exact image/board/adapter?
- Is the priority a personal field appliance, a reproducible lab instrument, or a distributable product?
- Which two new workflows would be used weekly?
- Which features belong in the core versus optional packages?
- What concrete evidence would count as each workflow being complete?

Please discuss these choices with the owner. This note itself authorizes no implementation changes.

## Follow-up: capability priorities from the owner discussion

The owner requested that the subsequent recommendations also be retained here. The table above already covers these ideas; this addendum records the explicit priority order and integration expectations from that follow-up. These remain discussion proposals.

### Highest-priority additions for the existing workflows

1. **Capture quality inspector:** explain what each artifact contains, structural validity, missing prerequisites, and compatibility with installed analysis tools. Make it immediately clear whether collected material is useful and why.
2. **Offline packet-analysis workspace:** import captures, inspect authentication timelines and protocol summaries, search observations, and annotate evidence from the dashboard without requiring a live radio.
3. **Radio ownership manager:** show which component owns each adapter, prevent conflicting operations, and restore interface state after completion or failure.

These priorities specifically strengthen the existing capture/analysis/operator workflow. They complement the earlier recommendation for unified network detail and a session-aware data model.

### Next expansion in assessment coverage

- **Enterprise Wi-Fi assessment:** go beyond home-network PSKs with enterprise authentication inventory, observable EAP interpretation, and records of controlled client certificate-validation tests.
- **Optional wired-network assessment:** host/service inventory and expected-versus-observed segmentation checks on operator-selected lab networks.

### Other ideas to keep in the discussion

- Wi-Fi security posture summaries for encryption, WPA2/WPA3, PMF, WPS exposure, and changes between visits.
- Rogue AP and impersonation detection against a known baseline, accounting for legitimate mesh and roaming behavior.
- BLE advertisement inventory and change tracking, with randomized-address and management-link coexistence limitations.
- Repeatable lab scenarios with prerequisites, expected evidence, cleanup checks, and recorded results.
- Findings and retest tracking: observations, evidence, confirmation, remediation, and comparison at a later assessment.

### What an integrated optional module should provide

Each module should have dashboard controls, dependency and hardware checks, shared evidence storage, clear running/completed/failed status, and verified cleanup. Record its resource requirements and supported image/hardware combinations. Installing a command-line tool alone does not complete the feature.

The goal is to make each addition a complete usable workflow while keeping optional capabilities separately installable and maintainable. No implementation has been authorized by this note or addendum.
