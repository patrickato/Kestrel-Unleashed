# Wordlist recommendations (for the on-device quick-crack)

Which wordlists to use, in what order, on **this** hardware — a Raspberry Pi
cracking WPA2 on its **CPU** (no usable cracking GPU). See the README "Wordlists"
section for *how* to add them; this file is about *which* and *why*.

## The one fact that drives everything

WPA2 is deliberately slow to crack (PBKDF2, 4096 iterations), and the Pi has no
GPU hashcat can use, so it does roughly **1,000–2,000 guesses/second** — versus
hundreds of thousands to millions on a desktop GPU. WPA is also **salted by the
SSID**, so each distinct network is its own job. Consequences:

- A big list is an *overnight* job, not a "quick" one. `rockyou` (~9.6M usable
  entries) is ~1.5–3 hours **per network** at this speed.
- **Smallest-first wins.** Quick, targeted lists catch the easy keys in minutes;
  the big list is the last resort that grinds in the background. Kestrel does this
  automatically (`[crack] order = "size"`), so you just drop lists in.
- **Rules are for small lists here.** A ruleset multiplies the candidate count,
  which is cheap on a GPU and brutal on a CPU — so pair rules with a *small* base
  list, never with `rockyou`.

Two curated lists ship on the device already (`starter.txt`, `wpa-top.txt`), so
cracking works out of the box; the lists below are what you add for real
coverage.

## Combinations at a glance (speed vs. odds)

The same table is on the device, on the web **Loot** page ("Which wordlist +
rule should I use?"). Times are **per network** (each SSID is its own salted
job) at a Pi 5 CPU's ~1,500 guesses/sec; "odds" is a rough relative guide, not a
guarantee (real WPA success depends on the target). ★ = recommended.

| Combination | ~Guesses/net | Est. time/net | Odds | Best for |
| --- | --- | --- | --- | --- |
| `starter.txt` + `wpa-top.txt` *(shipped)* | ~500 | instant | Low | the automatic first pass |
| ★ `probable-v2-wpa-top4800` | ~4.8k | ~3 sec | Low–Med | best tiny WPA list — drop it in |
| `top-100000` | ~100k | ~1 min | Med | broad quick sweep |
| ★ `probable-v2-wpa-top4800` + `best64.rule` | ~0.3M | ~3–4 min | Med | quick deep pass — the sweet spot |
| `top-100000` + `best64.rule` | ~6.4M | ~1–1.5 hr | Med–High | thorough daytime run |
| ★ `rockyou.txt` (8+ filtered) | ~9.6M | ~1.5–3 hr | Med–High | the overnight workhorse |
| `top-1000000` + `best64.rule` | ~64M | ~8–16 hr | High | deep overnight dig |
| `rockyou` + `best64`, or any + `rockyou-30000` | 100M–billions | days+ | High\* | \*GPU/desktop only — too slow on the Pi |

**Recommended ladder:** auto-run the small lists → add `probable-v2-wpa-top4800`
and filtered `rockyou.txt` → deep-pass stragglers with
`probable-v2-wpa-top4800 + best64.rule` → let `rockyou` grind overnight.

## Tier 1 — quick passes (seconds to minutes). Run these first; they're small.

| List | Size | Why |
| --- | --- | --- |
| `starter.txt` *(shipped)* | ~190 | Lazy defaults, instant. |
| `wpa-top.txt` *(shipped)* | ~300 | WPA-focused: numeric/date/phone patterns, ISP and router defaults. |
| SecLists **`WiFi-WPA/probable-v2-wpa-top4800.txt`** | ~4,800 | The single best tiny WPA list — real captured WPA keys, superb hit rate per second. |
| SecLists **`Common-Credentials/10-million-password-list-top-100000.txt`** | 100k | Broad top-100k; a few minutes on the Pi. |

## Tier 2 — the workhorses (tens of minutes to a few hours).

| List | Size | Why |
| --- | --- | --- |
| **Probable-Wordlists – `WPA-probable`** (Berzerk0) | ~1–40M (several cuts) | Built from real breaches, **WPA-length filtered** (≥8 chars), so nothing is wasted on keys WPA can't have. Start with a smaller cut. |
| **`rockyou.txt` (8+ filtered)** | ~9.6M / ~115 MB | The classic. Use the WPA-ready variant (drop sub-8-char lines) so you aren't feeding hashcat candidates it discards. The standard mid-tier. |
| SecLists **`Common-Credentials/10-million-password-list-top-1000000.txt`** | 1M | A fast, high-value million; excellent base for a rules pass (below). |

## Tier 3 — the overnight run

**Short answer to "rockyou or something bigger overnight?": on a Pi, `rockyou`
(8+ filtered) is about the right size for one overnight run — going *bigger* is
not prudent.** The multi-gigabyte lists everyone names (`weakpass_4` ~26 GB,
`hashesorg2019` ~12.8 GB, `kaonashi` ~5 GB) would take **days to weeks per
network** at CPU speed and may not even fit the SD card. Raw size is the wrong
lever on this hardware.

The better overnight value is **rules on a small base list**, because a good rule
set reaches far more real passwords per candidate than a giant raw list:

- **`rockyou.txt` straight through** — the simple overnight default.
- **or** the top-1M list **+ `best64.rule`** — 1M × 64 ≈ 64M candidates,
  comparable runtime to rockyou but it catches *mangled* variants (`Summer2024!`,
  `p@ssw0rd`) rockyou-straight misses.

For a genuinely thorough hunt, the honest answer is to **offload to a desktop**:
on a GPU, `rockyou` + **OneRuleToRuleThemAll** (≈52k rules) cracks ~68% of a
typical breach vs ~33% for best64 and ~66% for dive — but that's 745 **billion**
candidates, which is a GPU job, not a Pi one. (Kestrel stays CPU-only on purpose;
copy the `.hc22000` off the device for a GPU run if you want that.)

## Small base lists for rule attacks (keep these ≤ ~100k on a Pi)

Rules shine on small, high-quality bases. Good pairings:

- `starter.txt` / `wpa-top.txt` *(shipped)* — instant with `best64.rule`.
- SecLists **`probable-v2-wpa-top4800.txt`** — the best tiny WPA base.
- SecLists **`top-10000`** and **`top-100000`** — broad coverage, still fast.
- A **names + years** list (e.g. SecLists `Names/` + a year suffix) — common in
  home PSKs; great with a leetspeak/year rule.

## Rulesets — already on the device, nothing to download

hashcat ships its rules at `/usr/share/hashcat/rules/`, and Kestrel resolves a
bare rule name there automatically, so you just name it in `config.toml`:

- **`best64.rule`** — ~64 rules, the recommended booster. Cheap enough for the
  Pi, and still roughly doubles a small list's hits. **This is the one to use.**
- **`rockyou-30000.rule`** — ~30k rules, a deeper weekend pass on a *tiny* base
  only (it's 30k× the candidates — fine on `top4800`, far too slow on `rockyou`).
- `dive.rule` / **OneRuleToRuleThemAll** (download) — desktop/GPU only; listed
  for completeness, not for Pi use.

Two rulesets is the whole kit here: **best64 for routine deeper passes, and
rockyou-30000 for an occasional deep dig on a small base.** Set one with:

```toml
[crack]
rules = ["best64.rule"]
```

## Brute-force masks (the one thing wordlists can't catch)

A random all-numeric router default like `81736402` is in no wordlist, but a
**mask** attack walks every combination and *will* find it. Masks run on the
device too (`hashcat -a 3`), after every wordlist (the deepest tier):

- `?d` digit, `?l` lower, `?u` upper, `?s` symbol, `?a` any.
- The highest-value WPA mask is **all-8-digit**: `?d?d?d?d?d?d?d?d` (10⁸ = 100M
  candidates, ≈ 18 hours per network on the Pi CPU). 10-digit phone-style
  (`?d?d?d?d?d?d?d?d?d?d`) is 100× that — so pick your targets.

Because a mask is a multi-hour commitment, auto-crack ships with **no masks**
(`[crack] masks = []`). Two ways to use one:

- **On a chosen target** (recommended): queue it where it's worth the time, from
  the Loot page's mask box or the CLI —
  ```bash
  kestrel crack run <file>.hc22000 --mask '?d?d?d?d?d?d?d?d'
  ```
- **Automatically, after the wordlists**: add masks to `config.toml` —
  ```toml
  [crack]
  masks = ["?d?d?d?d?d?d?d?d"]
  ```
  Only if you're happy for the Pi to spend many hours per network on brute force.

## Putting it together — best chances, fastest

1. Drop in **`probable-v2-wpa-top4800.txt`** and **`rockyou.txt` (8+ filtered)**
   alongside the shipped lists. The device runs them smallest-first automatically.
2. For a deeper pass on what didn't crack, queue a small base **+ best64** from
   the web **Loot** page or the CLI:
   ```bash
   kestrel crack run <file>.hc22000 --wordlist probable-v2-wpa-top4800.txt --rules best64.rule
   ```
3. Let **rockyou** grind overnight on the rest (it's already queued — anything
   uncracked keeps trying).
4. If a specific network really matters and the Pi hasn't got it, copy its
   `.hc22000` to a desktop GPU and throw `rockyou` + OneRule at it.

## Where to get them (names, links, and exact commands)

Sources:

- **SecLists** — <https://github.com/danielmiessler/SecLists> (`Passwords/WiFi-WPA/`, `Passwords/Common-Credentials/`, `Passwords/Leaked-Databases/`).
- **Probable-Wordlists** (Berzerk0) — <https://github.com/berzerk0/Probable-Wordlists> (the WPA lists are under `Real-Passwords/`; the big cuts are released via the repo's download links/torrents).

### Download the recommended set

The two core lists (verified paths): the best small WPA list and rockyou.

**On the Kestrel Pi (or any Linux/WSL bash shell)** — real `wget`, into the
wordlists folder (owned by `pi`, so no `sudo`); it is picked up automatically:

```bash
cd /var/lib/kestrel/wordlists/
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
tar xzf rockyou.txt.tar.gz && rm rockyou.txt.tar.gz
```

(hashcat skips sub-8-char lines for WPA automatically, so filtering rockyou to
8+ is optional. If you want it: `awk 'length>=8' rockyou.txt > rockyou-wpa.txt`.)

**On a Windows PC (PowerShell)** to stage them first — use `curl.exe` (the real
curl; plain `wget`/`curl` in PowerShell are aliases that don't save a file), and
remember PowerShell has no `&&`, so run each line separately:

```powershell
cd $HOME\Downloads
curl.exe -L -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt
curl.exe -L -O https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
tar -xzf rockyou.txt.tar.gz
```

**More lists (optional):** browse these directories on GitHub and download what
you want (a browser avoids any path guesswork):
<https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials>
(the `10-million-password-list-top-100000.txt` / `-top-1000000.txt` live here) and
<https://github.com/danielmiessler/SecLists/tree/master/Passwords/WiFi-WPA>.

Then get them onto the device: if the Kestrel Pi has internet, `wget` straight
into `/var/lib/kestrel/wordlists/`; if it's offline (isolated lab), stage the
files on the SD card's boot partition in a folder named `kestrel-wordlists/` —
they move into the wordlists folder on the next boot (see the README "Wordlists"
section).

Rules need no download — hashcat ships `best64.rule`, `rockyou-30000.rule` and
`dive.rule` at `/usr/share/hashcat/rules/`, and Kestrel resolves them by bare
name (`rules = ["best64.rule"]`). If you have a bigger desktop GPU, grab
**OneRuleToRuleThemAll** (<https://github.com/NotSoSecure/password_cracking_rules>)
for offline runs there — it is too slow for the Pi.

All of these are standard, openly published security wordlists. Use them only
against networks you own or are authorized to test.
