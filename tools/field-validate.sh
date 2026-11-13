#!/usr/bin/env bash
# Kestrel field self-test -- a read-mostly health + capability check for a
# flashed device. It fires NO attacks and changes NO config: it reports what
# the hardware can do and what is already working, then lists the few checks
# that still need a human (a GPS fix outdoors, a phone on the portal, an attack
# on an AP you own). Run it on the device:
#
#   bash tools/field-validate.sh            # as pi: skips the WPS scan
#   sudo bash tools/field-validate.sh       # also runs the passive WPS scan
#
# Maps to docs/developer/hardware-validation.md (V1-V7).

PASS=0
FAIL=0
section() { printf '\n== %s ==\n' "$1"; }
ok()    { printf '  [PASS]  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()   { printf '  [FAIL]  %s\n' "$1"; FAIL=$((FAIL + 1)); }
info()  { printf '  [INFO]  %s\n' "$1"; }
human() { printf '  [HUMAN] %s\n' "$1"; }
indent() { sed 's/^/    /'; }
have()  { command -v "$1" >/dev/null 2>&1; }

printf 'Kestrel field self-test  (%s)\n' "$(date 2>/dev/null || echo '')"

# -- Environment ------------------------------------------------------------
section "Environment (pre-flight)"
ver=$(cat /etc/kestrel/version 2>/dev/null || echo unknown)
info "image version: ${ver}"
[ "${ver}" = master ] && info "('master' = a dev build: updates are never offered to it)"
have kestrel && ok "kestrel CLI present" || bad "kestrel CLI not found on PATH"

# -- Radios / adapters (V3 + V4 prerequisites) ------------------------------
section "Radios / adapters -- monitor + AP capability"
if have iw; then
  for phypath in /sys/class/ieee80211/*; do
    [ -e "${phypath}" ] || continue
    phy=$(basename "${phypath}")
    ifs=$(iw phy "${phy}" info 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')
    pinfo=$(iw phy "${phy}" info 2>/dev/null)
    modes=$(printf '%s\n' "${pinfo}" | sed -n '/Supported interface modes/,/[Bb]and /p')
    mon=no; ap=no
    printf '%s\n' "${modes}" | grep -qE '^[[:space:]]*\* monitor$' && mon=yes
    printf '%s\n' "${modes}" | grep -qE '^[[:space:]]*\* AP$' && ap=yes
    info "${phy} [${ifs}] monitor=${mon} AP=${ap}"
  done
  if iw phy 2>/dev/null | awk '/Supported interface modes/,/[Bb]and /' | grep -qE '^[[:space:]]*\* AP$'; then
    ok "at least one radio supports AP mode (evil-portal V4 can run)"
  else
    bad "no radio advertises AP mode -- evil-portal (V4) needs an AP-capable dongle"
  fi
  if iw phy 2>/dev/null | awk '/Supported interface modes/,/[Bb]and /' | grep -qE '^[[:space:]]*\* monitor$'; then
    ok "at least one radio supports monitor mode (capture + WPS V3)"
  else
    bad "no radio advertises monitor mode -- capture and WPS need one"
  fi
else
  bad "'iw' not installed -- cannot read radio capabilities"
fi

# -- Capture store (what there is to crack) ---------------------------------
section "Capture store"
kestrel capture status 2>/dev/null | indent
store=/var/lib/kestrel/capture
if [ -d "${store}" ]; then
  pmkid=$(grep -rhE '^WPA\*01\*' "${store}" 2>/dev/null | wc -l | tr -d ' ')
  eapol=$(grep -rhE '^WPA\*02\*' "${store}" 2>/dev/null | wc -l | tr -d ' ')
  info "hashlines in store: PMKID(01)=${pmkid}  EAPOL(02)=${eapol}"
  [ "${pmkid:-0}" -gt 0 ] && ok "PMKID hashlines present (only John can crack these)" \
    || info "no PMKID hashlines in the store yet"
else
  info "capture store directory not found at ${store}"
fi

# -- Crack engine + John (V2 + V7) ------------------------------------------
section "Crack engine + jumbo John (V2 / V7)"
cs=$(kestrel crack status 2>/dev/null)
printf '%s\n' "${cs}" | indent
printf '%s\n' "${cs}" | grep -q 'engine: john' \
  && ok "crack engine is jumbo John (active)" \
  || bad "crack engine is NOT John -- falling back to aircrack (no PMKID cracking)"
if have john; then
  jb=$(readlink -f "$(command -v john)")
  info "john resolves to: ${jb}"
  file "${jb}" 2>/dev/null | indent
  if john --test=0 --format=wpapsk >/tmp/kv_john.out 2>&1; then
    ok "john wpapsk self-test PASS (jumbo build confirmed)"
  else
    bad "john wpapsk self-test FAILED -- not a usable jumbo build"
    tail -3 /tmp/kv_john.out 2>/dev/null | indent
  fi
  have hccapx2john.py && ok "hccapx2john.py on PATH" \
    || info "hccapx2john.py not on PATH (John may still find it beside the binary)"
  if [ -d /opt/kestrel/john ]; then
    info "install layout at /opt/kestrel/john:"
    ls -la /opt/kestrel/john/ 2>/dev/null | head -20 | indent
  fi
else
  bad "no 'john' on PATH"
fi
human "V2 John proof: run 'kestrel crack show <a PMKID network>' and confirm a"
human "  PMKID-only network shows a recovered key (aircrack cannot do that)."

# -- GPU offload reachability (V5 / V6) -------------------------------------
section "GPU offload -- remote-crack (V5/V6)"
kestrel remote-crack status 2>&1 | indent
human "If the host shows reachable: 'kestrel remote-crack now' offloads everything."
human "If not set up yet (one-time, asks the TUF password once):"
human "  sudo kestrel remote-crack setup"

# -- WPS scan (V3 detection only; attack stays manual) ----------------------
section "WPS scan (V3 -- detection only, NO attack)"
if [ "$(id -u)" -eq 0 ]; then
  info "scanning 20s with 'wash' (capture pauses if it was running)..."
  kestrel wps scan --seconds 20 2>&1 | indent
  human "V3 finish: attack an AP you OWN -> sudo kestrel wps attack <BSSID> --yes"
else
  human "re-run with sudo to include the WPS scan, or run:"
  human "  sudo kestrel wps scan --seconds 20"
fi

# -- Daemon / plugins -------------------------------------------------------
section "Daemon + plugins"
kestrel plugins list 2>/dev/null | indent

# -- What still needs a human ----------------------------------------------
section "Still needs your hands (nothing remote can do these)"
human "V1 GPS/map: take the Pi to a window/outside, 'kestrel capture enable --yes',"
human "  move ~10 m, open http://127.0.0.1:8080/ (or the wlan0 URL) -> Map page,"
human "  confirm cursor+route+pins, download KML/GPX/CSV, then 'kestrel capture disable'."
human "V3 WPS: run the attack line above against your own WPS AP."
human "V4 evil-portal: 'sudo kestrel evil-portal start --yes', join the SSID from your"
human "  phone, submit the form, 'kestrel evil-portal creds', then 'sudo kestrel evil-portal stop'."

# -- Summary ----------------------------------------------------------------
section "Summary"
printf '  automated checks: %d passed, %d failed\n' "${PASS}" "${FAIL}"
if [ "${FAIL}" -eq 0 ]; then
  printf '  No automated failures. Finish the [HUMAN] steps above for a full V1-V7 pass.\n'
else
  printf '  Address the [FAIL] lines above before the release.\n'
fi
