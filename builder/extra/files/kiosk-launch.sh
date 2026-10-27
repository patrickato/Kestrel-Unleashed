#!/bin/bash
# Kestrel-Unleashed on-device kiosk: show the dashboard full-screen on an
# attached HDMI touchscreen. Run by kestrel-kiosk.service (as pi). Inert unless
# [kiosk] enabled. cage (a single-app Wayland kiosk compositor) runs chromium
# full-screen on the dashboard; seatd hands cage the seat. Local hardware only --
# no radio, no network, no root. See docs/user-guide/kiosk-setup.md.
set -euo pipefail
# shellcheck source=common.sh
. "${PWN_LIB_DIR:-/usr/local/lib/kestrel}/common"

[ "$(cfg kiosk.enabled false)" = true ] || { log "kiosk disabled; nothing to do"; exit 0; }

url=$(cfg kiosk.url "http://127.0.0.1:8080/")

# RPiOS ships chromium-browser; Debian ships chromium. Use whichever is present.
chrome=""
for c in chromium-browser chromium; do
    if command -v "$c" >/dev/null 2>&1; then chrome=$c; break; fi
done
[ -n "$chrome" ] || die "no chromium found (install chromium-browser)"
command -v cage >/dev/null 2>&1 || die "cage not found (install cage)"

# Operator's extra chromium flags (config array -> one per line).
extra=()
while IFS= read -r line; do
    [ -n "$line" ] && extra+=("$line")
done < <(cfg kiosk.extra_args "" || true)

# chromium kiosk flags: a full-screen app on the url, no first-run/crash noise,
# updates off, touch scrolling sane, private cache under the pi home.
args=(--kiosk "--app=$url"
      --ozone-platform=wayland
      --no-first-run --disable-infobars --disable-session-crashed-bubble
      --disable-features=TranslateUI --noerrdialogs --no-default-browser-check
      --check-for-update-interval=31536000
      --overscroll-history-navigation=0
      --password-store=basic
      --user-data-dir=/home/pi/.config/kestrel-kiosk)

log "starting kiosk: $chrome on $url"
# cage -s: keep the single app full-screen; it is the whole session.
exec cage -s -- "$chrome" "${args[@]}" "${extra[@]:-}"
