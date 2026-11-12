#!/bin/bash
# Kestrel-Unleashed on-device kiosk: show the dashboard full-screen on an
# attached HDMI touchscreen. Run by kestrel-kiosk.service (as pi). Inert unless
# [kiosk] enabled. cage (a single-app Wayland kiosk compositor) runs chromium
# full-screen on the dashboard; seatd hands cage the seat. Local hardware only --
# no radio, no network, no root. See docs/user-guide/kiosk-setup.md.
#
# Self-healing: the launcher waits for the dashboard to answer before starting
# the browser, and a watchdog relaunches it if the dashboard goes unreachable, so
# a boot race or a momentary daemon blip never strands the screen on a chromium
# "connection refused" page (which has no way back without a keyboard).
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

# Dashboard reachability, dependency-free: the daemon binds the web port only
# while it is serving, so an open TCP port means the dashboard is up. Parse
# host:port out of the url for a bash /dev/tcp probe (no curl/wget needed).
hostport=${url#*://}; hostport=${hostport%%/*}
khost=${hostport%%:*}; kport=${hostport##*:}
[ "$kport" = "$khost" ] && kport=80
dash_up() { (exec 3<>"/dev/tcp/$khost/$kport") 2>/dev/null; }

# Seconds the dashboard may be unreachable before the browser is relaunched (so a
# one-second blip doesn't flash the screen). 0 disables the watchdog.
grace=$(cfg kiosk.reload_after_seconds 15)
[[ "$grace" =~ ^[0-9]+$ ]] || grace=15

cage_pid=""
trap 'if [ -n "$cage_pid" ]; then kill "$cage_pid" 2>/dev/null || true; fi; exit 0' TERM INT

# Supervisor loop: wait for the dashboard, run the browser full-screen, and tear
# it down if the dashboard stays unreachable past the grace window so the loop
# brings it back cleanly the moment the daemon returns.
while true; do
    until dash_up; do
        log "kiosk: waiting for dashboard at $url"
        sleep 2
    done
    log "starting kiosk: $chrome on $url"
    cage -s -- "$chrome" "${args[@]}" "${extra[@]:-}" &
    cage_pid=$!
    down=0
    while kill -0 "$cage_pid" 2>/dev/null; do
        if dash_up; then
            down=0
        elif [ "$grace" -gt 0 ]; then
            down=$((down + 3))
            if [ "$down" -ge "$grace" ]; then
                log "kiosk: dashboard unreachable ${down}s; relaunching browser"
                kill "$cage_pid" 2>/dev/null || true
                break
            fi
        fi
        sleep 3
    done
    wait "$cage_pid" 2>/dev/null || true
    cage_pid=""
    sleep 1
done
