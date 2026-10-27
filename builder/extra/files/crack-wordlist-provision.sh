#!/bin/bash
# Pre-load crack wordlists staged on the boot partition into the device's
# wordlists dir, then clear the staged copies so the FAT boot partition is not
# bloated and config.toml's wordlists_dir stays the lasting source of truth.
# Runs from kestrel-crack-wordlist-provision.service when the staged dir exists.
# Mirrors the capture whitelist / Wi-Fi provisioning flow.
#
# Dir: /boot/firmware/kestrel-wordlists/  -- drop any plain-text wordlist (and/or
# *.rule hashcat rule files) in here from your PC. On boot each file is MOVED
# into the device wordlists dir (owned pi:pi) and the staged dir is cleared.
# See the README "Wordlists" section and docs/developer/crack-interface.md.
set -euo pipefail
# shellcheck source=common.sh
. "${PWN_LIB_DIR:-/usr/local/lib/kestrel}/common"

src=${1:-/boot/firmware/kestrel-wordlists}
dest=$(cfg crack.wordlists_dir /var/lib/kestrel/wordlists)
[ -d "$src" ] || exit 0

mkdir -p "$dest"
moved=0
shopt -s nullglob
for f in "$src"/*; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    # A README the operator left in the staged dir is guidance, not a wordlist.
    case "$base" in README*|readme*|.*) rm -f "$f"; continue ;; esac
    install -m 0644 -o pi -g pi "$f" "$dest/$base"
    rm -f "$f"
    moved=$((moved + 1))
done
# Remove the staged dir if it is now empty, so the service condition is false on
# the next boot; re-creating it to stage more later works again.
rmdir "$src" 2>/dev/null || true

log "wordlists pre-loaded ($moved) into $dest"
