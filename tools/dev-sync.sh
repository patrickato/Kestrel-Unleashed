#!/usr/bin/env bash
# dev-sync: pull the latest code and reinstall the APP-LAYER files in place on a
# running device -- no reflash, no data loss -- for testing commits before they
# are cut as a release. It reuses the update engine's own install plan
# (file_plan / apply_plan / install_package in builder/extra/files/
# update-apply.py), so it installs exactly what an app-layer release would, with
# no drift: the lib scripts, the CLI, every plugin, the systemd units, the
# journald drop-in, and the kestrel_pi venv package.
#
# It deliberately does NOT touch apt packages, pip packages, boot config, kernel
# modules or shipped config.toml/default.conf -- those are reflash-class. If a
# change needs any of those, reflash a freshly built image instead.
#
# This skips the release-verification the in-field updater requires: it is a
# maintainer convenience you run by hand on a device you own, syncing from a
# branch you control. Run on the device as root:
#
#   sudo bash tools/dev-sync.sh                       # default: main
#   sudo KESTREL_REF=claude/my-topic bash tools/dev-sync.sh
#   curl -fsSL <raw-url>/tools/dev-sync.sh | sudo bash
#
set -euo pipefail

REPO="${KESTREL_REPO:-https://github.com/patrickato/Kestrel-Unleashed}"
REF="${KESTREL_REF:-main}"

if [ "$(id -u)" -ne 0 ]; then
    echo "dev-sync: run as root (e.g. sudo bash tools/dev-sync.sh)" >&2
    exit 1
fi

work="$(mktemp -d /var/tmp/kestrel-dev-sync.XXXXXX)"
trap 'rm -rf "$work"' EXIT

echo "dev-sync: cloning ${REPO}@${REF} ..."
git clone --depth 1 --branch "$REF" "$REPO" "$work/clone"

echo "dev-sync: validating + installing app-layer files and the package ..."
/usr/bin/python3 -I - "$work/clone" <<'PY'
import importlib.util
import os
import sys

root = sys.argv[1]
engine_path = os.path.join(root, "builder", "extra", "files", "update-apply.py")
spec = importlib.util.spec_from_file_location("kestrel_dev_sync_engine",
                                              engine_path)
eng = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eng)

ok, err = eng.validate_source(root)
if not ok:
    sys.stderr.write("dev-sync: source check failed: %s\n" % err)
    raise SystemExit(1)

os.makedirs(eng.STAGING_PARENT, exist_ok=True)
plan = eng.file_plan(root)
eng.apply_plan(plan)          # lib scripts, CLI, plugins, units, journald drop-in
eng.install_package(root)     # reinstall kestrel_pi into pi's venv (offline)
print("dev-sync: installed %d file(s) + the kestrel_pi package" % len(plan))
PY

echo "dev-sync: reloading units and bouncing services ..."
systemctl daemon-reload
systemctl restart kestrel-daemon.service || true
systemctl restart kestrel-crack.service || true

echo "dev-sync: done (app-layer only; apt/pip/boot changes still need a reflash)."
