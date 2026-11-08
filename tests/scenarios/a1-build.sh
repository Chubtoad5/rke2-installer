#!/bin/bash
# A1, on the host that builds the bundle: save, then hand the archive to the next role.
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
# within <seconds> <command...>: true once the command is, checking every 3 seconds
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
cp "$REPO/rke2_installer.sh" .; chmod +x rke2_installer.sh
if DEBUG=0 ./rke2_installer.sh save > "$W/o" 2>&1 && [ -s rke2-save.tar.gz ]; then
  ok "save builds rke2-save.tar.gz ($(du -h rke2-save.tar.gz | cut -f1))"
  cp rke2-save.tar.gz "$CI_HANDOFF/" && ok "hand the bundle on" || bad "hand the bundle on"
else
  bad "save"; tail -8 "$W/o" | cut -c1-170
fi
echo "=== exit $fail"; exit $fail
