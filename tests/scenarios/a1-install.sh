#!/bin/bash
# A1, on a host with no route out: install from the bundle the build role made, check the cluster, uninstall.
# Nothing is installed first: whatever the install needs has to come from the bundle or be refused with a reason.
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
# within <seconds> <command...>: true once the command is, checking every 3 seconds
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml"
. /etc/os-release
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then export RKE2_SELINUX_FALLBACK=permissive; fi
cp "$REPO/rke2_installer.sh" .; chmod +x rke2_installer.sh
tar -xzf "$CI_HANDOFF/rke2-save.tar.gz" && ok "unpack the bundle" || { bad "unpack the bundle"; echo "=== exit 1"; exit 1; }
DEBUG=0 ./rke2_installer.sh install > "$W/o" 2>&1 && ok "install with no route out" || { bad "install with no route out"; tail -10 "$W/o" | cut -c1-170; }
ready() { $K get nodes --no-headers 2>/dev/null | grep -qw Ready; }
within 300 ready && ok "the node is Ready" || bad "the node isn't Ready"
notready() { local out; out=$($K get pods -A --no-headers 2>/dev/null | grep -vE 'Running|Completed'); [ -z "$out" ]; }
within 300 notready && ok "every pod is running or done" || { bad "pods not running: $($K get pods -A --no-headers 2>/dev/null | grep -vE 'Running|Completed' | head -4)"; }
$K get storageclass local-path >/dev/null 2>&1 && ok "the local-path StorageClass is there" || bad "no local-path StorageClass"
DEBUG=0 ./rke2_installer.sh uninstall > "$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; tail -6 "$W/o" | cut -c1-170; }
systemctl is-active --quiet rke2-server && bad "rke2-server is still running" || ok "rke2-server is gone"
echo "=== exit $fail"; exit $fail
