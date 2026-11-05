#!/bin/bash
# The real installer on a throwaway host, as root, from the repo root: single-node install, same-settings re-run, uninstall.
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
W=$(mktemp -d); cd "$W" || exit 1
cp "$REPO/rke2_installer.sh" .; chmod +x rke2_installer.sh
export INSTALL_LOCAL_PATH_PROVISIONER=false INSTALL_DNS_UTILITY=false DEBUG=0
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml"
./rke2_installer.sh install >"$W/o" 2>&1 && ok "install" || { bad "install"; tail -8 "$W/o" | cut -c1-170; }
for _ in $(seq 1 60); do $K get nodes --no-headers 2>/dev/null | grep -qw Ready && break; sleep 5; done
$K get nodes --no-headers 2>/dev/null | grep -qw Ready && ok "the node is Ready" || bad "the node isn't Ready"
./rke2_installer.sh install >"$W/o" 2>&1 && ok "same-settings re-run" || { bad "re-run"; tail -8 "$W/o" | cut -c1-170; }
systemctl is-active --quiet rke2-server && ok "rke2-server stayed up" || bad "rke2-server is down"
./rke2_installer.sh uninstall >"$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; tail -8 "$W/o" | cut -c1-170; }
systemctl is-active --quiet rke2-server && bad "rke2-server is still running" || ok "rke2-server is gone"
echo "=== exit $fail"; exit $fail
