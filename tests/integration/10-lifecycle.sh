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
. /etc/os-release
# Leap 16 and Ubuntu minimal have no iptables, which the built-in ingress needs. The installer should refuse before
# installing anything, and name it. This comes first: it refuses before the SELinux check below can.
if ! command -v iptables >/dev/null 2>&1; then
  if ./rke2_installer.sh install >"$W/o" 2>&1; then bad "installed with no iptables"
  elif grep -q "iptables" "$W/o" && [ ! -e /etc/rancher/rke2/config.yaml ]; then ok "refuses with no iptables, before installing anything, and names it"
  else bad "the refusal doesn't name iptables, or something was installed"; tail -8 "$W/o" | cut -c1-170; fi
  case "$ID" in
    ubuntu|debian) DEBIAN_FRONTEND=noninteractive apt-get install -y iptables >/dev/null 2>&1 ;;
    sles|opensuse-leap) zypper --non-interactive install -y iptables >/dev/null 2>&1 ;;
    *) dnf install -y iptables >/dev/null 2>&1 ;;
  esac
  command -v iptables >/dev/null 2>&1 && ok "iptables installed" || bad "couldn't install iptables"
fi
# SUSE has no rke2-selinux policy. On an enforcing host the installer should refuse, and say to opt in to permissive.
enforcing=0
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then
  enforcing=1
  if DEBUG=1 ./rke2_installer.sh install >"$W/o" 2>&1; then bad "installed with no SELinux policy"
  elif grep -q "RKE2_SELINUX_FALLBACK=permissive" "$W/o"; then ok "refuses with no SELinux policy, and says how to go on"
  else bad "the refusal doesn't name the way to go on"; tail -8 "$W/o" | cut -c1-170; fi
  export RKE2_SELINUX_FALLBACK=permissive
fi
./rke2_installer.sh install >"$W/o" 2>&1 && ok "install" || { bad "install"; tail -8 "$W/o" | cut -c1-170; }
for _ in $(seq 1 60); do $K get nodes --no-headers 2>/dev/null | grep -qw Ready && break; sleep 5; done
$K get nodes --no-headers 2>/dev/null | grep -qw Ready && ok "the node is Ready" || bad "the node isn't Ready"
./rke2_installer.sh install >"$W/o" 2>&1 && ok "same-settings re-run" || { bad "re-run"; tail -8 "$W/o" | cut -c1-170; }
systemctl is-active --quiet rke2-server && ok "rke2-server stayed up" || bad "rke2-server is down"
./rke2_installer.sh uninstall >"$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; tail -8 "$W/o" | cut -c1-170; }
systemctl is-active --quiet rke2-server && bad "rke2-server is still running" || ok "rke2-server is gone"
if ((enforcing)); then [[ "$(getenforce)" == Enforcing ]] && ok "uninstall put SELinux back to enforcing" || bad "SELinux is $(getenforce) after uninstall"; fi
# Spec 11, U3: a wait that runs out says which pods weren't ready. Pods can't all be ready 1 s into a fresh install.
if POD_WAIT_TIMEOUT=1 ./rke2_installer.sh install >"$W/o" 2>&1; then bad "an install with POD_WAIT_TIMEOUT=1 exited 0"
elif grep -qE "weren't ready after 1s: [a-z0-9.-]+ \(" "$W/o"; then ok "with POD_WAIT_TIMEOUT=1, install fails, and the error names the pods"
else bad "the timeout's error doesn't name the pods"; tail -8 "$W/o" | cut -c1-170; fi
./rke2_installer.sh uninstall >"$W/o" 2>&1 && ok "uninstall after an install that timed out" || { bad "uninstall after the timeout"; tail -8 "$W/o" | cut -c1-170; }
echo "=== exit $fail"; exit $fail
