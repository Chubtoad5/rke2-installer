#!/bin/bash
# The Day-2 fixes (v1.1.0) on a throwaway host, as root, from the repo root. Each check here failed at v1.0.0.
# Runs after 10-lifecycle.sh, which leaves the host uninstalled. A single node; the multi-node fixes (RC1, R9) and the
# air-gapped upgrade check (R4) have unit tests. Takes about 15 minutes.
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
cp "$REPO/rke2_installer.sh" .; chmod +x rke2_installer.sh
IP=${CI_CLONE_IP:-$(hostname -I | awk '{print $1}')}
export INSTALL_LOCAL_PATH_PROVISIONER=false INSTALL_DNS_UTILITY=false DEBUG=0
# Rancher's EL10 packages start at 1.33.7 and 1.34.3, so OLD has to be at least that for Rocky 10.
OLD=v1.33.13+rke2r1 NEW=v1.34.5+rke2r1
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml"
show() { tail -8 "$W/o" | cut -c1-170; }
ready() { for _ in $(seq 1 60); do $K get nodes --no-headers 2>/dev/null | grep -qw Ready && return 0; sleep 5; done; return 1; }
. /etc/os-release
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then export RKE2_SELINUX_FALLBACK=permissive; fi
# 10-lifecycle.sh installs iptables where it's missing. Run alone, do it here.
if ! command -v iptables >/dev/null 2>&1; then
  case "$ID" in
    ubuntu|debian) DEBIAN_FRONTEND=noninteractive apt-get install -y iptables >/dev/null 2>&1 ;;
    sles|opensuse-leap) zypper --non-interactive install -y iptables >/dev/null 2>&1 ;;
    *) dnf install -y iptables >/dev/null 2>&1 ;;
  esac
fi

echo "=== R2: a stale sentinel with no bundle"
mkdir -p "$W/stale"; cp rke2_installer.sh "$W/stale/"; touch "$W/stale/rke2-save-version.txt"
if (cd "$W/stale" && ./rke2_installer.sh install >"$W/o" 2>&1); then bad "installed from a stale sentinel"
elif grep -q "no extracted bundle" "$W/o" && grep -q "RKE2_FORCE_ONLINE=true" "$W/o" && [ ! -e /etc/rancher/rke2/config.yaml ]; then
  ok "a stale sentinel is refused, with the ways out, before anything is installed"
else bad "the stale-sentinel refusal is wrong"; show; fi

echo "=== Install $OLD with a registry (R1, R8)"
# A TLS endpoint stands in for the registry: the installer only fetches its certificate. It stops once the
# certificate is in place, so containerd's mirror falls straight back to the public registries.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$IP" -addext "subjectAltName=IP:$IP" \
  -keyout "$W/k.pem" -out "$W/c.pem" >/dev/null 2>&1
openssl s_server -quiet -accept 5443 -cert "$W/c.pem" -key "$W/k.pem" -www >/dev/null 2>&1 &
SRV=$!
CA=/etc/rancher/rke2/certs.d/$IP:5443/ca.crt
( RKE2_VERSION=$OLD ./rke2_installer.sh install -registry "$IP:5443" u p > "$W/o" 2>&1; echo $? > "$W/rc" ) &
for _ in $(seq 1 120); do [ -s "$CA" ] && break; sleep 1; done
kill "$SRV" 2>/dev/null
for _ in $(seq 1 180); do [ -f "$W/rc" ] && break; sleep 5; done
[ "$(cat "$W/rc" 2>/dev/null)" = 0 ] && ok "install $OLD with -registry" || { bad "install $OLD with -registry"; show; }
ready && ok "the node is Ready" || bad "the node isn't Ready"
[ -s "$CA" ] && ok "the registry's CA is saved" || bad "no registry CA"
sum=$(md5sum < "$CA")
if RKE2_VERSION=$OLD ./rke2_installer.sh install -registry "$IP:5443" u p > "$W/o" 2>&1; then bad "a re-run with the registry down exited 0"
else
  [ "$(md5sum < "$CA")" = "$sum" ] && ok "a failed certificate fetch leaves the CA as it was" || bad "a failed fetch changed the CA ($(wc -c < "$CA") bytes)"
  grep -q "Failed to retrieve a certificate" "$W/o" && ok "with DEBUG=0, the failure's reason reaches the console" || { bad "the failure's reason isn't shown"; show; }
fi
RKE2_VERSION=$OLD ./rke2_installer.sh install > "$W/o" 2>&1 && ok "a re-run without -registry" || { bad "a re-run without -registry"; show; }
grep -q "WARNING: no -registry given" "$W/o" && grep -q "$IP:5443" "$W/o" && ok "it warns that the node still uses the registry, and names it" \
  || bad "no warning about the registry left in place"

echo "=== Upgrade a tainted control plane, waiting for it (RC2, R7)"
$K taint nodes "$(hostname)" node-role.kubernetes.io/control-plane:NoSchedule >/dev/null 2>&1
UPGRADE_WAIT=true UPGRADE_WAIT_TIMEOUT=900 ./rke2_installer.sh upgrade server "$NEW" > "$W/o" 2>&1 \
  && ok "upgrade server $NEW with UPGRADE_WAIT=true" || { bad "upgrade with UPGRADE_WAIT=true"; show; }
line=$($K get nodes --no-headers 2>/dev/null)
[[ "$line" == *"$NEW"* ]] && ok "the tainted node runs $NEW when the upgrade returns" || bad "the node runs: $line"
[[ "$line" != *SchedulingDisabled* ]] && ok "and is schedulable again" || bad "the node is still cordoned"
./rke2_installer.sh uninstall > "$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; show; }

echo "=== CNI_TYPE=none (R3's second failure)"
CNI_TYPE=none ./rke2_installer.sh install > "$W/o" 2>&1 && ok "a CNI_TYPE=none install exits 0" || { bad "a CNI_TYPE=none install"; show; }
grep -q "NOTE: CNI_TYPE=none" "$W/o" && ok "it says the node waits for a CNI" || bad "no note about installing a CNI"
$K get --raw /readyz >/dev/null 2>&1 && ok "the API server answers" || bad "the API server doesn't answer"
./rke2_installer.sh uninstall > "$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; show; }
systemctl is-active --quiet rke2-server && bad "rke2-server is still running" || ok "rke2-server is gone"
echo "=== exit $fail"; exit $fail
