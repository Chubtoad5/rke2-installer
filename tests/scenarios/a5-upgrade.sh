#!/bin/bash
# A5: install the last release (its source archive from GitHub), run a workload that writes to a local-path volume, then
# run the commit under test's install over it. Same config and version: it reconciles, the service isn't restarted, and
# the workload and its data are still there.
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
R=rke2-installer
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml"
. /etc/os-release
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then export RKE2_SELINUX_FALLBACK=permissive; fi
export DEBUG=0
old=$(curl -sI -m 20 "https://github.com/Chubtoad5/$R/releases/latest" | tr -d '\r' | sed -n 's#^[Ll]ocation: .*/tag/##p')
[[ "$old" =~ ^v[0-9]+(\.[0-9]+)+$ ]] && ok "the last release is $old" || { bad "couldn't find the last release: '$old'"; echo "=== exit 1"; exit 1; }
mkdir old new
curl -sfL -m 180 "https://github.com/Chubtoad5/$R/archive/refs/tags/$old.tar.gz" | tar -xz -C old --strip-components=1 && [ -f old/rke2_installer.sh ] \
  && ok "download $old" || { bad "download $old"; echo "=== exit 1"; exit 1; }
cp "$REPO/rke2_installer.sh" new/; chmod +x old/rke2_installer.sh new/rke2_installer.sh
ready() { $K get nodes --no-headers 2>/dev/null | grep -qw Ready; }
pods_up() { local all; all=$($K get pods -A --no-headers 2>/dev/null) || return 1; [ -n "$all" ] && ! grep -vqE 'Running|Completed' <<< "$all"; }
data() { $K exec -n a5 deploy/keeper -- cat /data/f 2>/dev/null; }
started() { systemctl show -p ActiveEnterTimestampMonotonic --value rke2-server; }

(cd old && ./rke2_installer.sh install) > o1 2>&1 && ok "install $old" || { bad "install $old"; tail -10 o1 | cut -c1-170; echo "=== exit 1"; exit 1; }
within 300 ready && ok "$old's node is Ready" || bad "$old's node isn't Ready"
$K apply -f - > /dev/null <<'YAML' && ok "a workload with a local-path volume" || bad "couldn't create the workload"
apiVersion: v1
kind: Namespace
metadata: { name: a5 }
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: data, namespace: a5 }
spec: { accessModes: [ReadWriteOnce], storageClassName: local-path, resources: { requests: { storage: 1Gi } } }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: keeper, namespace: a5 }
spec:
  replicas: 1
  selector: { matchLabels: { app: keeper } }
  template:
    metadata: { labels: { app: keeper } }
    spec:
      containers:
        - name: c
          image: busybox:1.36
          command: [sh, -c, '[ -f /data/f ] || echo a5-before-upgrade > /data/f; exec sleep 1000000']
          volumeMounts: [{ name: d, mountPath: /data }]
      volumes: [{ name: d, persistentVolumeClaim: { claimName: data } }]
YAML
wrote() { [ "$(data)" = a5-before-upgrade ]; }
within 300 wrote && ok "it wrote to its volume" || bad "the workload didn't write: $($K get pods -n a5 --no-headers 2>&1 | head -2)"
t1=$(started)

(cd new && ./rke2_installer.sh install) > o2 2>&1 && ok "install the commit under test over $old: it reconciles" || { bad "install the commit under test over $old"; tail -12 o2 | cut -c1-170; }
[ "$(started)" = "$t1" ] && ok "rke2-server wasn't restarted (same config, same version)" || bad "rke2-server was restarted"
within 300 ready && ok "the node is Ready after the upgrade" || bad "the node isn't Ready after the upgrade"
within 300 pods_up && ok "every pod is running or done after the upgrade" || bad "pods not running: $($K get pods -A --no-headers 2>/dev/null | grep -vE 'Running|Completed' | head -4 | tr '\n' ';')"
within 120 wrote && ok "the workload and its data survived" || bad "the workload's data is gone: '$(data)'"
(cd new && ./rke2_installer.sh uninstall) > o3 2>&1 && ok "uninstall" || { bad "uninstall"; tail -6 o3 | cut -c1-170; }
systemctl is-active --quiet rke2-server && bad "rke2-server is still running" || ok "rke2-server is gone"
echo "=== exit $fail"; exit $fail
