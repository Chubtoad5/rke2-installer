#!/bin/bash
# A4 on the first server. By CI_STEP:
#   server    install, then hand on the join token and a kubeconfig that points at this server
#   server.2  after server2 and the agent joined: three nodes Ready, two of them etcd and control plane, every pod up, a
#             pod on each node reached from every other pod and through a Service, and server2's own API answers
#   server.3  the agent has uninstalled: the API still answers, and the two servers are Ready
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=/var/tmp/a4; mkdir -p "$W"; cd "$W" || exit 1
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml"
. /etc/os-release
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then export RKE2_SELINUX_FALLBACK=permissive; fi
export DEBUG=0 INSTALL_INGRESS=false
nodes_ready() { [ "$($K get nodes --no-headers 2>/dev/null | awk '$2 == "Ready"' | wc -l)" -eq "$1" ]; }
pods_up() { local all; all=$($K get pods -A --no-headers 2>/dev/null) || return 1; [ -n "$all" ] && ! grep -vqE 'Running|Completed' <<< "$all"; }

case "${CI_STEP:-server}" in
server)
  cp "$REPO/rke2_installer.sh" .; chmod +x rke2_installer.sh
  ./rke2_installer.sh install > o 2>&1 && ok "install the first server" || { bad "install the first server"; tail -10 o | cut -c1-170; echo "=== exit 1"; exit 1; }
  within 300 nodes_ready 1 && ok "the first server is Ready" || bad "the first server isn't Ready"
  install -m 600 /var/lib/rancher/rke2/server/node-token "$CI_HANDOFF/token" && ok "hand on the join token" || bad "no join token"
  sed "s#https://127.0.0.1:6443#https://$CI_CLONE_IP:6443#" /etc/rancher/rke2/rke2.yaml > "$CI_HANDOFF/kubeconfig" && chmod 600 "$CI_HANDOFF/kubeconfig" \
    && ok "hand on a kubeconfig for this server" || bad "no kubeconfig to hand on"
  ;;
server.2)
  within 300 nodes_ready 3 && ok "three nodes are Ready" || bad "not three Ready nodes: $($K get nodes --no-headers 2>/dev/null | awk '{print $1, $2, $3}' | tr '\n' ';')"
  n=$($K get nodes -l node-role.kubernetes.io/etcd=true --no-headers 2>/dev/null | wc -l)
  [ "$n" -eq 2 ] && ok "two nodes run etcd and the control plane" || bad "$n nodes run etcd, not 2"
  [ "$($K get node -l '!node-role.kubernetes.io/control-plane' --no-headers 2>/dev/null | wc -l)" -eq 1 ] && ok "one node is an agent" || bad "not exactly one agent"
  within 300 pods_up && ok "every pod is running or done" || bad "pods not running: $($K get pods -A --no-headers 2>/dev/null | grep -vE 'Running|Completed' | head -4 | tr '\n' ';')"
  # A pod on every node that serves its node's name, and a Service in front of them
  $K apply -f - > /dev/null <<'YAML' && ok "a DaemonSet and a Service" || bad "couldn't create the DaemonSet and Service"
apiVersion: apps/v1
kind: DaemonSet
metadata: { name: a4, namespace: default }
spec:
  selector: { matchLabels: { app: a4 } }
  template:
    metadata: { labels: { app: a4 } }
    spec:
      tolerations: [{ operator: Exists }]
      containers:
        - name: web
          image: busybox:1.36
          env: [{ name: NODE, valueFrom: { fieldRef: { fieldPath: spec.nodeName } } }]
          command: [sh, -c, 'mkdir -p /www && echo "$NODE" > /www/index.html && exec httpd -f -p 8080 -h /www']
---
apiVersion: v1
kind: Service
metadata: { name: a4, namespace: default }
spec: { selector: { app: a4 }, ports: [{ port: 8080 }] }
YAML
  ds_up() { [ "$($K get ds a4 -o jsonpath='{.status.numberReady}' 2>/dev/null)" = 3 ]; }
  within 300 ds_up && ok "a pod runs on each of the three nodes" || bad "the DaemonSet isn't ready on 3 nodes: $($K get pods -l app=a4 -o wide --no-headers 2>/dev/null | awk '{print $3, $7}' | tr '\n' ';')"
  mapfile -t pods < <($K get pods -l app=a4 -o jsonpath='{range .items[*]}{.metadata.name} {.status.podIP} {.spec.nodeName}{"\n"}{end}' 2>/dev/null)
  for a in "${pods[@]}"; do
    read -r an _ anode <<< "$a"
    for b in "${pods[@]}"; do
      read -r _ bip bnode <<< "$b"
      [ "$anode" = "$bnode" ] && continue
      got=$($K exec "$an" -- wget -qO- -T 10 "http://$bip:8080/" 2>/dev/null)
      [ "$got" = "$bnode" ] && ok "a pod on $anode reaches the pod on $bnode" || bad "a pod on $anode can't reach the pod on $bnode ($bip): '$got'"
    done
    names=""
    for i in 1 2 3 4 5 6 7 8 9; do names+="$($K exec "$an" -- wget -qO- -T 10 http://a4.default.svc.cluster.local:8080/ 2>/dev/null) "; done
    [ -n "${names// /}" ] && ok "from $anode, the Service resolves by name and answers (it reached: $(tr ' ' '\n' <<< "$names" | sort -u | tr '\n' ' '))" \
      || bad "from $anode, the Service doesn't answer by name"
  done
  s2=${CI_ROLE_SERVER2_IP:?}
  $K --server "https://$s2:6443" get nodes > /dev/null 2>&1 && ok "server2's own API answers, with the cluster's certificate" || bad "server2's API doesn't answer at https://$s2:6443"
  ;;
server.3)
  ag=$(cat "$CI_HANDOFF/agent-node" 2>/dev/null)
  gone() { ! $K get node "$ag" --no-headers 2>/dev/null | grep -qw Ready; }
  [ -n "$ag" ] && within 120 gone && ok "the agent ($ag) is no longer Ready" || bad "the agent '$ag' still shows Ready"
  $K delete node "$ag" > /dev/null 2>&1 && ok "remove the agent's node" || bad "couldn't remove node '$ag'"
  within 120 nodes_ready 2 && ok "the two servers are Ready" || bad "the two servers aren't both Ready"
  within 120 pods_up && ok "every pod is running or done without the agent" || bad "pods not running: $($K get pods -A --no-headers 2>/dev/null | grep -vE 'Running|Completed' | head -4 | tr '\n' ';')"
  ;;
esac
echo "=== exit $fail"; exit $fail
