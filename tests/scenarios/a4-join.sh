#!/bin/bash
# A4 on a node that joins the first server. CI_ROLE server2 joins as a server, agent as an agent. By CI_STEP:
#   server2, agent  join, then this node is Ready in the cluster
#   agent.2         uninstall the agent, and hand on its node name so the server can remove it
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=/var/tmp/a4; mkdir -p "$W"; cd "$W" || exit 1
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig $CI_HANDOFF/kubeconfig"
. /etc/os-release
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then export RKE2_SELINUX_FALLBACK=permissive; fi
export DEBUG=0 INSTALL_INGRESS=false
kind=server; svc=rke2-server
[ "$CI_ROLE" = agent ] && { kind=agent; svc=rke2-agent; }
me=$(hostname)
ready() { $K get node "$me" --no-headers 2>/dev/null | grep -qw Ready; }

case "${CI_STEP:-$CI_ROLE}" in
server2 | agent)
  cp "$REPO/rke2_installer.sh" .; chmod +x rke2_installer.sh
  ./rke2_installer.sh join "$kind" "${CI_ROLE_SERVER_IP:?}" "$(cat "$CI_HANDOFF/token")" > o 2>&1 && ok "join as a$([ $kind = agent ] && echo "n") $kind" \
    || { bad "join as $kind"; tail -10 o | cut -c1-170; echo "=== exit 1"; exit 1; }
  systemctl is-active -q "$svc" && ok "$svc is running" || bad "$svc isn't running"
  within 300 ready && ok "this node ($me) is Ready in the cluster" || bad "this node ($me) isn't Ready: $($K get nodes --no-headers 2>&1 | tr '\n' ';' | cut -c1-160)"
  ;;
agent.2)
  echo "$me" > "$CI_HANDOFF/agent-node"
  ./rke2_installer.sh uninstall > o2 2>&1 && ok "uninstall the agent" || { bad "uninstall the agent"; tail -6 o2 | cut -c1-170; }
  systemctl is-active -q rke2-agent && bad "rke2-agent is still running" || ok "rke2-agent is gone"
  ;;
esac
echo "=== exit $fail"; exit $fail
