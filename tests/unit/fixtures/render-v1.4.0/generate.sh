#!/bin/bash
# Renders /etc/rancher/rke2/config.yaml with v1.4.0's render_rke2_config, for the settings tests/unit/versions.bats
# compares with: spec 29 says 1.34 and 1.35 render exactly as before. Run once, from the repo root, with v1.4.0's
# script as $1 (git show v1.4.0:rke2_installer.sh > /tmp/v140.sh). The resolv-conf line depends on the host, so it's
# written as RESOLV, and the tests do the same to theirs.
set -euo pipefail
src=$1 out=tests/unit/fixtures/render-v1.4.0
render() { # render <file> <ingress> <join mode> <join type> [extra settings...]
  local f=$1; shift
  bash -c '
    set -e; source "$1"; trap - EXIT; set +u
    INSTALL_INGRESS=$2 JOIN_MODE=$3 JOIN_TYPE=$4; shift 4
    for kv in "$@"; do eval "$kv"; done
    MGMT_IP=192.0.2.10 JOIN_SERVER_FQDN=server.ci.test JOIN_TOKEN=K10test::server:pw RKE2_DATA=/var/lib/rancher/rke2 KUBELET_DATA=/var/lib/kubelet
    render_rke2_config /dev/stdout; rmdir "$TMP_DIR"' _ "$src" "$@" | sed 's/^  - "resolv-conf=.*"$/  - "resolv-conf=RESOLV"/' > "$out/$f"
}
render server-ingress.yaml true 0 ""
render server-noingress.yaml false 0 ""
render server-noingress-cis-tls.yaml false 0 "" ENABLE_CIS=true TLS_SAN_MODE=1 TLS_SAN=api.ci.test CONTROL_PLANE_TAINT=true
render joinserver-ingress.yaml true 1 server
render joinserver-noingress.yaml false 1 server
render agent.yaml true 1 agent
render agent-noingress.yaml false 1 agent
