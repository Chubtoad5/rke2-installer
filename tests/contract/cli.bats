#!/usr/bin/env bats
# What ap-tools and the blueprints rely on.
load ../helpers
SCRIPT="$BATS_TEST_DIRNAME/../../rke2_installer.sh"
@test "needs root" {
  run su -s /bin/bash nobody -c "bash '$SCRIPT' install"
  [ "$status" -ne 0 ]
  [[ "$output" == *"root"* ]]
}
@test "the sentinel and archive names stay the same" {
  grep -q 'rke2-save-version.txt' "$SCRIPT"
  grep -q 'rke2-save.tar.gz' "$SCRIPT"
}
@test "every setting ap-tools forwards is still read" {
  for v in RKE2_VERSION CNI_TYPE ENABLE_CIS CLUSTER_CIDR SERVICE_CIDR MAX_PODS INSTALL_INGRESS INSTALL_SERVICELB INSTALL_LOCAL_PATH_PROVISIONER LOCAL_PATH_PROVISIONER_VERSION INSTALL_DNS_UTILITY MGMT_IP NTP_SERVERS COREDNS_HOSTS RKE2_RECONFIGURE; do
    grep -q "^$v=\${$v:-" "$SCRIPT"
  done
}
render() { # render with the given settings, for a first install
  load_script rke2_installer.sh
  JOIN_MODE=0; INSTALL_MODE=1; TLS_SAN_MODE=0
  RKE2_DATA=/var/lib/rancher/rke2; KUBELET_DATA=/var/lib/kubelet; PVC_DATA=/opt/local-path-provisioner
  out=$(mktemp)
  render_rke2_config "$out"
}
@test "INSTALL_INGRESS=false disables the built-in ingress, which ap-tools depends on" {
  INSTALL_INGRESS=false
  export INSTALL_INGRESS
  render
  grep -A1 '^disable:' "$out" | grep -q 'rke2-ingress-nginx'
}
@test "the default keeps the built-in ingress" {
  unset INSTALL_INGRESS
  render
  ! grep -q 'rke2-ingress-nginx' "$out"
}
@test "no download URL for dnsutils.yaml or the upgrade controller names a branch or 'latest'" {
  ! grep -nE 'kubernetes/website/(main|master)/' "$SCRIPT"
  ! grep -n 'system-upgrade-controller/releases/latest' "$SCRIPT"
}
@test "SCRIPT_VERSION is set" {
  grep -qE '^SCRIPT_VERSION="[0-9]+\.[0-9]+\.[0-9]+"' "$SCRIPT"
}
