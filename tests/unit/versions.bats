#!/usr/bin/env bats
# Spec 29: RKE2 versions and the ingress, function by function, with stubs. v1.36.6 is the default; 1.34 and 1.35 must
# render exactly as v1.4.0 did (fixtures/render-v1.4.0, made by its generate.sh). Tests that write under /etc run only as
# root in a container, as CI's unit tier does.
load ../helpers

FIX="$BATS_TEST_DIRNAME/fixtures/render-v1.4.0"

setup() {
  setup_stubs
  load_script rke2_installer.sh
  T=$(mktemp -d)
  TMP_DIR=$T
  stub sleep
  MGMT_IP=192.0.2.10 JOIN_SERVER_FQDN=server.ci.test JOIN_TOKEN=K10test::server:pw
  RKE2_DATA=/var/lib/rancher/rke2 KUBELET_DATA=/var/lib/kubelet
  INSTALL_INGRESS=true INGRESS_CONTROLLER="" JOIN_MODE=0 JOIN_TYPE=""
}

in_container() {
  [[ $EUID -eq 0 && ( -f /run/.containerenv || -f /.dockerenv ) ]] || skip "writes under /etc: root in a container only"
}

# rendered <version>: the config for this invocation, with the host's resolv-conf line written as the fixtures write it
rendered() {
  RKE2_VERSION=$1 render_rke2_config "$T/r.yaml"
  sed -i 's/^  - "resolv-conf=.*"$/  - "resolv-conf=RESOLV"/' "$T/r.yaml"
  cat "$T/r.yaml"
}

# --- The default ---

@test "the default RKE2_VERSION is v1.36.6+rke2r1, and the script says v2.1.0" {
  run bash -c 'grep -E "^RKE2_VERSION=|^SCRIPT_VERSION=" "$1"' _ "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [[ "$output" == *'RKE2_VERSION=${RKE2_VERSION:-"v1.36.6+rke2r1"}'* ]]
  [[ "$output" == *'SCRIPT_VERSION="2.1.0"'* ]]
}

@test "the add-on defaults are spec 31's checked set (Q4)" {
  local f="$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  grep -qF 'VELERO_VERSION=${VELERO_VERSION:-"v1.18.4"}' "$f"
  grep -qF 'VELERO_AWS_PLUGIN_VERSION=${VELERO_AWS_PLUGIN_VERSION:-"v1.14.4"}' "$f"
  grep -qF 'KUBE_PROMETHEUS_STACK_VERSION=${KUBE_PROMETHEUS_STACK_VERSION:-"92.22.0"}' "$f"
  grep -qF 'FLUENT_BIT_CHART_VERSION=${FLUENT_BIT_CHART_VERSION:-"0.58.3"}' "$f"
  grep -qF 'FLUENT_BIT_VERSION=${FLUENT_BIT_VERSION:-"5.1.5"}' "$f"
}

@test "the verified list matches tests/rke2-versions.conf" {
  conf=$(grep -vE '^#|^$' "$BATS_TEST_DIRNAME/../rke2-versions.conf" | grep -E '\|(default|verified|documented)$' | cut -d'|' -f1 | tr '\n' ' ')
  [ "${conf% }" = "$RKE2_VERIFIED_VERSIONS" ]
  [ "$(grep '|default$' "$BATS_TEST_DIRNAME/../rke2-versions.conf" | cut -d'|' -f1)" = v1.36.6+rke2r1 ]
}

@test "rke2_minor reads the minor, and refuses anything else" {
  [ "$(rke2_minor v1.36.6+rke2r1)" = 36 ]
  [ "$(rke2_minor v1.35.10+rke2r1)" = 35 ]
  [ "$(rke2_minor v1.34.5)" = 34 ]
  run rke2_minor stable;           [ "$status" -eq 1 ]; [ -z "$output" ]
  run rke2_minor v2.0.0+rke2r1;    [ "$status" -eq 1 ]
  run rke2_minor "v1.36.6+rke2r1 x"; [ "$status" -eq 1 ]
}

# --- R17 and R24: what's rendered ---

@test "R17/R24: 1.34 and 1.35 render byte for byte as v1.4.0 did, for every ingress setting and role" {
  for v in v1.34.5+rke2r1 v1.35.10+rke2r1; do
    for ic in "" ingress-nginx; do
      INGRESS_CONTROLLER=$ic
      JOIN_MODE=0 JOIN_TYPE="" INSTALL_INGRESS=true;  diff "$FIX/server-ingress.yaml" <(rendered "$v")
      JOIN_MODE=0 JOIN_TYPE="" INSTALL_INGRESS=false; diff "$FIX/server-noingress.yaml" <(rendered "$v")
      JOIN_MODE=1 JOIN_TYPE=server INSTALL_INGRESS=true;  diff "$FIX/joinserver-ingress.yaml" <(rendered "$v")
      JOIN_MODE=1 JOIN_TYPE=server INSTALL_INGRESS=false; diff "$FIX/joinserver-noingress.yaml" <(rendered "$v")
      JOIN_MODE=1 JOIN_TYPE=agent INSTALL_INGRESS=true;   diff "$FIX/agent.yaml" <(rendered "$v")
      JOIN_MODE=1 JOIN_TYPE=agent INSTALL_INGRESS=false;  diff "$FIX/agent-noingress.yaml" <(rendered "$v")
    done
  done
  JOIN_MODE=0 JOIN_TYPE="" INSTALL_INGRESS=false ENABLE_CIS=true TLS_SAN_MODE=1 TLS_SAN=api.ci.test CONTROL_PLANE_TAINT=true
  diff "$FIX/server-noingress-cis-tls.yaml" <(rendered v1.34.5+rke2r1)
}

@test "R17: on 1.36, INSTALL_INGRESS=false disables Traefik as well as ingress-nginx, for an install and a server join" {
  for mode in "0 " "1 server"; do
    read -r JOIN_MODE JOIN_TYPE <<< "$mode"
    INSTALL_INGRESS=false
    out=$(rendered v1.36.6+rke2r1)
    grep -qx 'disable:' <<< "$out"
    [ "$(sed -n '/^disable:$/,/^[^ ]/p' <<< "$out" | grep -c '^  - ')" -eq 2 ]
    grep -qx '  - rke2-ingress-nginx' <<< "$out"
    grep -qx '  - rke2-traefik' <<< "$out"
    ! grep -q 'ingress-controller' <<< "$out" || false
  done
  # The rest of the file is v1.4.0's: only the one line is added.
  JOIN_MODE=0 JOIN_TYPE=""
  diff "$FIX/server-noingress.yaml" <(rendered v1.36.6+rke2r1 | grep -vx '  - rke2-traefik')
}

@test "R24: on 1.36, INGRESS_CONTROLLER writes ingress-controller, and unset writes nothing (RKE2 decides)" {
  INGRESS_CONTROLLER=traefik
  out=$(rendered v1.36.6+rke2r1)
  [ "$(sed -n '/^ingress-controller:$/,+1p' <<< "$out")" = $'ingress-controller:\n  - traefik' ]
  INGRESS_CONTROLLER=ingress-nginx
  out=$(rendered v1.36.6+rke2r1)
  [ "$(sed -n '/^ingress-controller:$/,+1p' <<< "$out")" = $'ingress-controller:\n  - ingress-nginx' ]
  ! grep -q '^disable:' <<< "$out" || false
  INGRESS_CONTROLLER=""
  diff "$FIX/server-ingress.yaml" <(rendered v1.36.6+rke2r1)
}

@test "R24: an agent's config never says anything about the ingress" {
  JOIN_MODE=1 JOIN_TYPE=agent
  for ic in "" traefik ingress-nginx; do
    INGRESS_CONTROLLER=$ic INSTALL_INGRESS=true;  diff "$FIX/agent.yaml" <(rendered v1.36.6+rke2r1)
    INGRESS_CONTROLLER=$ic INSTALL_INGRESS=false; diff "$FIX/agent-noingress.yaml" <(rendered v1.36.6+rke2r1)
  done
}

@test "R24: check_ingress_controller refuses a bad value, and Traefik before 1.36" {
  RKE2_VERSION=v1.36.6+rke2r1 INGRESS_CONTROLLER=nginx
  run check_ingress_controller
  [ "$status" -eq 1 ]; [[ "$output" == *"must be 'traefik', 'ingress-nginx'"* ]]
  RKE2_VERSION=v1.35.10+rke2r1 INGRESS_CONTROLLER=traefik
  run check_ingress_controller
  [ "$status" -eq 1 ]; [[ "$output" == *"needs RKE2 1.36 or later"* ]]
}

@test "R24: ingress-nginx is accepted silently before 1.36, with a warning on 1.36, and refused from 1.37" {
  RKE2_VERSION=v1.35.10+rke2r1 INGRESS_CONTROLLER=ingress-nginx
  run check_ingress_controller
  [ "$status" -eq 0 ]; [ -z "$output" ]
  RKE2_VERSION=v1.36.6+rke2r1
  run check_ingress_controller
  [ "$status" -eq 0 ]; [[ "$output" == *"deprecated"*"1.37"* ]]
  RKE2_VERSION=v1.37.2+rke2r1
  run check_ingress_controller
  [ "$status" -eq 1 ]; [[ "$output" == *"1.37 removed ingress-nginx"* ]]
}

@test "R24: with INSTALL_INGRESS=false, INGRESS_CONTROLLER is ignored, and says so" {
  RKE2_VERSION=v1.36.6+rke2r1 INSTALL_INGRESS=false INGRESS_CONTROLLER=traefik
  run check_ingress_controller
  [ "$status" -eq 0 ]; [[ "$output" == *"is ignored"* ]]
}

# --- R18: upgrade one minor version at a time ---

@test "R18: a skipped minor is refused, naming the verified step between" {
  run minor_step_refusal v1.34.5+rke2r1 v1.34.5+rke2r1 v1.36.6+rke2r1
  [ "$status" -eq 0 ]
  [[ "$output" == *"Upgrade to v1.35.10+rke2r1, then v1.36.6+rke2r1"* ]]
  run minor_step_refusal v1.32.9+rke2r1 v1.32.9+rke2r1 v1.35.10+rke2r1
  [[ "$output" == *"Upgrade to the newest v1.33 release (https://update.rke2.io/v1-release/channels/v1.33), then v1.34.5+rke2r1, then v1.35.10+rke2r1"* ]]
}

@test "R18: a lower minor is refused; a patch and the next minor are accepted" {
  run minor_step_refusal v1.36.6+rke2r1 v1.36.6+rke2r1 v1.35.10+rke2r1
  [ "$status" -eq 0 ]; [[ "$output" == *"older Kubernetes minor"* ]]
  run minor_step_refusal v1.34.5+rke2r1 v1.34.5+rke2r1 v1.34.13+rke2r1;  [ "$status" -eq 1 ]
  run minor_step_refusal v1.34.5+rke2r1 v1.34.5+rke2r1 v1.35.10+rke2r1;  [ "$status" -eq 1 ]
  run minor_step_refusal v1.35.10+rke2r1 v1.35.10+rke2r1 v1.36.6+rke2r1; [ "$status" -eq 1 ]
}

@test "R18: a mixed cluster is judged by its lowest node going up, and its highest going down" {
  run minor_step_refusal v1.34.5+rke2r1 v1.35.10+rke2r1 v1.36.6+rke2r1;  [ "$status" -eq 0 ]
  run minor_step_refusal v1.34.5+rke2r1 v1.35.10+rke2r1 v1.34.13+rke2r1; [ "$status" -eq 0 ]
  run minor_step_refusal v1.34.5+rke2r1 v1.35.10+rke2r1 v1.35.10+rke2r1; [ "$status" -eq 1 ]
}

@test "R18: version_extreme orders by minor, then patch" {
  [ "$(printf 'v1.35.10+rke2r1\nv1.35.9+rke2r1\nv1.34.13+rke2r1\n' | version_extreme min)" = v1.34.13+rke2r1 ]
  [ "$(printf 'v1.35.10+rke2r1\nv1.35.9+rke2r1\nv1.34.13+rke2r1\n' | version_extreme max)" = v1.35.10+rke2r1 ]
  [ -z "$(printf 'junk\n' | version_extreme min)" ]
}

@test "R18: check_upgrade_minor_step reads the nodes, and refuses 1.34 -> 1.36" {
  stub kubectl 'case "$*" in *control-plane*) printf "v1.34.5+rke2r1\n";; *) printf "v1.34.5+rke2r1\nv1.34.5+rke2r1\n";; esac'
  UPGRADE_TYPE=server UPGRADE_VERSION=v1.36.6+rke2r1
  run check_upgrade_minor_step
  [ "$status" -eq 1 ]; [[ "$output" == *"Upgrade to v1.35.10+rke2r1, then v1.36.6+rke2r1"* ]]
  UPGRADE_VERSION=v1.35.10+rke2r1
  run check_upgrade_minor_step
  [ "$status" -eq 0 ]
}

@test "R18: an agent-only upgrade can't take agents past the servers' minor" {
  stub kubectl 'case "$*" in *control-plane*) printf "v1.35.10+rke2r1\n";; *) printf "v1.35.10+rke2r1\nv1.35.10+rke2r1\n";; esac'
  UPGRADE_TYPE=agent UPGRADE_VERSION=v1.36.6+rke2r1
  run check_upgrade_minor_step
  [ "$status" -eq 1 ]; [[ "$output" == *"Upgrade the servers first"* ]]
  UPGRADE_TYPE=both
  run check_upgrade_minor_step
  [ "$status" -eq 0 ]
}

@test "R18: 'stable' is resolved first, and the plan pins that version" {
  resolve_rke2_stable_version() { echo v1.36.6+rke2r1; }
  UPGRADE_VERSION=stable UPGRADE_TYPE=server
  resolve_upgrade_version > "$T/o"
  [ "$UPGRADE_VERSION" = v1.36.6+rke2r1 ]
  stub kubectl 'printf "v1.34.5+rke2r1\n"'
  run check_upgrade_minor_step
  [ "$status" -eq 1 ]
  stub kubectl 'cat > '"$T"'/plan'
  create_upgrade_plan > /dev/null
  grep -q '^  version: v1.36.6+rke2r1$' "$T/plan"
  ! grep -q channel "$T/plan" || false
}

@test "R18: 'stable' that can't be resolved is refused, not left to the cluster" {
  resolve_rke2_stable_version() { :; }
  UPGRADE_VERSION=stable UPGRADE_TYPE=server
  run resolve_upgrade_version
  [ "$status" -eq 1 ]; [[ "$output" == *"Pass an explicit version"* ]]
}

# --- R19: an ingress-off server keeps Traefik off on its way to 1.36 ---

r19_setup() {
  in_container
  rm -rf /etc/rancher/rke2; mkdir -p /etc/rancher/rke2
  RKE2_DATA=$T/data; mkdir -p "$RKE2_DATA/bin"
  JOIN_MODE=0 INSTALL_INGRESS=false RKE2_VERSION=v1.35.10+rke2r1
  render_rke2_config /etc/rancher/rke2/config.yaml
  printf '#!/bin/bash\necho "rke2 version v1.35.10+rke2r1 (abc)"\n' > "$RKE2_DATA/bin/rke2"; chmod +x "$RKE2_DATA/bin/rke2"
  UPGRADE_VERSION=v1.36.6+rke2r1
}

@test "R19: one server: rke2-traefik is added to disable:, and the file is what v2 renders for 1.36" {
  r19_setup
  stub kubectl 'echo "node1   Ready   control-plane,etcd,master   1d   v1.35.10+rke2r1"'
  run keep_ingress_off_for_traefik
  [ "$status" -eq 0 ]; [[ "$output" == *"rke2-traefik was added"* ]]
  RKE2_VERSION=v1.36.6+rke2r1 render_rke2_config "$T/want.yaml"
  diff "$T/want.yaml" /etc/rancher/rke2/config.yaml
  [ -f /etc/rancher/rke2/config.yaml.pre-traefik ]
  run keep_ingress_off_for_traefik
  [ -z "$output" ]
}

@test "R19: more than one server: stops, and prints the line to add on each" {
  r19_setup
  stub kubectl 'printf "n1 Ready cp 1d v1.35.10+rke2r1\nn2 Ready cp 1d v1.35.10+rke2r1\nn3 Ready cp 1d v1.35.10+rke2r1\n"'
  cp /etc/rancher/rke2/config.yaml "$T/before"
  run keep_ingress_off_for_traefik
  [ "$status" -eq 1 ]; [[ "$output" == *"its 3 servers"* ]]; [[ "$output" == *"- rke2-traefik"* ]]
  diff "$T/before" /etc/rancher/rke2/config.yaml
}

@test "R19: nothing changes with the ingress on, a target before 1.36, or a node already on 1.36" {
  r19_setup
  stub kubectl 'echo "node1 Ready cp 1d v1.35.10+rke2r1"'
  cp /etc/rancher/rke2/config.yaml "$T/before"
  UPGRADE_VERSION=v1.35.11+rke2r1; run keep_ingress_off_for_traefik; [ -z "$output" ]
  UPGRADE_VERSION=v1.36.6+rke2r1
  printf '#!/bin/bash\necho "rke2 version v1.36.5+rke2r1 (abc)"\n' > "$RKE2_DATA/bin/rke2"
  run keep_ingress_off_for_traefik; [ -z "$output" ]
  diff "$T/before" /etc/rancher/rke2/config.yaml
  INSTALL_INGRESS=true RKE2_VERSION=v1.35.10+rke2r1 render_rke2_config /etc/rancher/rke2/config.yaml
  printf '#!/bin/bash\necho "rke2 version v1.35.10+rke2r1 (abc)"\n' > "$RKE2_DATA/bin/rke2"
  run keep_ingress_off_for_traefik; [ -z "$output" ]
}

# --- R20: ingress-nginx's images from 1.36 ---

# curl_urls: the release files a run fetched, by name
curl_urls() { grep -o 'releases/download/[^ ]*' "$STUB_LOG" | sed 's#.*/##' | sort -u; }

@test "R20: save fetches ingress-nginx's tarball and list for 1.36, and not for 1.35" {
  WORKING_DIR=$T/w base_dir=$T CNI_NONE=false CNI_TYPE=canal
  mkdir -p "$WORKING_DIR"/{rke2-core-images,rke2-cni-images,rke2-ingress-images}/images "$WORKING_DIR/rke2-binaries"
  stub curl 'while [ $# -gt 0 ]; do [ "$1" = -o ] && : > "$2"; shift; done'
  RKE2_VERSION=v1.36.6+rke2r1 TRANSLATED_VERSION=v1.36.6%2Brke2r1
  download_rke2_binaries > /dev/null
  [[ "$(curl_urls)" == *rke2-images-ingress-nginx.linux-amd64.tar.gz* ]]
  [[ "$(curl_urls)" == *rke2-images-ingress-nginx.linux-amd64.txt* ]]
  [ -f "$WORKING_DIR/rke2-ingress-images/rke2-ingress-nginx-images.tar.gz" ]
  : > "$STUB_LOG"; rm -rf "$WORKING_DIR"/*; mkdir -p "$WORKING_DIR"/{rke2-core-images,rke2-cni-images,rke2-ingress-images}/images "$WORKING_DIR/rke2-binaries"
  RKE2_VERSION=v1.35.10+rke2r1 TRANSLATED_VERSION=v1.35.10%2Brke2r1
  download_rke2_binaries > /dev/null
  [[ "$(curl_urls)" != *ingress-nginx* ]]
  [[ "$(curl_urls)" == *rke2-images-core.linux-amd64.tar.gz* ]]
}

@test "R20: an online push sends ingress-nginx's list for 1.36 only" {
  WORKING_DIR=$T/w AIR_GAPPED_MODE=0 CNI_NONE=false CNI_TYPE=canal REGISTRY_INFO=reg.ci.test:443 REG_USER=u REG_PASS=p
  mkdir -p "$WORKING_DIR"/{rke2-core-images,rke2-cni-images,rke2-ingress-images} "$WORKING_DIR/rke2-utilities"
  printf '#!/bin/bash\necho "ipp $*" >> "$STUB_LOG"\n' > "$WORKING_DIR/rke2-utilities/image_pull_push.sh"; chmod +x "$WORKING_DIR/rke2-utilities/image_pull_push.sh"
  image_pull_push_check() { :; }
  stub curl
  RKE2_VERSION=v1.36.6+rke2r1 TRANSLATED_VERSION=v1.36.6%2Brke2r1
  push_rke2_images > /dev/null
  grep -q 'ipp -f .*rke2-images-ingress-nginx.linux-amd64.txt push' "$STUB_LOG"
  : > "$STUB_LOG"
  RKE2_VERSION=v1.35.10+rke2r1 TRANSLATED_VERSION=v1.35.10%2Brke2r1
  push_rke2_images > /dev/null
  ! grep -q ingress-nginx "$STUB_LOG" || false
}

@test "R20: an air-gapped push sends the bundle's ingress-nginx tarball when it has one" {
  WORKING_DIR=$T/w AIR_GAPPED_MODE=1 CNI_NONE=false CNI_TYPE=canal REGISTRY_INFO=reg.ci.test:443 REG_USER=u REG_PASS=p
  mkdir -p "$WORKING_DIR"/{rke2-core-images,rke2-cni-images,rke2-ingress-images} "$WORKING_DIR/rke2-utilities"
  : > "$WORKING_DIR/rke2-core-images/rke2-core-images.tar.gz"; : > "$WORKING_DIR/rke2-cni-images/rke2-canal-images.tar.gz"
  printf '#!/bin/bash\necho "ipp $*" >> "$STUB_LOG"\n' > "$WORKING_DIR/rke2-utilities/image_pull_push.sh"; chmod +x "$WORKING_DIR/rke2-utilities/image_pull_push.sh"
  push_rke2_images > /dev/null
  ! grep -q ingress "$STUB_LOG" || false
  : > "$WORKING_DIR/rke2-ingress-images/rke2-ingress-nginx-images.tar.gz"
  push_rke2_images > /dev/null
  grep -q 'ipp -f .*rke2-ingress-nginx-images.tar.gz push' "$STUB_LOG"
}

@test "R20: the upgrade push sends ingress-nginx's list for a 1.36 target only" {
  WORKING_DIR=$T/w CNI_NONE=false CNI_TYPE=canal REGISTRY_INFO=reg.ci.test:443 REG_USER=u REG_PASS=p SUC_VERSION=v0.21.0
  mkdir -p "$WORKING_DIR"/{rke2-core-images,rke2-cni-images} "$WORKING_DIR/rke2-utilities/images"
  echo "        image: rancher/system-upgrade-controller:v0.21.0" > "$WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml"
  printf '#!/bin/bash\necho "ipp $*" >> "$STUB_LOG"\n' > "$WORKING_DIR/rke2-utilities/image_pull_push.sh"; chmod +x "$WORKING_DIR/rke2-utilities/image_pull_push.sh"
  image_pull_push_check() { :; }
  stub curl
  UPGRADE_VERSION=v1.36.6+rke2r1 UPGRADE_TYPE=server
  push_upgrade_images > /dev/null
  grep -q 'ipp -f .*rke2-images-ingress-nginx-upgrade.linux-amd64.txt push' "$STUB_LOG"
  grep -q 'releases/download/v1.36.6%2Brke2r1/rke2-images-ingress-nginx.linux-amd64.txt' "$STUB_LOG"
  : > "$STUB_LOG"
  UPGRADE_VERSION=v1.35.10+rke2r1
  push_upgrade_images > /dev/null
  ! grep -q ingress-nginx "$STUB_LOG" || false
}

ingress_bundle() { # a bundle's ingress-nginx archive, as save builds it
  WORKING_DIR=$T/w RKE2_DATA=$T/data
  mkdir -p "$WORKING_DIR/rke2-ingress-images/images" "$WORKING_DIR/rke2-binaries" "$RKE2_DATA/agent/images"
  echo img > "$WORKING_DIR/rke2-ingress-images/images/rke2-images-ingress-nginx.linux-amd64.tar.gz"
  (cd "$WORKING_DIR/rke2-ingress-images" && tar czf rke2-ingress-nginx-images.tar.gz --remove-files images)
}

@test "R20: air-gapped, INGRESS_CONTROLLER=ingress-nginx puts its images in agent/images; Traefik's install doesn't" {
  ingress_bundle
  RKE2_VERSION=v1.36.6+rke2r1 INGRESS_CONTROLLER=traefik
  install_ingress_nginx_images > /dev/null
  [ ! -e "$RKE2_DATA/agent/images/rke2-images-ingress-nginx.linux-amd64.tar.gz" ]
  INGRESS_CONTROLLER=ingress-nginx
  install_ingress_nginx_images > /dev/null
  [ "$(cat "$RKE2_DATA/agent/images/rke2-images-ingress-nginx.linux-amd64.tar.gz")" = img ]
}

@test "R20: air-gapped, any join from a 1.36 bundle takes ingress-nginx's images too" {
  ingress_bundle
  RKE2_VERSION=v1.36.6+rke2r1 JOIN_MODE=1 JOIN_TYPE=agent
  install_ingress_nginx_images > /dev/null
  [ -f "$RKE2_DATA/agent/images/rke2-images-ingress-nginx.linux-amd64.tar.gz" ]
}

@test "R20: INGRESS_CONTROLLER=ingress-nginx from a bundle without its images stops, and says to save again" {
  WORKING_DIR=$T/w RKE2_DATA=$T/data; mkdir -p "$WORKING_DIR/rke2-ingress-images"
  RKE2_VERSION=v1.36.6+rke2r1 INGRESS_CONTROLLER=ingress-nginx
  run install_ingress_nginx_images
  [ "$status" -eq 1 ]; [[ "$output" == *"no ingress-nginx images"*"save"* ]]
  INGRESS_CONTROLLER=""
  run install_ingress_nginx_images
  [ "$status" -eq 0 ]
}

# --- R22: the bundle's notices ---

@test "R22: a 1.36 bundle's notices name Traefik, MIT; a 1.35 bundle's don't" {
  base_dir=$T WORKING_DIR=$T/w PUSH_SAVE_MONITORING=false; mkdir -p "$WORKING_DIR"
  RKE2_VERSION=v1.36.6+rke2r1 generate_bundle_licenses > /dev/null
  grep -q 'Traefik.*MIT' "$T/LICENSES/THIRD_PARTY_NOTICES.txt"
  RKE2_VERSION=v1.35.10+rke2r1 generate_bundle_licenses > /dev/null
  ! grep -q Traefik "$T/LICENSES/THIRD_PARTY_NOTICES.txt" || false
}

# --- R23: the new default meets existing clusters ---

r23_running() { # a node "running" <version>
  RKE2_DATA=$T/data; mkdir -p "$RKE2_DATA/bin"
  printf '#!/bin/bash\necho "rke2 version %s (abc)"\n' "$1" > "$RKE2_DATA/bin/rke2"; chmod +x "$RKE2_DATA/bin/rke2"
  stub systemctl '[ "$1" = is-active ] && [[ "$*" == *rke2-server* ]] && exit 0; exit 1'
}

@test "R23: a re-run without RKE2_VERSION on a 1.34 node says to set the running version, and names the step, not the jump" {
  r23_running v1.34.5+rke2r1
  INSTALL_MODE=1 RKE2_VERSION=v1.36.6+rke2r1 RKE2_VERSION_GIVEN=""
  run reconcile_existing_install
  [ "$status" -eq 1 ]
  [[ "$output" == *"set RKE2_VERSION=v1.34.5+rke2r1"* ]]
  [[ "$output" == *"Before v2.0.0 the default was v1.34.5+rke2r1"* ]]
  [[ "$output" == *"Upgrade to v1.35.10+rke2r1, then v1.36.6+rke2r1"* ]]
  [[ "$output" != *"upgrade [server|agent|both] v1.36.6+rke2r1"* ]]
}

@test "R23: a re-run asking for the next minor names that upgrade" {
  r23_running v1.35.10+rke2r1
  INSTALL_MODE=1 RKE2_VERSION=v1.36.6+rke2r1 RKE2_VERSION_GIVEN=v1.36.6+rke2r1
  run reconcile_existing_install
  [ "$status" -eq 1 ]
  [[ "$output" == *"set RKE2_VERSION=v1.35.10+rke2r1"* ]]
  [[ "$output" == *"upgrade [server|agent|both] v1.36.6+rke2r1"* ]]
  [[ "$output" != *"Before v2.0.0"* ]]
}

@test "R23: join without RKE2_VERSION takes the cluster's version" {
  server_version() { echo v1.34.5+rke2r1; }
  RKE2_VERSION=v1.36.6+rke2r1 RKE2_VERSION_GIVEN="" JOIN_MODE=1 JOIN_TYPE=agent
  resolve_join_version > "$T/o"
  [ "$RKE2_VERSION" = v1.34.5+rke2r1 ]
  [ "$TRANSLATED_VERSION" = v1.34.5%2Brke2r1 ]
  grep -q "joining with the cluster's version, v1.34.5+rke2r1" "$T/o"
}

@test "R23: join with RKE2_VERSION a newer minor than the cluster's is refused; an older or equal one goes on" {
  server_version() { echo v1.34.5+rke2r1; }
  RKE2_VERSION=v1.36.6+rke2r1 RKE2_VERSION_GIVEN=v1.36.6+rke2r1 JOIN_MODE=1 JOIN_TYPE=server
  run resolve_join_version
  [ "$status" -eq 1 ]; [[ "$output" == *"Join with RKE2_VERSION=v1.34.5+rke2r1"* ]]
  RKE2_VERSION=v1.34.13+rke2r1 RKE2_VERSION_GIVEN=v1.34.13+rke2r1
  run resolve_join_version
  [ "$status" -eq 0 ]; [[ "$output" == *"the cluster runs v1.34.5+rke2r1"* ]]
}

@test "R23: join warns and goes on when the cluster's version can't be read" {
  server_version() { echo "no answer"; return 1; }
  RKE2_VERSION=v1.36.6+rke2r1 RKE2_VERSION_GIVEN="" JOIN_MODE=1 JOIN_TYPE=agent
  run resolve_join_version
  [ "$status" -eq 0 ]; [[ "$output" == *"WARNING: couldn't read the cluster's version: no answer"* ]]
  [[ "$output" == *"installer's default, v1.36.6+rke2r1"* ]]
}

# server_version's curl: the CA, the client certificate and /version, by URL. CA_PEM is what /cacerts answers.
server_stub() {
  CA_PEM=$'-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'
  printf '%s\n' "$CA_PEM" > "$T/ca"
  stub curl 'out=""; url=""; while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift;; https://*) url=$1;; esac; shift; done
  [ "$url" != "${url%/cacerts}" ] && cat '"$T"'/ca > "$out"
  [ "$url" != "${url%client-kube-proxy.crt}" ] && { cat > '"$T"'/curl-config; printf "%s\n" "-----BEGIN EC PRIVATE KEY-----" > "$out"; }
  [ "$url" != "${url%/version}" ] && printf "{\n  \"major\": \"1\",\n  \"gitVersion\": \"v1.34.5+rke2r1\",\n}\n"
  exit 0'
}

@test "R23: server_version checks the CA against the token's hash, then reads /version with the kube-proxy certificate" {
  server_stub
  hash=$(sha256sum < "$T/ca" | awk '{print $1}')
  run server_version server.ci.test "K10${hash}::server:s3cret"
  [ "$status" -eq 0 ]; [ "$output" = v1.34.5+rke2r1 ]
  grep -qx 'user = "node:s3cret"' "$T/curl-config"
  ! grep -q s3cret "$STUB_LOG" || false
  [ ! -d "$T/server-version" ]
}

@test "R23: server_version refuses a CA that doesn't match the token, before sending it" {
  server_stub
  run server_version server.ci.test "K10$(printf '0%.0s' {1..64})::server:s3cret"
  [ "$status" -eq 1 ]; [[ "$output" == *"doesn't match the join token's hash"* ]]
  ! grep -q client-kube-proxy "$STUB_LOG" || false
}

# --- The bundle's version, air-gapped ---

@test "air-gapped: the bundle's version is used when RKE2_VERSION isn't set, and a different one is refused" {
  base_dir=$T
  printf '# RKE2 Version: v1.35.10+rke2r1\n' > "$T/rke2-save-version.txt"
  RKE2_VERSION=v1.36.6+rke2r1 RKE2_VERSION_GIVEN=""
  bundle_version_check
  [ "$RKE2_VERSION" = v1.35.10+rke2r1 ]; [ "$TRANSLATED_VERSION" = v1.35.10%2Brke2r1 ]
  RKE2_VERSION=v1.36.6+rke2r1 RKE2_VERSION_GIVEN=v1.36.6+rke2r1
  run bundle_version_check
  [ "$status" -eq 1 ]; [[ "$output" == *"the bundle in $T is for v1.35.10+rke2r1"* ]]
  [[ "$output" == *"Set RKE2_VERSION=v1.35.10+rke2r1"* ]]
  RKE2_VERSION=v1.35.10+rke2r1 RKE2_VERSION_GIVEN=v1.35.10+rke2r1
  run bundle_version_check
  [ "$status" -eq 0 ]
}

# --- R26: a custom RKE2_DATA on an SELinux-enforcing host ---

@test "R26: a custom RKE2_DATA gets /var/lib/rancher/rke2's labels, recorded for uninstall; trailing slashes trimmed" {
  STATE_FILE=$T/state SELINUX_ENFORCING=true RKE2_DATA=$T/opt-rke2/
  stub semanage
  stub restorecon
  stub matchpathcon 'echo "$2 system_u:object_r:var_lib_t:s0"; exit 1'
  run label_custom_data_dir
  [ "$status" -eq 0 ]
  called "semanage fcontext -a -e /var/lib/rancher/rke2 $T/opt-rke2"
  called "restorecon -R $T/opt-rke2"
  grep -qx "RKE2I_SELINUX_EQUIV=\"$T/opt-rke2\"" "$T/state"
}

@test "R26: a path already labelled right (its own rule or a parent's) gets no rule, no record, and no relabel" {
  STATE_FILE=$T/state SELINUX_ENFORCING=true RKE2_DATA=$T/opt-rke2
  stub semanage
  stub restorecon
  stub matchpathcon '[ "$1" = -n ] && echo "system_u:object_r:rke2_service_db_file_t:s0"; exit 0'
  run label_custom_data_dir
  [ "$status" -eq 0 ]; [[ "$output" == *"already has"* ]]
  ! called "semanage" || false
  ! called "restorecon" || false
  [ ! -f "$T/state" ]
}

@test "R26: semanage refusing the rule is a warning, not a failed install" {
  STATE_FILE=$T/state SELINUX_ENFORCING=true RKE2_DATA=$T/opt-rke2
  stub semanage 'exit 1'
  stub restorecon
  stub matchpathcon 'echo "x"; exit 1'
  run label_custom_data_dir
  [ "$status" -eq 0 ]; [[ "$output" == *"WARNING: semanage couldn't"* ]]
  [ ! -f "$T/state" ]
}

@test "R26: install refuses RKE2_DATA=/ and a relative path, before anything" {
  for d in / // rke2 ./rke2; do
    run env RKE2_DATA="$d" bash "$BATS_TEST_DIRNAME/../../rke2_installer.sh" install
    [ "$status" -eq 1 ]
    [[ "$output" == *"must be 'default' or an absolute path other than /"* || "$output" == *"root privileges"* ]]
  done
}

@test "R26: nothing is labelled for the default path, or with SELinux not enforcing" {
  STATE_FILE=$T/state
  stub semanage; stub restorecon
  SELINUX_ENFORCING=true RKE2_DATA=/var/lib/rancher/rke2/ label_custom_data_dir
  SELINUX_ENFORCING=false RKE2_DATA=$T/opt-rke2 label_custom_data_dir
  [ ! -s "$STUB_LOG" ]
}

@test "R26: every install path labels after the host settings and before the service starts, outside run_debug" {
  body=$(sed -n '/^run_install () {/,/^}/p' "$BATS_TEST_DIRNAME/../../rke2_installer.sh")
  [ "$(grep -cx ' *label_custom_data_dir' <<< "$body")" -eq 3 ]
  [ "$(grep -A1 'run_debug config_host_settings' <<< "$body" | grep -cx ' *label_custom_data_dir')" -eq 3 ]
  [ "$(grep -A1 -x ' *label_custom_data_dir' <<< "$body" | grep -c 'start_rke2_service')" -eq 3 ]
}

@test "R26: uninstall removes only the equivalence install recorded" {
  grep -q 'semanage fcontext -d -e /var/lib/rancher/rke2 "$RKE2I_SELINUX_EQUIV"' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
}
