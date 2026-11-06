#!/usr/bin/env bats
# The Day-2 fixes (v1.1.0), function by function, with stubs. Tests that write under /etc run only as root in a
# container, as CI's unit tier does, so they can't touch a real host.
load ../helpers

setup() {
  setup_stubs
  load_script rke2_installer.sh
  T=$(mktemp -d)
  stub sleep
}

in_container() {
  [[ $EUID -eq 0 && ( -f /run/.containerenv || -f /.dockerenv ) ]] || skip "writes under /etc: root in a container only"
}

# --- R1: a failed fetch leaves the working CA alone ---

registry_setup() {
  REGISTRY_MODE=1 REGISTRY_INFO=reg.x.lab:443 REG_FQDN=reg.x.lab REG_PORT=443 REG_USER=u REG_PASS=p
  CA=/etc/rancher/rke2/certs.d/reg.x.lab:443/ca.crt
  rm -rf /etc/rancher/rke2; mkdir -p "$(dirname "$CA")"
  echo "old-good-ca" > "$CA"
}

@test "R1: a connection that fails leaves the existing ca.crt as it was" {
  in_container; registry_setup
  stub openssl 'exit 1'
  run create_registry_config
  [ "$status" -eq 1 ]
  [[ "$output" == *"left unchanged"* ]]
  [ "$(cat "$CA")" = old-good-ca ]
}

@test "R1: a connection that returns no certificate is an error, not 'Certificate saved'" {
  in_container; registry_setup
  stub openssl '[ "$1" = x509 ] && exit 1; exit 0'
  run create_registry_config
  [ "$status" -eq 1 ]
  [[ "$output" != *"Certificate saved"* ]]
  [ "$(cat "$CA")" = old-good-ca ]
}

@test "R1: a good certificate replaces ca.crt, mode 644" {
  in_container; registry_setup
  stub openssl '[ "$1" = s_client ] && printf "%s\n" "-----BEGIN CERTIFICATE-----" "new" "-----END CERTIFICATE-----"; exit 0'
  run create_registry_config
  [ "$status" -eq 0 ]
  grep -q '^new$' "$CA"
  [ "$(stat -c %a "$CA")" = 644 ]
}

# --- R2: save leaves no sentinel in the folder ---

@test "R2: save removes rke2-save-version.txt from the folder once the archive holds it" {
  base_dir=$T WORKING_DIR=$T/rke2-install
  mkdir -p "$WORKING_DIR" "$T/LICENSES"
  generate_bundle_licenses() { :; }
  stub tar 'echo "$@" > '"$T"'/tar-args; : > "$2"'
  create_save_archive
  [ ! -e "$T/rke2-save-version.txt" ]
  [ -e "$T/rke2-save.tar.gz" ]
  grep -q 'rke2-save-version.txt' "$T/tar-args"
}

@test "R2: the archive's sentinel names its CNI type" {
  base_dir=$T WORKING_DIR=$T/rke2-install CNI_TYPE=calico
  mkdir -p "$WORKING_DIR" "$T/LICENSES"
  generate_bundle_licenses() { :; }
  stub tar 'cp '"$T"'/rke2-save-version.txt '"$T"'/kept; : > "$2"'
  create_save_archive
  grep -qx '# CNI Type: calico' "$T/kept"
}

# The sentinel check runs in the main flow, so these run the script itself, as root, up to that check.
@test "R2: a sentinel with no extracted bundle is refused for install, with the ways out" {
  in_container
  cd "$T"; touch rke2-save-version.txt
  run bash "$BATS_TEST_DIRNAME/../../rke2_installer.sh" install
  [ "$status" -eq 1 ]
  [[ "$output" == *"no extracted bundle"* && "$output" == *"RKE2_FORCE_ONLINE=true"* ]]
}

@test "R2: RKE2_FORCE_ONLINE=true gets past a stale sentinel" {
  in_container
  cd "$T"; touch rke2-save-version.txt
  # It goes on to install, so it's time-limited: CI's container has no network, so it soon fails after the check.
  run timeout 60 env RKE2_FORCE_ONLINE=true bash "$BATS_TEST_DIRNAME/../../rke2_installer.sh" install
  [[ "$output" == *"RKE2_FORCE_ONLINE=true: staying online"* ]]
  [[ "$output" != *"no extracted bundle"* ]]
}

# --- R3: CNI_TYPE=none, and a bundle saved for another CNI ---

airgap_setup() {
  AIR_GAPPED_MODE=1 WORKING_DIR=$T/w base_dir=$T RKE2_DATA=$T/data
  mkdir -p "$WORKING_DIR"/{rke2-core-images/images,rke2-cni-images,rke2-binaries,rke2-utilities} "$RKE2_DATA/agent/images"
  stub tar 'mkdir -p '"$T"'/w/rke2-core-images/images '"$T"'/w/rke2-cni-images/images; touch '"$T"'/w/rke2-core-images/images/rke2-images-core.linux-amd64.tar.gz '"$T"'/w/rke2-cni-images/images/rke2-images-canal.linux-amd64.tar.gz'
  : > "$WORKING_DIR/rke2-core-images/rke2-core-images.tar.gz"
  select_newest() { return 1; }
}

@test "R3: an air-gapped CNI_TYPE=none install doesn't look for CNI images" {
  airgap_setup
  CNI_TYPE=none CNI_NONE=true
  run install_rke2_binaries
  ! called "rke2-none-images"
  [[ "$output" != *"no images for CNI_TYPE"* ]]
}

@test "R3: a bundle without this CNI's images is a clear error naming the bundle's CNI" {
  airgap_setup
  CNI_TYPE=canal CNI_NONE=false
  echo "# CNI Type: calico" > "$T/rke2-save-version.txt"
  run install_rke2_binaries
  [ "$status" -eq 1 ]
  [[ "$output" == *"no images for CNI_TYPE=canal (it was saved with CNI_TYPE=calico)"* ]]
}

# --- R4: the upgrade image for the bundle's own version; the registry check ---

@test "R4: the bundle lists rke2-upgrade for RKE2_VERSION, whatever stable is" {
  WORKING_DIR=$T; mkdir -p "$T/rke2-utilities/images"
  RKE2_VERSION=v1.34.5+rke2r1
  stub curl 'printf "        image: rancher/system-upgrade-controller:v0.21.0\n" > "${@: -1}"'
  resolve_rke2_stable_version() { echo v1.36.6+rke2r1; }
  download_upgrade_artifacts
  grep -qx 'rancher/rke2-upgrade:v1.34.5-rke2r1' "$T/rke2-utilities/images/utility-images.txt"
  grep -qx 'rancher/rke2-upgrade:v1.36.6-rke2r1' "$T/rke2-utilities/images/utility-images.txt"
  resolve_rke2_stable_version() { :; }
  : > "$T/rke2-utilities/images/utility-images.txt"
  download_upgrade_artifacts 2>/dev/null
  grep -qx 'rancher/rke2-upgrade:v1.34.5-rke2r1' "$T/rke2-utilities/images/utility-images.txt"
}

@test "R4: the bundle holds the kubectl image the upgrade jobs cordon with" {
  WORKING_DIR=$T; mkdir -p "$T/rke2-utilities/images"
  RKE2_VERSION=v1.34.5+rke2r1
  stub curl 'printf "  SYSTEM_UPGRADE_JOB_KUBECTL_IMAGE: rancher/kubectl:v1.30.3\n        image: rancher/system-upgrade-controller:v0.21.0\n" > "${@: -1}"'
  resolve_rke2_stable_version() { :; }
  download_upgrade_artifacts 2>/dev/null
  grep -qx 'rancher/kubectl:v1.30.3' "$T/rke2-utilities/images/utility-images.txt"
}

@test "R4: system-upgrade-controller comes from SUC_VERSION, not latest" {
  WORKING_DIR=$T; mkdir -p "$T/rke2-utilities/images"
  SUC_VERSION=v0.99.0
  stub curl ': > "${@: -1}"'
  resolve_rke2_stable_version() { :; }
  download_upgrade_artifacts 2>/dev/null
  called "releases/download/v0.99.0/crd.yaml"
  ! called "releases/latest"
}

reg_check() { # reg_check <curl output: body then a code line>
  REGISTRY_INFO=reg.x.lab:443 REG_FQDN=reg.x.lab REG_PORT=443 REG_USER=u REG_PASS='p"w\x' UPGRADE_VERSION=v1.34.5+rke2r1
  printf '%s' "$1" > "$T/resp"
  stub curl 'cat > '"$T"'/curl-config; cat '"$T"'/resp'
  run check_upgrade_image_in_registry
}

@test "R4: an air-gapped upgrade goes on when the registry has the tag" {
  reg_check $'{"name":"rancher/rke2-upgrade","tags":["v1.34.5-rke2r1"]}\n200'
  [ "$status" -eq 0 ]
  [[ "$output" == *"The registry has rancher/rke2-upgrade:v1.34.5-rke2r1"* ]]
}

@test "R4: it refuses when the registry lacks the tag, or the image" {
  reg_check $'{"name":"rancher/rke2-upgrade","tags":["v1.36.6-rke2r1"]}\n200'
  [ "$status" -eq 1 ]
  [[ "$output" == *"has no rancher/rke2-upgrade:v1.34.5-rke2r1"* ]]
  reg_check $'{"errors":[{"code":"NAME_UNKNOWN"}]}\n404'
  [ "$status" -eq 1 ]
}

@test "R4: an answer it can't read is a warning, not a refusal" {
  reg_check $'unauthorized\n401'
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING: couldn't check the registry"* ]]
}

@test "R4: the registry password goes to curl on stdin, escaped, not in its arguments" {
  reg_check $'{"tags":["v1.34.5-rke2r1"]}\n200'
  ! grep -q 'p"w' "$STUB_LOG"
  grep -qF 'user = "u:p\"w\\x"' "$T/curl-config"
}

# --- R6 ---

@test "R6: when stable can't be resolved, the message says to pass a version on the command line" {
  WORKING_DIR=$T; mkdir -p "$T/rke2-utilities/images"
  UPGRADE_VERSION=stable UPGRADE_TYPE=both
  image_pull_push_check() { :; }
  resolve_rke2_stable_version() { :; }
  run push_upgrade_images
  [ "$status" -eq 1 ]
  [[ "$output" == *"Pass an explicit version instead"* && "$output" == *"upgrade both v1.34.5+rke2r1"* ]]
  [[ "$output" != *"Set UPGRADE_VERSION"* ]]
}

# --- R7: UPGRADE_WAIT ---

@test "R7: UPGRADE_WAIT returns once every node runs the version and is schedulable" {
  UPGRADE_VERSION=v1.34.5+rke2r1 UPGRADE_TYPE=both UPGRADE_WAIT_TIMEOUT=60
  echo 0 > "$T/n"
  stub kubectl 'n=$(cat '"$T"'/n); echo $((n + 1)) > '"$T"'/n; if [ "$n" -lt 2 ]; then printf "a=v1.33.4+rke2r1=\nb=v1.34.5+rke2r1=true\n"; else printf "a=v1.34.5+rke2r1=\nb=v1.34.5+rke2r1=\n"; fi'
  run wait_for_upgrade
  [ "$status" -eq 0 ]
  [[ "$output" == *"schedulable again"* ]]
  [ "$(cat "$T/n")" -ge 3 ]
}

@test "R7: UPGRADE_WAIT fails on timeout, naming the nodes behind" {
  UPGRADE_VERSION=v1.34.5+rke2r1 UPGRADE_TYPE=server UPGRADE_WAIT_TIMEOUT=0
  stub kubectl 'printf "cp1=v1.33.4+rke2r1=\n"'
  run wait_for_upgrade
  [ "$status" -eq 1 ]
  [[ "$output" == *"cp1"* ]]
  called "node-role.kubernetes.io/control-plane=true"
}

@test "R7: UPGRADE_WAIT treats an empty node list as not done" {
  UPGRADE_VERSION=v1.34.5+rke2r1 UPGRADE_TYPE=both UPGRADE_WAIT_TIMEOUT=0
  stub kubectl 'exit 0'
  run wait_for_upgrade
  [ "$status" -eq 1 ]
}

# --- R8, R9 ---

@test "R8: a run without -registry warns, naming the registry the node uses" {
  in_container
  rm -rf /etc/rancher/rke2; mkdir -p /etc/rancher/rke2
  printf 'mirrors:\n  docker.io:\n    endpoint:\n      - "https://reg.x.lab:443"\n' > /etc/rancher/rke2/registries.yaml
  REGISTRY_MODE=0
  run warn_registry_not_passed
  [[ "$output" == *"WARNING: no -registry given"* && "$output" == *"https://reg.x.lab:443"* ]]
  REGISTRY_MODE=1
  run warn_registry_not_passed
  [ -z "$output" ]
}

@test "R9: an agent names the server-only settings it ignores, and only those that were changed" {
  JOIN_MODE=1 JOIN_TYPE=agent CLUSTER_CIDR=10.99.0.0/16 PVC_DATA=/opt/local-path-provisioner
  run warn_agent_ignored_settings
  [[ "$output" == *"this agent ignores CLUSTER_CIDR:"* ]]
  [[ "$output" != *PVC_DATA* && "$output" != *SERVICE_CIDR* ]]
  CLUSTER_CIDR=10.42.0.0/16
  run warn_agent_ignored_settings
  [ -z "$output" ]
  JOIN_TYPE=server CLUSTER_CIDR=10.99.0.0/16
  run warn_agent_ignored_settings
  [ -z "$output" ]
}

# --- R11: iptables ---

@test "R11: a server install with the built-in ingress requires iptables" {
  INSTALL_MODE=1 INSTALL_TYPE=rke2 JOIN_MODE=0 JOIN_TYPE="" INSTALL_INGRESS=true AIR_GAPPED_MODE=1 REGISTRY_MODE=0
  require_cmds() { echo "REQUIRE $*"; }
  run preflight_checks
  [[ "$output" == *"REQUIRE"*"iptables"* ]]
}

@test "R11: with the ingress off, or on an agent, a missing iptables only warns" {
  INSTALL_MODE=1 INSTALL_TYPE=rke2 JOIN_MODE=0 JOIN_TYPE="" INSTALL_INGRESS=false AIR_GAPPED_MODE=1 REGISTRY_MODE=0
  require_cmds() { echo "REQUIRE $*"; }
  # This host may have iptables: hide it from the lookup only. Shrinking PATH would break bats' own cleanup.
  command() { if [[ "$1" == -v && "$2" == iptables ]]; then return 1; fi; builtin command "$@"; }
  run preflight_checks
  [[ "$output" == *"WARNING: iptables isn't installed"* ]]
  [[ "$(grep REQUIRE <<< "$output")" != *iptables* ]]
  INSTALL_MODE=0 JOIN_MODE=1 JOIN_TYPE=agent INSTALL_INGRESS=true
  run preflight_checks
  [[ "$(grep REQUIRE <<< "$output")" != *iptables* ]]
  [[ "$output" == *"WARNING: iptables isn't installed"* ]]
}

@test "R11: uninstall, save and upgrade don't need iptables" {
  INSTALL_MODE=0 JOIN_MODE=0 INSTALL_INGRESS=true AIR_GAPPED_MODE=1 REGISTRY_MODE=0
  require_cmds() { echo "REQUIRE $*"; }
  run preflight_checks
  [[ "$output" != *iptables* ]]
}

# --- RC1: a server change, only for the cluster the node is already in ---

A=1b9e9bb201773f85a6213deb818a7a8717599100b4e30030a1286cb1e2dcb4e0
B=2c0f0cc312884f96b7324efc929b8b9828600211c5f41141b2397dc2f3edc5f1
serves() { # serves <hash>: the new server's /cacerts body, and sha256sum reporting that hash
  stub curl 'while [ $# -gt 0 ]; do [ "$1" = -o ] && { printf "ca-bundle" > "$2"; shift; }; shift; done'
  stub sha256sum 'echo "'"$1"'  file"'
}

@test "RC1: a new address serving the CA of the node's current cluster is the same cluster" {
  serves "$A"
  same_cluster_server cp-new.x.lab "K10${A}::server:secret" "K10${A}::server:secret"
  called "https://cp-new.x.lab:9345/cacerts"
}

@test "RC1: another cluster's real server and token, passed together, are refused" {
  serves "$B"
  ! same_cluster_server cp-b.x.lab "K10${B}::server:other" "K10${A}::server:secret"
  [[ "$SAME_CLUSTER_WHY" == *"different cluster"* ]]
}

@test "RC1: a server with another cluster's CA is refused, even with the node's own token" {
  serves "$B"
  ! same_cluster_server cp-b.x.lab "K10${A}::server:secret" "K10${A}::server:secret"
  [[ "$SAME_CLUSTER_WHY" == *"another cluster's"* ]]
}

@test "RC1: a current token with no CA hash can't prove the cluster" {
  serves "$A"
  ! same_cluster_server cp-new.x.lab "K10${A}::server:secret" "plain-shared-secret"
  [[ "$SAME_CLUSTER_WHY" == *"current join token has no CA hash"* ]]
}

@test "RC1: an unreachable server is reported as unreachable" {
  stub curl 'exit 7'
  ! same_cluster_server cp-new.x.lab "K10${A}::server:secret" "K10${A}::server:secret"
  [[ "$SAME_CLUSTER_WHY" == *"couldn't be read"* ]]
}

# --- RC2 ---

@test "RC2: the server plan tolerates the control-plane taint; the agent plan doesn't need to" {
  UPGRADE_VERSION=v1.34.5+rke2r1 UPGRADE_TYPE=both
  stub kubectl 'cat >> '"$T"'/plans'
  create_upgrade_plan
  awk '/name: server-plan/,/^PLANEND/' "$T/plans" | sed '/name: agent-plan/,$d' > "$T/server"
  grep -q 'key: node-role.kubernetes.io/control-plane' "$T/server"
  grep -q 'operator: Exists' "$T/server"
  sed -n '/name: agent-plan/,$p' "$T/plans" | grep -vq 'tolerations:'
}
