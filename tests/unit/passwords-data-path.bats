#!/usr/bin/env bats
# Spec 20: R12, the registry user and password pass whole (escaped in registries.yaml, quoted on every push); R13,
# uninstall gives Rancher's uninstaller the data path; R14, the API-server wait finds kubectl under a custom data path.
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

# yaml_auth <field>: that field of registries.yaml's one auth block, as Python's YAML parser reads it
yaml_auth() {
  python3 -I -c 'import sys, yaml
d = yaml.safe_load(open("/etc/rancher/rke2/registries.yaml"))
sys.stdout.write(list(d["configs"].values())[0]["auth"][sys.argv[1]])' "$1"
}

write_registries() { # write_registries <user> <password>
  REGISTRY_MODE=1 REGISTRY_INFO=reg.x.lab:443 REG_FQDN=reg.x.lab REG_PORT=443 REG_USER=$1 REG_PASS=$2
  rm -rf /etc/rancher/rke2
  stub openssl '[ "$1" = s_client ] && printf "%s\n" "-----BEGIN CERTIFICATE-----" "c" "-----END CERTIFICATE-----"; exit 0'
  run create_registry_config
  [ "$status" -eq 0 ]
}

@test "R12: registries.yaml holds a user and password with \", \\, a space and * exactly, as YAML reads them" {
  in_container
  write_registries 'ci "u\ser' 'Ci 9"pw\x*Z\"'
  [ "$(yaml_auth username)" = 'ci "u\ser' ]
  [ "$(yaml_auth password)" = 'Ci 9"pw\x*Z\"' ]
  [ "$(stat -c %a /etc/rancher/rke2/registries.yaml)" = 600 ]
}

@test "R12: a password with neither \" nor \\ is written as before, so an existing node sees no change" {
  in_container
  write_registries admin 'Rk2$HOME`x!&;|(#:9q ?[a]'
  grep -qxF '      password: "Rk2$HOME`x!&;|(#:9q ?[a]"' /etc/rancher/rke2/registries.yaml
  grep -qxF '      username: "admin"' /etc/rancher/rke2/registries.yaml
  [ "$(yaml_auth password)" = 'Rk2$HOME`x!&;|(#:9q ?[a]' ]
}

@test "R12: dq_escape doubles \\ and escapes \", and nothing else" {
  [ "$(dq_escape 'a\b"c d*$e')" = 'a\\b\"c d*$e' ]
  [ "$(dq_escape 'plain')" = plain ]
  [ "$(dq_escape '')" = '' ]
}

@test "R12: every image_pull_push.sh push passes the registry, user and password quoted" {
  n=$(grep -c 'image_pull_push.sh .* push ' "$BATS_TEST_DIRNAME/../../rke2_installer.sh")
  q=$(grep -c 'image_pull_push.sh .* push "$REGISTRY_INFO" "$REG_USER" "$REG_PASS"$' "$BATS_TEST_DIRNAME/../../rke2_installer.sh")
  [ "$n" -eq 9 ]
  [ "$q" -eq "$n" ]
}

@test "R12: a push hands the helper the password as one argument, unsplit and unglobbed" {
  WORKING_DIR=$T/w AIR_GAPPED_MODE=1 SAVE_MODE=0 CNI_NONE=false CNI_TYPE=canal
  REGISTRY_INFO=reg.x.lab:443 REG_USER='ci user' REG_PASS='Ci 9"pw\x*Z'
  mkdir -p "$WORKING_DIR/rke2-utilities" "$WORKING_DIR/rke2-core-images" "$WORKING_DIR/rke2-cni-images"
  touch "$WORKING_DIR/rke2-utilities/container_images_1.tar.gz" "$WORKING_DIR/rke2-core-images/rke2-core-images.tar.gz" \
        "$WORKING_DIR/rke2-cni-images/rke2-canal-images.tar.gz"
  # files the password's * could glob to, where the push runs from
  touch "$T/w/Ci-bait" "$T/w/9xZ"
  cat > "$WORKING_DIR/rke2-utilities/image_pull_push.sh" <<EOF
#!/bin/bash
printf '%s\n' "\$#" "\$@" >> "$T/calls"
EOF
  chmod +x "$WORKING_DIR/rke2-utilities/image_pull_push.sh"
  cd "$T/w"
  run run_push
  [ "$status" -eq 0 ]
  # three pushes, each: -f <archive> push <registry> <user> <password>
  [ "$(grep -cx 6 "$T/calls")" -eq 3 ]
  [ "$(grep -cxF 'Ci 9"pw\x*Z' "$T/calls")" -eq 3 ]
  [ "$(grep -cxF 'ci user' "$T/calls")" -eq 3 ]
}

@test "R13: uninstall runs Rancher's uninstaller with RKE2_DATA_DIR set to the data path" {
  in_container
  # A stand-in for Rancher's uninstaller, where uninstall_rke2 looks for it, that records what it was given
  printf '#!/bin/sh\necho "rke2-uninstall.sh RKE2_DATA_DIR=$RKE2_DATA_DIR" >> "%s"\n' "$STUB_LOG" > /usr/local/bin/rke2-uninstall.sh
  chmod +x /usr/local/bin/rke2-uninstall.sh
  stub systemctl '[ "$1" = is-active ] && exit 3; exit 0'
  stub findmnt
  STATE_FILE=$T/state RKE2_DATA=$T/rke2 KUBELET_DATA=$T/kubelet PVC_DATA=$T/pvc WORKING_DIR=$T/wd user_name=root
  mkdir -p "$RKE2_DATA" "$KUBELET_DATA" "$PVC_DATA"
  run uninstall_rke2
  rm -f /usr/local/bin/rke2-uninstall.sh
  [ "$status" -eq 0 ]
  called "rke2-uninstall.sh RKE2_DATA_DIR=$T/rke2"
  [[ "$output" == *"(RKE2_DATA_DIR=$T/rke2)"* ]]
  [ ! -e "$T/rke2" ]
}

@test "R13: a relative RKE2_DATA isn't handed to the uninstaller's rm -rf; it gets its default, with a warning" {
  in_container
  printf '#!/bin/sh\necho "rke2-uninstall.sh RKE2_DATA_DIR=${RKE2_DATA_DIR-unset}" >> "%s"\n' "$STUB_LOG" > /usr/local/bin/rke2-uninstall.sh
  chmod +x /usr/local/bin/rke2-uninstall.sh
  stub systemctl '[ "$1" = is-active ] && exit 3; exit 0'
  stub findmnt
  STATE_FILE=$T/state RKE2_DATA=None KUBELET_DATA=$T/kubelet PVC_DATA=$T/pvc WORKING_DIR=$T/wd user_name=root
  cd "$T" && mkdir None
  run uninstall_rke2
  rm -f /usr/local/bin/rke2-uninstall.sh
  called "rke2-uninstall.sh RKE2_DATA_DIR=unset"
  [[ "$output" == *"RKE2_DATA=None isn't an absolute path"* ]]
  [ -d "$T/None" ]
}

@test "R14: wait_for_api_server asks RKE2's kubectl under a custom RKE2_DATA" {
  RKE2_DATA=$T/rke2
  mkdir -p "$RKE2_DATA/bin"
  printf '#!/bin/sh\necho "kubectl $*" >> "%s"\n' "$STUB_LOG" > "$RKE2_DATA/bin/kubectl"; chmod +x "$RKE2_DATA/bin/kubectl"
  run wait_for_api_server
  [ "$status" -eq 0 ]
  [[ "$output" == *"The API server is up."* ]]
  called "kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get --raw /readyz"
}

@test "R14: nothing runs RKE2's binaries from the default path any more" {
  ! grep -nE '/var/lib/rancher/rke2/bin' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
}
