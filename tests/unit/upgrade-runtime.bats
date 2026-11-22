#!/usr/bin/env bats
# V11 (spec 31): an air-gapped upgrade checked the registry for rancher/rke2-upgrade only. A push that stopped partway
# (a Harbor project missing for an add-on image) left rke2-runtime out, the upgrade went ahead, and the upgraded server
# stayed down with "rke2-runtime ... NOT_FOUND". It now also needs rke2-runtime, and push sends RKE2's images first.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  T=$(mktemp -d)
  REGISTRY_INFO=reg.x.lab:443 REG_FQDN=reg.x.lab REG_PORT=443 REG_USER=u REG_PASS=p UPGRADE_VERSION=v1.36.6+rke2r1
}
teardown() { rm -rf "$T"; }

answer() { # answer <upgrade body> <runtime body>: curl answers each repository's tag list, then the HTTP code
  printf '%s' "$1" > "$T/upgrade"; printf '%s' "$2" > "$T/runtime"
  stub curl 'cat > /dev/null; case "$*" in *rke2-upgrade/tags*) cat '"$T"'/upgrade ;; *rke2-runtime/tags*) cat '"$T"'/runtime ;; esac'
}

@test "V11: both images there: the upgrade goes on" {
  answer $'{"tags":["v1.36.6-rke2r1"]}\n200' $'{"tags":["v1.36.6-rke2r1"]}\n200'
  run check_upgrade_image_in_registry
  [ "$status" -eq 0 ]
  [[ "$output" == *"has rancher/rke2-upgrade:v1.36.6-rke2r1"* && "$output" == *"has rancher/rke2-runtime:v1.36.6-rke2r1"* ]]
}

@test "V11: rke2-upgrade there but no rke2-runtime: refused, before anything changes" {
  answer $'{"tags":["v1.36.6-rke2r1"]}\n200' $'{"tags":["v1.35.10-rke2r1"]}\n200'
  run check_upgrade_image_in_registry
  [ "$status" -eq 1 ]
  [[ "$output" == *"has no rancher/rke2-runtime:v1.36.6-rke2r1"*"Nothing was changed"* ]]
}

@test "V11: no rke2-runtime repository at all (404): refused" {
  answer $'{"tags":["v1.36.6-rke2r1"]}\n200' $'{"errors":[{"code":"NAME_UNKNOWN"}]}\n404'
  run check_upgrade_image_in_registry
  [ "$status" -eq 1 ]
}

@test "V11: push sends RKE2's images before the utility and add-on images" {
  push_rke2_images() { echo core >> "$T/order"; }
  push_utility_images() { echo utility >> "$T/order"; }
  run_push > /dev/null
  [ "$(tr '\n' ' ' < "$T/order")" = "core utility " ]
}
