#!/usr/bin/env bats
# V14 (spec 31): under a custom PVC_DATA on an SELinux-enforcing host, local-path-provisioner's folder was default_t,
# its helper pods' mkdir was denied, and every local-path PVC stayed Pending (Prometheus' volume, on Rocky 10). The folder
# gets /opt/local-path-provisioner's labels (container_file_t) through an equivalence, recorded for uninstall.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  T=$(mktemp -d); STATE_FILE=$T/state SELINUX_ENFORCING=true RKE2_DATA=/var/lib/rancher/rke2
  stub semanage; stub restorecon
}
teardown() { rm -rf "$T"; }

@test "V14: a custom PVC_DATA's local-path folder gets /opt/local-path-provisioner's labels, recorded for uninstall" {
  PVC_DATA=$T/pvc/
  stub matchpathcon 'echo "$2 system_u:object_r:default_t:s0"; exit 1'
  run label_custom_data_dir
  [ "$status" -eq 0 ]
  called "semanage fcontext -a -e /opt/local-path-provisioner $T/pvc/local-path-provisioner"
  called "restorecon -R $T/pvc/local-path-provisioner"
  grep -qx "RKE2I_SELINUX_EQUIV_PVC=\"$T/pvc/local-path-provisioner\"" "$T/state"
}

@test "V14: nothing for the default PVC_DATA, an empty one, or with SELinux not enforcing" {
  stub matchpathcon 'exit 0'
  PVC_DATA=/opt/local-path-provisioner label_custom_data_dir
  PVC_DATA="" label_custom_data_dir
  SELINUX_ENFORCING=false PVC_DATA=$T/pvc label_custom_data_dir
  ! called "semanage" || false
}

@test "V14: a folder already labelled container_file_t gets no rule and no record" {
  PVC_DATA=$T/pvc
  stub matchpathcon '[ "$1" = -n ] && echo "system_u:object_r:container_file_t:s0"; exit 0'
  run label_custom_data_dir
  [[ "$output" == *"already has local-path-provisioner's SELinux labels"* ]]
  ! called "semanage" || false
  [ ! -f "$T/state" ]
}

@test "V14: uninstall removes the equivalence install recorded" {
  run grep -n -A3 'RKE2I_SELINUX_EQUIV_PVC:-' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [[ "$output" == *'semanage fcontext -d -e /opt/local-path-provisioner "$RKE2I_SELINUX_EQUIV_PVC"'* ]]
}
