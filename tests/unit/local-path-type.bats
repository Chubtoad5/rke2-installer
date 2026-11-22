#!/usr/bin/env bats
# Q19 (spec 31): local-path makes "local" volumes, because Velero's node-agent never backs up hostPath ones (its default),
# and install velero names the PVCs whose volumes are still hostPath.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  T=$(mktemp -d)
}
teardown() { rm -rf "$T"; }
kubectl_with() { # kubectl_with <defaultVolumeType now, or "none" for no StorageClass> [<hostPath PVCs>]
  stub kubectl 'case "$*" in
  "get storageclass local-path") [[ "'"$1"'" != none ]] ;;
  *"jsonpath={.metadata.annotations.defaultVolumeType}"*) printf "%s" "'"${1/none/}"'" ;;
  *"get pv -o jsonpath"*) printf "%s" "'"${2:-}"'" ;;
  *) exit 0 ;;
esac'
}

@test "Q19: a StorageClass with no volume type gets 'local'" {
  kubectl_with ""
  run set_local_path_volume_type
  [ "$status" -eq 0 ]
  called "kubectl annotate storageclass local-path defaultVolumeType=local --overwrite"
  [[ "$output" == *"local-path makes 'local' volumes from now on"* ]]
}

@test "Q19: one that's already 'local' is left alone, quietly" {
  kubectl_with local
  run set_local_path_volume_type
  [ "$status" -eq 0 ]
  ! called "annotate"
  [ -z "$output" ]
}

@test "Q19: a type set by hand is left alone, and the note says what Velero can't do" {
  kubectl_with hostPath
  run set_local_path_volume_type
  ! called "annotate"
  [[ "$output" == *"defaultVolumeType is 'hostPath' (set by hand): left as it is"* ]]
}

@test "Q19: no local-path StorageClass, nothing to do" {
  kubectl_with none
  run set_local_path_volume_type
  [ "$status" -eq 0 ]
  ! called "annotate"
}

@test "Q19: install velero names the PVCs whose volumes are hostPath" {
  kubectl_with local "app/data b31-data/b31-pvc "
  run warn_hostpath_volumes
  [ "$status" -eq 0 ]
  [[ "$output" == *"Velero can't back up the data of these PVCs, because their volumes are hostPath: app/data b31-data/b31-pvc"* ]]
}

@test "Q19: no hostPath volumes, no warning" {
  kubectl_with local ""
  run warn_hostpath_volumes
  [ -z "$output" ]
}

@test "Q19: install calls it after making local-path the default class, and install velero before its backup" {
  grep -A1 'is-default-class":"true"' "$BATS_TEST_DIRNAME/../../rke2_installer.sh" | grep -q 'set_local_path_volume_type'
  sed -n '/^run_install_velero/,/^}/p' "$BATS_TEST_DIRNAME/../../rke2_installer.sh" | grep -q '^  warn_hostpath_volumes$'
}
