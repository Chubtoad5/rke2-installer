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

@test "N3: with a CSI driver, PVCs on local-path are named, because CSI snapshots don't cover them" {
  stub kubectl 'case "$*" in
  *"storageClassName==\"local-path\""*) printf "app/data " ;;
  *) exit 0 ;;
esac'
  VSC_DRIVER=driver.longhorn.io run warn_local_path_without_fs_backup
  [[ "$output" == *"these PVCs are on local-path, which CSI snapshots (driver.longhorn.io) don't cover"*"app/data"* ]]
}

@test "N3: no local-path PVCs, no warning" {
  stub kubectl 'exit 0'
  run warn_local_path_without_fs_backup
  [ -z "$output" ]
}

# local-path v0.0.32's stock helper pod template, as the ConfigMap holds it
helper_tpl() { printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata:' '  name: helper-pod' 'spec:' \
  '  priorityClassName: system-node-critical' '  tolerations:' '    - key: node.kubernetes.io/disk-pressure' \
  '      operator: Exists' '      effect: NoSchedule' '  containers:' '  - name: helper-pod' '    image: busybox' \
  '    imagePullPolicy: IfNotPresent'; }
stub_lp() { # stub_lp <template file>
  stub kubectl 'case "$*" in
  "get namespace local-path-storage") exit 0 ;;
  *"get configmap local-path-config"*) cat "'"$1"'" ;;
  *) exit 0 ;;
esac'
}

@test "N2: with SELinux enforcing, the helper pod becomes privileged, as valid YAML with the rest kept" {
  helper_tpl > "$T/tpl"; stub_lp "$T/tpl"
  SELINUX_ENFORCING=true ENABLE_CIS=false run local_path_helper_access
  [ "$status" -eq 0 ]
  line=$(grep 'patch configmap local-path-config' "$STUB_LOG")
  json=${line#*--type merge -p }
  python3 -c 'import json,sys,yaml; t=json.loads(sys.argv[1])["data"]["helperPod.yaml"]; d=yaml.safe_load(t); c=d["spec"]["containers"][0]; assert c["securityContext"]["privileged"] is True and c["image"]=="busybox" and d["spec"]["priorityClassName"]=="system-node-critical", d' "$json"
}

@test "N2: already privileged, or not enforcing: no patch" {
  helper_tpl > "$T/tpl"; printf '    securityContext: {privileged: true}\n' >> "$T/tpl"; stub_lp "$T/tpl"
  SELINUX_ENFORCING=true run local_path_helper_access
  ! called "patch configmap"
  helper_tpl > "$T/tpl"; : > "$STUB_LOG"
  SELINUX_ENFORCING=false run local_path_helper_access
  ! called "patch configmap"
}

@test "V17: under CIS, local-path-storage is labelled privileged, so its helper pods are admitted" {
  helper_tpl > "$T/tpl"; stub_lp "$T/tpl"
  SELINUX_ENFORCING=false ENABLE_CIS=true run local_path_helper_access
  grep 'label namespace local-path-storage' "$STUB_LOG" | grep -q 'pod-security.kubernetes.io/enforce=privileged'
  : > "$STUB_LOG"
  SELINUX_ENFORCING=false ENABLE_CIS=false run local_path_helper_access
  ! called "label namespace local-path-storage"
}

@test "N2/V17: install calls it right after applying local-path's manifest, and install velero too" {
  grep -A1 'kubectl apply -f $WORKING_DIR/rke2-utilities/local-path-storage.yaml' "$BATS_TEST_DIRNAME/../../rke2_installer.sh" | grep -q 'local_path_helper_access'
  sed -n '/^run_install_velero/,/^}/p' "$BATS_TEST_DIRNAME/../../rke2_installer.sh" | grep -q '^  local_path_helper_access$'
}
