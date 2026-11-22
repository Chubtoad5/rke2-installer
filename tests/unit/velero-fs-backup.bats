#!/usr/bin/env bats
# T11 (spec 31, Q14): install velero turns off Velero's native AWS snapshotter, removes the location an earlier install
# made with no region, and, when VSC_DRIVER isn't a registered CSI driver, backs volumes up with the node-agent: a new
# schedule gets --default-volumes-to-fs-backup and an existing one is patched. With the CSI driver nothing else changes.
load ../helpers
setup() {
  [[ $EUID -eq 0 && ( -f /run/.containerenv || -f /.dockerenv ) ]] || skip "installs a fake velero CLI: root in a container only"
  setup_stubs
  T=$(mktemp -d); mkdir -p "$T/tmp" "$T/velero/velero-v1.18.4-linux-amd64"
  # velero: install and schedule create succeed; schedule get says whether the schedule exists ($T/schedule-exists)
  cat > "$T/velero/velero-v1.18.4-linux-amd64/velero" <<'V'
#!/bin/bash
echo "velero $*" >> "$STUB_LOG"
if [[ "$1 $2" == "schedule get" ]]; then [[ -f "$SCHED_FLAG" ]]; exit; fi
exit 0
V
  chmod +x "$T/velero/velero-v1.18.4-linux-amd64/velero"
  tar -czf "$T/velero/velero-v1.18.4-linux-amd64.tar.gz" -C "$T/velero" velero-v1.18.4-linux-amd64
  rm -rf "$T/velero/velero-v1.18.4-linux-amd64"
  export SCHED_FLAG=$T/schedule-exists
  # kubectl: the CSI driver is there when $T/csi exists; the old location (aws, no region) when $T/vsl exists
  stub kubectl 'case "$*" in
  *"get pods -n kube-system"*) echo "rke2-snapshot-controller-1 1/1 Running 0 1m" ;;
  *"get csidriver"*) [[ -f "'"$T"'/csi" ]] ;;
  *"get volumesnapshotlocation default -o jsonpath={.spec.provider}"*) [[ -f "'"$T"'/vsl" ]] && echo aws || exit 1 ;;
  *"get volumesnapshotlocation default -o jsonpath={.spec.config.region}"*) [[ -f "'"$T"'/vsl" ]] || exit 1 ;;
  *"get schedule daily-full-backup"*) cat "'"$T"'/fs-now" 2>/dev/null ;;
  *"get daemonset node-agent -o jsonpath={.spec.template.spec.volumes"*) [[ -f "'"$T"'/ds" ]] && echo /var/lib/kubelet/pods || exit 1 ;;
  *"get daemonset node-agent -o jsonpath={.spec.template.spec.containers[0].args}"*) cat "'"$T"'/ds" 2>/dev/null ;;
  *"-n velero get daemonset"*) exit 1 ;;
  "get namespace velero") [[ ! -f "'"$T"'/nons" ]] ;;
  *) cat > /dev/null 2>&1; exit 0 ;;
esac'
}
teardown() { rm -rf "$T"; rm -f /usr/local/bin/velero; }
drive() { # in its own bash, with the installer's errexit, as a real run has it
  cat > "$T/drive.sh" <<D
source "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
trap - EXIT
set -o errexit -o pipefail
PATH="$STUB_DIR:\$PATH" STUB_LOG="$STUB_LOG" SCHED_FLAG="$SCHED_FLAG"
WORKING_DIR=$T TMP_DIR=$T/tmp AIR_GAPPED_MODE=1 VELERO_VERSION=v1.18.4 VELERO_AWS_PLUGIN_VERSION=v1.14.4 VELERO_BUCKET=b
VELERO_S3_URL=https://s3.x:8333 VELERO_S3_ACCESS_KEY=AKIAEXAMPLE VELERO_S3_SECRET_KEY=abc RKE2_CONFIG_YAML=$T/none KUBELET_DATA=/var/lib/kubelet
SELINUX_ENFORCING=${SEL:-false}
check_namespace_pods_ready() { return 0; }
velero_converge_versions() { :; }
run_install_velero
D
  run bash "$T/drive.sh"
}

@test "Q14: no CSI driver: the native snapshotter is off, and a new schedule backs volumes up with the node-agent" {
  drive
  [ "$status" -eq 0 ]
  called "velero install"
  grep -q -- '--use-volume-snapshots=false' "$STUB_LOG"
  ! grep -q -- '--use-volume-snapshots=true' "$STUB_LOG"
  grep 'velero schedule create daily-full-backup' "$STUB_LOG" | grep -q -- '--default-volumes-to-fs-backup'
  [[ "$output" == *"backed up by Velero's node-agent (file-system backup)"* ]]
  [[ "$output" != *"Object/resource backups are unaffected"* ]]
}

@test "Q14: with the CSI driver, the schedule is as before: CSI snapshots with the data mover, no fs-backup" {
  touch "$T/csi"
  drive
  [ "$status" -eq 0 ]
  grep 'velero schedule create daily-full-backup' "$STUB_LOG" | grep -q -- '--snapshot-move-data'
  ! grep 'velero schedule create' "$STUB_LOG" | grep -q -- '--default-volumes-to-fs-backup'
  grep -q -- '--use-volume-snapshots=false' "$STUB_LOG"
  [[ "$output" != *"node-agent (file-system backup)"* ]]
}

@test "Q14: a re-run removes the location an earlier install made with no region" {
  touch "$T/vsl"
  drive
  [ "$status" -eq 0 ]
  called "kubectl -n velero delete volumesnapshotlocation default"
  [[ "$output" == *"Removing the volume snapshot location an earlier install made"* ]]
}

@test "Q14: a location with a region is someone's own, and stays" {
  touch "$T/vsl"
  stub kubectl 'case "$*" in
  *"get pods -n kube-system"*) echo "rke2-snapshot-controller-1 1/1 Running 0 1m" ;;
  *"get csidriver"*) exit 1 ;;
  *"jsonpath={.spec.provider}"*) echo aws ;;
  *"jsonpath={.spec.config.region}"*) echo us-west-2 ;;
  *"-n velero get daemonset"*) exit 1 ;;
  *) cat > /dev/null 2>&1; exit 0 ;;
esac'
  drive
  [ "$status" -eq 0 ]
  ! called "delete volumesnapshotlocation"
}

@test "Q14: an existing schedule without fs-backup, and no CSI driver: it's patched, not recreated" {
  touch "$SCHED_FLAG"
  drive
  [ "$status" -eq 0 ]
  ! called "velero schedule create"
  called 'kubectl -n velero patch schedule daily-full-backup --type merge -p {"spec":{"template":{"defaultVolumesToFsBackup":true}}}'
  [[ "$output" == *"Turning on file-system backup in the existing schedule"* ]]
}

@test "Q14: an existing schedule that already has fs-backup, or a cluster with the CSI driver, isn't patched" {
  touch "$SCHED_FLAG"; echo true > "$T/fs-now"
  drive
  [ "$status" -eq 0 ]
  ! called "patch schedule"
  rm -f "$T/fs-now"; : > "$STUB_LOG"; touch "$T/csi"
  drive
  [ "$status" -eq 0 ]
  ! called "patch schedule"
}

@test "Q19: with SELinux enforcing, the fs-backup pods run privileged, through the node-agent's ConfigMap" {
  SEL=true drive
  [ "$status" -eq 0 ]
  grep 'velero install' "$STUB_LOG" | grep -q -- '--node-agent-configmap node-agent-config'
  grep -q 'create configmap node-agent-config --from-literal=node-agent-config.json={"privilegedFsBackup": true}' "$STUB_LOG"
  ! grep -q -- '--privileged-node-agent' "$STUB_LOG"
  [[ "$output" == *"file-system backup pods run privileged"* ]]
}

@test "Q19: without SELinux enforcing, no ConfigMap and no flag" {
  drive
  [ "$status" -eq 0 ]
  ! grep -q -- '--node-agent-configmap' "$STUB_LOG"
  ! called "create configmap node-agent-config"
}

@test "Q19: an existing node-agent that doesn't read the ConfigMap is replaced on an enforcing host; one that does stays" {
  echo '["node-agent","server","--features=EnableCSI"]' > "$T/ds"
  SEL=true drive
  [ "$status" -eq 0 ]
  called "kubectl -n velero delete daemonset node-agent --wait=true"
  : > "$STUB_LOG"; echo '["node-agent","server","--node-agent-configmap=node-agent-config"]' > "$T/ds"
  SEL=true drive
  ! called "delete daemonset node-agent"
}

@test "N1: on an enforcing host with no velero namespace yet, it's made with Velero's Pod Security labels (CIS)" {
  touch "$T/nons"
  SEL=true drive
  [ "$status" -eq 0 ]
  called "kubectl create namespace velero"
  grep 'kubectl label namespace velero' "$STUB_LOG" | grep -q 'pod-security.kubernetes.io/enforce=privileged'
  grep 'kubectl label namespace velero' "$STUB_LOG" | grep -q 'component=velero'
}

@test "N1: an existing velero namespace is left as it is" {
  SEL=true drive
  [ "$status" -eq 0 ]
  ! called "kubectl create namespace velero"
  ! called "kubectl label namespace velero"
}
