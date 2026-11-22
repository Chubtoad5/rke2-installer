#!/usr/bin/env bats
# V1 follow-up (spec 31): the node-agent check V1 added read the velero namespace's DaemonSet. On a first install there's
# no such namespace, kubectl failed, and under errexit install velero ended silently after "Creating Velero S3
# credentials". It must reach velero install on a cluster that has never had Velero.
load ../helpers
setup() {
  [[ $EUID -eq 0 && ( -f /run/.containerenv || -f /.dockerenv ) ]] || skip "installs a fake velero CLI: root in a container only"
  setup_stubs
  load_script rke2_installer.sh
  set -o errexit -o pipefail
  T=$(mktemp -d); WORKING_DIR=$T; TMP_DIR=$T/tmp; mkdir -p "$TMP_DIR" "$T/velero/velero-v1.18.4-linux-amd64"
  printf '#!/bin/bash\necho "velero $*" >> "$STUB_LOG"\n[ "$1" = install ] && exit 7\nexit 0\n' > "$T/velero/velero-v1.18.4-linux-amd64/velero"
  chmod +x "$T/velero/velero-v1.18.4-linux-amd64/velero"
  tar -czf "$T/velero/velero-v1.18.4-linux-amd64.tar.gz" -C "$T/velero" velero-v1.18.4-linux-amd64
  rm -rf "$T/velero/velero-v1.18.4-linux-amd64"
  AIR_GAPPED_MODE=1 VELERO_VERSION=v1.18.4 VELERO_AWS_PLUGIN_VERSION=v1.14.4 VELERO_BUCKET=b VELERO_S3_URL=https://s3.x:8333
  VELERO_S3_ACCESS_KEY=AKIAEXAMPLE VELERO_S3_SECRET_KEY=abc RKE2_CONFIG_YAML=$T/none KUBELET_DATA=/var/lib/kubelet
  stub kubectl 'case "$*" in
  *"get pods -n kube-system"*) echo "rke2-snapshot-controller-1 1/1 Running 0 1m" ;;
  *"get csidriver"*) exit 0 ;;
  *"-n velero get"*) echo "Error from server (NotFound): namespaces \"velero\" not found" >&2; exit 1 ;;
  *) cat > /dev/null 2>&1; exit 0 ;;
esac'
}
teardown() { rm -rf "$T"; rm -f /usr/local/bin/velero; }

@test "V1: a first install velero, with no velero namespace yet, gets as far as velero install" {
  # In its own bash, with the installer's own errexit, as a real run has it (bats' run doesn't keep errexit)
  cat > "$T/drive.sh" <<D
source "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
trap - EXIT
PATH="$STUB_DIR:\$PATH" STUB_LOG="$STUB_LOG"
WORKING_DIR=$T TMP_DIR=$T/tmp AIR_GAPPED_MODE=1 VELERO_VERSION=v1.18.4 VELERO_AWS_PLUGIN_VERSION=v1.14.4 VELERO_BUCKET=b
VELERO_S3_URL=https://s3.x:8333 VELERO_S3_ACCESS_KEY=AKIAEXAMPLE VELERO_S3_SECRET_KEY=abc RKE2_CONFIG_YAML=$T/none KUBELET_DATA=/var/lib/kubelet
run_install_velero
D
  run bash "$T/drive.sh"
  called "velero install"
}
