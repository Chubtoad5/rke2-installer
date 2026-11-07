#!/usr/bin/env bats
# Spec 11, U3: a mount containerd left under its tmpmounts made uninstall fail with "Device or resource busy".
load ../helpers

setup() {
  setup_stubs
  load_script rke2_installer.sh
  stub findmnt 'printf "%s\n" /run/k3s/containerd/x/rootfs /var/lib/rancher/rke2/agent/containerd/tmpmounts/containerd-mount111 /var/lib/rancher/rke2/agent/containerd/tmpmounts/containerd-mount222 /var/lib/kubelet/pods/y/volumes/z /data/rke2/agent/containerd/tmpmounts/containerd-mount333'
  stub umount 'exit 0'
  RKE2_DATA=default
}

@test "only the mounts under the data folder's containerd tmpmounts are unmounted" {
  run unmount_containerd_tmpmounts
  [ "$status" -eq 0 ]
  called "umount -- /var/lib/rancher/rke2/agent/containerd/tmpmounts/containerd-mount111"
  called "umount -- /var/lib/rancher/rke2/agent/containerd/tmpmounts/containerd-mount222"
  ! called "umount -- /run/k3s"
  ! called "umount -- /var/lib/kubelet"
  ! called "umount -- /data/rke2"
}
@test "a custom RKE2_DATA is followed" {
  RKE2_DATA=/data/rke2
  run unmount_containerd_tmpmounts
  called "umount -- /data/rke2/agent/containerd/tmpmounts/containerd-mount333"
  ! called "umount -- /var/lib/rancher"
}
@test "a busy mount is unmounted lazily" {
  stub umount '[ "$1" = -l ] && exit 0; exit 32'
  run unmount_containerd_tmpmounts
  [ "$status" -eq 0 ]
  called "umount -l -- /var/lib/rancher/rke2/agent/containerd/tmpmounts/containerd-mount111"
}
@test "with nothing left behind, uninstall carries on under the script's errexit and pipefail" {
  stub findmnt 'echo /run/k3s/containerd/x/rootfs'
  run bash -c 'source "$1"; set -euo pipefail; unmount_containerd_tmpmounts; echo carried-on' _ "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [[ "$output" == *carried-on* ]]
  ! called "umount"
}
@test "uninstall unmounts them before Rancher's uninstaller, and before removing the data folder" {
  body=$(sed -n '/^uninstall_rke2() {/,/^}/p' "$BATS_TEST_DIRNAME/../../rke2_installer.sh")
  [[ "$body" == *"unmount_containerd_tmpmounts"*'Running upstream uninstaller'* ]]
  [[ "$body" == *"unmount_containerd_tmpmounts"*'rm -rf -- "$RKE2_DATA"'* ]]
}
