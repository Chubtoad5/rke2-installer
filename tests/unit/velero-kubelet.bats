#!/usr/bin/env bats
# V1 (spec 31): Velero's node-agent mounts <kubelet root>/pods. With a custom KUBELET_DATA it crash-looped on
# "unexpected directory structure for host-pods volume", and install velero failed. The root now comes from the node's
# config.yaml (what the kubelet runs with), then KUBELET_DATA, then the default, and reaches velero install.
load ../helpers
setup() {
  load_script rke2_installer.sh
  setup_stubs
  RKE2_CONFIG_YAML=$(mktemp)
}
teardown() { rm -f "$RKE2_CONFIG_YAML"; }

@test "V1: the default kubelet root when config.yaml has no root-dir and KUBELET_DATA is the default" {
  printf 'cni: "canal"\nkubelet-arg:\n  - max-pods=110\n' > "$RKE2_CONFIG_YAML"
  KUBELET_DATA=/var/lib/kubelet
  [ "$(velero_kubelet_root)" = /var/lib/kubelet ]
}

@test "V1: config.yaml's root-dir, as render_rke2_config writes it" {
  printf 'kubelet-arg:\n  - max-pods=110\n  - root-dir=/data/kubelet\n' > "$RKE2_CONFIG_YAML"
  KUBELET_DATA=/var/lib/kubelet
  [ "$(velero_kubelet_root)" = /data/kubelet ]
}

@test "V1: config.yaml's root-dir in quotes, and a trailing slash" {
  printf 'kubelet-arg:\n  - "root-dir=/srv/kube let/"\n' > "$RKE2_CONFIG_YAML"
  [ "$(velero_kubelet_root)" = "/srv/kube let" ]
}

@test "V1: config.yaml wins over a different KUBELET_DATA" {
  printf 'kubelet-arg:\n  - root-dir=/data/kubelet\n' > "$RKE2_CONFIG_YAML"
  KUBELET_DATA=/other
  [ "$(velero_kubelet_root)" = /data/kubelet ]
}

@test "V1: KUBELET_DATA when there's no config.yaml (a host that isn't the server)" {
  rm -f "$RKE2_CONFIG_YAML"
  KUBELET_DATA=/data/kubelet/
  [ "$(velero_kubelet_root)" = /data/kubelet ]
}

@test "V1: install velero passes --kubelet-root-dir only for a custom root" {
  run grep -n -- '--kubelet-root-dir' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [ "$status" -eq 0 ]
  run grep -n -A3 'velero install \\' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [[ "$output" == *'"${kubelet_args[@]}"'* ]]
}
