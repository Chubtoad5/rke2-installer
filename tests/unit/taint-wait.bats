#!/usr/bin/env bats
# V10 (spec 31): with CONTROL_PLANE_TAINT=true, RKE2's add-on charts' helm-install jobs (and local-path-provisioner)
# can't run on a first server until an agent joins, and every such install failed its pod wait after 300 s. While every
# node carries the control-plane taint, their Pending pods are left out; once any node is untainted, they count again.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  export TAINTS="node1=node-role.kubernetes.io/control-plane" JOB_STATE=Pending
  stub date 'echo 1000'
  stub sleep 'exit 0'
  stub kubectl 'case "$*" in
  *Succeeded*) exit 0 ;;
  *"get pods -A"*) echo "ALL PODS" ;;
  *"get pods -n"*)
    echo "rke2-coredns-rke2-coredns-77f5     1/1   Running   0   2m"
    echo "helm-install-rke2-traefik-j25vc    0/1   $JOB_STATE   0   5m" ;;
  *"get nodes -o jsonpath"*) printf "%s\n" $TAINTS ;;
  *"get nodes --no-headers"*) echo "node1 Ready" ;;
esac'
}

@test "V10: every node tainted: Pending helm-install jobs don't fail the wait, and it says why" {
  POD_WAIT_TIMEOUT=0
  run check_namespace_pods_ready
  [ "$status" -eq 0 ]
  [[ "$output" == *"install when the first agent joins"* ]]
}

@test "V10: once an untainted node is there, a Pending helm-install job counts again" {
  TAINTS="node1=node-role.kubernetes.io/control-plane agent1=" POD_WAIT_TIMEOUT=0
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
  [[ "$output" == *"helm-install-rke2-traefik-j25vc"* ]]
}

@test "V10: a helm-install job that's failing, not Pending, still counts" {
  JOB_STATE=Error POD_WAIT_TIMEOUT=0
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
}

@test "V10: all_nodes_control_plane_tainted is false with no nodes listed" {
  TAINTS=""
  ! all_nodes_control_plane_tainted
}

@test "V10: apply_utilities skips the local-path wait, with a note, while every node is tainted" {
  run grep -n -A1 'if \[\[ \$CNI_NONE == "false" \]\] && all_nodes_control_plane_tainted; then' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"local-path-provisioner starts when the first agent joins"* ]]
}
