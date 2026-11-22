#!/usr/bin/env bats
# V8 (spec 31): on one node, RKE2's two host-network cilium-operator replicas can't both be placed, so the second stays
# Pending while the first works, and every single-node CNI_TYPE=cilium install failed its pod wait. Such a pod is left
# out while the Deployment has a ready replica and there are fewer nodes than replicas; anything else still counts.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  export READY=1 WANT=2 NODES=1 OP_STATE=Pending
  stub date 'echo 1000'
  stub sleep 'exit 0'
  stub kubectl 'case "$*" in
  *Succeeded*) exit 0 ;;
  *"get pods -A"*) echo "ALL PODS" ;;
  *"get pods -n"*)
    echo "rke2-coredns-rke2-coredns-77f5     1/1   Running   0   2m"
    echo "cilium-operator-6889444fcb-jkdk5   1/1   Running   0   5m"
    echo "cilium-operator-6889444fcb-krpzp   0/1   $OP_STATE   0   5m" ;;
  *readyReplicas*) echo "$READY" ;;
  *spec.replicas*) echo "$WANT" ;;
  *"get nodes"*) for i in $(seq 1 "$NODES"); do echo "node$i Ready"; done ;;
esac'
}

@test "V8: one node, one ready operator: the Pending second replica doesn't fail the wait" {
  POD_WAIT_TIMEOUT=0
  run check_namespace_pods_ready
  [ "$status" -eq 0 ]
  [[ "$output" == *"All pods are ready in kube-system"* ]]
}

@test "V8: with as many nodes as replicas, a Pending operator still counts" {
  NODES=2 POD_WAIT_TIMEOUT=0
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
  [[ "$output" == *"cilium-operator-6889444fcb-krpzp"* ]]
}

@test "V8: with no ready operator, a Pending one still counts" {
  READY=0 POD_WAIT_TIMEOUT=0
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
}

@test "V8: an operator that's crashing, not Pending, still counts" {
  OP_STATE=CrashLoopBackOff POD_WAIT_TIMEOUT=0
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
}
