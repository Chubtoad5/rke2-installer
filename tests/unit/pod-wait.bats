#!/usr/bin/env bats
# Spec 11, U3: the pod wait. A fake clock moves only when the wait sleeps, and a fake kubectl turns ready at a set time.
load ../helpers

setup() {
  setup_stubs
  load_script rke2_installer.sh
  export CLOCK=$STUB_DIR/clock READY_AT=999999
  echo 1000 > "$CLOCK"
  stub date 'cat "$CLOCK"'
  stub sleep 'echo $(( $(cat "$CLOCK") + $1 )) > "$CLOCK"'
  stub kubectl 'case "$*" in
  *Succeeded*) exit 0 ;;
  *"get pods -A"*) echo "ALL PODS" ;;
  *"get pods -n"*)
    if [ "$(cat "$CLOCK")" -ge "$READY_AT" ]; then
      echo "rke2-coredns-rke2-coredns-77f5   1/1   Running   0   2m"
    else
      echo "rke2-coredns-rke2-coredns-77f5   0/1   Pending   0   2m"
      echo "rke2-canal-2whhz                 0/2   Init:0/2  0   101s"
      echo "rke2-metrics-server-69f4         1/1   Running   0   60s"
    fi ;;
esac'
}

# v1.1.0 checked the deadline first, so this failed with its fixed 120 s, as in spec 09's full pass
@test "a namespace that turns ready exactly at the deadline passes" {
  POD_WAIT_TIMEOUT=120 READY_AT=1120
  run check_namespace_pods_ready
  [ "$status" -eq 0 ]
  [[ "$output" == *"All pods are ready in kube-system"* ]]
}
@test "the default wait is 300 seconds" {
  [ "$POD_WAIT_TIMEOUT" = 300 ]
  READY_AT=1290
  run check_namespace_pods_ready
  [ "$status" -eq 0 ]
}
@test "a timeout names each pod that isn't ready, and what it's waiting on" {
  POD_WAIT_TIMEOUT=20
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
  [[ "$output" == *"2 pods in kube-system weren't ready after 20s (POD_WAIT_TIMEOUT)"* ]]
  [[ "$output" == *"rke2-coredns-rke2-coredns-77f5"*"Pending"* ]]
  [[ "$output" == *"rke2-canal-2whhz"*"Init:0/2"* ]]
  [[ "$output" != *"rke2-metrics-server-69f4  "*"Running"*"old"* ]]
}
@test "one pod is one pod" {
  POD_WAIT_TIMEOUT=10
  stub kubectl 'case "$*" in *Succeeded*) exit 0 ;; *"get pods -n"*) echo "rke2-ingress-nginx-controller-r7wxw   0/1   ContainerCreating   0   118s" ;; esac'
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
  [[ "$output" == *"1 pod in kube-system wasn't ready after 10s"* ]]
}
@test "the error comes after the full listing, so it's the last thing shown" {
  POD_WAIT_TIMEOUT=10
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
  [[ "${lines[-1]}" == *"rke2-canal-2whhz"* ]]
  [[ "$output" == *"ALL PODS"*"weren't ready"* ]]
}
@test "the caller gets the pods by name" {
  POD_WAIT_TIMEOUT=10
  check_namespace_pods_ready >/dev/null 2>&1 || true
  [ "$NOT_READY_PODS" = "rke2-coredns-rke2-coredns-77f5 (Pending, 0/1), rke2-canal-2whhz (Init:0/2, 0/2)" ]
}
@test "pods that can't be listed aren't taken as ready" {
  POD_WAIT_TIMEOUT=10
  stub kubectl 'case "$*" in *Succeeded*) exit 0 ;; *"get pods -A"*) exit 1 ;; *) echo "The connection to the server 127.0.0.1:6443 was refused" >&2; exit 1 ;; esac'
  run check_namespace_pods_ready
  [ "$status" -eq 1 ]
  [[ "$output" == *"the pods in kube-system can't be listed: The connection to the server 127.0.0.1:6443 was refused"* ]]
}
@test "kubectl's warnings on stderr aren't pods" {
  stub kubectl 'case "$*" in
  *Succeeded*) exit 0 ;;
  *"get pods -n"*)
    echo "E1107 13:21:40.1 memcache.go:265] couldn'"'"'t get current server API group list: the server is currently unable to handle the request" >&2
    echo "Warning: metrics.k8s.io/v1beta1 is not available" >&2
    echo "rke2-coredns-x   1/1   Running   0   2m" ;;
esac'
  run check_namespace_pods_ready
  [ "$status" -eq 0 ]
}
@test "a namespace with no pods is ready, as before" {
  stub kubectl 'case "$*" in *Succeeded*) exit 0 ;; *"get pods -n"*) echo "No resources found in velero namespace." >&2 ;; esac'
  run check_namespace_pods_ready velero
  [ "$status" -eq 0 ]
}
@test "completed pods are deleted, and don't hold the wait up" {
  stub kubectl 'case "$*" in
  *Succeeded*) echo "pod/helm-install-rke2-canal-x" ;;
  *"get pods -n"*) echo "rke2-coredns-x   1/1   Running   0   2m" ;;
esac'
  run check_namespace_pods_ready
  [ "$status" -eq 0 ]
  called "kubectl delete -n kube-system pod/helm-install-rke2-canal-x --ignore-not-found"
}
@test "another namespace is waited on by name" {
  READY_AT=1000
  run check_namespace_pods_ready velero
  [ "$status" -eq 0 ]
  called "kubectl get pods -n velero --no-headers"
}
@test "POD_WAIT_TIMEOUT must be a whole number of seconds" {
  for bad in abc 0 -5 1.5 ""; do
    POD_WAIT_TIMEOUT=$bad
    run preflight_checks
    [ "$status" -eq 1 ]
    [[ "$output" == *"POD_WAIT_TIMEOUT must be a whole number of seconds"* ]]
  done
}
