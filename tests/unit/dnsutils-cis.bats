#!/usr/bin/env bats
# V6 (spec 31): with ENABLE_CIS=true, Pod Security "restricted" on 'default' refused the dnsutils pod and the install
# exited 1 at its last step. Under CIS the same pod now gets a restricted-compliant security context, and a dnsutils
# that can't be created is a warning, not a failed install.
load ../helpers
setup() {
  load_script rke2_installer.sh
  setup_stubs
  WORKING_DIR=$(mktemp -d); mkdir -p "$WORKING_DIR/rke2-utilities"
  cat > "$WORKING_DIR/rke2-utilities/dnsutils.yaml" <<'Y'
apiVersion: v1
kind: Pod
metadata:
  name: dnsutils
  namespace: default
spec:
  containers:
  - name: dnsutils
    image: registry.k8s.io/e2e-test-images/agnhost:2.39
    imagePullPolicy: IfNotPresent
  restartPolicy: Always
Y
  stub kubectl 'if [ "$3" = "-" ]; then cat > "$STUB_LOG.manifest"; fi'
  AIR_GAPPED_MODE=1
}
teardown() { rm -rf "$WORKING_DIR"; }

@test "V6: without CIS, the manifest is applied as it is" {
  ENABLE_CIS=false
  apply_dnsutils
  called "kubectl apply -f $WORKING_DIR/rke2-utilities/dnsutils.yaml"
}

@test "V6: with CIS, the same image runs as non-root with no privilege escalation, all capabilities dropped, RuntimeDefault seccomp" {
  ENABLE_CIS=true
  apply_dnsutils
  called "kubectl apply -f -"
  run python3 - "$STUB_LOG.manifest" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
s, c = d["spec"], d["spec"]["containers"][0]
assert d["metadata"]["namespace"] == "default" and d["metadata"]["name"] == "dnsutils"
assert c["image"] == "registry.k8s.io/e2e-test-images/agnhost:2.39"
assert s["securityContext"]["runAsNonRoot"] is True and s["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
assert c["securityContext"]["allowPrivilegeEscalation"] is False and c["securityContext"]["capabilities"]["drop"] == ["ALL"]
print("ok")
PY
  [ "$output" = ok ]
}

@test "V6: a dnsutils that can't be created warns and doesn't fail apply_utilities" {
  run grep -n -A2 'if ! apply_dnsutils; then' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING: the dnsutils pod couldn't be created; continuing"* ]]
}
