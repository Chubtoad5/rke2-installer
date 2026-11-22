#!/usr/bin/env bats
# V13 (spec 31): save's monitoring image list missed Prometheus' config-reloader (an operator argument, not an image:
# line) and took Fluent Bit's chart default tag instead of FLUENT_BIT_VERSION, so an air-gapped Prometheus and Fluent Bit
# couldn't pull. Both are listed as install monitoring will run them.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  WORKING_DIR=$(mktemp -d); mkdir -p "$WORKING_DIR/rke2-utilities/images" "$WORKING_DIR/monitoring"
  KUBE_PROMETHEUS_STACK_VERSION=92.22.0 FLUENT_BIT_CHART_VERSION=0.58.3 FLUENT_BIT_VERSION=5.1.5
  touch "$WORKING_DIR/monitoring/kube-prometheus-stack-92.22.0.tgz" "$WORKING_DIR/monitoring/fluent-bit-0.58.3.tgz"
  stub helm 'case "$*" in
  *kube-prometheus-stack*) printf "%s\n" "      containers:" "          image: \"quay.io/prometheus-operator/prometheus-operator:v0.94.2\"" \
      "          args:" "            - --prometheus-config-reloader=quay.io/prometheus-operator/prometheus-config-reloader:v0.94.2" ;;
  *fluent-bit*) tag=5.1.3; a="$*"; case "$a" in *image.tag=*) tag=${a##*image.tag=}; tag=${tag%% *} ;; esac
      printf "%s\n" "          image: \"cr.fluentbit.io/fluent/fluent-bit:$tag\"" ;;
esac'
}
teardown() { rm -rf "$WORKING_DIR"; }
list() { sort -u "$WORKING_DIR/rke2-utilities/images/utility-images.txt"; }

@test "V13: the config-reloader from the operator's arguments is in the bundle's list" {
  extract_monitoring_images >/dev/null
  list | grep -qx 'quay.io/prometheus-operator/prometheus-config-reloader:v0.94.2'
  list | grep -qx 'quay.io/prometheus-operator/prometheus-operator:v0.94.2'
}

@test "V13: Fluent Bit is listed with FLUENT_BIT_VERSION, not the chart's default tag" {
  extract_monitoring_images >/dev/null
  list | grep -qx 'cr.fluentbit.io/fluent/fluent-bit:5.1.5'
  ! list | grep -q 'fluent-bit:5.1.3'
}
