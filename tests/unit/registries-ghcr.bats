#!/usr/bin/env bats
# V9 (spec 31): kube-prometheus-stack 84.x and later pull their admission webhook's image from ghcr.io, which
# registries.yaml didn't mirror, so air-gapped install monitoring couldn't pull it. A new registries.yaml mirrors
# ghcr.io; an existing one without it is rewritten byte for byte (a running node's re-run sees no change), unless
# RKE2_RECONFIGURE=true.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  stub sleep
  [[ $EUID -eq 0 && ( -f /run/.containerenv || -f /.dockerenv ) ]] || skip "writes under /etc: root in a container only"
  REGISTRY_MODE=1 REGISTRY_INFO=reg.x.lab:443 REG_FQDN=reg.x.lab REG_PORT=443 REG_USER=admin REG_PASS=pw
  stub openssl '[ "$1" = s_client ] && printf "%s\n" "-----BEGIN CERTIFICATE-----" "c" "-----END CERTIFICATE-----"; exit 0'
  rm -rf /etc/rancher/rke2
}
mirrors() { python3 -I -c 'import yaml; print(" ".join(sorted(yaml.safe_load(open("/etc/rancher/rke2/registries.yaml"))["mirrors"])))'; }

@test "V9: a new registries.yaml mirrors ghcr.io to the registry, with the others" {
  run create_registry_config
  [ "$status" -eq 0 ]
  [ "$(mirrors)" = "cr.fluentbit.io docker.io ghcr.io quay.io reg.x.lab:443 registry.k8s.io" ]
  python3 -I -c 'import yaml; d=yaml.safe_load(open("/etc/rancher/rke2/registries.yaml")); assert d["mirrors"]["ghcr.io"]["endpoint"]==["https://reg.x.lab:443"]'
}

@test "V9: an existing registries.yaml without ghcr.io is written back byte for byte, with a note" {
  run create_registry_config
  sed -i '/^  ghcr.io:/,+2d' /etc/rancher/rke2/registries.yaml
  cp /etc/rancher/rke2/registries.yaml "$BATS_TMPDIR/before"
  run create_registry_config
  [ "$status" -eq 0 ]
  cmp -s "$BATS_TMPDIR/before" /etc/rancher/rke2/registries.yaml
  [[ "$output" == *"no ghcr.io mirror"*"RKE2_RECONFIGURE=true"* ]]
}

@test "V9: RKE2_RECONFIGURE=true adds ghcr.io to an existing registries.yaml" {
  run create_registry_config
  sed -i '/^  ghcr.io:/,+2d' /etc/rancher/rke2/registries.yaml
  RKE2_RECONFIGURE=true
  run create_registry_config
  [ "$status" -eq 0 ]
  [[ "$(mirrors)" == *ghcr.io* ]]
}

@test "V9: an existing registries.yaml that has ghcr.io keeps it" {
  run create_registry_config
  run create_registry_config
  [[ "$(mirrors)" == *ghcr.io* ]]
}
