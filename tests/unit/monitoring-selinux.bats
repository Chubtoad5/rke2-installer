#!/usr/bin/env bats
# V2 (spec 31): on an SELinux-enforcing host, Fluent Bit (container_t) couldn't create its position databases in /var/log
# and crash-looped, so install monitoring failed on Rocky. With SELinux enforcing, its pod runs as spc_t; otherwise the
# values stay as they were.
load ../helpers
S="$BATS_TEST_DIRNAME/../../rke2_installer.sh"

block() { # the Fluent Bit values and helm call, from the values file to the helm upgrade
  sed -n '/fb_values=$(mktemp)/,/helm upgrade --install fluent-bit/p' "$S"
}

@test "V2: spc_t is added to Fluent Bit's values only under SELINUX_ENFORCING" {
  run block
  [[ "$output" == *'if [[ "$SELINUX_ENFORCING" == "true" ]]; then'* ]]
  [[ "$output" == *'podSecurityContext:'* ]]
  [[ "$output" == *'type: spc_t'* ]]
}

@test "V2: the spc_t lines render as YAML that adds podSecurityContext.seLinuxOptions.type" {
  setup_stubs
  local f; f=$(mktemp)
  # Render the appended part as the script does, after the static values
  SELINUX_ENFORCING=true
  eval "$(sed -n '/^  if \[\[ "\$SELINUX_ENFORCING" == "true" \]\]; then$/,/^  fi$/p' "$S" | sed 's/"\$fb_values"/"$f"/')"
  run python3 -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); print(d["podSecurityContext"]["seLinuxOptions"]["type"])' "$f"
  [ "$output" = spc_t ]
  : > "$f"; SELINUX_ENFORCING=false
  eval "$(sed -n '/^  if \[\[ "\$SELINUX_ENFORCING" == "true" \]\]; then$/,/^  fi$/p' "$S" | sed 's/"\$fb_values"/"$f"/')"
  [ ! -s "$f" ]
  rm -f "$f"
}

@test "V2: os_check sets SELINUX_ENFORCING from getenforce, before any command runs" {
  run grep -n 'SELINUX_ENFORCING="true"' "$S"
  [ "$status" -eq 0 ]
  run grep -nx 'os_check' "$S"
  [ "$status" -eq 0 ]
}
