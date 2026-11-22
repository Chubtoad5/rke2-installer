#!/usr/bin/env bats
# V12 (spec 31): a push run from an extracted bundle ended in cleanup, which removed the extracted rke2-install folder,
# so the upgrade or install that followed in the same folder failed ("manifests not found ... Re-run 'save'"). A run
# that starts in an extracted bundle keeps it; a save or an online push still cleans its working folder up.
load ../helpers
setup() {
  setup_stubs
  load_script rke2_installer.sh
  WORKING_DIR=$(mktemp -d); touch "$WORKING_DIR/keep"
  INSTALL_MODE=0 JOIN_MODE=0 UPGRADE_MODE=0
}
teardown() { rm -rf "$WORKING_DIR"; }

@test "V12: a push from an extracted bundle keeps the bundle" {
  FROM_BUNDLE=1
  run cleanup
  [ -f "$WORKING_DIR/keep" ]
  [[ "$output" == *"is an extracted bundle: kept"* ]]
}

@test "V12: an online push or a save still removes its working folder" {
  FROM_BUNDLE=0
  run cleanup
  [ ! -d "$WORKING_DIR" ]
}

@test "V12: only a non-save run from a bundle marks it as the user's" {
  run grep -n -B2 '\[\[ \$SAVE_MODE -eq 0 \]\] && FROM_BUNDLE=1' "$BATS_TEST_DIRNAME/../../rke2_installer.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"AIR_GAPPED_MODE=1"* ]]
}
