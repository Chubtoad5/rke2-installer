#!/usr/bin/env bats
# Spec 12: image_pull_push.sh comes from an images-pull-push release, not main. A copy is reused only when its .ref
# record matches, and an air-gapped run never downloads.
load ../helpers

setup() {
  setup_stubs
  unset IMAGE_PULL_PUSH_REF IMAGE_PULL_PUSH_URL IMAGE_PULL_PUSH_SHA256
  load_script rke2_installer.sh
  WORKING_DIR=$BATS_TEST_TMPDIR/w
  DEST=$WORKING_DIR/rke2-utilities/image_pull_push.sh
  REF_FILE=$WORKING_DIR/rke2-utilities/.image_pull_push.sh.ref
  AIR_GAPPED_MODE=0
  # A curl that writes a small script to its -o path
  stub curl 'out=""; prev=""; for a in "$@"; do [ "$prev" = "-o" ] && out=$a; prev=$a; done
printf "#!/bin/bash\necho helper\n" > "$out"'
}
helper_sha() { printf '#!/bin/bash\necho helper\n' | sha256sum | cut -d' ' -f1; }

@test "the default fetches image_pull_push.sh from images-pull-push v1.1.1, by tag" {
  [ "$IMAGE_PULL_PUSH_REF" = v1.1.1 ]
  run image_pull_push_check
  [ "$status" -eq 0 ]
  called "curl -fsSL https://raw.githubusercontent.com/Chubtoad5/images-pull-push/v1.1.1/image_pull_push.sh"
  [ -x "$DEST" ]
  [ "$(cat "$REF_FILE")" = v1.1.1 ]
}
@test "IMAGE_PULL_PUSH_REF sets the URL" {
  export IMAGE_PULL_PUSH_REF=v9.9.9
  unset IMAGE_PULL_PUSH_URL
  load_script rke2_installer.sh
  [ "$IMAGE_PULL_PUSH_URL" = "https://raw.githubusercontent.com/Chubtoad5/images-pull-push/v9.9.9/image_pull_push.sh" ]
}
@test "IMAGE_PULL_PUSH_URL wins over the ref" {
  IMAGE_PULL_PUSH_URL=https://mirror.example/ipp.sh
  run image_pull_push_check
  [ "$status" -eq 0 ]
  called "curl -fsSL https://mirror.example/ipp.sh"
}
@test "a copy whose record names the same ref is reused" {
  image_pull_push_check >/dev/null
  : > "$STUB_LOG"
  run image_pull_push_check
  [ "$status" -eq 0 ]
  ! called "curl" || false
}
@test "a copy from another ref is fetched again" {
  mkdir -p "$(dirname "$DEST")"
  echo old > "$DEST"
  echo main > "$REF_FILE"
  run image_pull_push_check
  [ "$status" -eq 0 ]
  called "curl"
  [ "$(cat "$REF_FILE")" = v1.1.1 ]
  grep -q "echo helper" "$DEST"
}
@test "a copy with no record, as main used to leave, is fetched again" {
  mkdir -p "$(dirname "$DEST")"
  echo old > "$DEST"
  run image_pull_push_check
  called "curl"
  grep -q "echo helper" "$DEST"
}
@test "a matching checksum passes" {
  IMAGE_PULL_PUSH_SHA256=$(helper_sha)
  run image_pull_push_check
  [ "$status" -eq 0 ]
  [ -x "$DEST" ]
}
@test "a checksum mismatch stops, and leaves no file behind" {
  IMAGE_PULL_PUSH_SHA256=$(printf '0%.0s' {1..64})
  run image_pull_push_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"doesn't match IMAGE_PULL_PUSH_SHA256"* ]]
  [ ! -e "$DEST" ]
  [ ! -e "$DEST.tmp" ]
  [ ! -e "$REF_FILE" ]
}
@test "a failed download stops, and leaves no file behind" {
  stub curl 'exit 22'
  run image_pull_push_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"failed to download https://raw.githubusercontent.com/Chubtoad5/images-pull-push/v1.1.1/image_pull_push.sh"* ]]
  [ ! -e "$DEST" ]
  [ ! -e "$DEST.tmp" ]
}
@test "air-gapped, the bundled copy is used as it is, with no download" {
  AIR_GAPPED_MODE=1
  mkdir -p "$(dirname "$DEST")"
  echo bundled > "$DEST"
  run image_pull_push_check
  [ "$status" -eq 0 ]
  ! called "curl" || false
  [ "$(cat "$DEST")" = bundled ]
}
@test "air-gapped with no bundled copy stops, and never downloads" {
  AIR_GAPPED_MODE=1
  run image_pull_push_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"Extract the whole rke2-save.tar.gz"* ]]
  ! called "curl" || false
}
@test "nothing fetches image_pull_push.sh from main any more" {
  ! grep -n 'images-pull-push/raw/refs/heads/main' "$BATS_TEST_DIRNAME/../../rke2_installer.sh" || false
}
