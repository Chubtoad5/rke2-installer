#!/usr/bin/env bats
# R15 (spec 21): Velero's S3 keys reach its AWS credentials file in a form the AWS SDK's parser reads back exactly, and a
# key it can't carry is refused before anything changes. The parser below is a line-for-line port of aws-sdk-go-v2
# internal/ini v1.7.2, which velero v1.17.1 and velero-plugin-for-aws v1.13.0 use for this file.
load ../helpers
load ../vectors
setup() {
  load_script rke2_installer.sh
  setup_stubs
  load_vectors
  CREDS=$(mktemp -u)
  AWSINI=$(mktemp)
  cat > "$AWSINI" <<'PY'
import sys
GO_WS = " \t\n\v\f\r"
def cut(s, sep):
    i = s.find(sep)
    return s if i < 0 else s[:i]
def trim_property_comment(s):
    for sep in (" #", " ;", "\t#", "\t;"):
        s = cut(s, sep)
    return s
def split_property(s):
    eq, co = s.find("="), s.find(":")
    sep = "=" if not (eq == -1 or (co != -1 and co < eq)) else ":"
    i = s.find(sep)
    return None if i < 0 else (s[:i].strip(GO_WS), s[i + 1:].strip(GO_WS))
def unquote(s):
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        if len(s) < 2:
            raise RuntimeError("the Go parser panics here")
        return s[1:-1]
    return s
def legacy_strconv(s):
    return unquote(s).replace('\\"', '"').replace("\\'", "'").replace("\\n", "\n")
sections, cur = {}, None
for line in open(sys.argv[1]).read().split("\n"):
    if not line.strip(GO_WS) or line.lstrip(" \t").startswith(("#", ";")):
        continue
    t = cut(cut(line, "#"), ";").strip(GO_WS)
    if t.startswith("[") and t.endswith("]"):
        cur = t[1:-1].strip(GO_WS); sections[cur] = {}; continue
    kv = split_property(trim_property_comment(line).rstrip(" \t"))
    if kv:
        sections.setdefault(cur, {})[kv[0].lower()] = legacy_strconv(kv[1])
print(sections["default"][sys.argv[2]], end="")
PY
}
# reads <key name>: what Velero would read from the credentials file
reads() { python3 -I "$AWSINI" "$CREDS" "$1"; }

@test "R15: keys of every shape Velero carries reach it exactly, written as before, in a private file" {
  local a k
  for a in AKIAIOSFODNN7EXAMPLE aaaa1111bbbb2222 velero-backup; do
    for k in 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' 'cccc3333dddd4444eeee5555ffff6666' 'a+b/c=d.e_f-g' '==' '-x' \
             'MySecret@123' 'ab"c' 'a b' '!@#$%^&*()' 'ab\c' 'x#y;z'; do
      VELERO_S3_ACCESS_KEY=$a VELERO_S3_SECRET_KEY=$k
      check_velero_keys
      rm -f "$CREDS"; write_velero_credentials "$CREDS"
      [ "$(reads aws_access_key_id)" = "$a" ]
      [ "$(reads aws_secret_access_key)" = "$k" ]
      [ "$(stat -c %a "$CREDS")" = 600 ]
    done
  done
  # A plain key is written exactly as main wrote it, so nothing that worked changes
  VELERO_S3_ACCESS_KEY=aaaa1111bbbb2222 VELERO_S3_SECRET_KEY=cccc3333dddd4444eeee5555ffff6666
  rm -f "$CREDS"; write_velero_credentials "$CREDS"
  [ "$(cat "$CREDS")" = $'[default]\naws_access_key_id=aaaa1111bbbb2222\naws_secret_access_key=cccc3333dddd4444eeee5555ffff6666' ]
}
@test "R15: every test password as a key is refused exactly when Velero would read it changed" {
  local n v kept=0 refused=0
  for n in "${VEC_NAMES[@]}"; do
    v=${VEC[$n]}
    VELERO_S3_ACCESS_KEY=AKIAEXAMPLE VELERO_S3_SECRET_KEY=$v
    rm -f "$CREDS"; write_velero_credentials "$CREDS"
    if check_velero_keys >/dev/null; then
      [ "$(reads aws_secret_access_key)" = "$v" ]; kept=$((kept + 1))
    else
      [ "$(reads aws_secret_access_key 2>/dev/null)" != "$v" ]; refused=$((refused + 1))
    fi
  done
  [ "$refused" -gt 0 ] && [ "$kept" -gt 0 ]
}
@test "R15: the shapes Velero reads changed are refused, and the message names the format, not the key" {
  local k
  for k in 'abc #def' 'abc ;def' ' abc' 'abc ' '"abc"' "'abc'" '"' "'" 'ab\"c' "ab\\'c" 'ab\nc'; do
    VELERO_S3_ACCESS_KEY=AKIAEXAMPLE VELERO_S3_SECRET_KEY=$k
    run check_velero_keys
    [ "$status" -eq 1 ]
    [[ "$output" == *"VELERO_S3_SECRET_KEY has"* && "$output" == *"credentials file can't carry exactly"* ]]
    [[ "$output" == *"Nothing has been changed"* ]]
    [[ "$output" != *"$k"* || ${#k} -le 1 ]]
  done
  VELERO_S3_ACCESS_KEY=' AKIA' VELERO_S3_SECRET_KEY=abc
  run check_velero_keys
  [ "$status" -eq 1 ]
  [[ "$output" == *"VELERO_S3_ACCESS_KEY has a space at the start or the end"* ]]
}
@test "R15: install velero refuses such a key before anything else" {
  run env VELERO_S3_URL=https://s3.example:8333 VELERO_S3_ACCESS_KEY=AKIAEXAMPLE VELERO_S3_SECRET_KEY='abc #def' \
    bash "$BATS_TEST_DIRNAME/../../rke2_installer.sh" install velero
  [ "$status" -ne 0 ]
  [[ "$output" == *"VELERO_S3_SECRET_KEY has a # or ; after a space"* ]]
  ! called kubectl || false
  ! called velero || false
}
