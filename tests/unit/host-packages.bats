#!/usr/bin/env bats
# Spec 15: the bundle carries iptables (F6) and, on EL, the running kernel's kernel-modules-extra (F1), and an
# air-gapped install uses them.
load ../helpers
KVER=6.12.0-211.16.1.el10_2.0.1.x86_64
setup() {
  setup_stubs
  load_script rke2_installer.sh
  stub uname "echo $KVER"
  stub dnf 'exit 0'
  WORKING_DIR=$(mktemp -d) base_dir=$(mktemp -d)
  OS_ID=rocky AIR_GAPPED_MODE=1
}
bundle_with() { # bundle_with <package file names...>: rke2-packages with an archive of them and a logging install_packages.sh
  local d; d=$(mktemp -d); mkdir -p "$d/offline-packages" "$WORKING_DIR/rke2-packages"
  for n in "$@"; do touch "$d/offline-packages/$n"; done
  tar -czf "$WORKING_DIR/rke2-packages/offline-packages.tar.gz" -C "$d" offline-packages
  printf '#!/bin/bash\necho "install_packages.sh $*" >> "$STUB_LOG"\n' > "$WORKING_DIR/rke2-packages/install_packages.sh"
  chmod +x "$WORKING_DIR/rke2-packages/install_packages.sh"
}
no_br_netfilter() { stub modprobe '[ "$2" = br_netfilter ] && exit 1; exit 0'; }

@test "F1: air-gapped, the bundle's kernel-modules-extra for this kernel is installed" {
  no_br_netfilter
  bundle_with iptables-1.8.11-1.el10.x86_64.rpm "kernel-modules-extra-$KVER.rpm"
  run ensure_el_required_modules
  [ "$status" -eq 0 ]
  called "install_packages.sh offline kernel-modules-extra-$KVER"
  ! called "dnf"
}
@test "F1: a package for another kernel isn't used, and the message names that kernel" {
  no_br_netfilter
  bundle_with kernel-modules-extra-6.12.0-211.74.1.el10_2.x86_64.rpm
  run ensure_el_required_modules
  [ "$status" -eq 1 ]
  ! called "install_packages.sh"
  [[ "$output" == *"built on a host running 6.12.0-211.74.1.el10_2.x86_64"* ]]
  [[ "$output" == *"dnf install kernel-modules-extra-$KVER"* ]]
}
@test "F1: a bundle from before v1.3.1 gives today's message" {
  no_br_netfilter
  run ensure_el_required_modules
  [ "$status" -eq 1 ]
  [[ "$output" == *"dnf install kernel-modules-extra-$KVER"* ]]
  [[ "$output" != *"another kernel"* ]]
}
@test "F1: save adds the running kernel's package on EL when the repos have it, and nothing elsewhere" {
  stub dnf "echo kernel-modules-extra-0:$KVER"
  run el_modules_extra_pkg
  [ "$output" = "kernel-modules-extra-$KVER" ]
  stub dnf 'exit 0'
  run el_modules_extra_pkg
  [[ "$output" == *"isn't in this host's repos"* ]]
  OS_ID=ubuntu
  run el_modules_extra_pkg
  [ -z "$output" ]
}
@test "F6: air-gapped, a missing iptables is installed from the bundle before R11's check" {
  INSTALL_MODE=1 INSTALL_TYPE=rke2 JOIN_MODE=0 JOIN_TYPE="" INSTALL_INGRESS=true REGISTRY_MODE=0
  require_cmds() { echo "REQUIRE $*"; }
  command() { if [[ "$1" == -v && "$2" == iptables ]]; then return 1; fi; builtin command "$@"; }
  bundle_with iptables-1.8.11-1.el10.x86_64.rpm
  run preflight_checks
  called "install_packages.sh offline iptables"
  [[ "$output" == *"Installing iptables from the bundle"*"REQUIRE"*"iptables"* ]]
}
@test "F6: online, or with iptables there, nothing is installed" {
  INSTALL_MODE=1 INSTALL_TYPE=rke2 JOIN_MODE=0 JOIN_TYPE="" INSTALL_INGRESS=true REGISTRY_MODE=0
  require_cmds() { echo "REQUIRE $*"; }
  bundle_with iptables-1.8.11-1.el10.x86_64.rpm
  command() { if [[ "$1" == -v && "$2" == iptables ]]; then return 1; fi; builtin command "$@"; }
  AIR_GAPPED_MODE=0
  run preflight_checks
  ! called "install_packages.sh"
  unset -f command
  stub iptables
  AIR_GAPPED_MODE=1
  run preflight_checks
  ! called "install_packages.sh"
}
@test "F6: save bundles iptables, and the running kernel's package on EL" {
  stub dnf "echo kernel-modules-extra-0:$KVER"
  install_packages_check() { mkdir -p "$WORKING_DIR/rke2-packages"; printf '#!/bin/bash\necho "install_packages.sh $*" >> "$STUB_LOG"\n' > "$WORKING_DIR/rke2-packages/install_packages.sh"; chmod +x "$WORKING_DIR/rke2-packages/install_packages.sh"; }
  run download_host_packages
  [ "$status" -eq 0 ]
  called "install_packages.sh save iptables kernel-modules-extra-$KVER"
  OS_ID=ubuntu
  : > "$STUB_LOG"
  run download_host_packages
  called "install_packages.sh save iptables"
  ! called "kernel-modules-extra"
}
@test "the licence notice lists the bundled OS packages, and the written offer covers them" {
  bundle_with iptables-1.8.11-1.el10.x86_64.rpm "kernel-modules-extra-$KVER.rpm"
  PUSH_SAVE_MONITORING=false LICENSE_OFFER_CONTACT=me
  run generate_bundle_licenses
  [ "$status" -eq 0 ]
  grep -q "iptables-1.8.11-1.el10.x86_64.rpm" "$base_dir/LICENSES/THIRD_PARTY_NOTICES.txt"
  grep -q "kernel-modules-extra-$KVER.rpm" "$base_dir/LICENSES/THIRD_PARTY_NOTICES.txt"
  grep -q "rke2-install/rke2-packages/offline-packages.tar.gz" "$base_dir/LICENSES/WRITTEN_OFFER.txt"
  grep -q "contact: me" "$base_dir/LICENSES/WRITTEN_OFFER.txt"
}
@test "no bundled OS packages: no offer for them" {
  PUSH_SAVE_MONITORING=false
  run generate_bundle_licenses
  [ ! -f "$base_dir/LICENSES/WRITTEN_OFFER.txt" ]
}
