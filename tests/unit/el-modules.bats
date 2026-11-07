#!/usr/bin/env bats
# Spec 11, U4: Rocky 10's cloud image has no br_netfilter, which is in kernel-modules-extra. The running kernel's
# package is installed, with no newer kernel and no reboot.
load ../helpers

setup() {
  setup_stubs
  load_script rke2_installer.sh
  stub uname 'echo 6.12.0-211.16.1.el10_2.0.1.x86_64'
  stub dnf 'exit 0'
  OS_ID=rocky AIR_GAPPED_MODE=0
}
no_br_netfilter() { stub modprobe '[ "$2" = br_netfilter ] && exit 1; exit 0'; }

@test "Rocky with no br_netfilter: the running kernel's kernel-modules-extra is installed" {
  no_br_netfilter
  run ensure_el_required_modules
  [ "$status" -eq 0 ]
  called "dnf install -y kernel-modules-extra-6.12.0-211.16.1.el10_2.0.1.x86_64"
  [[ "$output" == *"has no br_netfilter"* ]]
}
@test "the package has left the repo: stop, and say to update and reboot" {
  no_br_netfilter
  stub dnf 'exit 1'
  run ensure_el_required_modules
  [ "$status" -eq 1 ]
  [[ "$output" == *"no longer in this host's repositories"* ]]
  [[ "$output" == *"reboot into the new kernel"* ]]
}
@test "air-gapped: name the package to install from local media, and install nothing" {
  no_br_netfilter
  AIR_GAPPED_MODE=1
  run ensure_el_required_modules
  [ "$status" -eq 1 ]
  [[ "$output" == *"dnf install kernel-modules-extra-6.12.0-211.16.1.el10_2.0.1.x86_64"* ]]
  ! called "dnf install"
}
@test "with both modules there, nothing is installed" {
  stub modprobe 'exit 0'
  run ensure_el_required_modules
  [ "$status" -eq 0 ]
  ! called "dnf"
}
@test "Ubuntu, Leap and SLES aren't touched" {
  no_br_netfilter
  for OS_ID in ubuntu debian opensuse-leap sles; do
    run ensure_el_required_modules
    [ "$status" -eq 0 ]
  done
  ! called "dnf"
  ! called "modprobe"
}
@test "the check runs first in the host settings" {
  grep -A3 '^config_host_settings () {' "$BATS_TEST_DIRNAME/../../rke2_installer.sh" | grep -q ensure_el_required_modules
}
