# Changelog — rke2-installer

## 2026-09-09 — Idempotence release (feature/idempotence-phase2)

The largest change in the suite. `install`/`join` are now **re-runnable on a running node**
(reconcile instead of hard-fail), `uninstall` restores recorded pre-install host state instead
of guessing, the installer is SELinux-aware on enforcing hosts, and failures are reported
honestly. Two defaults changed — read **Behavior changes** before upgrading an existing
workflow.

### Behavior changes (action may be required)
- **`HELM_VERSION` default bumped `3.12.0` → `4.0.1`** (still overridable). Helm is only
  installed if not already present.
- **Pod-readiness timeouts now fail the command.** If pods are not ready within 120 s the
  install exits **non-zero** — previously it printed an error and exited `0`. The only
  warn-and-continue site is the non-critical `dnsutils` check in the `default` namespace.
  Re-running `install` after the cluster settles completes the remaining steps.
- **`install`/`join` on a node already running RKE2 no longer fails.** The installer renders
  the requested `config.yaml` and compares it with the live one:

  | Situation | Behavior |
  |---|---|
  | Fresh host | Normal install |
  | Same config, same version | Core install skipped; idempotent post-steps re-run (config/manifests, host settings, kubeconfig, symlinks, utilities) — useful to resume an interrupted install |
  | Config differs, `RKE2_RECONFIGURE=false` (default) | Clear error with a diff; nothing is changed |
  | Config differs, `RKE2_RECONFIGURE=true` | New config written and the rke2 service **restarted** |
  | Requested `RKE2_VERSION` differs from the running version | Error directing you to `upgrade` |
  | `join` pointed at a different cluster | Error — `uninstall` first |
  | Host runs the other role (server vs agent) | Error — `uninstall` first |

### Fixed
- **Truthful exit codes** via an `EXIT` trap; `run_debug` reworked and dead `$?` handlers
  removed. Failures still print the failed step's captured output even with `DEBUG=0`.
- **Safe uninstall on rpm-method installs.** `uninstall` stops the rke2 services **before**
  removing anything and finds the upstream uninstaller for both tar-method
  (`/usr/local/bin`) and rpm-method (`/usr/bin`, Rocky/RHEL online) installs, removing the
  RKE2 rpm packages on rpm hosts. It removes `/etc/rancher/rke2` (including the
  credential-bearing `registries.yaml`) and only the kubeconfig **files** it wrote — never the
  whole `.kube` directory. Dead CSI `globalmounts` are unmounted before the kubelet-data sweep.
- **Secrets hygiene** — `JOIN_TOKEN`/`REG_PASS` kept out of stdout, `registries.yaml` mode
  0600, Velero credentials hardened.
- **`install monitoring` / `install velero` standalone** no longer assume Longhorn, and
  `velero schedule create` is guarded so `install velero` is re-runnable.
- **Kernel-module loading softened** to a per-module probe with actionable warnings instead of
  a hard failure.
- **`logname` replaced** with a non-tty-safe fallback chain (it failed under
  `systemd-run`/non-login sessions).
- **Air-gap archive correctness** — absolute-path-safe atomic save archive, image-list
  regeneration, deterministic archive selection. `upgrade … stable` is rejected in air-gapped
  mode with a clear error.
- **Config generation unified** into a single `render_rke2_config()` for server / join-server
  / agent, removing three divergent copies.
- The apiserver audit log now lives under `RKE2_DATA`, and loopback `resolv.conf` detection
  handles a plain file, not just the stub symlink.
- Velero downloads use `curl -f`; `registries.yaml` changes obey the `RKE2_RECONFIGURE`
  contract in reconcile mode.

### Added
- **`RKE2_RECONFIGURE`** (default `false`) — allow a changed `config.yaml` to be applied and
  the service restarted on a running node.
- **`NTP_SERVERS`** (default empty) — optional space/comma-separated NTP list applied during
  `install`/`join`, with chrony or systemd-timesyncd auto-detected. Empty leaves the host's
  time source completely untouched. Same semantics as the `ap-tools` variable of the same name.
- **`/etc/rke2-installer/install-state.env`** (mode 0600) written by the first install,
  recording the pre-install state of swap, multipathd, UFW/firewalld, the NetworkManager CNI
  conf and the CIS `etcd` user. `uninstall` restores swap (fstab entries are commented with a
  `# rke2-installer-swap` marker, not deleted), re-enables multipathd/UFW/firewalld only if
  they were enabled before, removes the `etcd` user only if this tool created it, and removes
  any NTP config this tool added. Hosts installed by an older version get file cleanup only,
  with a note.
- **SELinux support for enforcing hosts** (Rocky 9/10, Leap 16) — `selinux: true` is
  configured and the `rke2-selinux` policy verified before the cluster starts. `save` bundles
  `rke2-selinux` + `container-selinux` RPMs on rpm-based hosts (`rke2-install/rke2-selinux-rpms/`)
  and the enforcing gate installs from the bundle first; `save` fails hard on an Enforcing
  build host if that download fails.
- **`RKE2_SELINUX_FALLBACK=permissive`** — explicit opt-in, **SUSE-only** escape hatch for
  Leap 16, where no upstream RKE2 SELinux policy exists. It prints a loud warning, records the
  change in the install state, and `uninstall` restores Enforcing. Never silent, and never
  honoured on the RHEL family.
- **Dependency preflight (`require_cmds`)** for minimal images.
- README section: "Re-Runs, Reconcile and Uninstall Behavior", plus `RKE2_RECONFIGURE`,
  `NTP_SERVERS`, `DEBUG` and the new `HELM_VERSION` default.
- `rke2_installer.sh` is now tracked executable (mode 755).

### Unchanged
- CLI surface (`install`, `uninstall`, `save`, `push`, `join`, `upgrade`, plus
  `install velero` / `install monitoring`), the `-registry` and `-tls-san` options, all `RKE2_*` variable names, and the save-archive
  layout are unchanged. `automation-platform-tools` needs no changes to keep working.
