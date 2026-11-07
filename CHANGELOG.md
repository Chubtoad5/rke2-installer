# Changelog — rke2-installer

## v1.1.0 — 2026-11-06 — Day-2 fixes

The first release with `SCRIPT_VERSION`. Every defect was reproduced on Ubuntu 24.04 clones first (R11 in CI on Leap 16
and Ubuntu minimal), and each fix has a test that failed before it. Commands, settings and exit codes that callers use
are unchanged, apart from the additions below and some new refusals. Each replaces a failure that used to come later,
or a silent `ImagePullBackOff`: no `iptables` on a server with the built-in ingress; a save marker with no extracted
bundle; a bundle without this `CNI_TYPE`'s images; an air-gapped upgrade with no `registries.yaml`, or with the target
tag missing from the registry.

### Fixed
- **A failed re-run emptied the registry CA.** `ca.crt` was truncated before the certificate fetch, so one re-run
  during a registry outage left a running node with an empty CA, which broke it at its next restart. The fetch now
  goes to a temporary file, is checked as a certificate, and only then replaces `ca.crt`. A connection that returns
  no certificate is an error too, where it used to print "Certificate saved".
- **With `DEBUG=0`, a failed step exited 1 with no reason.** The failure message went into the step's own log, which
  was then deleted. The console now gets it.
- **`save` left its marker behind.** `rke2-save-version.txt` stayed in the folder after the working directory was
  removed, so a later `install` there went air-gapped with no files and failed. `save` now removes it once the
  archive holds it. An `install`, `join` or `push` that finds the marker with no extracted bundle stops with an
  error naming the ways out, and the new `RKE2_FORCE_ONLINE=true` ignores a stale marker.
- **`CNI_TYPE=none` failed, air-gapped and online.** The air-gapped install looked for CNI images `save` never
  bundled. Online, the install waited 120 s for pods that can't start without a CNI, then exited 1. It now waits for
  the API server only, and says the node stays `NotReady` until you install a CNI. A bundle saved for another
  `CNI_TYPE` gives a clear error naming it.
- **Air-gapped upgrades only worked when the target was that day's stable release.** The bundle held
  `rke2-upgrade` for stable only, while an air-gapped upgrade has to name a version, so the job sat in
  `ImagePullBackOff` after `upgrade` exited 0. The bundle now holds the image for its own `RKE2_VERSION` as well,
  and the `kubectl` image the controller's jobs cordon nodes with (`rancher/kubectl`, from the controller's own
  config), which was never bundled or pushed.
  An air-gapped upgrade refuses when the node has no `registries.yaml`, or when the registry's tag list lacks the
  target, and warns if it can't ask. The README example used `stable`, which the script refuses. It now shows the rule:
  build the bundle for the target, then upgrade to that version.
- **Upgrade plans didn't tolerate the control-plane taint,** so with `CONTROL_PLANE_TAINT=true` a server upgrade job
  stayed `Pending`. The server plan now tolerates it.
- **The "can't resolve stable" error named a setting that does nothing** (`UPGRADE_VERSION`). It now says to pass a
  version on the command line.
- **Floating downloads:** the system-upgrade-controller came from `releases/latest`, and `dnsutils.yaml` from the
  Kubernetes website's `main` branch. Both are pinned now: `SUC_VERSION` (default `v0.21.0`) and a fixed commit.
- **`install` didn't check for `iptables`,** so on Leap 16 or Ubuntu minimal the built-in ingress controller stayed in
  `ContainerCreating` and the install timed out. A server with the ingress on now refuses without it, naming the
  package. An agent warns.

### Not covered
- **An air-gapped upgrade end to end, with egress cut,** hasn't been run. The bundle and push lists, and the
  pre-checks, were tested on their own.
- **A cluster that already runs system-upgrade-controller** keeps it: `upgrade` doesn't replace an installed one, so a
  controller installed earlier from `latest` keeps its own `kubectl` image tag, which a new bundle may not hold.

### Added
- `join` to a new address for the **same** cluster, with `RKE2_RECONFIGURE=true`. It's allowed only when the new
  address serves the CA of the cluster the node is already in: its hash has to match the one in the node's current
  secure join token (`K10<hash>::…`), and a new token has to carry the same hash. Another cluster's server and token,
  passed together, are refused. So is any other server change, as before.
- `UPGRADE_WAIT=true` (and `UPGRADE_WAIT_TIMEOUT`, default 1800 s): `upgrade` waits until every targeted node runs
  the new version and is schedulable again, and exits 1 if it doesn't in time. By default, `upgrade` still returns once
  the plans are applied.
- Warnings when a re-run leaves out `-registry` on a node that has one configured, and when an agent is given
  settings only servers read.

## 2026-10-23 — Minimal CoreDNS override + optional `COREDNS_HOSTS` pins

**Fix:** the generated `rke2-coredns-helmchartconfig.yaml` re-declared the chart's whole `servers:` list. Because Helm
replaces lists instead of merging them, that silently dropped chart defaults — the `kube-dns` Service served **UDP only**
(no DNS-over-TCP) and the lameduck delay was 5s instead of 10s — and froze the Corefile against future chart updates.
The only override that is actually needed is `service.name: kube-dns`: the chart names the Service
`rke2-coredns-rke2-coredns`, while Dell Automation Platform's nginx gateways (`dell-orchestrator`, `dell-portal`)
hard-code `resolver kube-dns.kube-system.svc.cluster.local`. The file now contains only that.

**New:** `COREDNS_HOSTS="<fqdn>=<ipv4>[,...]"` (optional, empty by default) renders an extra CoreDNS server block that
pins those names in-cluster, via the chart's `zoneFiles` + `extraConfig: import` (the default server block is left
untouched). Use it for split-horizon: LAN DNS sends browsers to a TLS-terminating reverse proxy while pods keep reaching
the cluster ingress — DAP's `fusion-mgmtworker` fetches its estate token from its own portal FQDN and trusts only DAP's
CA, so routing it through a proxy with a public cert breaks every plugin call (403). Rendered by `install`, so re-runs
keep the pins instead of wiping a hand edit. Invalid entries fail fast.

### Existing clusters
- Re-running `install` applies the new file; CoreDNS rolls with no downtime (validated on a live 3-node DAP cluster).
- **TCP 53 is not added to an existing `kube-dns` Service** by the Helm upgrade (Service ports merge on `port` alone, so
  the new `tcp-53` collapses into `udp-53`). Fresh installs get both. To add it on an upgraded cluster:
  ```bash
  kubectl -n kube-system patch svc kube-dns --type=json \
    -p '[{"op":"add","path":"/spec/ports/-","value":{"name":"tcp-53","port":53,"protocol":"TCP","targetPort":53}}]'
  ```

## 2026-10-10 — Bounded `update.rke2.io` stable-channel lookup

**Fix:** a pinned-version `install … push` / `save` hung indefinitely when `update.rke2.io` stopped
answering HTTPS (observed 2026-10-10: plain HTTP still returned its 308 redirect, every HTTPS address
timed out). The lookup only names the optional `rancher/rke2-upgrade:<stable>` image for the
utility-images list, but the `curl` had no timeout, so the whole install blocked on it.

- New `resolve_rke2_stable_version` (`--connect-timeout 10 --max-time 30`, validates the result looks
  like `vX.Y.Z+rke2rN`) replaces the four unbounded lookups.
- `install … push` and `save`: if the channel can't be resolved, the rke2-upgrade image falls back to
  the pinned `RKE2_VERSION` with a warning (worst case adds ~30 s instead of hanging).
- `upgrade` with `UPGRADE_VERSION=stable`: now fails fast with a clear error asking for an explicit
  `UPGRADE_VERSION`, instead of hanging (or continuing with an empty tag).
- The installed RKE2 version was never affected — Rancher's `install.sh` only consults the channel
  when `INSTALL_RKE2_VERSION` is empty, and this script always pins it.

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
