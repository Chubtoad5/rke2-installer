# rke2-installer

A flexible RKE2 installer for Linux systems that supports online and air-gapped deployments, optional add-on components, and multi-node cluster expansion.

---

## Table of Contents

- [Key Features](#key-features)
- [Supported Operating Systems](#supported-operating-systems)
- [Quick Start](#quick-start)
- [Configuration Variables](#configuration-variables)
- [Commands Reference](#commands-reference)
- [Re-Runs, Reconcile and Uninstall Behavior](#re-runs-reconcile-and-uninstall-behavior)
- [Options Reference](#options-reference)
- [Optional Components](#optional-components)
  - [NGINX Ingress Controller](#nginx-ingress-controller)
  - [Klipper LoadBalancer](#klipper-loadbalancer)
  - [Local Path Provisioner](#local-path-provisioner)
  - [CIS Hardening](#cis-hardening)
  - [Velero Backup](#velero-backup)
  - [Monitoring Stack](#monitoring-stack)
- [Cluster Upgrades](#cluster-upgrades)
- [Air-Gapped Deployments](#air-gapped-deployments)
- [Multi-Node Clusters](#multi-node-clusters)
- [Examples](#examples)

---

## Key Features

- Installs a Rancher RKE2 cluster as a server or agent node
- Supports joining an existing RKE2 cluster as a server or agent
- Supports offline/air-gapped deployment via a portable save archive
- Supports pulling and pushing images to a private OCI registry (mirror)
- Configurable CNI plugin: `canal` (default), `calico`, `cilium`, or `none`
- Built-in support for CIS Kubernetes hardening profile
- Optional NGINX ingress controller (enabled by default)
- Optional Klipper LoadBalancer (enabled by default)
- Optional Rancher Local Path Provisioner as default storage class
- Optional Kubernetes DNS utility deployment
- Optional TLS SAN configuration for API server
- Optional control-plane taint for multi-node workload separation
- Optional Velero backup with S3 and CSI snapshot support
- Optional in-cluster monitoring stack (kube-prometheus-stack + Fluent Bit)
- Automated cluster upgrades via the system-upgrade-controller
- Automatic host configuration (swap, sysctl, firewall, NetworkManager, multipath, optional NTP)
- SELinux-aware on enforcing hosts (Rocky/RHEL, openSUSE Leap 16): configures `selinux: true` and verifies the `rke2-selinux` policy before starting the cluster
- Re-run safe: `install`/`join` on an already-running node reconciles instead of failing (see [Re-Runs, Reconcile and Uninstall Behavior](#re-runs-reconcile-and-uninstall-behavior))
- Uninstall support for server and agent nodes, restoring recorded pre-install host state (swap, firewall, multipathd, NTP)

---

## Supported Operating Systems

- Ubuntu / Debian
- RHEL / CentOS / Rocky Linux / AlmaLinux / Fedora
- SLES / OpenSUSE Leap

With the built-in ingress (`INSTALL_INGRESS=true`, the default), a server needs `iptables` installed, because the ingress controller's host ports are set up with it. `install` and `join server` refuse without it, naming the package. Leap 16 and Ubuntu minimal don't ship it. An agent only warns, because it can't tell whether its cluster runs the ingress. A `save` bundle carries `iptables`, and an air-gapped install or join that finds it missing installs it from the bundle first. On Rocky, Alma or RHEL 10, whose images leave out the `kernel-modules-extra` that holds `br_netfilter`, the bundle also carries the build host's running kernel's package, and an air-gapped install uses it when the target runs that same kernel.

---

## Quick Start

`rke2-installer` is a **standalone** tool — it stands up a complete single-node RKE2 Kubernetes cluster
on its own. (It is also used under the hood by `automation-platform-tools`, but you don't need that to
use it here.)

**Prerequisites**
- A Linux host with `root` / `sudo` (see [Supported Operating Systems](#supported-operating-systems))
- A static IP (or DHCP reservation) and a valid hostname
- Internet access for an online install — or a `save` archive for air-gapped (see
  [Air-Gapped Deployments](#air-gapped-deployments))

**1. Get the script**
```bash
git clone https://github.com/Chubtoad5/rke2-installer.git
cd rke2-installer
chmod +x rke2_installer.sh
```

**2. (Optional) adjust settings, then install as root.** The defaults give you a working single-node
cluster with the NGINX ingress controller, Klipper load balancer, and Local Path storage class:

```bash
sudo ./rke2_installer.sh install
```

You can also override any variable inline, e.g.
`sudo RKE2_VERSION=v1.34.5+rke2r1 ./rke2_installer.sh install`.

**Want more than one node?** Install the first server as above, then on each additional machine run
`join server <fqdn> <token>` (control-plane) or `join agent <fqdn> <token>` (worker). The token lives at
`/var/lib/rancher/rke2/server/node-token` on the first server. See
[Multi-Node Clusters](#multi-node-clusters).

---

## Configuration Variables

All configuration is done by editing the `USER DEFINED VARIABLES` section at the top of `rke2_installer.sh`. Variables can also be overridden by prefixing the command with environment variable assignments.

### Core RKE2 Settings

| Variable | Default | Description |
|---|---|---|
| `RKE2_VERSION` | `v1.34.5+rke2r1` | RKE2 version to install |
| `CNI_TYPE` | `canal` | CNI plugin: `calico`, `canal`, `cilium`, or `none` |
| `CLUSTER_CIDR` | `10.42.0.0/16` | Pod network CIDR |
| `SERVICE_CIDR` | `10.43.0.0/16` | Service network CIDR |
| `MAX_PODS` | `110` | Maximum pods per node |
| `MGMT_IP` | *(auto-detected)* | Node management IP used for advertise/node-ip |
| `RKE2_DATA` | `default` | Custom path for RKE2 data (etcd, containerd). Default: `/var/lib/rancher/rke2` |
| `KUBELET_DATA` | `default` | Custom path for kubelet data. Default: `/var/lib/kubelet` |
| `PVC_DATA` | `default` | Custom path for local-path-provisioner PVCs. Default: `/opt/local-path-provisioner` |
| `CONTROL_PLANE_TAINT` | `false` | Set `true` to taint the control-plane node (recommended for multi-node clusters) |
| `ENABLE_CIS` | `false` | Enable CIS Kubernetes hardening profile |
| `RKE2_RECONFIGURE` | `false` | Set `true` to allow `install`/`join` on a **running** node to apply a changed `config.yaml` and restart the rke2 service. With the default `false`, a config change on a running node fails with a diff instead (see [Re-Runs, Reconcile and Uninstall Behavior](#re-runs-reconcile-and-uninstall-behavior)) |
| `NTP_SERVERS` | *(empty)* | Optional space/comma-separated NTP server list applied during `install`/`join` (chrony or systemd-timesyncd auto-detected). Empty = the host's time source is left completely untouched. Same semantics as the `ap-tools` variable of the same name |
| `COREDNS_HOSTS` | *(empty)* | Optional in-cluster DNS pins, `<fqdn>=<ipv4>` (comma or space separated), applied on `install` (and kept on re-runs). Pods resolve these names to the given IP regardless of what the host's DNS says. Use it for split-horizon setups where LAN DNS sends browsers to a TLS-terminating reverse proxy, but workloads must keep reaching the cluster's own ingress — e.g. Dell Automation Platform, whose services call their own portal FQDN and trust only DAP's CA. Empty = no pins |
| `DEBUG` | `1` | Set to `1` for verbose output, `0` to suppress (failures still print the failed step's captured output) |
| `RKE2_FORCE_ONLINE` | `false` | Set `true` to ignore an `rke2-save-version.txt` in the working directory and run online. Without it, that file makes the run air-gapped, and an `install`, `join` or `push` with no extracted bundle next to it stops with an error |
| `IMAGE_PULL_PUSH_REF` | `v1.1.1` | The `images-pull-push` release (a tag, branch or commit) whose `image_pull_push.sh` is fetched for image work. A copy already here is reused only if it came from the same ref. Air-gapped, the copy in the bundle is used and nothing is downloaded |
| `IMAGE_PULL_PUSH_URL` | the ref's file on `raw.githubusercontent.com` | Full URL of `image_pull_push.sh`, for a mirror. Wins over `IMAGE_PULL_PUSH_REF` |
| `IMAGE_PULL_PUSH_SHA256` | empty | Optional checksum of `image_pull_push.sh`. A mismatch stops the run, and leaves no file behind |
| `INSTALL_PACKAGES_REF` | `v1.1.3` | The `install-packages` release whose `install_packages.sh` `save` uses to bundle host packages for an air-gapped install (`iptables`, and `kernel-modules-extra` on EL). The bundle carries that copy |
| `INSTALL_PACKAGES_URL` | the ref's file on `raw.githubusercontent.com` | Full URL of `install_packages.sh`, for a mirror. Wins over `INSTALL_PACKAGES_REF` |
| `INSTALL_PACKAGES_SHA256` | empty | Optional checksum of `install_packages.sh`. A mismatch stops the save, and leaves no file behind |
| `UPGRADE_WAIT` | `false` | `upgrade`: set `true` to wait until every targeted node runs the new version and is schedulable again, and exit 1 if that doesn't happen within `UPGRADE_WAIT_TIMEOUT`. By default `upgrade` exits once the plans are applied, and the nodes upgrade in the background |
| `UPGRADE_WAIT_TIMEOUT` | `1800` | Seconds `UPGRADE_WAIT` waits |
| `POD_WAIT_TIMEOUT` | `300` | Seconds `install`, `join` and the add-ons wait for their pods to be ready. If they aren't ready in time, the error names each pod and its state. Raise it for a slow host or network. Through `ap-tools`, give it on the command line, `sudo POD_WAIT_TIMEOUT=600 ./ap-tools install rke2`: `ap-tools` doesn't pass it on from `inputs.env` |
| `SUC_VERSION` | `v0.21.0` | The system-upgrade-controller release used by `upgrade` and bundled by `save`. It used to follow whatever release was latest |

### Optional Component Settings (on by default)

| Variable | Default | Description |
|---|---|---|
| `INSTALL_INGRESS` | `true` | Install the RKE2 bundled NGINX ingress controller |
| `INSTALL_SERVICELB` | `true` | Enable the Klipper service LoadBalancer |
| `INSTALL_LOCAL_PATH_PROVISIONER` | `true` | Install Rancher local-path-provisioner as the default storage class |
| `LOCAL_PATH_PROVISIONER_VERSION` | `v0.0.32` | Version of the local-path-provisioner |
| `INSTALL_DNS_UTILITY` | `true` | Deploy a Kubernetes DNS utility pod for DNS troubleshooting |

### Velero Backup Settings

> **Required before running `install velero`**. See [Velero Backup](#velero-backup).

| Variable | Default | Description |
|---|---|---|
| `VELERO_VERSION` | `v1.17.1` | Velero CLI/server version |
| `VELERO_AWS_PLUGIN_VERSION` | `v1.13.0` | Velero AWS plugin version (used for S3 backend) |
| `VELERO_BUCKET` | `velero` | S3 bucket name for backup storage. In a multi-cluster environment set this per cluster (e.g. `VELERO_BUCKET=$CLUSTER_NAME`) to avoid backup collision. The installer prints a warning if `VELERO_BUCKET` is left at the default `velero` while `CLUSTER_NAME` has been customised. |
| `VELERO_S3_URL` | *(required)* | S3 endpoint URL, e.g. `https://s3.example.com:8333` |
| `VELERO_S3_ACCESS_KEY` | *(required)* | S3 access key |
| `VELERO_S3_SECRET_KEY` | *(required)* | S3 secret key |
| `VELERO_BACKUP_NAMESPACES` | `default` | Comma-separated list of namespaces to include in scheduled backups |
| `VELERO_BACKUP_TTL` | `720h` | Backup retention period (30 days) |
| `VELERO_BACKUP_SCHEDULE` | `0 2 * * *` | Cron schedule for the daily backup (default: 2 AM) |
| `VSC_NAME` | `longhorn-snapshot-vsc` | VolumeSnapshotClass name for CSI snapshots |
| `VSC_DRIVER` | `driver.longhorn.io` | CSI driver for VolumeSnapshotClass (Longhorn by default) |

### Monitoring Settings

> **Required before running `install monitoring`**. See [Monitoring Stack](#monitoring-stack).

| Variable | Default | Description |
|---|---|---|
| `MONITORING_HOST` | *(required)* | IP or FQDN of external monitoring host (runs Loki, Grafana, and Prometheus) |
| `MONITORING_LOKI_PORT` | `3100` | Loki HTTP port on the external monitoring host |
| `MONITORING_PROMETHEUS_PORT` | `9090` | Prometheus remote-write receiver port |
| `CLUSTER_NAME` | `edge-lab` | Cluster label applied to all metrics and logs for multi-cluster filtering |
| `HELM_VERSION` | `4.0.1` | Helm version to install if not already present (default bumped from 3.12.0; still overridable) |
| `KUBE_PROMETHEUS_STACK_VERSION` | `69.8.0` | kube-prometheus-stack Helm chart version |
| `FLUENT_BIT_CHART_VERSION` | `0.55.0` | Fluent Bit Helm chart version |
| `FLUENT_BIT_VERSION` | `4.2.2` | Fluent Bit application/image version |
| `PROMETHEUS_RETENTION` | `48h` | In-cluster Prometheus retention (short-term; long-term is on the external host) |
| `PROMETHEUS_STORAGE_SIZE` | `50Gi` | PVC size for the in-cluster Prometheus |
| `PROMETHEUS_STORAGE_CLASS` | `longhorn` | StorageClass used for Prometheus PVCs |
| `MONITOR_EXCLUDE_NS` | `kube-system kube-public kube-node-lease default monitoring` | Namespaces skipped during ServiceMonitor auto-discovery |
| `MONITOR_PORT_NAMES` | `manager metrics http-metrics prometheus monitoring prom` | Port names treated as Prometheus metrics endpoints during auto-discovery |
| `MONITOR_CONFIGS_DIR` | *(empty)* | Optional directory of additional ServiceMonitor YAML files to apply |

---

## Commands Reference

```
sudo ./rke2_installer.sh [command ...] [option ...]
```

| Command | Description |
|---|---|
| `install` | Install RKE2 as a single-node untainted server. If `rke2-save.tar.gz` is present, installs from the offline archive. |
| `install velero` | Install Velero with CSI snapshot support into an existing RKE2 cluster. Requires S3 variables to be set. |
| `install monitoring` | Install kube-prometheus-stack and Fluent Bit into an existing RKE2 cluster. Requires `MONITORING_HOST` to be set. |
| `uninstall` | Uninstall RKE2 from the host. Cannot be combined with other commands. |
| `save` | Download all RKE2 binaries, Velero, monitoring charts, and utility images into a portable `rke2-save.tar.gz` archive for air-gapped use. |
| `push` | Push RKE2 and utility images to a private registry. Requires `-registry`. Can be combined with `save`. |
| `join agent <server-fqdn> <token>` | Join this host to an existing cluster as a worker agent node. |
| `join server <server-fqdn> <token>` | Join this host to an existing cluster as an additional control-plane server. |
| `upgrade server [stable\|version]` | Upgrade server (control-plane) nodes to the specified version. |
| `upgrade agent [stable\|version]` | Upgrade agent (worker) nodes to the specified version. |
| `upgrade both [stable\|version]` | Upgrade all nodes — servers first, then agents. |

---

## Re-Runs, Reconcile and Uninstall Behavior

**`install`/`join` on a node that is already running RKE2 no longer fails.** The installer renders the
requested `config.yaml` and compares it with the live `/etc/rancher/rke2/config.yaml`:

| Situation | Behavior |
|---|---|
| Fresh host | Normal install |
| Same config, same version | Core install is skipped; the idempotent post-steps re-run (config/manifests, host settings, kubeconfig copies, symlink repair, utilities). Useful to resume an interrupted install |
| Config differs, `RKE2_RECONFIGURE=false` (default) | Clear error with a diff (install mode); nothing is changed |
| Config differs, `RKE2_RECONFIGURE=true` | New config is written and the rke2 service is **restarted** |
| Requested `RKE2_VERSION` differs from the running version | Error directing you to the `upgrade` command |
| `join` pointed at a different cluster server | Error — a node cannot switch clusters; `uninstall` first |
| `join` pointed at a new address for the **same** cluster, `RKE2_RECONFIGURE=true` | Allowed, if the join token is a secure one (`K10<hash>::…`) and the CA the new address serves at `https://<address>:9345/cacerts` matches the token's hash. The node's `server:` changes, and the service restarts. Otherwise the error above stands |
| A run without `-registry` on a node that has a registry configured | The registry config is left in place, with a warning naming it |
| `join agent` with settings only servers read (`CLUSTER_CIDR`, `SERVICE_CIDR`, `INSTALL_SERVICELB`, `INSTALL_LOCAL_PATH_PROVISIONER`, `INSTALL_DNS_UTILITY`, `CONTROL_PLANE_TAINT`, `COREDNS_HOSTS`, `PVC_DATA`) | A warning naming the ones it ignores |
| The host runs the other RKE2 role (server vs agent) | Error — `uninstall` first |

**Pod-readiness timeouts now fail the command.** If pods are not ready within `POD_WAIT_TIMEOUT` (300 s) the install
exits non-zero, and names the pods that weren't ready (previously it printed an error but exited 0). The only warn-and-continue site is the
non-critical `dnsutils` check in the `default` namespace. Re-running `install` after the cluster
settles completes the remaining steps.

**`CNI_TYPE=none`** brings up the control plane with no CNI, for you to install your own. No pod can start until you
do, so the install waits only for the API server, and doesn't wait for any pod. The node stays `NotReady` until then.

**Uninstall restores recorded host state.** The first install writes
`/etc/rke2-installer/install-state.env` (mode 0600) recording the pre-install state of swap,
multipathd, UFW/firewalld, the NetworkManager CNI conf, and the CIS `etcd` user. `uninstall`:

- stops the rke2 services **before** removing anything, and finds the upstream uninstaller for both
  tar-method (`/usr/local/bin`) and rpm-method (`/usr/bin`, Rocky/RHEL online) installs — removing the
  RKE2 rpm packages on rpm-method hosts
- removes `/etc/rancher/rke2` (including `registries.yaml`, which holds registry credentials)
- removes only the kubeconfig **files** it wrote (`/root/.kube/config`, `~user/.kube/config`) — never
  the whole `.kube` directory
- restores swap (fstab entries are commented out with a `# rke2-installer-swap` marker at install, not
  deleted), re-enables multipathd/UFW/firewalld only if they were enabled before install, removes the
  `etcd` user only if this tool created it, and removes any NTP config this tool added
- hosts installed by an older version (no state file) get file cleanup only; host-setting restoration
  is skipped with a note

---

## Options Reference

| Option | Description |
|---|---|
| `-tls-san <fqdn-or-ip>` | Add an extra TLS SAN to the API server certificate. Use with `install` or `join server`. |
| `-registry <registry:port> <username> <password>` | Configure a private registry as a pull-through mirror. Use with `install`, `install velero`, `join`, `push`, or `upgrade`. |

---

## Optional Components

### NGINX Ingress Controller

**Enabled by default** (`INSTALL_INGRESS=true`)

The RKE2-bundled NGINX ingress controller is installed during `install` and `join server`. Set `INSTALL_INGRESS=false` to disable it, which removes `rke2-ingress-nginx` from the cluster manifests.

---

### Klipper LoadBalancer

**Enabled by default** (`INSTALL_SERVICELB=true`)

Klipper is the RKE2 built-in service LoadBalancer. It allows `LoadBalancer` type services to receive an external IP on bare-metal hosts. Set `INSTALL_SERVICELB=false` to disable it if you are using an external load balancer solution (e.g. MetalLB).

---

### Local Path Provisioner

**Enabled by default** (`INSTALL_LOCAL_PATH_PROVISIONER=true`)

Installs the Rancher local-path-provisioner and sets it as the default `StorageClass`. Persistent volume claims using this class are stored on the local node filesystem under `PVC_DATA`. Disable with `INSTALL_LOCAL_PATH_PROVISIONER=false`.

---

### CIS Hardening

**Disabled by default** (`ENABLE_CIS=false`)

Set `ENABLE_CIS=true` to apply the RKE2 CIS Kubernetes hardening profile. This includes:

- Applying the `cis` profile to the RKE2 server configuration
- Configuring CIS-required sysctl parameters on the host
- Creating a dedicated `etcd` system user
- Patching service accounts in all namespaces to disable auto-mount of service account tokens

---

### Velero Backup

**Optional** — Run as a separate step after RKE2 is installed.

Velero provides Kubernetes cluster backup and restore using an S3-compatible object store and CSI volume snapshots (e.g. Longhorn).

#### Prerequisites

1. An S3-compatible object store (MinIO, Ceph RGW, AWS S3, etc.)
2. A pre-created S3 bucket (default name: `velero`)
3. Longhorn (or another CSI driver) installed in the cluster for volume snapshots
4. Set the following variables in the script before running:

```bash
VELERO_S3_URL="https://s3.example.com:8333"
VELERO_S3_ACCESS_KEY="your-access-key"
VELERO_S3_SECRET_KEY="your-secret-key"
VELERO_BUCKET="velero"
VELERO_BACKUP_NAMESPACES="default,my-app"  # namespaces to back up
```

#### Install

```bash
sudo ./rke2_installer.sh install velero
```

#### What Gets Installed

- Velero CLI binary at `/usr/local/bin/velero`
- Velero server and node-agent pods in the `velero` namespace
- A VolumeSnapshotClass (`longhorn-snapshot-vsc` by default) for CSI snapshots
- A daily scheduled backup (`daily-full-backup`) with configurable schedule and TTL

#### Post-Install Verification

```bash
velero backup-location get          # should show 'Available'
velero schedule get                 # should show 'daily-full-backup'
kubectl get pods -n velero          # server + node-agent pods
```

#### Common Operations

```bash
# Trigger a backup manually
velero backup create manual-backup --from-schedule daily-full-backup --wait

# List backups
velero backup get

# Describe a backup
velero backup describe <backup-name> --details

# Restore from a backup
velero restore create --from-backup <backup-name> --wait
```

#### Air-Gapped Velero

```bash
# Save velero images into the archive
sudo ./rke2_installer.sh save

# Push velero images to a registry and install
sudo ./rke2_installer.sh install velero push -registry my.registry.com:443 myuser mypassword
```

---

### Monitoring Stack

**Optional** — Run as a separate step after RKE2 is installed.

Installs an in-cluster monitoring stack that ships metrics and logs to an external monitoring host running Grafana, Loki, and Prometheus.

#### What Gets Installed

- **kube-prometheus-stack**: Prometheus, node-exporter, and kube-state-metrics
- **Fluent Bit** (DaemonSet): Collects container logs and systemd/host logs, ships to external Loki
- **Prometheus remote-write**: Forwards metrics to the external Prometheus host
- **ServiceMonitors**: Auto-discovered for any service with a known metrics port name (`metrics`, `http-metrics`, `prometheus`, etc.)

> Grafana is **not** deployed in-cluster. Grafana runs on the external monitoring host pointed to by `MONITORING_HOST`.

#### Prerequisites

1. An external Docker host running Loki, Grafana, and Prometheus with remote-write enabled
2. Set the following variable in the script before running:

```bash
MONITORING_HOST="192.168.1.100"   # IP or FQDN of external monitoring host
CLUSTER_NAME="my-cluster"         # Label applied to all metrics and logs
```

3. A StorageClass that supports `ReadWriteOnce` PVCs (Longhorn by default). Update `PROMETHEUS_STORAGE_CLASS` if using a different storage class.

#### Install

```bash
sudo ./rke2_installer.sh install monitoring
```

#### Post-Install Verification

```bash
kubectl -n monitoring get pods            # kube-prometheus-stack + fluent-bit pods
kubectl -n monitoring get servicemonitors # auto-generated ServiceMonitors

# Verify data is flowing to the external host
curl -s http://<MONITORING_HOST>:3100/loki/api/v1/labels
curl -s http://<MONITORING_HOST>:9090/api/v1/label/__name__/values | grep -c .
```

External monitoring dashboards (Grafana at `https://<MONITORING_HOST>:3000`):

| Grafana Dashboard ID | Description |
|---|---|
| 3119 | Kubernetes Cluster Overview |
| 1860 | Node Exporter Full |
| 16888 | Longhorn |
| 7752 | Fluent Bit |
| 13639 | Loki Logs |

#### Multi-Cluster Log Filtering (LogQL)

```logql
{cluster="my-cluster", job="fluent-bit"}           # all k8s logs from this cluster
{cluster="my-cluster", job="fluent-bit-systemd"}    # systemd/host logs
{cluster="my-cluster"} |= "my-pod-name"            # filter by pod name
```

#### Custom ServiceMonitors

To apply additional custom ServiceMonitor YAML files, set `MONITOR_CONFIGS_DIR` to a directory containing your YAML files before running `install monitoring`. They will be applied automatically after auto-discovery.

#### Air-Gapped Monitoring

```bash
# Save monitoring charts and images into the archive
sudo ./rke2_installer.sh save

# Install monitoring from the offline archive
sudo ./rke2_installer.sh install monitoring
```

---

## Cluster Upgrades

The `upgrade` command uses the [system-upgrade-controller](https://docs.rke2.io/upgrades/automated) to perform automated, rolling upgrades of your RKE2 cluster. The controller is installed automatically if not already present.

```
sudo ./rke2_installer.sh upgrade [server|agent|both] [stable|version] [-registry ...]
```

| Argument | Description |
|---|---|
| `server` | Upgrade only server (control-plane) nodes |
| `agent` | Upgrade only agent (worker) nodes |
| `both` | Upgrade all nodes — servers are upgraded first, then agents |
| `stable` | Use the latest stable RKE2 release channel |
| `v1.x.x+rke2r1` | Upgrade to a specific RKE2 version |

When `both` is specified, the agent upgrade plan waits for the server plan to complete before proceeding.

`upgrade` exits once the plans are applied, and the nodes upgrade in the background. Set `UPGRADE_WAIT=true` to wait until they all run the new version and are schedulable again. The server plan tolerates the control-plane taint (`CONTROL_PLANE_TAINT=true`), so a tainted control plane upgrades too.

#### Examples

```bash
# Upgrade all nodes to the latest stable release
sudo ./rke2_installer.sh upgrade both stable

# Upgrade only server nodes to a specific version
sudo ./rke2_installer.sh upgrade server v1.33.4+rke2r1

# Upgrade with a private registry (pushes upgrade images first)
sudo ./rke2_installer.sh upgrade both stable -registry my.registry.com:443 myuser mypassword
```

#### Post-Upgrade Verification

```bash
kubectl get plans -n system-upgrade    # Check upgrade plan status
kubectl get nodes                       # Verify node versions
```

#### Air-Gapped Upgrades

The `save` command includes the system-upgrade-controller manifests and the `rancher/rke2-upgrade` image for the `RKE2_VERSION` the bundle is built for, plus the stable release's when it can be looked up. An air-gapped upgrade can't use `stable`, because that needs `update.rke2.io`. So the rule is: build the bundle with `RKE2_VERSION=<target>`, then upgrade to that same version.

1. On an internet-connected machine, run `save` and `push` for the target version, to put its upgrade images in the registry
2. On the air-gapped host, run `upgrade` to that version with `-registry`. The script skips the downloads and uses the pushed images

```bash
# Online machine: save and push the target version (includes upgrade artifacts)
sudo RKE2_VERSION=v1.34.5+rke2r1 ./rke2_installer.sh save push -registry my.registry.com:443 myuser mypassword

# Air-gapped host: upgrade to that same version, using the registry
sudo ./rke2_installer.sh upgrade both v1.34.5+rke2r1 -registry my.registry.com:443 myuser mypassword
```

Before it starts, an air-gapped upgrade refuses when the node has no `/etc/rancher/rke2/registries.yaml`, or when the registry's tag list lacks `rancher/rke2-upgrade:<version>`. Without those, the upgrade job would sit in `ImagePullBackOff`. If the registry can't be asked (no `curl`, or an answer it can't read), it warns and goes on.

> When `-registry` is used with `upgrade`, the script verifies that `/etc/rancher/rke2/registries.yaml` exists and contains the specified registry.

---

## Air-Gapped Deployments

Use the `save` command on an internet-connected machine to download all required files, then transfer the archive to the air-gapped host.

#### Step 1 — Create the offline archive (on internet-connected machine)

```bash
sudo ./rke2_installer.sh save
```

This creates `rke2-save.tar.gz` containing:
- RKE2 binaries and images (core + CNI)
- Velero CLI and images
- Monitoring Helm charts (kube-prometheus-stack + Fluent Bit) and images
- System-upgrade-controller manifests and upgrade images
- Utility manifests (local-path-provisioner, dnsutils)
- Helm binary

#### Step 2 — Transfer the archive

```bash
scp rke2-save.tar.gz rke2_installer.sh user@air-gapped-host:~/
```

#### Step 3 — Extract and install on the air-gapped host

```bash
tar -xzf rke2-save.tar.gz
sudo ./rke2_installer.sh install
```

The script auto-detects `rke2-save.tar.gz` and switches to air-gapped mode.

#### Optional — Push images to a private registry

```bash
# From internet-connected machine: save + push
sudo ./rke2_installer.sh save push -registry my.registry.com:443 myuser mypassword

# Then install using the registry as a mirror (no archive needed)
sudo ./rke2_installer.sh install -registry my.registry.com:443 myuser mypassword
```

> The registry project path `/rancher` must pre-exist on the target registry (e.g. `my.registry.com:443/rancher`).

---

## Multi-Node Clusters

After the first server node is installed, its join token is written to `$RKE2_DATA/server/node-token`. Use this token to join additional nodes.

#### Join a worker (agent) node

```bash
sudo ./rke2_installer.sh join agent my.rke2-server.lab <join-token>
```

#### Join an additional control-plane (server) node

```bash
sudo ./rke2_installer.sh join server my.rke2-server.lab <join-token>
```

> Set `CONTROL_PLANE_TAINT=true` before installing the first server if you want workloads to run only on agent nodes.

---

## Examples

```bash
# Install RKE2 (online or from archive if present)
sudo ./rke2_installer.sh install

# Install with a custom TLS SAN
sudo ./rke2_installer.sh install -tls-san my.rke2-cluster.lab

# Install using a private registry mirror
sudo ./rke2_installer.sh install -registry my.registry.com:443 myuser mypassword

# Install and push images to a registry (for future air-gapped use)
sudo ./rke2_installer.sh install push -registry my.registry.com:443 myuser mypassword

# Install Velero backup (set S3 vars in script first)
sudo ./rke2_installer.sh install velero

# Install Velero in air-gapped mode with a registry mirror
sudo ./rke2_installer.sh install velero push -registry my.registry.com:443 myuser mypassword

# Install monitoring stack (set MONITORING_HOST in script first)
sudo ./rke2_installer.sh install monitoring

# Join as agent node
sudo ./rke2_installer.sh join agent my.rke2-server.lab <join-token>

# Join as additional server node
sudo ./rke2_installer.sh join server my.rke2-server.lab <join-token>

# Upgrade all nodes to the latest stable release
sudo ./rke2_installer.sh upgrade both stable

# Upgrade server nodes to a specific version
sudo ./rke2_installer.sh upgrade server v1.33.4+rke2r1

# Upgrade with a private registry
sudo ./rke2_installer.sh upgrade both stable -registry my.registry.com:443 myuser mypassword

# Create offline archive for air-gapped deployment
sudo ./rke2_installer.sh save

# Push images to registry only (without installing)
sudo ./rke2_installer.sh push -registry my.registry.com:443 myuser mypassword

# Uninstall RKE2 from the host
sudo ./rke2_installer.sh uninstall
```

---

## Upstream / Credits

This project automates the following open-source software; all credit to their authors. See [NOTICE](NOTICE) for
the full third-party list + licenses.

- Rancher RKE2 + bundled containerd / CoreDNS / Calico-Flannel (canal) / ingress-nginx / metrics-server — Apache-2.0
- Helm, Velero, local-path-provisioner, system-upgrade-controller, Fluent Bit — Apache-2.0
- kube-prometheus-stack (Apache-2.0 chart) — note its monitoring path deploys **Grafana (AGPL-3.0)**; provide source/offer if the Grafana image is bundled

## License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
