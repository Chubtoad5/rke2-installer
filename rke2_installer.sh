#!/bin/bash

# --- Script Configuration - DO NOT EDIT --- #
set -o errexit
set -o nounset
set -o pipefail

# --- USER DEFINED VARIABLES ---#
RKE2_VERSION=${RKE2_VERSION:-"v1.34.5+rke2r1"}
CNI_TYPE=${CNI_TYPE:-"canal"}                                                 # Valid values: calico, canal, cilium, none
ENABLE_CIS=${ENABLE_CIS:-"false"}                                             # Enables Kubernetes specific CIS hardening
CLUSTER_CIDR=${CLUSTER_CIDR:-"10.42.0.0/16"}
SERVICE_CIDR=${SERVICE_CIDR:-"10.43.0.0/16"}
MAX_PODS=${MAX_PODS:-"110"}
INSTALL_INGRESS=${INSTALL_INGRESS:-"true"}                                    # Install default NGINX ingress controller
INSTALL_SERVICELB=${INSTALL_SERVICELB:-"true"}                                # Install Klipper LoadBalancer
INSTALL_LOCAL_PATH_PROVISIONER=${INSTALL_LOCAL_PATH_PROVISIONER:-"true"}      # Install Rancher's local path storage-class
LOCAL_PATH_PROVISIONER_VERSION=${LOCAL_PATH_PROVISIONER_VERSION:-"v0.0.32"}
INSTALL_DNS_UTILITY=${INSTALL_DNS_UTILITY:-"true"}                            # Install kubernetes.io DNS utility container
MGMT_IP=${MGMT_IP:-$(hostname -I | awk '{print $1}')}
RKE2_DATA=${RKE2_DATA:-"default"}                                             # Path where etcd, containerd and RKE2 data is stored, update with valid local path
KUBELET_DATA=${KUBELET_DATA:-"default"}                                       # Path where kubelet data is stored, update with valid local path
PVC_DATA=${PVC_DATA:-"default"}                                               # Path where storage class PVCs are stored, update with valid local path
CONTROL_PLANE_TAINT=${CONTROL_PLANE_TAINT:-"false"}                           # Set to true to taint the control-plane node for multi-node clusters and workload separation
RKE2_RECONFIGURE=${RKE2_RECONFIGURE:-"false"}                                 # Set to true to allow 'install'/'join' on a RUNNING node to apply a changed config.yaml and restart the rke2 service
NTP_SERVERS=${NTP_SERVERS:-}                                                  # Optional space/comma-separated NTP server list applied during 'install'/'join'; empty = leave the OS default time source unchanged
DEBUG=${DEBUG:-"1"}

# Velero Backup Configuration
VELERO_VERSION=${VELERO_VERSION:-"v1.17.1"}
VELERO_AWS_PLUGIN_VERSION=${VELERO_AWS_PLUGIN_VERSION:-"v1.13.0"}
VELERO_BUCKET=${VELERO_BUCKET:-"velero"}
VELERO_S3_URL=${VELERO_S3_URL:-""}                                   # S3 endpoint URL, e.g. https://s3.example.com:8333
VELERO_S3_ACCESS_KEY=${VELERO_S3_ACCESS_KEY:-""}                     # S3 access key
VELERO_S3_SECRET_KEY=${VELERO_S3_SECRET_KEY:-""}                     # S3 secret key
VELERO_BACKUP_NAMESPACES=${VELERO_BACKUP_NAMESPACES:-"default"}      # Comma-separated list of namespaces to back up
VELERO_BACKUP_TTL=${VELERO_BACKUP_TTL:-"720h"}                       # Backup retention period (30 days)
VELERO_BACKUP_SCHEDULE=${VELERO_BACKUP_SCHEDULE:-"0 2 * * *"}        # Cron schedule for daily backups at 2 AM
VSC_NAME=${VSC_NAME:-"longhorn-snapshot-vsc"}                        # VolumeSnapshotClass name for Longhorn CSI snapshots
VSC_DRIVER=${VSC_DRIVER:-"driver.longhorn.io"}                       # CSI driver name for the VolumeSnapshotClass
PUSH_SAVE_VELERO=${PUSH_SAVE_VELERO:-"true"}                         # Allow saving and pushing velero images to private registry

# Monitoring Configuration
MONITORING_HOST=${MONITORING_HOST:-""}                               # IP/FQDN of external monitoring Docker host (Loki + Grafana + Prometheus)
MONITORING_LOKI_PORT=${MONITORING_LOKI_PORT:-"3100"}                 # Loki HTTP port on the monitoring host
MONITORING_PROMETHEUS_PORT=${MONITORING_PROMETHEUS_PORT:-"9090"}     # Prometheus remote-write receiver port on the monitoring host
CLUSTER_NAME=${CLUSTER_NAME:-"edge-lab"}                             # Cluster label applied to all metrics and logs
HELM_VERSION=${HELM_VERSION:-"3.12.0"}                               # Helm version to download if not already installed
KUBE_PROMETHEUS_STACK_VERSION=${KUBE_PROMETHEUS_STACK_VERSION:-"69.8.0"}  # kube-prometheus-stack Helm chart version
FLUENT_BIT_CHART_VERSION=${FLUENT_BIT_CHART_VERSION:-"0.55.0"}       # Fluent Bit Helm chart version (fluent/fluent-bit, uses 0.x.x versioning)
FLUENT_BIT_VERSION=${FLUENT_BIT_VERSION:-"4.2.2"}                    # Fluent Bit application/image version (appVersion in the chart above)
PROMETHEUS_RETENTION=${PROMETHEUS_RETENTION:-"48h"}                  # In-cluster Prometheus retention (short; long-term lives on external host)
PROMETHEUS_STORAGE_SIZE=${PROMETHEUS_STORAGE_SIZE:-"50Gi"}           # PVC size for in-cluster Prometheus
PROMETHEUS_STORAGE_CLASS=${PROMETHEUS_STORAGE_CLASS:-"longhorn"}     # StorageClass for Prometheus and Alertmanager PVCs
MONITOR_EXCLUDE_NS=${MONITOR_EXCLUDE_NS:-"kube-system kube-public kube-node-lease default monitoring"}  # Namespaces to skip during ServiceMonitor auto-discovery
MONITOR_PORT_NAMES=${MONITOR_PORT_NAMES:-"manager metrics http-metrics prometheus monitoring prom"}     # Port names treated as Prometheus metrics endpoints
MONITOR_CONFIGS_DIR=${MONITOR_CONFIGS_DIR:-""}                       # Optional dir of additional ServiceMonitor YAML files to apply
PUSH_SAVE_MONITORING=${PUSH_SAVE_MONITORING:-"true"}                 # Allow saving and pushing monitoring images to private registry
LICENSE_OFFER_CONTACT=${LICENSE_OFFER_CONTACT:-"the Chubtoad5 project via https://github.com/Chubtoad5"}  # contact named in the bundle's GPL/AGPL written offer

# --- INTERNAL VARIABLES - DO NOT EDIT --- #
user_name=${SUDO_USER:-}
SCRIPT_NAME=$(basename "$0")
AIR_GAPPED_MODE=0
SAVE_MODE=0
PUSH_MODE=0
INSTALL_MODE=0
INSTALL_TYPE="rke2"
TLS_SAN_MODE=0
TLS_SAN=""
UNINSTALL_MODE=0
JOIN_MODE=0
JOIN_TYPE=""
JOIN_TOKEN=""
JOIN_SERVER_FQDN=""
base_dir=$(pwd)
WORKING_DIR="$base_dir/rke2-install"
REGISTRY_MODE=0
REGISTRY_INFO=""
REG_FQDN=""
REG_PORT=""
REG_USER=""
REG_PASS=""
UPGRADE_MODE=0
UPGRADE_TYPE=""
UPGRADE_VERSION=""
SKIP_CORE_INSTALL=0
SERVICE_ACTION="start"
SELINUX_ENFORCING="false"
STATE_FILE="/etc/rke2-installer/install-state.env"
fqdn_pattern='^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
ipv4_pattern='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
TMP_DIR=$(mktemp -d /tmp/rke2-installer.XXXXXX)
RUN_DEBUG_STEP=""
RUN_DEBUG_LOG="$TMP_DIR/run-debug.log"

# EXIT trap: report the failing step (replaying captured output when DEBUG=0) and
# clean up temp files. Captures the exit code FIRST and re-exits with it so failures
# are never masked by the trap's own commands.
on_exit () {
    local rc=$?
    if [[ $rc -ne 0 && -n "$RUN_DEBUG_STEP" ]]; then
        echo "Error: step '$RUN_DEBUG_STEP' failed with exit code $rc." >&2
        if [[ "$DEBUG" != "1" && -s "$RUN_DEBUG_LOG" ]]; then
            echo "--- Last output from '$RUN_DEBUG_STEP' ---" >&2
            tail -n 40 "$RUN_DEBUG_LOG" >&2
            echo "--- (re-run with DEBUG=1 for full output) ---" >&2
        fi
    fi
    rm -rf "$TMP_DIR"
    rm -f "$base_dir/.rke2-save.tar.gz.partial"
    exit "$rc"
}
trap on_exit EXIT

# --- USAGE FUNCTION --- #
# Usage: $SCRIPT_NAME [install] [unintall] [save] [push] [join [server|agent] server-fqdn join-token-string] [upgrade [server|agent|both] [stable|version]] [-tls-san [server-fqdn-ip]] [-registry [registry:port username password]]

usage() {
    cat << EOF
Usage: $SCRIPT_NAME [command command ...] [option option ...]

Description:
- At least one command of [install], [uninstall], [save], [push], [join], or [upgrade] must be specified.
- [push] requires [-registry]. Project path must pre-exist (i.e. my.registry.com:443/rancher).
- [join] requires a type, [server-fqdn/ip], and a valid [join-token-string].
- [upgrade] requires a type [server|agent|both] and a version [stable|version].
- [-registry] option with [install], [join], or [upgrade], configures rke2 uses registry as a mirror.
- [-tls-san] option with [install] or [join server] configures the fqdn/ip as an extra tls-san.
- Edit $SCRIPT_NAME 'USER DEFINED VARIABLES' before running. See README.md for details.

Commands:
  [install]        : Installs the specified component. Defaults to rke2 if no type is given.
                     If an rke2-save.tar.gz file is detected in the directory, rke2 will be installed in air-gapped mode.
    (no type/rke2)   Installs rke2 as a single-node untainted server.
    [velero]         Installs Velero backup with CSI snapshot support into an existing RKE2 cluster.
                     Requires VELERO_S3_URL, VELERO_S3_ACCESS_KEY, and VELERO_S3_SECRET_KEY to be set.
    [monitoring]     Installs kube-prometheus-stack, Fluent Bit, and ServiceMonitors into an existing RKE2 cluster.
                     Requires MONITORING_HOST to be set to the IP/FQDN of the external monitoring Docker host.
  [uninstall]      : Uninstalls rke2 from the host.
  [save]           : Prepares an offline tar package with all rke2 install files and dependencies. Velero and monitoring are included based on PUSH_SAVE_* vars.
  [push]           : Pushes rke2 images to the specified registry. If an offline tar package is not found, it will first pull from the internet.
  [join]           : Joins the host to an existing cluster as a [server] or [agent]. [join-token-string] must be specified.
  [upgrade]        : Upgrades the RKE2 cluster using the system-upgrade-controller.
    [server|agent|both] Specifies which nodes to upgrade.
    [stable|version]    Use 'stable' for latest stable channel, or specify a version (e.g. v1.33.4+rke2r1).

Options:
  [agent|server <server-fqdn/ip> <join-token-string>]  : Only use with [join]
  [-registry <registry:port> <username> <password>]    : Only use with [install], [join], [push], [upgrade]
  [-tls-san <server-fqdn-ip>]                          : Only use with [install], [join server]

Examples:
  Install rke2 from the internet or offline package if it exists:
  sudo ./$SCRIPT_NAME install

  Install rke2 from the internet or offline package if it exists, and uses a private registry with existing images as a mirror:
  sudo ./$SCRIPT_NAME install -registry my.registry.com:443 myusername mypassword

  Install rke2 from the internet or offline package if it exists, and configure specified tls-san:
  sudo ./$SCRIPT_NAME install -tls-san my.rke2-cluster.lab

  Install rke2 from the internet or offline package if it exists, and push the rke2 images to a registry, using it as a mirror:
  sudo ./$SCRIPT_NAME install push -registry my.registry.com:443 myusername mypassword

  Install Velero into an existing RKE2 cluster (requires VELERO_S3_* vars to be configured):
  sudo ./$SCRIPT_NAME install velero

  Push images to a private registry from an offline tar package if it exists, or pull from the internet, but do not install rke2:
  sudo ./$SCRIPT_NAME push -registry my.registry.com:443 myusername mypassword

  Join the host to an existing cluster as a agent node:
  sudo ./$SCRIPT_NAME join agent my.rke2-server.lab [join-token-string]

  Create an offline tar package for installing rke2 and velero later in an air-gapped environment:
  sudo ./$SCRIPT_NAME save

  Upgrade all cluster nodes to the stable release:
  sudo ./$SCRIPT_NAME upgrade both stable

  Upgrade only server nodes to a specific version:
  sudo ./$SCRIPT_NAME upgrade server v1.33.4+rke2r1

  Upgrade agent nodes using a private registry:
  sudo ./$SCRIPT_NAME upgrade agent stable -registry my.registry.com:443 myusername mypassword

  Uninstall rke2 instance from the host:
  sudo ./$SCRIPT_NAME uninstall

EOF
    exit 1
}

# Displays the parsed and validated arguments
display_args() {
    echo "### RKE2 Installer Started at $(date) ###"
    echo "  AIR_GAPPED_MODE: $AIR_GAPPED_MODE"
    echo "  INSTALL_MODE: $INSTALL_MODE"
    echo "  INSTALL_TYPE: $INSTALL_TYPE"
    echo "  TLS_SAN_MODE: $TLS_SAN_MODE"
    echo "  TLS_SAN: $TLS_SAN"
    echo "  UNINSTALL_MODE: $UNINSTALL_MODE"
    echo "  SAVE_MODE: $SAVE_MODE"
    echo "  JOIN_MODE: $JOIN_MODE"
    echo "  JOIN_TYPE: $JOIN_TYPE"
    echo "  JOIN_SERVER_FQDN: $JOIN_SERVER_FQDN"
    echo "  JOIN_TOKEN: $JOIN_TOKEN"
    echo "  PUSH_MODE: $PUSH_MODE"
    echo "  REGISTRY_MODE: $REGISTRY_MODE"
    echo "  REGISTRY_INFO: $REGISTRY_INFO"
    echo "  REG_FQDN: $REG_FQDN"
    echo "  REG_PORT: $REG_PORT"
    echo "  REG_USER: $REG_USER"
    echo "  REG_PASS: $REG_PASS"
    echo "  OS: $OS_ID"
    echo "  SELINUX_ENFORCING: $SELINUX_ENFORCING"
    if [[ $INSTALL_TYPE == "monitoring" ]]; then
        echo "  MONITORING_HOST: $MONITORING_HOST"
        echo "  CLUSTER_NAME: $CLUSTER_NAME"
    fi
    if [[ $UPGRADE_MODE -eq 1 ]]; then
        echo "  UPGRADE_MODE: $UPGRADE_MODE"
        echo "  UPGRADE_TYPE: $UPGRADE_TYPE"
        echo "  UPGRADE_VERSION: $UPGRADE_VERSION"
    fi
}

# -- Install & Join Definitions -- #

run_install () {
    if [[ ! $(hostname) =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$ ]]; then
      echo "Error: Hostname '$(hostname)' is invalid."
      echo "It must match DNS-1123 subdomain format (i.e. lowercase alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character)."
      exit 1
    fi
    # Update non-default install paths
    if [[ $RKE2_DATA == "default" ]]; then RKE2_DATA="/var/lib/rancher/rke2"; else mkdir -p "$RKE2_DATA"; fi
    if [[ $KUBELET_DATA == "default" ]]; then KUBELET_DATA="/var/lib/kubelet"; else mkdir -p "$KUBELET_DATA"; fi
    if [[ $PVC_DATA == "default" ]]; then PVC_DATA="/opt/local-path-provisioner"; else mkdir -p "$PVC_DATA"; fi
    reconcile_existing_install
    run_debug create_registry_config
    if [[ $INSTALL_MODE -eq 1 ]]; then
        echo "--- Installing RKE2 ---"
        run_debug create_config_files
        if [[ $SKIP_CORE_INSTALL -eq 0 ]]; then
            run_debug install_rke2_binaries
        fi
        run_debug ensure_selinux_policy
        run_debug config_host_settings
        run_debug start_rke2_service "$SERVICE_ACTION"
        run_debug apply_utilities
    fi
    if [[ $JOIN_MODE -eq 1 && $JOIN_TYPE == "agent" ]]; then
        echo "--- Joining RKE2 agent ---"
        run_debug create_agent_join_config
        if [[ $SKIP_CORE_INSTALL -eq 0 ]]; then
            run_debug install_rke2_binaries
        fi
        run_debug ensure_selinux_policy
        run_debug config_host_settings
        run_debug start_rke2_service "$SERVICE_ACTION"
    fi
    if [[ $JOIN_MODE -eq 1 && $JOIN_TYPE == "server" ]]; then
        echo "--- Joining RKE2 server ---"
        run_debug create_server_join_config
        if [[ $SKIP_CORE_INSTALL -eq 0 ]]; then
            run_debug install_rke2_binaries
        fi
        run_debug ensure_selinux_policy
        run_debug config_host_settings
        run_debug start_rke2_service "$SERVICE_ACTION"
    fi
}

reconcile_existing_install () {
    # RK-2: make 'install'/'join' resumable on a host where RKE2 is already running.
    # Outcomes:
    #   - fresh host                          -> normal install (no-op here)
    #   - other role's service active         -> hard error (uninstall first)
    #   - running version != RKE2_VERSION     -> hard error directing to 'upgrade'
    #   - join to a different cluster server  -> hard error (uninstall first)
    #   - rendered config == live config      -> skip core install, re-run idempotent post-steps
    #   - rendered config != live config      -> apply + service restart, but ONLY when
    #                                            RKE2_RECONFIGURE=true; otherwise a clear error
    local requested_svc="rke2-server.service" other_svc="rke2-agent.service"
    if [[ $JOIN_MODE -eq 1 && $JOIN_TYPE == "agent" ]]; then
        requested_svc="rke2-agent.service"
        other_svc="rke2-server.service"
    fi
    if systemctl is-active --quiet "$other_svc"; then
        echo "Error: $other_svc is active on this host, but this invocation manages $requested_svc."
        echo "  This host already runs a different RKE2 role. Run 'sudo ./$SCRIPT_NAME uninstall' first."
        exit 1
    fi
    systemctl is-active --quiet "$requested_svc" || return 0
    echo "--- $requested_svc is already active: entering reconcile mode ---"
    # Version check: 'install' never changes the version of a running node.
    local rke2_bin running_version=""
    for rke2_bin in "$RKE2_DATA/bin/rke2" /usr/local/bin/rke2 /usr/bin/rke2; do
        if [[ -x "$rke2_bin" ]]; then
            running_version=$("$rke2_bin" --version 2>/dev/null | awk '/^rke2 version/ {print $3}') || true
            break
        fi
    done
    if [[ -n "$running_version" && "$running_version" != "$RKE2_VERSION" ]]; then
        echo "Error: RKE2 $running_version is already running, but RKE2_VERSION=$RKE2_VERSION was requested."
        echo "  'install' does not change the version of a running node."
        echo "  Use: sudo ./$SCRIPT_NAME upgrade [server|agent|both] $RKE2_VERSION"
        exit 1
    fi
    # Foreign-cluster guard: joining a different cluster requires uninstall, always.
    if [[ $JOIN_MODE -eq 1 && -f /etc/rancher/rke2/config.yaml ]]; then
        local existing_server
        existing_server=$(awk -F'https://' '/^server:/ {print $2}' /etc/rancher/rke2/config.yaml | cut -d: -f1)
        if [[ -n "$existing_server" && "$existing_server" != "$JOIN_SERVER_FQDN" ]]; then
            echo "Error: this node is already joined to cluster server '$existing_server', but a join to"
            echo "  '$JOIN_SERVER_FQDN' was requested. Joining a different cluster requires 'sudo ./$SCRIPT_NAME uninstall' first."
            exit 1
        fi
    fi
    # Config diff: render the requested config and compare with the live one.
    local rendered="$TMP_DIR/config.yaml.rendered"
    render_rke2_config "$rendered"
    if cmp -s "$rendered" /etc/rancher/rke2/config.yaml; then
        echo "  Existing /etc/rancher/rke2/config.yaml matches the requested configuration."
        echo "  Skipping core RKE2 install; re-running idempotent post-install steps."
        SKIP_CORE_INSTALL=1
        SERVICE_ACTION="start"
    elif [[ "${RKE2_RECONFIGURE,,}" == "true" ]]; then
        echo "  Requested configuration differs from the running node and RKE2_RECONFIGURE=true:"
        echo "  applying the new configuration and restarting $requested_svc."
        SKIP_CORE_INSTALL=1
        SERVICE_ACTION="restart"
    else
        echo "Error: RKE2 is running but the requested configuration differs from /etc/rancher/rke2/config.yaml."
        if [[ $INSTALL_MODE -eq 1 ]] && command -v diff &>/dev/null; then
            echo "--- diff (running vs requested) ---"
            diff /etc/rancher/rke2/config.yaml "$rendered" || true
            echo "-----------------------------------"
        fi
        echo "  Re-run with RKE2_RECONFIGURE=true to apply the new configuration and restart the service,"
        echo "  or align the environment variables with the running configuration."
        exit 1
    fi
}

ensure_selinux_policy () {
    # RK-3: RKE2 needs the rke2-selinux/container-selinux policies when SELinux is
    # enforcing. The upstream rpm install method (Rocky/RHEL online default) pulls
    # rke2-selinux in via its own repos automatically. The tar method - forced in
    # air-gap mode by INSTALL_RKE2_ARTIFACT_PATH, and used on SUSE hosts even online -
    # installs NO policy: bringing the cluster up like that yields AVC-broken
    # workloads. Verify/repair BEFORE the service is started.
    if [[ "$SELINUX_ENFORCING" != "true" ]]; then
        echo "  SELinux is not enforcing; no SELinux policy required."
        return 0
    fi
    echo "  SELinux is enforcing; verifying RKE2 SELinux policies..."
    if ! command -v rpm &>/dev/null; then
        echo "  WARNING: SELinux is enforcing but this is not an rpm-based host; cannot verify the"
        echo "  rke2-selinux policy. RKE2 workloads may hit AVC denials - verify SELinux policy manually."
        return 0
    fi
    if rpm -q rke2-selinux &>/dev/null; then
        echo "  rke2-selinux policy present ($(rpm -q rke2-selinux))."
        return 0
    fi
    if [[ $AIR_GAPPED_MODE -eq 0 ]]; then
        echo "  rke2-selinux not installed (tar-method install); attempting install from configured repos..."
        if command -v dnf &>/dev/null; then
            dnf install -y container-selinux rke2-selinux || true
        elif command -v yum &>/dev/null; then
            yum install -y container-selinux rke2-selinux || true
        elif command -v zypper &>/dev/null; then
            zypper --non-interactive install container-selinux rke2-selinux || true
        fi
    fi
    if rpm -q rke2-selinux &>/dev/null; then
        echo "  rke2-selinux policy installed."
        return 0
    fi
    echo "Error: SELinux is enforcing but the 'rke2-selinux' policy is not installed, and it could not be"
    echo "  installed automatically (air-gapped/tar-method installs cannot fetch it). Starting RKE2 now"
    echo "  would produce AVC-denied (broken) workloads. Remediation - choose ONE, then re-run:"
    echo "   1) Install the policies from local media/repos:"
    echo "        dnf|yum|zypper install -y container-selinux rke2-selinux"
    echo "      (offline: download from https://github.com/rancher/rke2-selinux/releases and 'rpm -ivh' them)"
    echo "   2) Or set SELinux to permissive mode:"
    echo "        setenforce 0    (and set SELINUX=permissive in /etc/selinux/config to persist)"
    exit 1
}

install_kubeconfigs_and_links () {
    mkdir -p /root/.kube
    cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
    chmod 600 /root/.kube/config
    if [[ -n "$user_name" && "$user_name" != "root" && -d "/home/$user_name" ]]; then
        mkdir -p /home/$user_name/.kube
        cp /etc/rancher/rke2/rke2.yaml /home/$user_name/.kube/config
        chown $user_name:$user_name /home/$user_name/.kube/config
        chmod 600 /home/$user_name/.kube/config
    fi
    export KUBECONFIG=/root/.kube/config
    export PATH=$PATH:$RKE2_DATA/bin
    # RK-17: -sfn repairs dangling/wrong symlinks on re-runs, but never clobber a
    # real binary the user installed at these paths.
    local tool
    for tool in kubectl ctr crictl; do
        if [[ ! -e "/usr/bin/$tool" || -L "/usr/bin/$tool" ]]; then
            ln -sfn "$RKE2_DATA/bin/$tool" "/usr/bin/$tool"
        fi
    done
}

start_rke2_service () {
    # $1 = systemctl action: 'start' (default; a no-op on an already-running service,
    # used by the reconcile skip path) or 'restart' (RKE2_RECONFIGURE apply path).
    local action="${1:-start}"
    local svc="rke2-server.service"
    if [[ $JOIN_TYPE == "agent" ]]; then
        svc="rke2-agent.service"
    fi
    systemctl enable "$svc"
    if [[ "$action" == "restart" ]]; then
        echo "  Restarting rke2 service to apply the updated configuration..."
    else
        echo "  Starting rke2 service, this may take several minutes..."
    fi
    if ! systemctl "$action" "$svc"; then
        echo "Error: rke2 service failed to $action. Exiting script."
        exit 1
    fi
    echo "  rke2 service ${action}ed successfully."
    if [[ $JOIN_TYPE == "agent" ]]; then
        echo "  Agent install completed, check the status with 'kubectl get nodes' and 'kubectl get pods -A' on the server for details."
    else
        echo "  Waiting for pods to start..."
        sleep 15
        install_kubeconfigs_and_links
        # Hard-fail: the rest of the install (utilities, add-ons) depends on a ready control plane.
        if ! check_namespace_pods_ready; then
            echo "Error: kube-system pods did not become ready within the timeout. The cluster may still be"
            echo "  converging - inspect with 'kubectl get pods -A' and re-run '$SCRIPT_NAME install' once it settles."
            exit 1
        fi
    fi
}

install_rke2_binaries () {
    echo "  Installing RKE2 binaries"
    if [[ "$AIR_GAPPED_MODE" -eq 1 ]]; then
        echo "  extracting rke2-core-images archive..."
        tar -xzf $WORKING_DIR/rke2-core-images/rke2-core-images.tar.gz -C $WORKING_DIR/rke2-core-images
        mv $WORKING_DIR/rke2-core-images/images/rke2-images-core.linux-amd64.tar.gz $WORKING_DIR/rke2-binaries
        cp $WORKING_DIR/rke2-binaries/rke2-images-core.linux-amd64.tar.gz $RKE2_DATA/agent/images
        rm -rf $WORKING_DIR/rke2-core-images/images
        echo "  extracting rke2-cni-images archive..."
        tar -xzf $WORKING_DIR/rke2-cni-images/rke2-$CNI_TYPE-images.tar.gz -C $WORKING_DIR/rke2-cni-images
        mv $WORKING_DIR/rke2-cni-images/images/rke2-images-$CNI_TYPE.linux-amd64.tar.gz $WORKING_DIR/rke2-binaries
        cp $WORKING_DIR/rke2-binaries/rke2-images-$CNI_TYPE.linux-amd64.tar.gz $RKE2_DATA/agent/images
        rm -rf $WORKING_DIR/rke2-cni-images/images
        if [[ $REGISTRY_MODE -eq 0 ]]; then
            echo "  extracting rke2-utilities archive..."
            tar -xzf $WORKING_DIR/rke2-utilities/container_images_*.tar.gz -C $WORKING_DIR/rke2-utilities
            cp $WORKING_DIR/rke2-utilities/images/images.tar.gz $RKE2_DATA/agent/images
            rm -rf $WORKING_DIR/rke2-utilities/images
        fi
        INSTALL_RKE2_ARTIFACT_PATH="$WORKING_DIR/rke2-binaries" INSTALL_RKE2_VERSION="$RKE2_VERSION" INSTALL_RKE2_TYPE="$JOIN_TYPE" sh $WORKING_DIR/rke2-binaries/install.sh
    else
        curl -sfL https://get.rke2.io | INSTALL_RKE2_VERSION="$RKE2_VERSION" INSTALL_RKE2_TYPE="$JOIN_TYPE" sh -
    fi
}

create_registry_config () {
    if [[ "$REGISTRY_MODE" -eq 1 ]]; then
        echo "  Configuring private registry for RKE2..."
        CERTS_DIR="/etc/rancher/rke2/certs.d/${REG_FQDN}:${REG_PORT}"
        mkdir -p "$CERTS_DIR"
        if openssl s_client -showcerts -connect "$REGISTRY_INFO" < /dev/null 2>/dev/null | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$CERTS_DIR/ca.crt"; then
            echo "  Certificate saved to $CERTS_DIR."
        else
            echo "Error: Failed to retrieve certificate from '$REG_FQDN'. Please ensure the registry is accessible and the port is correct."
            exit 1
        fi
        cat > /etc/rancher/rke2/registries.yaml <<EOF
configs:
  ${REG_FQDN}:${REG_PORT}:
    auth:
      username: "${REG_USER}"
      password: "${REG_PASS}"
    tls:
      ca_file: "${CERTS_DIR}/ca.crt"
mirrors:
  docker.io:
    endpoint:
      - "https://${REG_FQDN}:${REG_PORT}"
  quay.io:
    endpoint:
      - "https://${REG_FQDN}:${REG_PORT}"
  registry.k8s.io:
    endpoint:
      - "https://${REG_FQDN}:${REG_PORT}"
  cr.fluentbit.io:
    endpoint:
      - "https://${REG_FQDN}:${REG_PORT}"
  ${REG_FQDN}:${REG_PORT}:
    endpoint:
      - "https://${REG_FQDN}:${REG_PORT}"
EOF
        echo "  Private registry configuration written to /etc/rancher/rke2/registries.yaml"
    else
        echo "  Private registry not enabled. Skipping registry configuration."
    fi
}

render_rke2_config () {
    # Single source of truth for /etc/rancher/rke2/config.yaml generation (install server,
    # join server, and join agent were ~90% duplicated and had drifted - the agent copy was
    # missing data-dir/root-dir). Renders the config for the current invocation into the
    # file given as \$1; also used to diff against a running cluster in reconcile mode.
    local dest="$1"
    local resolv_conf_file
    if [[ -L /etc/resolv.conf ]]; then
        local resolv_link
        resolv_link=$(readlink -f /etc/resolv.conf)
        if [[ "$resolv_link" == "/run/systemd/resolve/stub-resolv.conf" ]]; then
            resolv_conf_file="/run/systemd/resolve/resolv.conf"
        else
            resolv_conf_file="$resolv_link"
        fi
    else
        resolv_conf_file="/etc/resolv.conf"
    fi
    : > "$dest"
    if [[ $JOIN_MODE -eq 1 ]]; then
        cat >> "$dest" <<EOF
server: https://${JOIN_SERVER_FQDN}:9345
token: "$JOIN_TOKEN"
EOF
    fi
    if [[ $JOIN_MODE -eq 1 && $JOIN_TYPE == "agent" ]]; then
        # Agent node config
        cat >> "$dest" <<EOF
node-ip: "$MGMT_IP"
kubelet-arg:
  - "max-pods=$MAX_PODS"
  - "resolv-conf=$resolv_conf_file"
EOF
        if [[ $KUBELET_DATA != "/var/lib/kubelet" ]]; then
            cat >> "$dest" <<EOF
  - root-dir=$KUBELET_DATA
EOF
        fi
        if [[ $RKE2_DATA != "/var/lib/rancher/rke2" ]]; then
            cat >> "$dest" <<EOF
data-dir: "$RKE2_DATA"
EOF
        fi
        if [[ "$SELINUX_ENFORCING" == "true" ]]; then
            cat >> "$dest" <<EOF
selinux: true
EOF
        fi
        if [[ ${ENABLE_CIS,,} == "true" ]]; then
            cat >> "$dest" <<EOF
profile: "cis"
EOF
        fi
        return 0
    fi
    # Server config (initial install and join server)
    cat >> "$dest" <<EOF
cni: "$CNI_TYPE"
write-kubeconfig-mode: "0600"
service-node-port-range: "443-40000"
cluster-cidr: "$CLUSTER_CIDR"
service-cidr: "$SERVICE_CIDR"
advertise-address: "$MGMT_IP"
node-ip: "$MGMT_IP"
etcd-extra-env:
  - "ETCD_AUTO_COMPACTION_RETENTION=72h"
  - "ETCD_AUTO_COMPACTION_MODE=periodic"
kube-apiserver-arg:
  - "audit-log-path=/var/log/rke2-apiserver-audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=10"
  - "audit-log-maxsize=200"
kubelet-arg:
  - "max-pods=$MAX_PODS"
  - "resolv-conf=$resolv_conf_file"
EOF
    if [[ $KUBELET_DATA != "/var/lib/kubelet" ]]; then
        cat >> "$dest" <<EOF
  - root-dir=$KUBELET_DATA
EOF
    fi
    if [[ $RKE2_DATA != "/var/lib/rancher/rke2" ]]; then
        cat >> "$dest" <<EOF
data-dir: "$RKE2_DATA"
EOF
    fi
    if [[ "$SELINUX_ENFORCING" == "true" ]]; then
        cat >> "$dest" <<EOF
selinux: true
EOF
    fi
    if [[ ${CONTROL_PLANE_TAINT,,} == "true" ]]; then
        cat >> "$dest" <<EOF
node-taint:
  - "node-role.kubernetes.io/control-plane:NoSchedule"
EOF
    fi
    if [[ ${INSTALL_INGRESS,,} == "false" ]]; then
        cat >> "$dest" <<EOF
disable:
  - rke2-ingress-nginx
EOF
    fi
    if [[ ${INSTALL_SERVICELB,,} == "true" ]]; then
        cat >> "$dest" <<EOF
enable-servicelb: $INSTALL_SERVICELB
EOF
    fi
    if [[ $TLS_SAN_MODE -eq 1 ]]; then
        cat >> "$dest" <<EOF
tls-san:
  - "$TLS_SAN"
EOF
    fi
    if [[ ${ENABLE_CIS,,} == "true" ]]; then
        cat >> "$dest" <<EOF
profile: "cis"
EOF
    fi
}

create_agent_join_config () {
    echo "  Generating /etc/rancher/rke2/config.yaml for agent"
    render_rke2_config /etc/rancher/rke2/config.yaml
}

create_server_join_config () {
    echo "  Generating /etc/rancher/rke2/config.yaml for server join"
    render_rke2_config /etc/rancher/rke2/config.yaml
}

create_config_files () {
    echo "  Generating /etc/rancher/rke2/config.yaml"
    render_rke2_config /etc/rancher/rke2/config.yaml
    if [[ ${ENABLE_CIS,,} == "true" ]]; then
        echo "  Generating $WORKING_DIR/rke2-utilities/account_update.yaml"
        cat > $WORKING_DIR/rke2-utilities/account_update.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
automountServiceAccountToken: false
EOF
    fi
    echo "  Generating $RKE2_DATA/server/manifests/rke2-coredns-helmchartconfig.yaml"
    cat > $RKE2_DATA/server/manifests/rke2-coredns-helmchartconfig.yaml <<EOF
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-coredns
  namespace: kube-system
spec:
  valuesContent: |-
    service:
      name: kube-dns
    servers:
    - zones:
      - zone: .
      port: 53
      plugins:
      - name: errors
      - name: health
        configBlock: |-
          lameduck 5s
      - name: ready
      - name: kubernetes
        parameters: cluster.local in-addr.arpa ip6.arpa
        configBlock: |-
          pods insecure
          fallthrough in-addr.arpa ip6.arpa
          ttl 30
      - name: prometheus
        parameters: 0.0.0.0:9153
      - name: forward
        parameters: . /etc/resolv.conf
      - name: cache
        parameters: 30
      - name: loop
      - name: reload
      - name: loadbalance
EOF
}

# Configure a user-defined NTP source on every node (install + join agent + join server).
# Clock skew across nodes breaks etcd and TLS. Only acts when NTP_SERVERS is set; otherwise
# the OS default time source is left untouched. Auto-detects the time daemon: chrony if
# present (Rocky/RHEL/SLES default; /etc/chrony.conf on Rocky, /etc/chrony/chrony.conf on
# Ubuntu), else systemd-timesyncd (the Ubuntu/Debian default incl. minimal images).
# Idempotent: marker-tagged lines are removed before re-appending. Ported from ap-tools'
# configure_node_ntp(); the '# ap-tools NTP' marker and the 10-ap-tools.conf drop-in name
# are kept INTENTIONALLY identical so hosts previously configured by ap-tools reconcile
# here instead of accumulating duplicate entries.
configure_node_ntp () {
  if [[ -z "${NTP_SERVERS// /}" ]]; then
    echo "  NTP_SERVERS not set; leaving the OS default time source unchanged."
    return 0
  fi
  # Normalise comma or space separated input to a clean space-separated list
  local ntp_list
  ntp_list=$(echo "$NTP_SERVERS" | tr ',' ' ' | xargs)
  echo "  Configuring user-defined NTP servers: $ntp_list"
  timedatectl set-ntp true 2>/dev/null || true
  if command -v chronyd >/dev/null 2>&1 || systemctl list-unit-files --no-legend 2>/dev/null | grep -q '^chronyd\.service'; then
    # chrony path (RHEL/Rocky/SLES default; Ubuntu when chrony is installed)
    local chrony_conf="/etc/chrony/chrony.conf"
    [[ -f /etc/chrony.conf ]] && chrony_conf="/etc/chrony.conf"
    sed -i '/# ap-tools NTP$/d' "$chrony_conf" 2>/dev/null || true
    local s
    for s in $ntp_list; do
      echo "server $s iburst # ap-tools NTP" >> "$chrony_conf"
    done
    systemctl enable chronyd 2>/dev/null || true
    systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null || true
    chronyc makestep >/dev/null 2>&1 || true
    state_set RKE2I_NTP_CONFIGURED "chrony"
  elif systemctl list-unit-files --no-legend 2>/dev/null | grep -q '^systemd-timesyncd\.service'; then
    # systemd-timesyncd path (Ubuntu/Debian default)
    mkdir -p /etc/systemd/timesyncd.conf.d
    printf '[Time]\nNTP=%s\n' "$ntp_list" > /etc/systemd/timesyncd.conf.d/10-ap-tools.conf
    systemctl enable systemd-timesyncd 2>/dev/null || true
    systemctl restart systemd-timesyncd 2>/dev/null || true
    state_set RKE2I_NTP_CONFIGURED "timesyncd"
  else
    # Neither daemon present: warn loudly instead of silently succeeding.
    echo "  WARNING: NTP_SERVERS is set but neither chrony nor systemd-timesyncd is present on this host."
    echo "  Time synchronization was NOT configured. Install chrony (apt/dnf/zypper install chrony) and"
    echo "  re-run, or configure NTP manually - clock skew across nodes breaks etcd and TLS."
    return 0
  fi
  # Give the daemon a moment, then report
  sleep 2
  echo "  NTP configured. Current status: $(timedatectl show -p NTP -p NTPSynchronized 2>/dev/null | tr '\n' ' ')"
}

state_set () {
    # state_set KEY VALUE - idempotent key=value write to the install-state file (RK-13)
    local key="$1" val="$2"
    mkdir -p "$(dirname "$STATE_FILE")"
    if [[ -f "$STATE_FILE" ]]; then
        sed -i "/^${key}=/d" "$STATE_FILE"
    fi
    echo "${key}=\"${val}\"" >> "$STATE_FILE"
    chmod 600 "$STATE_FILE"
}

record_install_state () {
    # RK-13: capture pre-install host state (first run only) so uninstall can restore
    # exactly what THIS tool changed - and nothing else.
    if [[ -f "$STATE_FILE" ]]; then
        return 0
    fi
    echo "  Recording pre-install host state to $STATE_FILE"
    state_set RKE2I_STATE_VERSION "1"
    local swap_was_on="false"
    if [[ -n "$(swapon --noheadings 2>/dev/null || true)" ]]; then
        swap_was_on="true"
    fi
    state_set RKE2I_SWAP_WAS_ON "$swap_was_on"
    local mp_svc_enabled mp_sock_enabled fw_enabled fw_active
    mp_svc_enabled=$(systemctl is-enabled multipathd.service 2>/dev/null) || true
    state_set RKE2I_MULTIPATHD_SERVICE_ENABLED "${mp_svc_enabled:-not-found}"
    mp_sock_enabled=$(systemctl is-enabled multipathd.socket 2>/dev/null) || true
    state_set RKE2I_MULTIPATHD_SOCKET_ENABLED "${mp_sock_enabled:-not-found}"
    local ufw_was_active="false"
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw_was_active="true"
    fi
    state_set RKE2I_UFW_WAS_ACTIVE "$ufw_was_active"
    fw_enabled=$(systemctl is-enabled firewalld.service 2>/dev/null) || true
    state_set RKE2I_FIREWALLD_ENABLED "${fw_enabled:-not-found}"
    fw_active=$(systemctl is-active firewalld.service 2>/dev/null) || true
    state_set RKE2I_FIREWALLD_WAS_ACTIVE "${fw_active:-inactive}"
    local nm_conf_preexisted="false"
    if [[ -f /etc/NetworkManager/conf.d/rke2-canal.conf ]]; then
        nm_conf_preexisted="true"
    fi
    state_set RKE2I_NM_CONF_PREEXISTED "$nm_conf_preexisted"
    state_set RKE2I_NTP_CONFIGURED "none"
}

config_host_settings () {
    record_install_state
    # Common kubernetes requirments
    # RK-7: probe per module. overlay and br_netfilter are hard requirements; dm_crypt and
    # nfs are only needed for encrypted/NFS-backed storage and are absent from minimal
    # kernels - warn with the exact kernel package to install instead of aborting.
    echo "  Enabling overlay, br_netfilter, dm_crypt, and nfs modules"
    local loaded_mods="" missing_optional="" mod
    for mod in overlay br_netfilter dm_crypt nfs; do
        if modprobe "$mod" 2>/dev/null; then
            loaded_mods="$loaded_mods $mod"
        else
            case "$mod" in
                overlay|br_netfilter)
                    echo "Error: required kernel module '$mod' could not be loaded. RKE2 cannot run without it."
                    exit 1
                    ;;
                *)
                    missing_optional="$missing_optional $mod"
                    ;;
            esac
        fi
    done
    if [[ -n "$missing_optional" ]]; then
        echo "  WARNING: optional kernel module(s) not available:$missing_optional"
        echo "  They are only needed for NFS-backed or encrypted (dm-crypt) storage. To add them,"
        echo "  install the extra kernel-modules package for your running kernel and re-run:"
        echo "    Ubuntu/Debian:  apt-get install -y linux-modules-extra-\$(uname -r)"
        echo "    RHEL/Rocky:     dnf install -y kernel-modules-extra"
        echo "    SUSE/Leap:      zypper install -y kernel-default   (minimal images ship kernel-default-base)"
    fi
    # Persist only the modules that actually loaded so systemd-modules-load stays clean at boot.
    printf '%s\n' $loaded_mods > /etc/modules-load.d/40-k8s.conf
    echo "  Disabling swap space"
    swapoff -a
    # Comment out (not delete) swap entries, tagged so uninstall can restore them (RK-13).
    if grep -qE '^[^#].*swap' /etc/fstab; then
        sed -i -E 's|^([^#].*swap.*)$|#\1 # rke2-installer-swap|' /etc/fstab
    fi
    echo "  Enabling k8s sysctl parameters"
    cat > /etc/sysctl.d/40-k8s.conf <<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
    if [[ ${ENABLE_CIS,,} == true ]]; then
        echo "  Enabling CIS host parameters"
        # tar-method installs ship the CIS sysctl profile under /usr/local/share,
        # rpm-method installs (Rocky/RHEL online) under /usr/share.
        local cis_sysctl_src="" cis_path
        for cis_path in /usr/local/share/rke2/rke2-cis-sysctl.conf /usr/share/rke2/rke2-cis-sysctl.conf; do
            if [[ -f "$cis_path" ]]; then
                cis_sysctl_src="$cis_path"
                break
            fi
        done
        if [[ -n "$cis_sysctl_src" ]]; then
            cp -f "$cis_sysctl_src" /etc/sysctl.d/60-rke2-cis.conf
        else
            echo "  WARNING: rke2-cis-sysctl.conf not found (checked tar and rpm locations); skipping CIS sysctl profile."
        fi
        # Re-run safe: only create the etcd user if missing; record it for uninstall (RK-13).
        if id etcd &>/dev/null; then
            echo "  etcd user already exists."
        else
            useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
            state_set RKE2I_ETCD_USER_CREATED "true"
        fi
    fi
    if ! systemctl restart systemd-sysctl; then
        echo "Error: systemd-sysctl.service failed to restart."
        exit 1
    fi
    echo "  systemd-sysctl.service restarted successfully"
# Configure NetworkManager to ignore CNI interfaces if it is in use
    if systemctl is-active --quiet NetworkManager; then
        echo "  NetworkManager is active. Creating rke2-canal.conf..."
        cat > /etc/NetworkManager/conf.d/rke2-canal.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:flannel*;interface-name:cali*;interface-name:tunl*;interface-name:vxlan.calico;interface-name:vxlan-v6.calico;interface-name:wireguard.cali;interface-name:wg-v6.cali
EOF
        echo "  Restarting NetworkManager to apply changes..."
        if ! systemctl restart NetworkManager; then
            echo "Error: NetworkManager failed to restart."
            exit 1
        fi
        echo "  NetworkManager restarted successfully"
    fi
# Disable multipath services
    if systemctl list-unit-files --no-legend --no-pager | grep -q "multipathd.service"; then
        echo "  Stopping and disabling multipathd"
        systemctl stop multipathd.service 2>/dev/null || true
        systemctl disable multipathd.service 2>/dev/null || true
        systemctl mask multipathd.service 2>/dev/null || true
    fi

    if systemctl list-unit-files --no-legend --no-pager | grep -q "multipathd.socket"; then
        echo "  Stopping and disabling multipathd.socket"
        systemctl stop multipathd.socket 2>/dev/null || true
        systemctl disable multipathd.socket 2>/dev/null || true
        systemctl mask multipathd.socket 2>/dev/null || true
    fi
    echo "  - Service status: $(systemctl is-active multipathd 2>/dev/null || echo 'inactive') / $(systemctl is-enabled multipathd 2>/dev/null || echo 'disabled')"
    echo "  - Socket status:  $(systemctl is-active multipathd.socket 2>/dev/null || echo 'inactive') / $(systemctl is-enabled multipathd.socket 2>/dev/null || echo 'disabled')"
 # Disable native firewall services
    echo "  Disabling native firewall services"
    if [[ "${OS_ID}" =~ ^(ubuntu|debian)$ ]] || [[ "${OS_ID_LIKE}" =~ (debian|ubuntu) ]]; then
        echo "  - Detected $OS_ID."
        if command -v ufw &>/dev/null; then
            echo "  - Disabling UFW (Uncomplicated Firewall)..."
            ufw disable || true
            # UFW status is safe for pipefail as 'ufw status' usually returns 0 if installed.
            echo "  - UFW Status: $(ufw status | grep 'Status:' || echo 'Status: inactive (check failed)')"
        else
            echo "  - UFW not installed. Skipping UFW disablement."
        fi
    # Check for RHEL/CentOS/Rocky/AlmaLinux/Fedora family (ID_LIKE or ID contains rhel/fedora/centos)
    elif [[ "${OS_ID}" =~ ^(rhel|centos|rocky|almalinux|fedora)$ ]] || [[ "${OS_ID_LIKE}" =~ (rhel|fedora|centos) ]]; then
        echo "  - Detected $OS_ID."
        if systemctl list-unit-files --no-legend --no-pager | grep "firewalld.service"; then
            echo "  - Stopping and disabling firewalld..."
            systemctl stop firewalld 2>/dev/null || true
            systemctl disable firewalld 2>/dev/null || true
            echo "  - Status: $(systemctl is-active firewalld 2>/dev/null || echo 'inactive') / $(systemctl is-enabled firewalld 2>/dev/null || echo 'disabled')"
        else
            echo "  - 'firewalld' service not found. Skipping."
        fi
    # Check for SLES/OpenSUSE (ID_LIKE or ID contains suse/sles)
    elif [[ "${OS_ID}" =~ ^(sles|opensuse-leap)$ ]] || [[ "${OS_ID_LIKE}" =~ (suse|sles) ]]; then
        echo "  - Detected $OS_ID."
        FIREWALL_DISABLED=false
        # Check firewalld first (common on modern SUSE)
        if systemctl list-unit-files --no-legend --no-pager | grep "firewalld.service"; then
            echo "  - Stopping and disabling firewalld..."
            systemctl stop firewalld 2>/dev/null || true
            systemctl disable firewalld 2>/dev/null || true
            echo "  - Status (firewalld): $(systemctl is-active firewalld 2>/dev/null || echo 'inactive') / $(systemctl is-enabled firewalld 2>/dev/null || echo 'disabled')"
            FIREWALL_DISABLED=true
        fi
        # Check SuSEfirewall2
        if systemctl list-unit-files --no-legend --no-pager | grep "SuSEfirewall2.service"; then
            echo "  - Stopping and disabling SuSEfirewall2..."
            systemctl stop SuSEfirewall2 2>/dev/null || true
            systemctl disable SuSEfirewall2 2>/dev/null || true
            echo "  - Status (SuSEfirewall2): $(systemctl is-active SuSEfirewall2 2>/dev/null || echo 'inactive') / $(systemctl is-enabled SuSEfirewall2 2>/dev/null || echo 'disabled')"
            FIREWALL_DISABLED=true
        fi
        if [ "$FIREWALL_DISABLED" == false ]; then
             echo "  - Firewall service (firewalld or SuSEfirewall2) not found. Skipping."
        fi
    else
        echo "  - WARNING: OS not explicitly handled for firewall configuration."
        echo "    Please manually verify the firewall service is stopped and disabled."
    fi
# Configure user-defined NTP servers (no-op when NTP_SERVERS is empty/unset)
    configure_node_ntp
}

apply_utilities () {
    if [[ ${ENABLE_CIS,,} == "true" ]]; then
        for namespace in $(kubectl get namespaces -A -o=jsonpath="{.items[*]['metadata.name']}"); do
            echo "  Patching ${namespace} namespace for CIS compliance"
            kubectl patch serviceaccount default -n ${namespace} -p "$(cat $WORKING_DIR/rke2-utilities/account_update.yaml)"
        done
    fi
    if [[ ${INSTALL_LOCAL_PATH_PROVISIONER,,} == "true" ]]; then
        echo "  Installing local-path-provisioner"
        # need to add check for registry and update yaml path
        if [[ $AIR_GAPPED_MODE -eq 0 ]]; then
            curl -sfL https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH_PROVISIONER_VERSION/deploy/local-path-storage.yaml -o $WORKING_DIR/rke2-utilities/local-path-storage.yaml
        fi
        if [[ $PVC_DATA != "/opt/local-path-provisioner" ]]; then
           sed -i "s|\"paths\":\[\s*\"[^\"]*\"\s*\]|\"paths\":[\"${PVC_DATA}/local-path-provisioner\"]|g" $WORKING_DIR/rke2-utilities/local-path-storage.yaml
        fi    
        kubectl apply -f $WORKING_DIR/rke2-utilities/local-path-storage.yaml
        # Hard-fail: the storageclass patch below and dependent PVCs need a live provisioner.
        if ! check_namespace_pods_ready local-path-storage; then
            echo "Error: local-path-provisioner pods did not become ready within the timeout."
            echo "  Inspect with 'kubectl get pods -n local-path-storage'."
            exit 1
        fi
        kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
    fi
    if [[ ${INSTALL_DNS_UTILITY,,} == "true" ]]; then
        echo "  Installing dnsutils"
        # need to add check for registry and update yaml path
        if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
            kubectl apply -f $WORKING_DIR/rke2-utilities/dnsutils.yaml
        else
            kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml
        fi
        # Warn-and-continue: 'default' may contain unrelated user workloads and dnsutils is a
        # non-critical troubleshooting pod - do not fail the install over it.
        if ! check_namespace_pods_ready default; then
            echo "  WARNING: pods in the 'default' namespace are not all ready; continuing (dnsutils is non-critical)."
        fi
    fi
}

# -- Upgrade Definitions -- #

run_upgrade () {
    echo "--- Running upgrade workflow"
    export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
    export PATH=$PATH:/var/lib/rancher/rke2/bin

    # Kubectl precheck - upgrade requires an existing cluster
    if ! kubectl get nodes &>/dev/null; then
        echo "Error: kubectl cannot reach the cluster. Ensure RKE2 is installed and running before upgrading."
        exit 1
    fi

    if [[ $REGISTRY_MODE -eq 1 ]]; then
        # Verify registries.yaml exists and contains the specified registry
        if [[ ! -f /etc/rancher/rke2/registries.yaml ]]; then
            echo "Error: /etc/rancher/rke2/registries.yaml not found. Registry must be configured before upgrading."
            exit 1
        fi
        if ! grep -q "$REGISTRY_INFO" /etc/rancher/rke2/registries.yaml; then
            echo "Error: Registry '$REGISTRY_INFO' not found in /etc/rancher/rke2/registries.yaml."
            exit 1
        fi
        # Only push images when online (airgapped assumes images already pushed)
        if [[ $AIR_GAPPED_MODE -eq 0 ]]; then
            run_debug push_upgrade_images
        fi
    fi

    run_debug install_system_upgrade_controller
    run_debug create_upgrade_plan

    echo "--- Finished upgrade workflow"
}

install_system_upgrade_controller () {
    echo "  Checking for system-upgrade-controller..."
    if kubectl get deployment -n system-upgrade system-upgrade-controller &>/dev/null; then
        echo "  system-upgrade-controller is already installed."
        return 0
    fi

    echo "  Installing system-upgrade-controller..."
    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        if [[ ! -f $WORKING_DIR/rke2-utilities/crd.yaml || ! -f $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml ]]; then
            echo "Error: system-upgrade-controller manifests not found in air-gapped archive."
            echo "  Re-run 'save' to include upgrade artifacts."
            exit 1
        fi
        kubectl apply -f $WORKING_DIR/rke2-utilities/crd.yaml -f $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
    else
        curl -sfL https://github.com/rancher/system-upgrade-controller/releases/latest/download/crd.yaml -o $WORKING_DIR/rke2-utilities/crd.yaml
        curl -sfL https://github.com/rancher/system-upgrade-controller/releases/latest/download/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
        kubectl apply -f $WORKING_DIR/rke2-utilities/crd.yaml -f $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
    fi

    # Hard-fail: upgrade plans are useless without a running controller.
    if ! check_namespace_pods_ready "system-upgrade"; then
        echo "Error: system-upgrade-controller did not become ready within the timeout."
        echo "  Inspect with 'kubectl get pods -n system-upgrade'."
        exit 1
    fi
    echo "  system-upgrade-controller installed successfully."
}

create_upgrade_plan () {
    echo "  Creating upgrade plan(s)..."

    # Determine version vs channel directive
    local version_directive
    if [[ "$UPGRADE_VERSION" == "stable" ]]; then
        version_directive="  channel: https://update.rke2.io/v1-release/channels/stable"
    else
        version_directive="  version: $UPGRADE_VERSION"
    fi

    # Apply server plan if type is server or both
    if [[ "$UPGRADE_TYPE" == "server" || "$UPGRADE_TYPE" == "both" ]]; then
        echo "  Applying server upgrade plan..."
        cat <<PLANEOF | kubectl apply -f -
apiVersion: upgrade.cattle.io/v1
kind: Plan
metadata:
  name: server-plan
  namespace: system-upgrade
spec:
  concurrency: 1
  cordon: true
  nodeSelector:
    matchExpressions:
    - key: node-role.kubernetes.io/control-plane
      operator: In
      values:
      - "true"
  serviceAccountName: system-upgrade
  upgrade:
    image: rancher/rke2-upgrade
$version_directive
PLANEOF
    fi

    # Apply agent plan if type is agent or both
    if [[ "$UPGRADE_TYPE" == "agent" || "$UPGRADE_TYPE" == "both" ]]; then
        echo "  Applying agent upgrade plan..."
        cat <<PLANEOF | kubectl apply -f -
apiVersion: upgrade.cattle.io/v1
kind: Plan
metadata:
  name: agent-plan
  namespace: system-upgrade
spec:
  concurrency: 1
  cordon: true
  nodeSelector:
    matchExpressions:
    - key: node-role.kubernetes.io/control-plane
      operator: DoesNotExist
  prepare:
    args:
    - prepare
    - server-plan
    image: rancher/rke2-upgrade
  serviceAccountName: system-upgrade
  upgrade:
    image: rancher/rke2-upgrade
$version_directive
PLANEOF
    fi

    echo "  Upgrade plan(s) applied successfully."
}

push_upgrade_images () {
    echo "  Pushing upgrade images to registry..."
    image_pull_push_check

    # Resolve the upgrade version tag for the rke2-upgrade image
    local upgrade_tag
    if [[ "$UPGRADE_VERSION" == "stable" ]]; then
        upgrade_tag=$(curl -sfL -o /dev/null -w '%{url_effective}' https://update.rke2.io/v1-release/channels/stable | awk -F/ '{gsub(/\+/,"-",$NF); print $NF}')
        echo "  Resolved stable version tag: $upgrade_tag"
    else
        upgrade_tag=$(echo "$UPGRADE_VERSION" | sed 's/+/-/')
    fi

    # Download SUC manifest to extract the controller image
    if [[ ! -f $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml ]]; then
        curl -sfL https://github.com/rancher/system-upgrade-controller/releases/latest/download/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
    fi
    local suc_image=$(grep 'rancher/system-upgrade-controller' $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml | awk '{print $2}')

    # Build upgrade-images.txt
    local upgrade_images_file="$WORKING_DIR/rke2-utilities/images/upgrade-images.txt"
    echo "rancher/rke2-upgrade:${upgrade_tag}" > "$upgrade_images_file"
    echo "$suc_image" >> "$upgrade_images_file"

    echo "--- Printing upgrade-images.txt"
    cat "$upgrade_images_file"
    echo "---"

    # Push upgrade images
    $WORKING_DIR/rke2-utilities/image_pull_push.sh -f "$upgrade_images_file" push $REGISTRY_INFO $REG_USER $REG_PASS

    # Push RKE2 core+CNI images for the target version (same method as push_rke2_images online path)
    local upgrade_translated_version
    if [[ "$UPGRADE_VERSION" == "stable" ]]; then
        # Convert the resolved stable tag back to URL-encoded format
        local stable_version=$(curl -sfL -o /dev/null -w '%{url_effective}' https://update.rke2.io/v1-release/channels/stable | awk -F/ '{print $NF}')
        upgrade_translated_version=$(echo "$stable_version" | sed 's/+/%2B/')
    else
        upgrade_translated_version=$(echo "$UPGRADE_VERSION" | sed 's/+/%2B/')
    fi

    echo "  Downloading and pushing rke2 core images for upgrade version..."
    curl -sfL https://github.com/rancher/rke2/releases/download/$upgrade_translated_version/rke2-images-core.linux-amd64.txt -o $WORKING_DIR/rke2-core-images/rke2-images-core-upgrade.linux-amd64.txt
    $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-core-images/rke2-images-core-upgrade.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS

    if [[ $CNI_NONE == "false" ]]; then
        echo "  Downloading and pushing rke2 cni images for upgrade version..."
        curl -sfL https://github.com/rancher/rke2/releases/download/$upgrade_translated_version/rke2-images-$CNI_TYPE.linux-amd64.txt -o $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE-upgrade.linux-amd64.txt
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE-upgrade.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS
    fi
}

download_upgrade_artifacts () {
    echo "  Downloading system-upgrade-controller manifests..."
    curl -sfL https://github.com/rancher/system-upgrade-controller/releases/latest/download/crd.yaml -o $WORKING_DIR/rke2-utilities/crd.yaml
    curl -sfL https://github.com/rancher/system-upgrade-controller/releases/latest/download/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml

    # Extract SUC controller image from manifest and add to utility-images list
    local suc_image=$(grep 'rancher/system-upgrade-controller' $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml | awk '{print $2}')
    echo "  Adding SUC controller image to utility-images list: $suc_image"
    echo "$suc_image" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt

    # Resolve stable version for rke2-upgrade image tag
    local stable_tag=$(curl -sfL -o /dev/null -w '%{url_effective}' https://update.rke2.io/v1-release/channels/stable | awk -F/ '{gsub(/\+/,"-",$NF); print $NF}')
    echo "  Adding rke2-upgrade image to utility-images list: rancher/rke2-upgrade:$stable_tag"
    echo "rancher/rke2-upgrade:$stable_tag" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
}

# -- Velero Install Definitions -- #

run_install_velero () {
  export KUBECONFIG=/root/.kube/config
  export PATH=$PATH:$RKE2_DATA/bin

  # Install Velero CLI binary
  echo "  Installing Velero CLI ${VELERO_VERSION}..."
  cd $WORKING_DIR/velero
  if [[ $AIR_GAPPED_MODE == "0" ]]; then
    curl -L https://github.com/vmware-tanzu/velero/releases/download/${VELERO_VERSION}/velero-${VELERO_VERSION}-linux-amd64.tar.gz \
      -o velero-${VELERO_VERSION}-linux-amd64.tar.gz
  fi
  tar -xzf velero-${VELERO_VERSION}-linux-amd64.tar.gz
  mv velero-${VELERO_VERSION}-linux-amd64/velero /usr/local/bin/velero
  rm -rf velero-${VELERO_VERSION}-linux-amd64
  velero version --client-only

  # Verify snapshot controller is running (provided by RKE2)
  echo "  Verifying snapshot controller..."
  if ! kubectl get pods -n kube-system 2>/dev/null | grep -q snapshot-controller; then
    echo "Error: Snapshot controller not found in kube-system namespace."
    echo "  The snapshot controller is required for Velero CSI integration and should be provided by RKE2."
    exit 1
  fi
  echo "  Snapshot controller is running."

  # Create VolumeSnapshotClass for Longhorn
  echo "  Creating VolumeSnapshotClass '${VSC_NAME}'..."
  cat <<SNAPEOF | kubectl apply -f -
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: ${VSC_NAME}
  labels:
    velero.io/csi-volumesnapshot-class: "true"
driver: ${VSC_DRIVER}
deletionPolicy: Delete
parameters:
  type: snap
SNAPEOF

  # Create S3 credentials file
  echo "  Creating Velero S3 credentials..."
  cat > /tmp/credentials-velero <<CREDEOF
[default]
aws_access_key_id=${VELERO_S3_ACCESS_KEY}
aws_secret_access_key=${VELERO_S3_SECRET_KEY}
CREDEOF

  # Install Velero into the cluster
  echo "  Installing Velero server into the cluster..."
  velero install \
    --provider aws \
    --plugins velero/velero-plugin-for-aws:${VELERO_AWS_PLUGIN_VERSION} \
    --bucket ${VELERO_BUCKET} \
    --backup-location-config \
      region=us-east-1,s3ForcePathStyle=true,s3Url=${VELERO_S3_URL},checksumAlgorithm="",insecureSkipTLSVerify=true \
    --secret-file /tmp/credentials-velero \
    --features=EnableCSI \
    --use-node-agent \
    --use-volume-snapshots=true \
    --wait

  # Clean up credentials file
  rm -f /tmp/credentials-velero

  # Verify installation
  echo "  Verifying Velero installation..."
  # Hard-fail: a scheduled backup against a broken Velero deployment is worse than no install.
  if ! check_namespace_pods_ready "velero"; then
      echo "Error: Velero pods did not become ready within the timeout."
      echo "  Inspect with 'kubectl get pods -n velero' and re-run '$SCRIPT_NAME install velero'."
      exit 1
  fi

  # Create scheduled backup
  echo "  Creating scheduled backup '${VELERO_BACKUP_SCHEDULE}'..."
  velero schedule create daily-full-backup \
    --schedule="${VELERO_BACKUP_SCHEDULE}" \
    --ttl ${VELERO_BACKUP_TTL} \
    --snapshot-move-data \
    --include-cluster-resources=true \
    --include-namespaces ${VELERO_BACKUP_NAMESPACES}

  cd $base_dir
}

# -- Monitoring Install Definitions -- #

helm_check () {
    if ! command -v helm &>/dev/null; then
        echo "  Helm not found. Installing Helm ${HELM_VERSION}..."
        local helm_tar="helm-v${HELM_VERSION}-linux-amd64.tar.gz"
        if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
            local local_helm="$WORKING_DIR/monitoring/${helm_tar}"
            if [[ ! -f "$local_helm" ]]; then
                echo "Error: Air-gapped mode but Helm binary not found at $local_helm"
                echo "  Run '$SCRIPT_NAME save' first to download all required binaries."
                exit 1
            fi
            tar -xzf "$local_helm" -C /tmp
        else
            curl -fsSLo /tmp/${helm_tar} https://get.helm.sh/${helm_tar}
            tar -xzf /tmp/${helm_tar} -C /tmp
        fi
        mv /tmp/linux-amd64/helm /usr/bin/helm
        rm -rf /tmp/linux-amd64
        echo "  Helm ${HELM_VERSION} installed."
    else
        echo "  Helm found: $(helm version --short)"
    fi
}

generate_service_monitors () {
    echo "  Scanning cluster for metrics-exposing services..."
    local found=0

    while IFS= read -r ns; do
        # Skip excluded namespaces
        echo "$MONITOR_EXCLUDE_NS" | grep -qw "$ns" && continue

        # Iterate over services in this namespace: "<svc_name>\t<port1>,<port2>,..."
        while IFS=$'\t' read -r svc_name svc_ports; do
            [[ -z "$svc_name" ]] && continue

            # Find the first port name that matches a known metrics port
            local metrics_port=""
            for pname in $MONITOR_PORT_NAMES; do
                if echo "$svc_ports" | tr ',' '\n' | grep -qx "$pname"; then
                    metrics_port="$pname"
                    break
                fi
            done
            [[ -z "$metrics_port" ]] && continue

            # Prefer app.kubernetes.io/name label, fall back to app
            local sel_key sel_val
            sel_val=$(kubectl get svc -n "$ns" "$svc_name" \
              -o jsonpath='{.metadata.labels.app\.kubernetes\.io/name}' 2>/dev/null)
            if [[ -n "$sel_val" ]]; then
                sel_key="app.kubernetes.io/name"
            else
                sel_val=$(kubectl get svc -n "$ns" "$svc_name" \
                  -o jsonpath='{.metadata.labels.app}' 2>/dev/null)
                sel_key="app"
            fi

            if [[ -z "$sel_val" ]]; then
                echo "    Skipping $ns/$svc_name: no 'app' or 'app.kubernetes.io/name' label found."
                continue
            fi

            echo "    Creating ServiceMonitor: $svc_name (namespace=$ns port=$metrics_port ${sel_key}=${sel_val})"
            kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ${svc_name}
  namespace: monitoring
  labels:
    release: kube-prometheus-stack
spec:
  namespaceSelector:
    matchNames:
      - ${ns}
  selector:
    matchLabels:
      ${sel_key}: ${sel_val}
  endpoints:
    - port: ${metrics_port}
      interval: 30s
EOF
            found=$((found + 1))

        done < <(kubectl get svc -n "$ns" \
          -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.ports[*]}{.name}{","}{end}{"\n"}{end}' \
          2>/dev/null)

    done < <(kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)

    if [[ $found -eq 0 ]]; then
        echo "  No metrics-exposing services found outside excluded namespaces."
    else
        echo "  Created/updated $found ServiceMonitor(s)."
    fi

    # Apply any user-supplied or caller-supplied ServiceMonitor YAML files
    if [[ -n "$MONITOR_CONFIGS_DIR" ]]; then
        if [[ -d "$MONITOR_CONFIGS_DIR" ]]; then
            echo "  Applying custom ServiceMonitors from $MONITOR_CONFIGS_DIR..."
            for f in "$MONITOR_CONFIGS_DIR"/*.yaml; do
                [[ -f "$f" ]] || continue
                echo "    Applying $(basename "$f")..."
                kubectl apply -f "$f"
            done
        else
            echo "  Warning: MONITOR_CONFIGS_DIR='$MONITOR_CONFIGS_DIR' not found, skipping custom monitors."
        fi
    fi
}

run_install_monitoring () {
  export KUBECONFIG=/root/.kube/config
  export PATH=$PATH:$RKE2_DATA/bin

  helm_check

  # Resolve chart references — local .tgz in air-gapped mode, remote repo in online mode
  local PROM_CHART_REF FB_CHART_REF prom_version_flag fb_version_flag
  if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
    echo "  Air-gapped mode: using local Helm charts from $WORKING_DIR/monitoring/"
    PROM_CHART_REF=$(ls "$WORKING_DIR/monitoring/kube-prometheus-stack-"*.tgz 2>/dev/null | head -1)
    FB_CHART_REF=$(ls "$WORKING_DIR/monitoring/fluent-bit-"*.tgz 2>/dev/null | head -1)
    if [[ -z "$PROM_CHART_REF" || -z "$FB_CHART_REF" ]]; then
      echo "Error: Air-gapped monitoring charts not found in $WORKING_DIR/monitoring/"
      echo "  Run '$SCRIPT_NAME save' first to download all required charts."
      exit 1
    fi
    prom_version_flag=""
    fb_version_flag=""
  else
    echo "  Adding Helm repositories..."
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add fluent https://fluent.github.io/helm-charts
    helm repo update
    PROM_CHART_REF="prometheus-community/kube-prometheus-stack"
    FB_CHART_REF="fluent/fluent-bit"
    prom_version_flag="--version ${KUBE_PROMETHEUS_STACK_VERSION}"
    fb_version_flag="--version ${FLUENT_BIT_CHART_VERSION}"
  fi

  echo "  Creating monitoring namespace..."
  kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -

  # Install kube-prometheus-stack
  echo "  Installing kube-prometheus-stack v${KUBE_PROMETHEUS_STACK_VERSION}..."
  local prom_values
  prom_values=$(mktemp)
  cat > "$prom_values" <<PROMEOF
grafana:
  enabled: false

prometheus:
  prometheusSpec:
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: ${PROMETHEUS_STORAGE_CLASS}
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: ${PROMETHEUS_STORAGE_SIZE}
    retention: ${PROMETHEUS_RETENTION}
    retentionSize: "45GB"
    externalLabels:
      cluster: "${CLUSTER_NAME}"
    remoteWrite:
      - url: "http://${MONITORING_HOST}:${MONITORING_PROMETHEUS_PORT}/api/v1/write"
        queueConfig:
          maxSamplesPerSend: 5000
          batchSendDeadline: 10s
          maxShards: 10
    serviceMonitorSelectorNilUsesHelmValues: false
    podMonitorSelectorNilUsesHelmValues: false
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: "2"
        memory: 4Gi
  service:
    type: ClusterIP

nodeExporter:
  enabled: true

kubeStateMetrics:
  enabled: true

alertmanager:
  enabled: false
PROMEOF
  # shellcheck disable=SC2086
  helm upgrade --install kube-prometheus-stack "$PROM_CHART_REF" \
    --namespace monitoring \
    --values "$prom_values" \
    $prom_version_flag \
    --wait --timeout 10m
  rm -f "$prom_values"

  # Install Fluent Bit
  echo "  Installing Fluent Bit chart v${FLUENT_BIT_CHART_VERSION} (app v${FLUENT_BIT_VERSION})..."
  local fb_values
  fb_values=$(mktemp)
  cat > "$fb_values" <<FBEOF
kind: DaemonSet

image:
  repository: cr.fluentbit.io/fluent/fluent-bit
  tag: "${FLUENT_BIT_VERSION}"

tolerations:
  - operator: Exists

serviceMonitor:
  enabled: true
  namespace: monitoring
  interval: 30s

config:
  service: |
    [SERVICE]
        Flush         5
        Log_Level     info
        Daemon        off
        Parsers_File  /fluent-bit/etc/parsers.conf
        HTTP_Server   On
        HTTP_Listen   0.0.0.0
        HTTP_Port     2020
        Health_Check  On

  inputs: |
    [INPUT]
        Name              tail
        Tag               kube.*
        Path              /var/log/containers/*.log
        Parser            cri
        DB                /var/log/fluentbit-kube.db
        Mem_Buf_Limit     50MB
        Skip_Long_Lines   On
        Refresh_Interval  5

    [INPUT]
        Name              systemd
        Tag               host.*
        Systemd_Filter    _SYSTEMD_UNIT=rke2-server.service
        Systemd_Filter    _SYSTEMD_UNIT=rke2-agent.service
        Systemd_Filter    _SYSTEMD_UNIT=kubelet.service
        Read_From_Tail    On
        DB                /var/log/fluentbit-systemd.db

  filters: |
    [FILTER]
        Name                kubernetes
        Match               kube.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     kube.var.log.containers.
        Merge_Log           On
        Merge_Log_Key       log_processed
        Keep_Log            Off
        K8S-Logging.Parser  On
        K8S-Logging.Exclude On
        Labels              On
        Annotations         Off
        Buffer_Size         256k

    [FILTER]
        Name    modify
        Match   kube.*
        Add     cluster ${CLUSTER_NAME}

    [FILTER]
        Name    modify
        Match   host.*
        Add     cluster ${CLUSTER_NAME}

  outputs: |
    [OUTPUT]
        Name                 loki
        Match                kube.*
        Host                 ${MONITORING_HOST}
        Port                 ${MONITORING_LOKI_PORT}
        Labels               job=fluent-bit, cluster=${CLUSTER_NAME}
        Label_Keys           \$kubernetes['namespace_name'],\$kubernetes['container_name']
        Remove_Keys          kubernetes,stream
        Auto_Kubernetes_Labels Off
        Line_Format          json
        Retry_Limit          5

    [OUTPUT]
        Name                 loki
        Match                host.*
        Host                 ${MONITORING_HOST}
        Port                 ${MONITORING_LOKI_PORT}
        Labels               job=fluent-bit-systemd, cluster=${CLUSTER_NAME}
        Line_Format          json
        Retry_Limit          5

  customParsers: |
    [PARSER]
        Name        cri
        Format      regex
        Regex       ^(?<time>[^ ]+) (?<stream>stdout|stderr) (?<logtag>[^ ]*) (?<message>.*)$
        Time_Key    time
        Time_Format %Y-%m-%dT%H:%M:%S.%L%z

volumeMounts:
  - name: varlog
    mountPath: /var/log
    readOnly: true
  - name: etcmachineid
    mountPath: /etc/machine-id
    readOnly: true

volumes:
  - name: varlog
    hostPath:
      path: /var/log
  - name: etcmachineid
    hostPath:
      path: /etc/machine-id

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
FBEOF
  # shellcheck disable=SC2086
  helm upgrade --install fluent-bit "$FB_CHART_REF" \
    --namespace monitoring \
    --values "$fb_values" \
    $fb_version_flag \
    --wait --timeout 5m
  rm -f "$fb_values"

  # Auto-discover and apply ServiceMonitors for metrics-exposing services
  generate_service_monitors

  # Hard-fail: both charts were installed with --wait, so a timeout here means the
  # monitoring stack regressed after install - surface it instead of blessing it.
  if ! check_namespace_pods_ready "monitoring"; then
      echo "Error: monitoring pods did not become ready within the timeout."
      echo "  Inspect with 'kubectl get pods -n monitoring'."
      exit 1
  fi
}

# -- Uninstall Definitions -- #

uninstall_rke2() {
    echo "--- Uninstalling RKE2"
    # Load recorded install state (written at install time; RK-13).
    local have_state=0
    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
        have_state=1
    else
        echo "  NOTE: no install-state file at $STATE_FILE (host installed by an older version)."
        echo "  Host-setting restoration (swap/firewall/multipathd) will be skipped; only files"
        echo "  created by this installer are removed."
    fi
    # RK-1: stop RKE2 services BEFORE any file removal - never delete live etcd/kubelet dirs.
    echo "  Stopping RKE2 services..."
    systemctl stop rke2-server.service 2>/dev/null || true
    systemctl stop rke2-agent.service 2>/dev/null || true
    # RK-1: the upstream uninstaller lands in /usr/local/bin for tar-method installs and
    # in /usr/bin for rpm-method installs (the Rocky/RHEL online default).
    local uninstaller="" uninstaller_path
    for uninstaller_path in /usr/local/bin/rke2-uninstall.sh /usr/bin/rke2-uninstall.sh; do
        if [[ -x "$uninstaller_path" ]]; then
            uninstaller="$uninstaller_path"
            break
        fi
    done
    if [[ -n "$uninstaller" ]]; then
        echo "  Running upstream uninstaller $uninstaller..."
        "$uninstaller" || echo "  WARNING: $uninstaller exited non-zero; continuing local cleanup."
    else
        echo "  WARNING: rke2-uninstall.sh not found in /usr/local/bin or /usr/bin; performing local cleanup only."
    fi
    # rpm-method installs: remove the RKE2 packages so a later install starts clean (RK-1).
    if command -v rpm &>/dev/null; then
        local rpm_pkgs="" rpm_pkg
        for rpm_pkg in rke2-server rke2-agent rke2-common rke2-selinux; do
            if rpm -q "$rpm_pkg" &>/dev/null; then
                rpm_pkgs="$rpm_pkgs $rpm_pkg"
            fi
        done
        if [[ -n "$rpm_pkgs" ]]; then
            echo "  Removing RKE2 rpm packages:$rpm_pkgs"
            if command -v dnf &>/dev/null; then
                dnf remove -y $rpm_pkgs || true
            elif command -v yum &>/dev/null; then
                yum remove -y $rpm_pkgs || true
            elif command -v zypper &>/dev/null; then
                zypper --non-interactive remove $rpm_pkgs || true
            fi
        fi
    fi
    # Safety gate: refuse to delete data directories while a service is somehow still running.
    if systemctl is-active --quiet rke2-server.service || systemctl is-active --quiet rke2-agent.service; then
        echo "Error: an RKE2 service is still active; refusing to delete data directories."
        echo "  Stop it manually ('systemctl stop rke2-server rke2-agent') and re-run uninstall."
        exit 1
    fi
    # Remove rke2 config incl. registries.yaml (contains registry credentials) in case the
    # upstream uninstaller did not run or left it behind.
    rm -rf /etc/rancher/rke2
    # Remove only the kubeconfig files this installer wrote - never the user's whole ~/.kube (RK-13).
    rm -f /root/.kube/config
    rmdir /root/.kube 2>/dev/null || true
    if [[ -n "$user_name" && "$user_name" != "root" ]]; then
        rm -f "/home/$user_name/.kube/config"
        rmdir "/home/$user_name/.kube" 2>/dev/null || true
    fi
    # Clean up the KUBECONFIG and command symlinks
    unset KUBECONFIG
    for link in /usr/bin/kubectl /usr/bin/ctr /usr/bin/crictl; do
        if [[ -L "$link" ]];then
            rm -f "$link"
        fi
    done
    # Remove host-settings files created by this installer (RK-13).
    rm -f /etc/modules-load.d/40-k8s.conf /etc/sysctl.d/40-k8s.conf /etc/sysctl.d/60-rke2-cis.conf
    if [[ "${RKE2I_NM_CONF_PREEXISTED:-false}" != "true" ]]; then
        rm -f /etc/NetworkManager/conf.d/rke2-canal.conf
    fi
    # Restore host settings to their recorded pre-install state (RK-13).
    if [[ $have_state -eq 1 ]]; then
        # Swap: uncomment the fstab lines this installer commented out; re-enable swap
        # only if it was on before install.
        sed -i -E 's|^#(.*) # rke2-installer-swap$|\1|' /etc/fstab
        if [[ "${RKE2I_SWAP_WAS_ON:-false}" == "true" ]]; then
            echo "  Re-enabling swap (was enabled before install)..."
            swapon -a 2>/dev/null || true
        fi
        # multipathd: unmask and restore recorded enablement.
        if [[ "${RKE2I_MULTIPATHD_SERVICE_ENABLED:-not-found}" == "enabled" ]]; then
            echo "  Restoring multipathd.service (was enabled before install)..."
            systemctl unmask multipathd.service 2>/dev/null || true
            systemctl enable --now multipathd.service 2>/dev/null || true
        fi
        if [[ "${RKE2I_MULTIPATHD_SOCKET_ENABLED:-not-found}" == "enabled" ]]; then
            systemctl unmask multipathd.socket 2>/dev/null || true
            systemctl enable --now multipathd.socket 2>/dev/null || true
        fi
        # Firewalls: re-enable only what was active/enabled before install.
        if [[ "${RKE2I_UFW_WAS_ACTIVE:-false}" == "true" ]] && command -v ufw &>/dev/null; then
            echo "  Re-enabling UFW (was active before install)..."
            ufw --force enable || true
        fi
        if [[ "${RKE2I_FIREWALLD_ENABLED:-not-found}" == "enabled" ]]; then
            echo "  Re-enabling firewalld (was enabled before install)..."
            systemctl enable firewalld.service 2>/dev/null || true
        fi
        if [[ "${RKE2I_FIREWALLD_WAS_ACTIVE:-inactive}" == "active" ]]; then
            systemctl start firewalld.service 2>/dev/null || true
        fi
        # etcd user (CIS): remove only if this installer created it.
        if [[ "${RKE2I_ETCD_USER_CREATED:-false}" == "true" ]] && id etcd &>/dev/null; then
            echo "  Removing etcd user (created by this installer)..."
            userdel etcd 2>/dev/null || true
        fi
        # NTP (W11): remove the marker-tagged lines/drop-in added by configure_node_ntp.
        if [[ "${RKE2I_NTP_CONFIGURED:-none}" != "none" ]]; then
            echo "  Removing NTP configuration added by this installer..."
            local ntp_conf
            for ntp_conf in /etc/chrony/chrony.conf /etc/chrony.conf; do
                if [[ -f "$ntp_conf" ]]; then
                    sed -i '/# ap-tools NTP$/d' "$ntp_conf"
                fi
            done
            rm -f /etc/systemd/timesyncd.conf.d/10-ap-tools.conf
            if [[ "${RKE2I_NTP_CONFIGURED}" == "chrony" ]]; then
                systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null || true
            else
                systemctl restart systemd-timesyncd 2>/dev/null || true
            fi
        fi
    fi
    systemctl daemon-reload 2>/dev/null || true
    # cleanup non-default paths
    if [[ -n "$RKE2_DATA" && "$RKE2_DATA" != "default" ]]; then
        if [[ "$RKE2_DATA" != /* || "$RKE2_DATA" == "/" ]]; then
            echo "Refusing removal of dir RKE2_DATA=$RKE2_DATA"
        else
            rm -rf -- "$RKE2_DATA"
        fi
    fi
    if [[ -n "$KUBELET_DATA" && "$KUBELET_DATA" != "default" ]]; then
        if [[ "$KUBELET_DATA" != /* || "$KUBELET_DATA" == "/" ]]; then
            echo "Refusing removal of dir KUBELET_DATA=$KUBELET_DATA"
        else
            # unmount projected/secret tmpfs mounts (best effort)
            find "$KUBELET_DATA" -type d -path '*kubernetes.io~*' -exec umount -lf {} \; 2>/dev/null || true
            # unmount anything else still mounted under the tree (best effort)
            findmnt -R -n -o TARGET "$KUBELET_DATA" 2>/dev/null | sort -r | xargs -r umount -l 2>/dev/null || true
            rm -rf -- "$KUBELET_DATA"
        fi
    fi
    if [[ -n "$PVC_DATA" && "$PVC_DATA" != "default" && "${INSTALL_LOCAL_PATH_PROVISIONER,,}" == "true" ]]; then
        if [[ "$PVC_DATA" != /* || "$PVC_DATA" == "/" ]]; then
            echo "Refusing removal of dir PVC_DATA=$PVC_DATA"
        else
            rm -rf -- "$PVC_DATA"
        fi
    fi
    [ ! -d "$WORKING_DIR" ] || rm -rf "$WORKING_DIR"
    rm -f "$STATE_FILE"
    rmdir "$(dirname "$STATE_FILE")" 2>/dev/null || true
    echo "  Completed"
    echo "### RKE2 Installer Ended at $(date) ###"
    exit 0
}

# -- Save Definitions -- #

run_save () {
    echo "--- Running save workflow"
    download_rke2_binaries
    if [[ ${PUSH_SAVE_VELERO,,} == "true" ]]; then
        download_velero
    fi
    if [[ ${PUSH_SAVE_MONITORING,,} == "true" ]]; then
        download_monitoring_charts
    fi
    download_upgrade_artifacts
    download_rke2_utilities
    create_save_archive
    echo "--- Finished save workflow"
    echo "  Copy the archive to an air-gapped host runing the same version of $OS_ID"
}

download_rke2_binaries () {
    # Download RKE2 binaries and images
    echo "  Downloading core rke2 files for $RKE2_VERSION"
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-core.linux-amd64.tar.gz -o $WORKING_DIR/rke2-core-images/images/rke2-images-core.linux-amd64.tar.gz
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-core.linux-amd64.txt -o $WORKING_DIR/rke2-core-images/images/rke2-images-core.linux-amd64.txt
    echo "  creating rke2-core-images archive"
    cd $WORKING_DIR/rke2-core-images
    tar czf rke2-core-images.tar.gz --remove-files images
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2.linux-amd64.tar.gz -o $WORKING_DIR/rke2-binaries/rke2.linux-amd64.tar.gz
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/sha256sum-amd64.txt -o $WORKING_DIR/rke2-binaries/sha256sum-amd64.txt
    curl -sfL https://get.rke2.io --output $WORKING_DIR/rke2-binaries/install.sh
    if [[ $CNI_NONE == "false" ]]; then
        echo "  Downloading CNI rke2 files for $CNI_TYPE"
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-$CNI_TYPE.linux-amd64.tar.gz -o $WORKING_DIR/rke2-cni-images/images/rke2-images-$CNI_TYPE.linux-amd64.tar.gz
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-$CNI_TYPE.linux-amd64.txt -o $WORKING_DIR/rke2-cni-images/images/rke2-images-$CNI_TYPE.linux-amd64.txt
        echo "  creating rke2-cni-images archive..."
        cd $WORKING_DIR/rke2-cni-images
        tar czf rke2-$CNI_TYPE-images.tar.gz --remove-files images
    fi
    cd $base_dir
}

download_rke2_utilities () {
    # check if local_path_provisioner should be downloaded
    if [[ ${INSTALL_LOCAL_PATH_PROVISIONER,,} == "true" ]]; then
        echo "  Downloading local-path-provisioner manifest..."
        curl -sfL https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH_PROVISIONER_VERSION/deploy/local-path-storage.yaml -o $WORKING_DIR/rke2-utilities/local-path-storage.yaml
        cat $WORKING_DIR/rke2-utilities/local-path-storage.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    fi
    # Download k8s dns utils regardless so docker binaries get saved by image_pull_push.sh
    echo "  Downloading k8s dns utils manifest..."
    curl -sfL https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml -o $WORKING_DIR/rke2-utilities/dnsutils.yaml
    cat $WORKING_DIR/rke2-utilities/dnsutils.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    # Add Helm utility images (Longhorn, MetalLB, HAProxy) before saving the archive
    if [[ -f $WORKING_DIR/rke2-utilities/images/utility-images.txt ]]; then
        image_pull_push_check
        cd $WORKING_DIR/rke2-utilities
        ./image_pull_push.sh -f images/utility-images.txt save
        cd $base_dir
    fi
}

download_velero () {
    echo "  Downloading Velero CLI ${VELERO_VERSION}..."
    curl -L https://github.com/vmware-tanzu/velero/releases/download/${VELERO_VERSION}/velero-${VELERO_VERSION}-linux-amd64.tar.gz \
        -o $WORKING_DIR/velero/velero-${VELERO_VERSION}-linux-amd64.tar.gz
    echo "  Adding Velero images to utility-images list..."
    echo "velero/velero:${VELERO_VERSION}" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    echo "velero/velero-plugin-for-aws:${VELERO_AWS_PLUGIN_VERSION}" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
}

extract_monitoring_images () {
    # Extracts container images from kube-prometheus-stack and fluent-bit Helm charts into
    # utility-images.txt so that image_pull_push.sh can save/push them for airgapped installs.
    # Uses charts already in $WORKING_DIR/monitoring/ (written by download_monitoring_charts).
    # If not present (online push without a prior save), pulls charts to a temp dir using helm.
    mkdir -p $WORKING_DIR/rke2-utilities/images

    local kps_chart="$WORKING_DIR/monitoring/kube-prometheus-stack-${KUBE_PROMETHEUS_STACK_VERSION}.tgz"
    local fb_chart="$WORKING_DIR/monitoring/fluent-bit-${FLUENT_BIT_CHART_VERSION}.tgz"
    local tmp_dir=""

    if [[ ! -f "$kps_chart" ]] || [[ ! -f "$fb_chart" ]]; then
        if ! command -v helm &>/dev/null; then
            echo "  WARNING: helm not found and monitoring charts not pre-downloaded; skipping monitoring image extraction."
            return 0
        fi
        echo "  Pulling monitoring charts temporarily to extract image list..."
        tmp_dir=$(mktemp -d)
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts &>/dev/null || true
        helm repo add fluent https://fluent.github.io/helm-charts &>/dev/null || true
        helm repo update &>/dev/null || true
        helm pull prometheus-community/kube-prometheus-stack --version ${KUBE_PROMETHEUS_STACK_VERSION} -d "$tmp_dir" &>/dev/null
        helm pull fluent/fluent-bit --version ${FLUENT_BIT_CHART_VERSION} -d "$tmp_dir" &>/dev/null
        kps_chart="$tmp_dir/kube-prometheus-stack-${KUBE_PROMETHEUS_STACK_VERSION}.tgz"
        fb_chart="$tmp_dir/fluent-bit-${FLUENT_BIT_CHART_VERSION}.tgz"
    fi

    echo "  Extracting images from kube-prometheus-stack v${KUBE_PROMETHEUS_STACK_VERSION} chart..."
    helm template airgap-check "$kps_chart" \
        | grep -E '^\s+image:' \
        | awk '{print $2}' \
        | tr -d '"' \
        | grep -v '^$' \
        | sort -u \
        >> $WORKING_DIR/rke2-utilities/images/utility-images.txt

    echo "  Extracting images from fluent-bit chart v${FLUENT_BIT_CHART_VERSION} (app v${FLUENT_BIT_VERSION})..."
    helm template airgap-check "$fb_chart" \
        | grep -E '^\s+image:' \
        | awk '{print $2}' \
        | tr -d '"' \
        | grep -v '^$' \
        | sort -u \
        >> $WORKING_DIR/rke2-utilities/images/utility-images.txt

    if [[ -n "$tmp_dir" ]]; then
        rm -rf "$tmp_dir"
    fi
}

download_monitoring_charts () {
    echo "  Downloading monitoring Helm charts (kube-prometheus-stack v${KUBE_PROMETHEUS_STACK_VERSION}, fluent-bit chart v${FLUENT_BIT_CHART_VERSION} app v${FLUENT_BIT_VERSION})..."
    local helm_tar="helm-v${HELM_VERSION}-linux-amd64.tar.gz"
    # Save helm binary tarball so helm_check() can use it in air-gapped mode
    if [[ ! -f $WORKING_DIR/monitoring/${helm_tar} ]]; then
        curl -fsSLo $WORKING_DIR/monitoring/${helm_tar} https://get.helm.sh/${helm_tar}
    fi
    # Install helm temporarily if not already available
    if ! command -v helm &>/dev/null; then
        tar -xzf $WORKING_DIR/monitoring/${helm_tar} -C /tmp
        mv /tmp/linux-amd64/helm /usr/bin/helm
        rm -rf /tmp/linux-amd64
    fi
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add fluent https://fluent.github.io/helm-charts
    helm repo update
    cd $WORKING_DIR/monitoring
    helm pull prometheus-community/kube-prometheus-stack --version ${KUBE_PROMETHEUS_STACK_VERSION}
    helm pull fluent/fluent-bit --version ${FLUENT_BIT_CHART_VERSION}
    cd $base_dir
    echo "  Extracting monitoring chart images to utility-images list..."
    extract_monitoring_images
    echo "  Monitoring charts saved to $WORKING_DIR/monitoring/"
}

# Write a LICENSES/ dir into the air-gap archive: a third-party manifest plus (when the
# monitoring stack is bundled) an AGPLv3 written offer for Grafana, which kube-prometheus-stack
# deploys. Satisfies the AGPL "corresponding source or written offer" requirement.
generate_bundle_licenses () {
    local dir="$base_dir/LICENSES"
    rm -rf "$dir"; mkdir -p "$dir"
    {
        echo "Third-party components redistributed in this RKE2 air-gap bundle"
        echo "Generated: $(date)"
        echo ""
        echo "Rancher RKE2 ${RKE2_VERSION} (incl. containerd, CoreDNS, Calico/Flannel"
        echo "  'canal', ingress-nginx, metrics-server) ........ Apache-2.0  https://github.com/rancher/rke2"
        echo "Helm, local-path-provisioner ${LOCAL_PATH_PROVISIONER_VERSION}, system-upgrade-controller,"
        echo "  Velero ${VELERO_VERSION}, Fluent Bit ${FLUENT_BIT_VERSION} ........ Apache-2.0"
        if [[ ${PUSH_SAVE_MONITORING,,} == "true" ]]; then
            echo "kube-prometheus-stack ${KUBE_PROMETHEUS_STACK_VERSION} (chart) .. Apache-2.0  https://github.com/prometheus-community/helm-charts"
            echo "  -> deploys Grafana ............................. AGPL-3.0   https://github.com/grafana/grafana  (see WRITTEN_OFFER.txt)"
        fi
        echo ""
        echo "The installer scripts are Apache-2.0 (Chubtoad5). Permissive components retain"
        echo "their copyright/license + NOTICE files inside the image/binary tarballs."
    } > "$dir/THIRD_PARTY_NOTICES.txt"
    if [[ ${PUSH_SAVE_MONITORING,,} == "true" ]]; then
        cat > "$dir/WRITTEN_OFFER.txt" <<EOF
WRITTEN OFFER FOR CORRESPONDING SOURCE CODE (AGPL-3.0)

This air-gap bundle, when built with the monitoring stack (PUSH_SAVE_MONITORING=true),
redistributes Grafana (deployed by kube-prometheus-stack ${KUBE_PROMETHEUS_STACK_VERSION})
in object (image) form. Grafana is licensed under the GNU Affero General Public License,
version 3.

In accordance with AGPLv3 section 6, the distributor of this bundle hereby makes a
written offer, valid for three (3) years from the date this bundle was created
($(date +%Y-%m-%d)), to give any third party who possesses this bundle a complete
machine-readable copy of the corresponding source code, for a charge no more than the
cost of physically performing the source distribution.

Grafana is redistributed UNMODIFIED; the AGPLv3 section 13 remote-source obligation
(which applies to modified versions only) therefore does not apply.

Upstream source: https://github.com/grafana/grafana

To request the source on a physical medium, contact: ${LICENSE_OFFER_CONTACT}

This offer is independent of the Apache-2.0 license covering the installer scripts.
EOF
        echo "  Wrote LICENSES/ (manifest + AGPL written offer for Grafana)."
    else
        echo "  Wrote LICENSES/ (third-party manifest; monitoring not bundled)."
    fi
}

create_save_archive () {
    # saves downloaded files into rke2-save.tar.gz
    cat > $base_dir/rke2-save-version.txt <<EOF
# SeaweedFS Installer Save Archive
# Created: $(date)
#
# RKE2 Version: $RKE2_VERSION
# Local Path Provisioner: $LOCAL_PATH_PROVISIONER_VERSION
# Velero Version: $VELERO_VERSION
# Velero AWS Plugin Version: $VELERO_AWS_PLUGIN_VERSION
# Prometheus Stack Version: $KUBE_PROMETHEUS_STACK_VERSION
# Fluent Bit Chart Version: $FLUENT_BIT_CHART_VERSION
# Fluent Bit Version: $FLUENT_BIT_VERSION
# Upgrade Artifacts: included
EOF
    generate_bundle_licenses
    echo "  Creating rke2 archive..."
    tar -czf rke2-save.tar.gz rke2-install rke2_installer.sh rke2-save-version.txt LICENSES
    echo "  Air-gapped archive 'rke2-save.tar.gz' created."
}

# -- Push Definitions -- #
run_push () {
    echo "--- Running push workflow"
    # check if save has already run so files are not downloaded again
    if [[ $SAVE_MODE -eq 1 ]]; then
        AIR_GAPPED_MODE=1
    fi
    push_utility_images
    push_rke2_images
    echo "--- Finished push workflow"
}

push_utility_images () {
    echo "  Checking for utility images to push..."
    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        local container_images_tar=$(basename $WORKING_DIR/rke2-utilities/container_images*.tar.gz)
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-utilities/$container_images_tar push $REGISTRY_INFO $REG_USER $REG_PASS
    elif [[ $AIR_GAPPED_MODE -eq 0 ]]; then
        if [[ ${INSTALL_LOCAL_PATH_PROVISIONER,,} == "true" ]]; then
            curl -sfL https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH_PROVISIONER_VERSION/deploy/local-path-storage.yaml -o $WORKING_DIR/rke2-utilities/local-path-storage.yaml
            cat $WORKING_DIR/rke2-utilities/local-path-storage.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        fi
        if [[ ${INSTALL_DNS_UTILITY,,} == "true" ]]; then
            curl -sfL https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml -o $WORKING_DIR/rke2-utilities/dnsutils.yaml
            cat $WORKING_DIR/rke2-utilities/dnsutils.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        fi
        if [[ ${PUSH_SAVE_VELERO,,} == "true" ]]; then
            echo "velero/velero:${VELERO_VERSION}" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
            echo "velero/velero-plugin-for-aws:${VELERO_AWS_PLUGIN_VERSION}" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        fi
        if [[ ${PUSH_SAVE_MONITORING,,} == "true" ]]; then
            download_monitoring_charts
        fi
        # Add upgrade images (SUC controller + rke2-upgrade)
        if [[ ! -f $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml ]]; then
            curl -sfL https://github.com/rancher/system-upgrade-controller/releases/latest/download/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
        fi
        local suc_image=$(grep 'rancher/system-upgrade-controller' $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml | awk '{print $2}')
        echo "$suc_image" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        local stable_tag=$(curl -sfL -o /dev/null -w '%{url_effective}' https://update.rke2.io/v1-release/channels/stable | awk -F/ '{gsub(/\+/,"-",$NF); print $NF}')
        echo "rancher/rke2-upgrade:$stable_tag" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        image_pull_push_check
        echo "--- Printing utility-images.txt"
        cat $WORKING_DIR/rke2-utilities/images/utility-images.txt
        echo "---"
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-utilities/images/utility-images.txt push $REGISTRY_INFO $REG_USER $REG_PASS
    else
        echo "  No utility images to push"
    fi
}

push_rke2_images () {
    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        echo "  Pushing rke2 core images"
        local container_images_tar=$(basename $WORKING_DIR/rke2-core-images/*.tar.gz)
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-core-images/$container_images_tar push $REGISTRY_INFO $REG_USER $REG_PASS
        echo "  Pushing rke2 cni images"
        local container_images_tar=$(basename $WORKING_DIR/rke2-cni-images/*.tar.gz)
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-cni-images/$container_images_tar push $REGISTRY_INFO $REG_USER $REG_PASS
    else
        echo "  Downloading and pushing rke2 core images"
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-core.linux-amd64.txt -o $WORKING_DIR/rke2-core-images/rke2-images-core.linux-amd64.txt
        image_pull_push_check
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-core-images/rke2-images-core.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS
        echo "  Downloading and pushing rke2 cni images"
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-$CNI_TYPE.linux-amd64.txt -o $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE.linux-amd64.txt
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS
    fi
}

# --- Helper Functions --- #

runtime_outputs () {
    if [[ $PUSH_MODE -eq 1 ]]; then
        echo "  Push to external registry $REG_FQDN completed, check the registry to confirm images are present"
    fi
    if [[ $SAVE_MODE -eq 1 ]]; then
        echo "  Air-gapped archive 'rke2-save.tar.gz' created."
        echo "  Copy the archive to an air-gapped host runing the same version of $OS_ID and extract it with 'tar -xzf rke2-save.tar.gz'."
    fi
    if [[ $INSTALL_MODE -eq 1 && $INSTALL_TYPE == "rke2" ]]; then
        local join_token=$(cat $RKE2_DATA/server/node-token)
        local host_ip=$(hostname -I |awk '{print $1}')
        echo "  RKE2 Server installed successfully."
        echo "  Verify API is reachable at:"
        echo "    https://$host_ip:6443"
        if [[ $TLS_SAN_MODE -eq 1 ]]; then
            echo "    https://$TLS_SAN:6443"
        fi
        echo "  Join token stored in: $RKE2_DATA/server/node-token"
        if [[ $TLS_SAN_MODE -eq 1 ]]; then
            echo "  To join more nodes to this cluster use the following config:"
            echo "----"
            echo "server: https://$TLS_SAN:9345"
            echo "token: $join_token"
            echo "----"
            echo "  For joing another server: './rke2_installer.sh join server -tls-san $TLS_SAN $TLS_SAN $join_token'."
            echo "  For joining an agent node: './rke2_installer.sh join agent $TLS_SAN $join_token'."
            echo "  Note: if using private registry, include -registry in the join command."
            echo "  After joining an agent, apply the worker role with 'kubectl label node <node name> node-role.kubernetes.io/worker=true'."
        else
            echo "  To join more nodes to this cluster use the following config:"
            echo "----"
            echo "server: https://$host_ip:9345"
            echo "token: $join_token"
            echo "----"
            echo "  For joining another server: './rke2_installer.sh join server $host_ip $join_token'." 
            echo "  For joining an agent node: './rke2_installer.sh join agent $host_ip $join_token'."
            echo "  Note: if using private registry, include -registry in the join command."
            echo "  After joining an agent, apply the worker role with 'kubectl label node <node name> node-role.kubernetes.io/worker=true'."
        fi
        echo "  Kube config stored in: /etc/rancher/rke2/rke2.yaml"
    fi
    if [[ $JOIN_MODE -eq 1 ]]; then
        if [[ $JOIN_TYPE == "server" ]]; then
            echo "  Server join completed, check the status with 'kubectl get nodes' and 'kubectl get pods -A' on the server for details."
            echo "  Kube config stored in: /etc/rancher/rke2/rke2.yaml"
        else
            echo "  Agent install completed, check the status with 'kubectl get nodes' and 'kubectl get pods -A' on the server node for details."
            echo "  Apply a worke role label with: 'kubectl label node <node name> node-role.kubernetes.io/worker=true' from the server node."
        fi
    fi
    if [[ $INSTALL_MODE -eq 1 && $INSTALL_TYPE == "monitoring" ]]; then
        echo ""
        echo "### MONITORING INSTALL COMPLETED ###"
        echo ""
        echo "In-cluster components:"
        echo "  kubectl -n monitoring get pods          # kube-prometheus-stack + fluent-bit"
        echo "  kubectl -n monitoring get servicemonitors"
        echo ""
        echo "External monitoring host ($MONITORING_HOST):"
        echo "  Grafana:    https://$MONITORING_HOST:3000"
        echo "  Loki:       http://$MONITORING_HOST:$MONITORING_LOKI_PORT"
        echo "  Prometheus: http://$MONITORING_HOST:$MONITORING_PROMETHEUS_PORT"
        echo ""
        echo "Verify data is flowing:"
        echo "  curl -s http://$MONITORING_HOST:$MONITORING_LOKI_PORT/loki/api/v1/labels"
        echo "  curl -s http://$MONITORING_HOST:$MONITORING_PROMETHEUS_PORT/api/v1/label/__name__/values | grep -c ."
        echo ""
        echo "Recommended Grafana dashboard IDs to import:"
        echo "  3119  - Kubernetes Cluster Overview"
        echo "  1860  - Node Exporter Full"
        echo "  16888 - Longhorn"
        echo "  7752  - Fluent Bit"
        echo "  13639 - Loki Logs"
        echo ""
        echo "Multi-cluster log filtering (LogQL):"
        echo "  {cluster=\"${CLUSTER_NAME}\", job=\"fluent-bit\"}           # all k8s logs from this cluster"
        echo "  {cluster=\"${CLUSTER_NAME}\", job=\"fluent-bit-systemd\"}    # systemd/host logs from this cluster"
        echo "  {cluster=\"${CLUSTER_NAME}\"} |= \"my-pod-name\"            # find a specific pod (pod name is in the log body)"
        echo ""
        echo "To add a cluster filter to a Grafana dashboard:"
        echo "  Dashboard Settings → Variables → Add variable"
        echo "  Type: Query, Datasource: Loki, Query: label_values(cluster)"
    fi
    if [[ $INSTALL_MODE -eq 1 && $INSTALL_TYPE == "velero" ]]; then
        echo ""
        echo "### VELERO INSTALL COMPLETED ###"
        echo ""
        echo "Velero Configuration:"
        echo "  S3 Endpoint:         $VELERO_S3_URL"
        echo "  S3 Bucket:           $VELERO_BUCKET"
        echo "  Backup Namespaces:   $VELERO_BACKUP_NAMESPACES"
        echo "  Backup Schedule:     $VELERO_BACKUP_SCHEDULE (TTL: $VELERO_BACKUP_TTL)"
        echo "  VolumeSnapshotClass: $VSC_NAME (driver: $VSC_DRIVER)"
        echo ""
        echo "Verify installation:"
        echo "  velero backup-location get          # Should show 'Available'"
        echo "  velero schedule get                 # Should show 'daily-full-backup'"
        echo "  kubectl get pods -n velero          # Velero server + node-agent pods"
        echo ""
        echo "Common operations:"
        echo "  velero backup create manual-backup --from-schedule daily-full-backup --wait"
        echo "  velero backup get"
        echo "  velero backup describe <backup-name> --details"
        echo "  velero restore create --from-backup <backup-name> --wait"
        echo ""
        echo "If backup-location shows 'Unavailable', check:"
        echo "  - S3 is running and accessible at $VELERO_S3_URL"
        echo "  - S3 credentials are correct (VELERO_S3_ACCESS_KEY / VELERO_S3_SECRET_KEY)"
        echo "  - kubectl logs deployment/velero -n velero | tail -20"
    fi
    if [[ $UPGRADE_MODE -eq 1 ]]; then
        echo ""
        echo "### UPGRADE INITIATED ###"
        echo "  Upgrade type: $UPGRADE_TYPE"
        echo "  Upgrade version: $UPGRADE_VERSION"
        echo "  Monitor progress: kubectl get plans -n system-upgrade"
        echo "  Watch nodes: kubectl get nodes -w"
    fi
}

create_working_dir () {
    # check for rke2-install directory and supporting directories, then create them
    [ -d "$WORKING_DIR" ] || mkdir -p "$WORKING_DIR"
    [ -d "$WORKING_DIR/rke2-core-images/images" ] || mkdir -p "$WORKING_DIR/rke2-core-images/images"
    [ -d "$WORKING_DIR/rke2-cni-images/images" ] || mkdir -p "$WORKING_DIR/rke2-cni-images/images"
    [ -d "$WORKING_DIR/rke2-binaries" ] || mkdir -p "$WORKING_DIR/rke2-binaries"
    [ -d "$WORKING_DIR/rke2-utilities/images" ] || mkdir -p "$WORKING_DIR/rke2-utilities/images"
    [ -d "$WORKING_DIR/velero" ] || mkdir -p "$WORKING_DIR/velero"
    [ -d "$WORKING_DIR/monitoring" ] || mkdir -p "$WORKING_DIR/monitoring"
    [ -d "$RKE2_DATA/agent/images" ] || mkdir -p "$RKE2_DATA/agent/images"
    [ -d "/etc/rancher/rke2" ] || mkdir -p "/etc/rancher/rke2"
    [ -d "$RKE2_DATA/server/manifests" ] || mkdir -p "$RKE2_DATA/server/manifests"
}


os_check () {
    # Get OS information from /etc/os-release
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_ID="${ID:-}"
    else
        echo "Unknown or unsupported OS $OS_ID."
        exit 1
    fi
    if [[ ! "$OS_ID" =~ ^(ubuntu|debian|rhel|centos|rocky|almalinux|fedora|sles|opensuse-leap)$ ]]; then
        echo "Unknown or unsupported OS $OS_ID."
        exit 1
    fi
    # RK-3: detect SELinux enforcement once (Rocky 9/10 default; Leap 16 defaults to SELinux too)
    SELINUX_ENFORCING="false"
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null || true)" == "Enforcing" ]]; then
        SELINUX_ENFORCING="true"
    fi
}

image_pull_push_check () {
    if [[ ! -f $WORKING_DIR/rke2-utilities/image_pull_push.sh ]]; then
        echo "  Downloading image_pull_push.sh..."
        curl -sfL https://github.com/Chubtoad5/images-pull-push/raw/refs/heads/main/image_pull_push.sh  -o $WORKING_DIR/rke2-utilities/image_pull_push.sh
        chmod +x $WORKING_DIR/rke2-utilities/image_pull_push.sh
    fi
}

check_namespace_pods_ready() {
  # Run this function as 'check_namespace_pods_ready $namespace', no argument will default to kube-system
  # checks status of pods, deletes any completed pods, and loops until all pods are ready or 120s has elapsed
  # Returns 1 on timeout (matches the ap-tools copy); callers decide fail-hard vs warn-and-continue.
  local timeout_seconds=120
  local start_time=$(date +%s)
  local ns=${1:-"kube-system"}
  while true; do
    local completed_pods=$(kubectl get pods -n $ns --field-selector status.phase=Succeeded -o name)
    echo "  Checking pod status in $ns namespace..."
    for pod_name in $completed_pods; do
      kubectl delete -n $ns "$pod_name" --ignore-not-found
    done
    local current_pods_not_ready=$(kubectl get pods -n $ns --no-headers | awk '{print $2}' | awk -F'/' '{if ($1 != $2) print $0}' | wc -l)
    local elapsed_time=$(($(date +%s) - start_time))
    if [ "$elapsed_time" -ge "$timeout_seconds" ]; then
      echo "Error: Timeout reached after $timeout_seconds seconds. Not all pods are ready." >&2
      kubectl get pods -A
      return 1
    fi
    if [ "$current_pods_not_ready" -eq 0 ]; then
      break
    fi
    echo "  - Wating on $current_pods_not_ready pods..."
    echo "  - Elapsed: ${elapsed_time}s/${timeout_seconds}s"
    sleep 10
  done
  echo "  - All pods are ready in $ns namespace!"
  return 0
}

run_debug() {
  # Runs a step while preserving 'set -e' semantics INSIDE the called function
  # (wrapping "$@" in an if/&&/|| condition would suppress errexit for the whole
  # call tree and let mid-function failures continue silently \u2014 the old failure
  # branch here was dead code for the same reason). On failure, errexit aborts the
  # script and the on_exit trap reports the failing step; with DEBUG=0 the step's
  # captured output is replayed by the trap so failures are never silent.
  RUN_DEBUG_STEP="$*"
  if [ "$DEBUG" = "1" ]; then
    local GREEN RED NC
    GREEN=$(tput setaf 2 2>/dev/null || true)
    NC=$(tput sgr0 2>/dev/null || true)
    local CHECKMARK='\u2714'
    local SUCCESS_MSG="Success"
    echo "--- Running '$*' with DEBUG enabled ---"
    "$@"
    echo -e "--- DEBUG: Finished '$*' ${GREEN}${CHECKMARK} ${SUCCESS_MSG}${NC} ---"
  else
    # DEBUG=0: capture output so the on_exit trap can replay it if the step fails.
    : > "$RUN_DEBUG_LOG"
    "$@" > "$RUN_DEBUG_LOG" 2>&1
  fi
  RUN_DEBUG_STEP=""
}

cleanup () {
    if [[ $INSTALL_MODE -eq 1 || $JOIN_MODE -eq 1 || $UPGRADE_MODE -eq 1 ]]; then
        echo "  Installation detected, no cleanup required..."
    else
        echo "  Cleaning up..."
        rm -rf "$WORKING_DIR"
    fi
}

# --- Main Script Execution --- #

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with root privileges."
   echo "Type './$SCRIPT_NAME -h' for help."
   exit 1
fi
# Resolve the invoking user without dying on non-tty invocations (cloud-init, ansible,
# systemd units): SUDO_USER -> logname -> owner of the working directory -> root.
if [[ -z "$user_name" ]]; then
    user_name=$(logname 2>/dev/null || true)
fi
if [[ -z "$user_name" ]]; then
    user_name=$(stat -c '%U' "$PWD" 2>/dev/null || true)
    if [[ "$user_name" == "UNKNOWN" ]]; then
        user_name=""
    fi
fi
if [[ -z "$user_name" ]]; then
    user_name="root"
fi

# Update non-default install paths
if [[ $RKE2_DATA == "default" ]]; then RKE2_DATA="/var/lib/rancher/rke2"; else mkdir -p "$RKE2_DATA"; fi
if [[ $KUBELET_DATA == "default" ]]; then KUBELET_DATA="/var/lib/kubelet"; else mkdir -p "$KUBELET_DATA"; fi
if [[ $PVC_DATA == "default" ]]; then PVC_DATA="/opt/local-path-provisioner"; else mkdir -p "$PVC_DATA"; fi

# Check for no arguments, and show usage if none are provided
if [[ "$#" -eq 0 ]]; then
    echo "Error: No arguments provided."
    usage
fi
# Check for the correct argument syntax
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        install)
            INSTALL_MODE=1
            if [[ "${2:-}" == "velero" ]]; then
                INSTALL_TYPE="velero"
                shift
            elif [[ "${2:-}" == "monitoring" ]]; then
                INSTALL_TYPE="monitoring"
                shift
            fi
            shift
            ;;
        uninstall)
            UNINSTALL_MODE=1
            shift
            ;;
        save)
            SAVE_MODE=1
            shift
            ;;
        push)
            PUSH_MODE=1
            shift
            ;;
        upgrade)
            UPGRADE_MODE=1
            UPGRADE_TYPE="${2:-}"
            UPGRADE_VERSION="${3:-}"
            if [[ -z "$UPGRADE_TYPE" || ! "$UPGRADE_TYPE" =~ ^(server|agent|both)$ ]]; then
                echo "Error: 'upgrade' command requires a type. Format: upgrade [server|agent|both] [stable|version]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            if [[ -z "$UPGRADE_VERSION" ]]; then
                echo "Error: 'upgrade' command requires a version. Format: upgrade [server|agent|both] [stable|v1.x.x+rke2r1]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            shift
            shift
            shift
            ;;
        join)
            JOIN_MODE=1
            JOIN_TYPE="${2:-}"
            JOIN_SERVER_FQDN="${3:-}"
            JOIN_TOKEN="${4:-}"
            if [[ -z "$JOIN_TYPE" || "$JOIN_TYPE" != "agent" && "$JOIN_TYPE" != "server" ]]; then
                echo "Error: 'join' command requires a join type. Format: join [server|agent] [server-fqdn] [join-token-string]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            if [[ -z "$JOIN_SERVER_FQDN" ]]; then
                echo "Error: 'join' command requires a server fqdn/ip. Format: join [server|agent] [server-fqdn] [join-token-string]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            if [[ -z "$JOIN_TOKEN" ]]; then
                echo "Error: 'join' command requires a join token. Format: join [server|agent] [server-fqdn] [join-token-string]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            shift
            shift
            shift
            shift
            ;;
        -tls-san)
            TLS_SAN_MODE=1
            TLS_SAN="${2:-}"
            if [[ -z "$TLS_SAN" ]]; then
                echo "Error: '-tls-san' command requires a server fqdn/ip. Format: -tls-san [server-fqdn-ip]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            shift
            shift
            ;;
        -registry)
            REGISTRY_MODE=1
            REGISTRY_INFO="${2:-}"
            REG_USER="${3:-}"
            REG_PASS="${4:-}"
            if [[ -z "$REG_USER" || -z "$REG_PASS" ]]; then
                echo "Error: Registry info requires a username and password. Format: -registry [registry:port username password]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            shift
            shift
            shift
            shift
            ;;
        *)
            echo "Error: Invalid argument '$1'."
            usage
            ;;
    esac
done
# Verify uninstall is not used with any other mode
if [[ "$UNINSTALL_MODE" == "1" ]]; then
    if [[ "$INSTALL_MODE" == "1" || "$SAVE_MODE" == "1" || "$PUSH_MODE" == "1" || "$JOIN_MODE" == "1" || "$REGISTRY_MODE" == "1" || "$UPGRADE_MODE" == "1" ]]; then
        echo "Error:'uninstall' command cannot be used with other commands."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
fi
# Verify UPGRADE_MODE is not used with INSTALL_MODE, SAVE_MODE, JOIN_MODE
if [[ "$UPGRADE_MODE" == "1" ]]; then
    if [[ "$INSTALL_MODE" == "1" || "$SAVE_MODE" == "1" || "$JOIN_MODE" == "1" ]]; then
        echo "Error: 'upgrade' command cannot be used with 'install', 'save', or 'join'."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
    if [[ "$UPGRADE_VERSION" != "stable" ]]; then
        if [[ ! "$UPGRADE_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$ ]]; then
            echo "Error: Upgrade version must be 'stable' or a valid RKE2 version (e.g. v1.33.4+rke2r1)."
            echo "Type './$SCRIPT_NAME -h' for help."
            exit 1
        fi
    fi
fi
# Verify PUSH_MODE has registry info and not used with JOIN_MODE
if [[ "$PUSH_MODE" == "1"  ]]; then
    if [[ "$JOIN_MODE" == "1" ]]; then
        echo "Error: 'push' command cannot be used with 'join'."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
    if [[ "$REGISTRY_MODE" == "0" ]]; then
        echo "Error: 'push' command requires registry config. Format: push -registry [registry:port] [username] [password]"
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
    if [[ "$TLS_SAN_MODE" == "1" && "$INSTALL_MODE" == "0" ]]; then
        echo "Error: 'push' command cannot be used with '-tls-san'."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
fi
# Verify SAVE_MODE is not used with JOIN_MODE
if [[ "$SAVE_MODE" == "1" && $JOIN_MODE == "1" ]]; then
    echo "Error: 'save' command cannot be used with 'join'."
    echo "Type './$SCRIPT_NAME -h' for help."
    exit 1
fi
# Verify INSTALL_MODE is not used with JOIN_MODE
if [[ "$INSTALL_MODE" == "1" && $JOIN_MODE == "1" ]]; then
    echo "Error: 'install' command cannot be used with 'join'."
    echo "Type './$SCRIPT_NAME -h' for help."
    exit 1
fi
# Verify velero S3 credentials and URL when installing velero
if [[ "$INSTALL_MODE" == "1" && "$INSTALL_TYPE" == "velero" ]]; then
    if [[ -z "$VELERO_S3_ACCESS_KEY" || -z "$VELERO_S3_SECRET_KEY" ]]; then
        echo "Error: 'install velero' requires S3 credentials. Set VELERO_S3_ACCESS_KEY and VELERO_S3_SECRET_KEY in the script."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
    if [[ -z "$VELERO_S3_URL" ]]; then
        echo "Error: 'install velero' requires VELERO_S3_URL to be set (e.g. https://s3.example.com:8333)."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
    # Preflight: warn if VELERO_BUCKET is still the default while CLUSTER_NAME has been customised.
    # In a multi-cluster environment each cluster needs its own Velero bucket to avoid backup
    # collision; the default 'velero' bucket may also not exist on the target SWFS (BSL Unavailable).
    if [[ "$VELERO_BUCKET" == "velero" && "$CLUSTER_NAME" != "edge-lab" ]]; then
        echo ""
        echo "  WARNING: VELERO_BUCKET is still the default ('velero') but CLUSTER_NAME is '${CLUSTER_NAME}'."
        echo "  In a multi-cluster environment each cluster should have its own Velero bucket to avoid"
        echo "  backup collision. Set VELERO_BUCKET=<cluster-id> to match CLUSTER_NAME."
        echo "  Continuing in 10 seconds — Ctrl-C to abort and fix."
        echo ""
        sleep 10
    fi
fi
# Verify MONITORING_HOST is set when installing monitoring
if [[ "$INSTALL_MODE" == "1" && "$INSTALL_TYPE" == "monitoring" ]]; then
    if [[ -z "$MONITORING_HOST" ]]; then
        echo "Error: 'install monitoring' requires MONITORING_HOST to be set to the IP/FQDN of the external monitoring host."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
    fi
fi
# Verify REGISTRY_MODE is used with one of PUSH_MODE, INSTALL_MODE, JOIN_MODE, or UPGRADE_MODE
if [[ "$REGISTRY_MODE" == "1" && "$PUSH_MODE" != "1" && "$INSTALL_MODE" != "1" && "$JOIN_MODE" != "1" && "$UPGRADE_MODE" != "1" ]]; then
    echo "Error: 'Registry config must be used with either 'push', 'join', 'install', or 'upgrade'."
    echo "Type './$SCRIPT_NAME -h' for help."
    exit 1
fi
# Verify REGISTRY_MODE is an FQDN/IP and port
if [[ "$REGISTRY_MODE" == "1" ]]; then
    if [[ "$REGISTRY_INFO" =~ ^https?:// ]]; then
        echo "Error: registry info must be a valid FQDN or IPv4 format. i.e. 'my.regsitry.com:443'."
        exit 1
    fi
    REG_FQDN=$(echo "$REGISTRY_INFO" | cut -d':' -f1)
    REG_PORT=$(echo "$REGISTRY_INFO" | cut -d':' -f2)
    if [[ ! ( "$REG_FQDN" =~ $fqdn_pattern || "$REG_FQDN" =~ $ipv4_pattern ) ]]; then
        echo "Error: Registry url must be a valid FQDN or IPv4 format. i.e. 'my.regsitry.com' or '192.168.1.50'."
        exit 1
    fi
    if [[ "$REG_PORT" =~ ^[0-9]+$ ]]; then
        if [[ "$REG_PORT" -lt 1 || "$REG_PORT" -gt 65535 ]]; then
            echo "Error: Registry port must be a number between 1 and 65535."
            exit 1
        fi
    else
        echo "Error: Registry port must be a number between 1 and 65535."
        exit 1
    fi
fi
# Verify JOIN_SERVER_FQDN is an FQDN/IP
if [[ "$JOIN_MODE" == "1" ]]; then
    if [[ "$JOIN_SERVER_FQDN" =~ ^https?:// ]]; then
        echo "Error: join server FQDN must be a valid FQDN or IPv4 format. i.e. 'my.kubernetes.com'."
        exit 1
    fi
    if [[ ! ( "$JOIN_SERVER_FQDN" =~ $fqdn_pattern || "$JOIN_SERVER_FQDN" =~ $ipv4_pattern ) ]]; then
        echo "Error: Join server FQDN must be a valid FQDN or IPv4 format. i.e. 'my.kubernetes.com' or '192.168.1.50'."
        exit 1
    fi
fi
# Verify TLS_SAN_MODE is an FQDN/IP
if [[ "$TLS_SAN_MODE" == "1" ]]; then
    if [[ "$TLS_SAN" =~ ^https?:// ]]; then
        echo "Error: tls san must be a valid FQDN or IPv4 format. i.e. 'my.kubernetes.com'."
        exit 1
    fi
    if [[ ! ( "$TLS_SAN" =~ $fqdn_pattern || "$TLS_SAN" =~ $ipv4_pattern ) ]]; then
        echo "Error: TLS SAN must be a valid FQDN or IPv4 format. i.e. 'my.kubernetes.com' or '192.168.1.50'."
        exit 1
    fi
fi
# Verify CNI type
TRANSLATED_VERSION=$(echo $RKE2_VERSION | sed 's/+/%2B/')
if  [[ ! $CNI_TYPE =~ ^(calico|canal|cilium|none)$ ]]; then
    echo "Error: CNI type must be 'calico', 'canal', 'cilium', or 'none'."
    exit 1
fi
CNI_NONE="false"
if [[ $CNI_TYPE == "none" ]]; then
    CNI_NONE="true"
fi
# Verify AIR_GAPPED_MODE based on rke-save.tar.gz file presence
[[ ! -f $base_dir/rke2-save-version.txt ]] || AIR_GAPPED_MODE=1

os_check
display_args
if [[ $UNINSTALL_MODE -eq 1 ]]; then
  run_debug uninstall_rke2
fi
create_working_dir
if [[ $SAVE_MODE -eq 1 ]]; then
    run_debug run_save
fi
if [[ $PUSH_MODE -eq 1 ]]; then
    run_debug run_push
fi
if [[ ($INSTALL_MODE -eq 1 && $INSTALL_TYPE == "rke2") || ($JOIN_MODE -eq 1 && $JOIN_TYPE == "agent") || ($JOIN_MODE -eq 1 && $JOIN_TYPE == "server") ]]; then
  run_install
fi
if [[ $INSTALL_MODE -eq 1 && $INSTALL_TYPE == "velero" ]]; then
  echo "  Installing Velero with CSI snapshot support..."
  run_install_velero
fi
if [[ $INSTALL_MODE -eq 1 && $INSTALL_TYPE == "monitoring" ]]; then
  echo "  Installing monitoring stack (kube-prometheus-stack + Fluent Bit)..."
  run_install_monitoring
fi
if [[ $UPGRADE_MODE -eq 1 ]]; then
    run_upgrade
fi
cleanup
runtime_outputs
echo "### RKE2 Installer Completed at $(date) ###"