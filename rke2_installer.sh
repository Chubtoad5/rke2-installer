#!/bin/bash

# --- Script Configuration - DO NOT EDIT --- #
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_VERSION="1.3.0"

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
COREDNS_HOSTS=${COREDNS_HOSTS:-}                                              # Optional in-cluster DNS pins '<fqdn>=<ipv4>[,...]' (split-horizon: pods resolve these names to the given IP regardless of the host's DNS); empty = chart defaults
RKE2_FORCE_ONLINE=${RKE2_FORCE_ONLINE:-"false"}                               # true = ignore an rke2-save-version.txt in the working directory and stay online
IMAGE_PULL_PUSH_REF=${IMAGE_PULL_PUSH_REF:-"v1.1.1"}                          # images-pull-push release (tag, branch or commit) whose image_pull_push.sh is fetched
IMAGE_PULL_PUSH_URL=${IMAGE_PULL_PUSH_URL:-"https://raw.githubusercontent.com/Chubtoad5/images-pull-push/${IMAGE_PULL_PUSH_REF}/image_pull_push.sh"}  # full URL of image_pull_push.sh; wins over IMAGE_PULL_PUSH_REF
IMAGE_PULL_PUSH_SHA256=${IMAGE_PULL_PUSH_SHA256:-}                            # optional sha256 of image_pull_push.sh; a mismatch stops the run
UPGRADE_WAIT=${UPGRADE_WAIT:-"false"}                                         # upgrade: true = wait until every targeted node runs the new version, and exit 1 if it doesn't in time
UPGRADE_WAIT_TIMEOUT=${UPGRADE_WAIT_TIMEOUT:-"1800"}                          # upgrade: seconds UPGRADE_WAIT waits
POD_WAIT_TIMEOUT=${POD_WAIT_TIMEOUT:-"300"}                                   # seconds install, join and the add-ons wait for their pods to be ready; raise it for a slow host or network
SUC_VERSION=${SUC_VERSION:-"v0.21.0"}                                         # system-upgrade-controller release, for upgrades and for the bundle (was whatever was latest)
RKE2_SELINUX_FALLBACK=${RKE2_SELINUX_FALLBACK:-}                              # 'permissive': on SUSE hosts (no upstream rke2-selinux policy exists) switch SELinux to permissive instead of failing pre-cluster; recorded in install state, restored to enforcing on uninstall (P4-08b)
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
HELM_VERSION=${HELM_VERSION:-"4.0.1"}                                # Helm version to download if not already installed
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
# dnsutils.yaml pinned to a commit, so a bundle has no floating downloads (it came from the website's main branch).
DNSUTILS_URL="https://raw.githubusercontent.com/kubernetes/website/c299e2887729c844ff2d35cfb7fe1746f25732c8/content/en/examples/admin/dns/dnsutils.yaml"

# EXIT trap: report the failing step (replaying captured output when DEBUG=0) and
# clean up temp files. Captures the exit code FIRST and re-exits with it so failures
# are never masked by the trap's own commands.
on_exit () {
    local rc=$?
    # With DEBUG=0, run_debug sends a step's output to its log, and a step that exits leaves that redirect in place.
    # Put the console back first, or the messages below go into the log this trap is about to delete.
    if [[ -e /dev/fd/7 && -e /dev/fd/8 ]]; then
        exec 1>&7 2>&8
    fi
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
# The console, kept on spare descriptors for on_exit. Not when a test harness sources this file.
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    exec 7>&1 8>&2
fi
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
    echo "  SCRIPT_VERSION: $SCRIPT_VERSION"
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
    echo "  JOIN_TOKEN: ${JOIN_TOKEN:+<hidden>}"
    echo "  PUSH_MODE: $PUSH_MODE"
    echo "  REGISTRY_MODE: $REGISTRY_MODE"
    echo "  REGISTRY_INFO: $REGISTRY_INFO"
    echo "  REG_FQDN: $REG_FQDN"
    echo "  REG_PORT: $REG_PORT"
    echo "  REG_USER: $REG_USER"
    echo "  REG_PASS: ${REG_PASS:+<hidden>}"
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
    # Before the paths below are resolved, so it compares the values as given.
    warn_agent_ignored_settings
    # Update non-default install paths
    if [[ $RKE2_DATA == "default" ]]; then RKE2_DATA="/var/lib/rancher/rke2"; else mkdir -p "$RKE2_DATA"; fi
    if [[ $KUBELET_DATA == "default" ]]; then KUBELET_DATA="/var/lib/kubelet"; else mkdir -p "$KUBELET_DATA"; fi
    if [[ $PVC_DATA == "default" ]]; then PVC_DATA="/opt/local-path-provisioner"; else mkdir -p "$PVC_DATA"; fi
    reconcile_existing_install
    warn_registry_not_passed
    run_debug create_registry_config
    reconcile_registry_config_change
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
        if [[ $CNI_NONE == "true" ]]; then
            echo "  NOTE: CNI_TYPE=none. The node stays NotReady, and its pods Pending, until you install a CNI."
        fi
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
    #   - join to a different cluster server  -> hard error (uninstall first), unless RKE2_RECONFIGURE=true and the
    #                                            new address is proven to serve the cluster this node is in
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
    # Snapshot the live registry config so a changed -registry on a running node is
    # detected after create_registry_config rewrites it (see reconcile_registry_config_change).
    RECONCILE_REGISTRIES_PRE=""
    if [[ -f /etc/rancher/rke2/registries.yaml ]]; then
        RECONCILE_REGISTRIES_PRE="$TMP_DIR/registries.yaml.pre"
        cp /etc/rancher/rke2/registries.yaml "$RECONCILE_REGISTRIES_PRE"
    fi
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
    # Foreign-cluster guard: joining a different cluster requires uninstall, always. A new address for the SAME
    # cluster is allowed under RKE2_RECONFIGURE=true, proven against the token this node already holds.
    if [[ $JOIN_MODE -eq 1 && -f /etc/rancher/rke2/config.yaml ]]; then
        local existing_server existing_token
        existing_server=$(awk -F'https://' '/^server:/ {print $2}' /etc/rancher/rke2/config.yaml | cut -d: -f1)
        existing_token=$(sed -n 's/^token: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' /etc/rancher/rke2/config.yaml | head -1) || existing_token=""
        if [[ -n "$existing_server" && "$existing_server" != "$JOIN_SERVER_FQDN" ]]; then
            if [[ "${RKE2_RECONFIGURE,,}" == "true" ]] && same_cluster_server "$JOIN_SERVER_FQDN" "$JOIN_TOKEN" "$existing_token"; then
                echo "  The join server changes from '$existing_server' to '$JOIN_SERVER_FQDN'. It serves the CA of the cluster"
                echo "  this node is in, so it is the same cluster, and RKE2_RECONFIGURE=true applies the change."
            else
                echo "Error: this node is already joined to cluster server '$existing_server', but a join to"
                echo "  '$JOIN_SERVER_FQDN' was requested. Joining a different cluster requires 'sudo ./$SCRIPT_NAME uninstall' first."
                if [[ "${RKE2_RECONFIGURE,,}" == "true" ]]; then
                    echo "  RKE2_RECONFIGURE=true allows a new address for the same cluster only, and that wasn't shown: $SAME_CLUSTER_WHY."
                else
                    echo "  If '$JOIN_SERVER_FQDN' is a new address for the same cluster, re-run with RKE2_RECONFIGURE=true."
                fi
                exit 1
            fi
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

# same_cluster_server <new server> <new token> <the node's current token>: true when the new server belongs to the
# cluster this node is ALREADY in. A secure token is K10<sha256 of the cluster CA bundle>::..., and the supervisor
# serves that bundle at https://<server>:9345/cacerts. The proof is against the current token: a new server and a new
# token come from the same source, so checking them only against each other would accept a wrong pair, another
# cluster's.
SAME_CLUSTER_WHY=""
same_cluster_server () {
    local server="$1" new_token="$2" current_token="$3" want got ca="$TMP_DIR/new-server-cacerts"
    if [[ ! "$current_token" =~ ^K10([0-9a-f]{64}):: ]]; then
        SAME_CLUSTER_WHY="this node's current join token has no CA hash, so its cluster can't be proven"
        return 1
    fi
    want=${BASH_REMATCH[1]}
    if [[ "$new_token" =~ ^K10([0-9a-f]{64}):: && "${BASH_REMATCH[1]}" != "$want" ]]; then
        SAME_CLUSTER_WHY="the new join token is for a different cluster: its CA hash differs from this node's current token"
        return 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
        SAME_CLUSTER_WHY="curl isn't installed, so the new server's CA can't be read"
        return 1
    fi
    # -f: an HTTP error page isn't a CA, so it counts as unreadable rather than as another cluster's.
    if ! curl -sfk -m 15 -o "$ca" "https://${server}:9345/cacerts" || [[ ! -s "$ca" ]]; then
        SAME_CLUSTER_WHY="https://${server}:9345/cacerts couldn't be read"
        return 1
    fi
    got=$(sha256sum "$ca" | cut -d' ' -f1) || got=""
    if [[ "$got" != "$want" ]]; then
        SAME_CLUSTER_WHY="the CA at https://${server}:9345/cacerts is another cluster's, not the one this node is in"
        return 1
    fi
}

# R8: a run without -registry leaves an existing registry config in place. Say so, naming the registry.
warn_registry_not_passed () {
    [[ "$REGISTRY_MODE" -eq 0 && -f /etc/rancher/rke2/registries.yaml ]] || return 0
    local endpoints
    endpoints=$(grep -oE 'https://[^"]+' /etc/rancher/rke2/registries.yaml | sort -u | tr '\n' ' ') || endpoints=""
    echo "  WARNING: no -registry given, but this node pulls through the registry in /etc/rancher/rke2/registries.yaml"
    echo "  (${endpoints% }). It is left as it is. To stop using it, remove that file and restart the rke2 service."
}

# R9: on an agent, settings that only servers read are ignored. Say so, rather than seem to apply them.
warn_agent_ignored_settings () {
    [[ $JOIN_MODE -eq 1 && $JOIN_TYPE == "agent" ]] || return 0
    local ignored=() kv key default
    for kv in CLUSTER_CIDR=10.42.0.0/16 SERVICE_CIDR=10.43.0.0/16 INSTALL_SERVICELB=true INSTALL_LOCAL_PATH_PROVISIONER=true \
              INSTALL_DNS_UTILITY=true CONTROL_PLANE_TAINT=false COREDNS_HOSTS= PVC_DATA=default; do
        key=${kv%%=*} default=${kv#*=}
        # The main flow has already turned PVC_DATA's "default" into its path.
        [[ $key == PVC_DATA && "${!key:-}" == "/opt/local-path-provisioner" ]] && continue
        [[ "${!key:-}" == "$default" ]] || ignored+=("$key")
    done
    if [[ ${#ignored[@]} -gt 0 ]]; then
        echo "  WARNING: this agent ignores ${ignored[*]}: only servers read these settings, so set them on the cluster's servers."
    fi
    return 0
}

reconcile_registry_config_change () {
    # Companion to reconcile_existing_install: on the reconcile path,
    # create_registry_config may have just rewritten /etc/rancher/rke2/registries.yaml,
    # but the running containerd only picks it up on a service restart. Apply the same
    # RKE2_RECONFIGURE contract as config.yaml changes; without the opt-in, revert the
    # file so disk and the running service stay consistent.
    [[ "${SKIP_CORE_INSTALL:-0}" -eq 1 ]] || return 0
    local live="/etc/rancher/rke2/registries.yaml"
    local pre="${RECONCILE_REGISTRIES_PRE:-}"
    [[ -f "$live" || -n "$pre" ]] || return 0
    if [[ -n "$pre" && -f "$live" ]] && cmp -s "$pre" "$live"; then
        return 0
    fi
    if [[ -z "$pre" && ! -s "$live" ]]; then
        return 0
    fi
    if [[ "${RKE2_RECONFIGURE,,}" == "true" ]]; then
        echo "  registries.yaml changed on a running node and RKE2_RECONFIGURE=true: the service will be restarted to apply it."
        SERVICE_ACTION="restart"
    else
        if [[ -n "$pre" ]]; then
            cp "$pre" "$live"
        else
            rm -f "$live"
        fi
        echo "Error: the requested registry configuration differs from the running node's registries.yaml."
        echo "  The on-disk change was reverted to keep disk and the running service consistent."
        echo "  Re-run with RKE2_RECONFIGURE=true to apply the registry change and restart the service."
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
    # P4-04: save bundles built on rpm-based hosts carry the policy RPMs - install
    # from the bundle first (works air-gapped; also fastest online)
    local bundled_rpm_dir="$WORKING_DIR/rke2-selinux-rpms"
    if [[ -d "$bundled_rpm_dir" ]] && compgen -G "$bundled_rpm_dir/*.rpm" >/dev/null; then
        echo "  Installing the SELinux policy RPMs bundled in the save archive..."
        if command -v dnf &>/dev/null; then
            dnf install -y --disablerepo='*' "$bundled_rpm_dir"/*.rpm || true
        else
            rpm -Uvh --replacepkgs "$bundled_rpm_dir"/*.rpm || true
        fi
        if rpm -q rke2-selinux &>/dev/null; then
            echo "  rke2-selinux policy installed from the bundled RPMs."
            return 0
        fi
        echo "  Bundled policy RPM install did not succeed; falling through..."
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
    # P4-08b: explicit opt-in fallback for distros with no upstream rke2-selinux
    # (SUSE): switch the host to permissive instead of failing pre-cluster.
    # Recorded in the install state and restored to enforcing on uninstall.
    # Never applied on RHEL-family, where the policy is installable (repo/bundle).
    if [[ "${RKE2_SELINUX_FALLBACK,,}" == "permissive" ]]; then
        if [[ "$OS_ID" =~ ^(sles|opensuse-leap)$ ]]; then
            echo "  RKE2_SELINUX_FALLBACK=permissive: no rke2-selinux policy is available for $OS_ID."
            echo "  WARNING: switching SELinux to PERMISSIVE (runtime + /etc/selinux/config)."
            echo "  This is recorded in the install state and restored to enforcing on uninstall."
            state_set RKE2I_SELINUX_WAS_ENFORCING "true"
            setenforce 0 2>/dev/null || true
            if [[ -f /etc/selinux/config ]]; then
                sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
            fi
            SELINUX_ENFORCING="false"
            # config.yaml was generated while the host was still enforcing - drop the
            # selinux flag so rke2 does not expect the (absent) policy
            if [[ -f /etc/rancher/rke2/config.yaml ]]; then
                sed -i '/^selinux: true$/d' /etc/rancher/rke2/config.yaml
            fi
            return 0
        fi
        echo "  NOTE: RKE2_SELINUX_FALLBACK=permissive is only honored on SUSE hosts (no upstream"
        echo "  policy exists there). On $OS_ID install the policy instead (repos or bundled RPMs)."
    fi
    echo "Error: SELinux is enforcing but the 'rke2-selinux' policy is not installed, and it could not be"
    echo "  installed automatically (air-gapped/tar-method installs cannot fetch it). Starting RKE2 now"
    echo "  would produce AVC-denied (broken) workloads. Remediation - choose ONE, then re-run:"
    echo "   1) Install the policies from local media/repos:"
    echo "        dnf|yum|zypper install -y container-selinux rke2-selinux"
    echo "      (offline: download from https://github.com/rancher/rke2-selinux/releases and 'rpm -ivh' them)"
    echo "   2) Or set SELinux to permissive mode:"
    echo "        setenforce 0    (and set SELINUX=permissive in /etc/selinux/config to persist)"
    echo "   3) SUSE only: re-run with RKE2_SELINUX_FALLBACK=permissive (recorded + restored on uninstall)"
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
        if [[ $CNI_NONE == "true" ]]; then
            # No CNI: the node stays NotReady and pods stay Pending until one is installed, by design. Wait for the
            # API server only.
            wait_for_api_server
            return 0
        fi
        # Hard-fail: the rest of the install (utilities, add-ons) depends on a ready control plane.
        if ! check_namespace_pods_ready; then
            echo "Error: kube-system pods weren't ready after ${POD_WAIT_TIMEOUT}s: ${NOT_READY_PODS}."
            echo "  The cluster may still be converging - inspect with 'kubectl get pods -A' and re-run"
            echo "  '$SCRIPT_NAME install' once it settles. On a slow host or network, set POD_WAIT_TIMEOUT higher."
            exit 1
        fi
    fi
}

# wait_for_api_server: up to 120 s for the API server to answer, for CNI_TYPE=none, where pods can't be ready yet.
wait_for_api_server () {
    local _
    for _ in $(seq 1 24); do
        if /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get --raw /readyz >/dev/null 2>&1; then
            echo "  The API server is up."
            return 0
        fi
        sleep 5
    done
    echo "Error: the API server didn't answer within 120 seconds. Inspect with 'journalctl -u rke2-server'."
    exit 1
}

install_rke2_binaries () {
    echo "  Installing RKE2 binaries"
    if [[ "$AIR_GAPPED_MODE" -eq 1 ]]; then
        echo "  extracting rke2-core-images archive..."
        tar -xzf $WORKING_DIR/rke2-core-images/rke2-core-images.tar.gz -C $WORKING_DIR/rke2-core-images
        mv $WORKING_DIR/rke2-core-images/images/rke2-images-core.linux-amd64.tar.gz $WORKING_DIR/rke2-binaries
        cp $WORKING_DIR/rke2-binaries/rke2-images-core.linux-amd64.tar.gz $RKE2_DATA/agent/images
        rm -rf $WORKING_DIR/rke2-core-images/images
        # CNI_TYPE=none has no CNI images: save skips them, so there is nothing to extract.
        if [[ $CNI_NONE == "false" ]]; then
            if [[ ! -f $WORKING_DIR/rke2-cni-images/rke2-$CNI_TYPE-images.tar.gz ]]; then
                local saved_cni
                saved_cni=$(sed -n 's/^# CNI Type: //p' "$base_dir/rke2-save-version.txt" 2>/dev/null) || saved_cni=""
                echo "Error: this bundle has no images for CNI_TYPE=$CNI_TYPE${saved_cni:+ (it was saved with CNI_TYPE=$saved_cni)}."
                echo "  Install with the CNI_TYPE the bundle was saved with, or run 'save' again with CNI_TYPE=$CNI_TYPE."
                exit 1
            fi
            echo "  extracting rke2-cni-images archive..."
            tar -xzf $WORKING_DIR/rke2-cni-images/rke2-$CNI_TYPE-images.tar.gz -C $WORKING_DIR/rke2-cni-images
            mv $WORKING_DIR/rke2-cni-images/images/rke2-images-$CNI_TYPE.linux-amd64.tar.gz $WORKING_DIR/rke2-binaries
            cp $WORKING_DIR/rke2-binaries/rke2-images-$CNI_TYPE.linux-amd64.tar.gz $RKE2_DATA/agent/images
            rm -rf $WORKING_DIR/rke2-cni-images/images
        fi
        if [[ $REGISTRY_MODE -eq 0 ]]; then
            echo "  extracting rke2-utilities archive..."
            local utilities_tar
            if ! utilities_tar=$(select_newest "$WORKING_DIR"/rke2-utilities/container_images_*.tar.gz); then
                echo "Error: no container_images_*.tar.gz archive found in $WORKING_DIR/rke2-utilities."
                echo "  Re-run 'save' on a connected host to build a complete archive."
                exit 1
            fi
            tar -xzf "$utilities_tar" -C $WORKING_DIR/rke2-utilities
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
        # Fetch to a temp file and check it: '> ca.crt' would empty a working CA before the fetch result is known,
        # so one failed re-run during a registry outage broke the node's next restart.
        local tmp_ca="$TMP_DIR/registry-ca.pem"
        if ! openssl s_client -showcerts -connect "$REGISTRY_INFO" < /dev/null 2>/dev/null \
             | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$tmp_ca" \
           || ! openssl x509 -in "$tmp_ca" -noout 2>/dev/null; then
            echo "Error: Failed to retrieve a certificate from '$REGISTRY_INFO'. Please ensure the registry is accessible and the port is correct."
            [[ -s "$CERTS_DIR/ca.crt" ]] && echo "  The existing $CERTS_DIR/ca.crt is left unchanged."
            exit 1
        fi
        install -m 0644 "$tmp_ca" "$CERTS_DIR/ca.crt"
        echo "  Certificate saved to $CERTS_DIR."
        # registries.yaml carries the registry credentials - write it 0600 (RK-8).
        ( umask 077; cat > /etc/rancher/rke2/registries.yaml <<EOF
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
        )
        chmod 600 /etc/rancher/rke2/registries.yaml
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
    elif grep -qE '^\s*nameserver\s+127\.' /etc/resolv.conf 2>/dev/null \
         && [[ -f /run/systemd/resolve/resolv.conf ]]; then
        # A PLAIN-FILE resolv.conf pointing at a loopback resolver (seen in the
        # wild after resolver-restore tools rewrite the systemd-resolved stub as
        # a regular file): handing it to kubelet makes CoreDNS detect a forward
        # loop and CrashLoop. Use the real systemd-resolved upstream list instead.
        resolv_conf_file="/run/systemd/resolve/resolv.conf"
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
  # Audit log lives under the RKE2 data dir, NOT /var/log: on SELinux-enforcing
  # hosts the containerized apiserver may only write paths labeled by the
  # rke2-selinux policy - /var/log/... gets EACCES and the apiserver crashloops
  - "audit-log-path=$RKE2_DATA/server/logs/rke2-apiserver-audit.log"
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
    render_coredns_helmchartconfig "$RKE2_DATA/server/manifests/rke2-coredns-helmchartconfig.yaml"
}

# CoreDNS overrides, layered on the rke2-coredns chart defaults (never replace the chart's
# 'servers' list - it is a YAML list, so overriding it drops every default, e.g. use_tcp).
# - service.name kube-dns: the chart names the Service 'rke2-coredns-rke2-coredns', but DAP's
#   nginx gateways (dell-orchestrator / dell-portal) hard-code
#   'resolver kube-dns.kube-system.svc.cluster.local' and cannot resolve anything without it.
# - COREDNS_HOSTS (optional): in-cluster pins as an extra server block per name, e.g. when LAN
#   DNS sends browsers to a TLS-terminating proxy but pods must still reach the cluster's own
#   ingress (split-horizon). Rendered here so 'install' re-runs keep the pins.
render_coredns_helmchartconfig () {
    local dest="$1"
    local entries=() names=() entry name ip
    for entry in $(echo "$COREDNS_HOSTS" | tr ',' ' '); do
        name="${entry%%=*}"
        ip="${entry#*=}"
        if [[ "$entry" != *=* || ! "$name" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ \
              || ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "Error: invalid COREDNS_HOSTS entry '$entry' (expected <fqdn>=<ipv4>, comma or space separated)."
            exit 1
        fi
        entries+=("$ip $name")
        names+=("$name:53")
    done
    echo "  Generating $dest"
    cat > "$dest" <<EOF
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-coredns
  namespace: kube-system
spec:
  valuesContent: |-
    service:
      name: kube-dns
EOF
    if [[ ${#entries[@]} -gt 0 ]]; then
        echo "  Pinning in-cluster DNS (COREDNS_HOSTS): ${entries[*]}"
        cat >> "$dest" <<EOF
    extraConfig:
      import:
        parameters: /etc/coredns/coredns-hosts.server
    zoneFiles:
    - filename: coredns-hosts.server
      domain: coredns-hosts
      contents: |
        ${names[*]} {
          errors
          hosts {
EOF
        for entry in "${entries[@]}"; do
            echo "            $entry" >> "$dest"
        done
        cat >> "$dest" <<EOF
            fallthrough
          }
          forward . /etc/resolv.conf
          cache 30
        }
EOF
    fi
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

# Rocky, Alma and RHEL 10's cloud images ship only kernel-modules-core, and br_netfilter is in kernel-modules-extra.
# Online, install the running kernel's own package: a newer kernel's modules can't load until a reboot. If that package
# has left the repo, stop and say to update and reboot. Air-gapped, name the package. Spec 11, U4.
ensure_el_required_modules () {
    case "$OS_ID" in rhel|centos|rocky|almalinux|fedora) ;; *) return 0 ;; esac
    local mod missing="" kver pm=dnf
    for mod in overlay br_netfilter; do
        modprobe -n "$mod" >/dev/null 2>&1 || missing="$missing $mod"
    done
    [[ -z "$missing" ]] && return 0
    kver=$(uname -r)
    command -v dnf >/dev/null 2>&1 || pm=yum
    echo "  The running kernel ($kver) has no$missing: it's in kernel-modules-extra, which this image leaves out."
    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        echo "Error: install kernel-modules-extra for the running kernel from local media"
        echo "  ($pm install kernel-modules-extra-$kver), then re-run this script."
        exit 1
    fi
    echo "  Installing kernel-modules-extra-$kver to match the running kernel..."
    if ! "$pm" install -y "kernel-modules-extra-$kver"; then
        echo "Error: kernel-modules-extra-$kver is no longer in this host's repositories, so the running kernel"
        echo "  can't get$missing. Update the host ($pm upgrade), reboot into the new kernel, then re-run this script."
        exit 1
    fi
}

config_host_settings () {
    record_install_state
    ensure_el_required_modules
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
                    echo "  Install the extra kernel modules package for the running kernel ($(uname -r)), or, if a"
                    echo "  newer kernel was installed since the last boot, reboot into it, then re-run this script."
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
        echo "    RHEL/Rocky:     dnf install -y kernel-modules-extra-\$(uname -r)"
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
        # Hard-fail: the storageclass patch below and dependent PVCs need a live provisioner. With CNI_TYPE=none it
        # can't start until a CNI is installed, so it isn't waited for.
        if [[ $CNI_NONE == "false" ]] && ! check_namespace_pods_ready local-path-storage; then
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
            kubectl apply -f $DNSUTILS_URL
        fi
        # Warn-and-continue: 'default' may contain unrelated user workloads and dnsutils is a
        # non-critical troubleshooting pod - do not fail the install over it.
        if [[ $CNI_NONE == "false" ]] && ! check_namespace_pods_ready default; then
            echo "  WARNING: pods in the 'default' namespace are not all ready; continuing (dnsutils is non-critical)."
        fi
    fi
}

# -- Upgrade Definitions -- #

run_upgrade () {
    echo "--- Running upgrade workflow"
    # RK-18: the 'stable' channel is resolved by the cluster from update.rke2.io -
    # unreachable in air-gapped environments, so the plan would hang forever.
    if [[ $AIR_GAPPED_MODE -eq 1 && "$UPGRADE_VERSION" == "stable" ]]; then
        echo "Error: air-gapped upgrades cannot use the 'stable' channel (it requires internet access"
        echo "  to update.rke2.io). Specify an explicit version instead, e.g.:"
        echo "  sudo ./$SCRIPT_NAME upgrade $UPGRADE_TYPE v1.34.5+rke2r1"
        exit 1
    fi
    export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
    export PATH=$PATH:/var/lib/rancher/rke2/bin

    # Kubectl precheck - upgrade requires an existing cluster
    if ! kubectl get nodes &>/dev/null; then
        echo "Error: kubectl cannot reach the cluster. Ensure RKE2 is installed and running before upgrading."
        exit 1
    fi

    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        # The upgrade job pulls rancher/rke2-upgrade through the node's registry mirror. With no mirror, or with the
        # tag missing from the registry, the job would sit in ImagePullBackOff after this script exited 0.
        if [[ ! -f /etc/rancher/rke2/registries.yaml ]]; then
            echo "Error: an air-gapped upgrade pulls rancher/rke2-upgrade:${UPGRADE_VERSION//+/-} through the node's registry,"
            echo "  but this node has no /etc/rancher/rke2/registries.yaml. Install or join it with -registry first."
            exit 1
        fi
        if [[ $REGISTRY_MODE -eq 1 ]]; then
            check_upgrade_image_in_registry
        else
            echo "  WARNING: no -registry given, so the registry can't be checked for rancher/rke2-upgrade:${UPGRADE_VERSION//+/-}."
        fi
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
    if [[ ${UPGRADE_WAIT,,} == "true" ]]; then
        wait_for_upgrade
    else
        echo "  The upgrade runs in the background. Follow it with 'kubectl get nodes', or set UPGRADE_WAIT=true to wait for it."
    fi

    echo "--- Finished upgrade workflow"
}

# check_upgrade_image_in_registry: refuse an air-gapped upgrade whose rke2-upgrade tag isn't in the registry. Any
# answer other than a tag list (no curl, an auth scheme curl can't use, a network error) is a warning, not a refusal.
check_upgrade_image_in_registry () {
    local tag="${UPGRADE_VERSION//+/-}" resp code body pass_esc
    if ! command -v curl >/dev/null 2>&1; then
        echo "  WARNING: curl isn't installed, so the registry can't be checked for rancher/rke2-upgrade:$tag."
        return 0
    fi
    local ca="/etc/rancher/rke2/certs.d/${REG_FQDN}:${REG_PORT}/ca.crt" tls=(-k)
    [[ -s "$ca" ]] && tls=(--cacert "$ca")
    # The credentials go through curl's config on stdin, not its arguments.
    pass_esc=${REG_PASS//\\/\\\\}; pass_esc=${pass_esc//\"/\\\"}
    resp=$(printf 'user = "%s:%s"\n' "$REG_USER" "$pass_esc" \
           | curl -s -m 20 "${tls[@]}" -K - -w '\n%{http_code}' "https://${REGISTRY_INFO}/v2/rancher/rke2-upgrade/tags/list") || resp=""
    code=${resp##*$'\n'}; body=${resp%$'\n'*}
    if [[ "$code" == "200" ]] && grep -q "\"$tag\"" <<< "$body"; then
        echo "  The registry has rancher/rke2-upgrade:$tag."
    elif [[ "$code" == "200" || "$code" == "404" ]]; then
        echo "Error: the registry $REGISTRY_INFO has no rancher/rke2-upgrade:$tag, so the upgrade job couldn't pull it."
        echo "  On a connected host, build and push a bundle for that version, then upgrade:"
        echo "  sudo RKE2_VERSION=$UPGRADE_VERSION ./$SCRIPT_NAME save push -registry $REGISTRY_INFO <user> <password>"
        exit 1
    else
        echo "  WARNING: couldn't check the registry for rancher/rke2-upgrade:$tag (HTTP ${code:-no answer}). Going on."
    fi
}

# wait_for_upgrade: until every node the upgrade targets reports UPGRADE_VERSION and is schedulable again (the plans
# cordon each node, and the controller uncordons it when its job is done), or UPGRADE_WAIT_TIMEOUT runs out.
wait_for_upgrade () {
    local target="$UPGRADE_VERSION" sel=() list behind deadline
    if [[ "$target" == "stable" ]]; then
        target=$(resolve_rke2_stable_version) || target=""
        if [[ -z "$target" ]]; then
            echo "  WARNING: UPGRADE_WAIT=true, but the stable channel couldn't be resolved here, so there is no version to wait for."
            return 0
        fi
    fi
    case "$UPGRADE_TYPE" in
        server) sel=(-l "node-role.kubernetes.io/control-plane=true") ;;
        agent)  sel=(-l "!node-role.kubernetes.io/control-plane") ;;
    esac
    echo "  Waiting up to ${UPGRADE_WAIT_TIMEOUT}s for the nodes to run $target..."
    deadline=$((SECONDS + UPGRADE_WAIT_TIMEOUT))
    while :; do
        list=$(kubectl get nodes "${sel[@]}" -o jsonpath='{range .items[*]}{.metadata.name}={.status.nodeInfo.kubeletVersion}={.spec.unschedulable}{"\n"}{end}' 2>/dev/null) || list=""
        behind=$(grep -v "=${target}=\$" <<< "$list" | grep -v '^$' | cut -d= -f1 | tr '\n' ' ') || behind=""
        if [[ -n "$list" && -z "${behind// /}" ]]; then
            echo "  Every node the upgrade targets runs $target, and is schedulable again."
            return 0
        fi
        if [[ $SECONDS -ge $deadline ]]; then
            echo "Error: after ${UPGRADE_WAIT_TIMEOUT}s, these nodes don't run $target yet, or are still cordoned: ${behind:-no nodes listed}."
            echo "  Inspect with 'kubectl -n system-upgrade get plans,jobs,pods'."
            exit 1
        fi
        sleep 15
    done
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
        curl -sfL https://github.com/rancher/system-upgrade-controller/releases/download/$SUC_VERSION/crd.yaml -o $WORKING_DIR/rke2-utilities/crd.yaml
        curl -sfL https://github.com/rancher/system-upgrade-controller/releases/download/$SUC_VERSION/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
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
  tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
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

# Resolve the RKE2 'stable' channel to a version (e.g. v1.34.5+rke2r1) via update.rke2.io.
# Bounded so an unresponsive channel server cannot hang the run; prints nothing on failure.
resolve_rke2_stable_version () {
    curl -sfL --connect-timeout 10 --max-time 30 -o /dev/null -w '%{url_effective}' https://update.rke2.io/v1-release/channels/stable 2>/dev/null \
        | awk -F/ '{print $NF}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$' || true
}

# The rke2-upgrade image tag for the utility-images list: the current stable release, or the
# pinned RKE2_VERSION when the channel server is unreachable (the image is optional).
rke2_upgrade_image_tag () {
    local version
    version=$(resolve_rke2_stable_version)
    if [[ -z "$version" ]]; then
        echo "  Warning: could not resolve the RKE2 stable channel from update.rke2.io; using RKE2_VERSION $RKE2_VERSION for the rke2-upgrade image" >&2
        version=$RKE2_VERSION
    fi
    echo "${version//+/-}"
}

push_upgrade_images () {
    echo "  Pushing upgrade images to registry..."
    image_pull_push_check

    # Resolve the upgrade version tag for the rke2-upgrade image
    local upgrade_tag stable_version=""
    if [[ "$UPGRADE_VERSION" == "stable" ]]; then
        stable_version=$(resolve_rke2_stable_version)
        if [[ -z "$stable_version" ]]; then
            echo "Error: could not resolve the RKE2 stable channel from update.rke2.io."
            echo "  Pass an explicit version instead, e.g.: sudo ./$SCRIPT_NAME upgrade $UPGRADE_TYPE v1.34.5+rke2r1"
            exit 1
        fi
        upgrade_tag=${stable_version//+/-}
        echo "  Resolved stable version tag: $upgrade_tag"
    else
        upgrade_tag=$(echo "$UPGRADE_VERSION" | sed 's/+/-/')
    fi

    # Download SUC manifest to extract the controller image
    if [[ ! -f $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml ]]; then
        curl -sfL https://github.com/rancher/system-upgrade-controller/releases/download/$SUC_VERSION/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
    fi
    local suc_image
    suc_image=$(grep 'rancher/system-upgrade-controller' $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml | awk '{print $2}') || true

    # Build upgrade-images.txt
    local upgrade_images_file="$WORKING_DIR/rke2-utilities/images/upgrade-images.txt"
    echo "rancher/rke2-upgrade:${upgrade_tag}" > "$upgrade_images_file"
    echo "$suc_image" >> "$upgrade_images_file"
    suc_job_kubectl_image "$WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml" >> "$upgrade_images_file" || true

    echo "--- Printing upgrade-images.txt"
    cat "$upgrade_images_file"
    echo "---"

    # Push upgrade images
    $WORKING_DIR/rke2-utilities/image_pull_push.sh -f "$upgrade_images_file" push $REGISTRY_INFO $REG_USER $REG_PASS

    # Push RKE2 core+CNI images for the target version (same method as push_rke2_images online path)
    local upgrade_translated_version
    if [[ "$UPGRADE_VERSION" == "stable" ]]; then
        # Convert the resolved stable version to URL-encoded format
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

# suc_job_kubectl_image <manifest>: the kubectl image the controller's jobs use to cordon and drain a node
# (SYSTEM_UPGRADE_JOB_KUBECTL_IMAGE). The plans cordon, and the jobs pull with policy Always, so an air-gapped
# upgrade needs it in the registry as much as the controller's own image.
suc_job_kubectl_image () {
    sed -n 's/^ *SYSTEM_UPGRADE_JOB_KUBECTL_IMAGE: *"\{0,1\}\([^" ]*\)"\{0,1\} *$/\1/p' "$1" | head -1
}

download_upgrade_artifacts () {
    echo "  Downloading system-upgrade-controller manifests..."
    curl -sfL https://github.com/rancher/system-upgrade-controller/releases/download/$SUC_VERSION/crd.yaml -o $WORKING_DIR/rke2-utilities/crd.yaml
    curl -sfL https://github.com/rancher/system-upgrade-controller/releases/download/$SUC_VERSION/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml

    # Extract SUC controller image from manifest and add to utility-images list
    local suc_image
    suc_image=$(grep 'rancher/system-upgrade-controller' $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml | awk '{print $2}') || true
    echo "  Adding SUC controller image to utility-images list: $suc_image"
    echo "$suc_image" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    local kubectl_image
    kubectl_image=$(suc_job_kubectl_image "$WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml") || kubectl_image=""
    if [[ -n "$kubectl_image" ]]; then
        echo "  Adding the upgrade jobs' kubectl image to utility-images list: $kubectl_image"
        echo "$kubectl_image" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    fi

    # The upgrade image for the version this bundle is built for: an air-gapped upgrade needs an explicit version,
    # and this is the natural one. The stable release is kept as well, when it can be resolved.
    echo "  Adding rke2-upgrade image to utility-images list: rancher/rke2-upgrade:${RKE2_VERSION//+/-}"
    echo "rancher/rke2-upgrade:${RKE2_VERSION//+/-}" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    local stable_tag
    stable_tag=$(rke2_upgrade_image_tag)
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
    curl -fL https://github.com/vmware-tanzu/velero/releases/download/${VELERO_VERSION}/velero-${VELERO_VERSION}-linux-amd64.tar.gz \
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

  # RK-11: the default VSC_DRIVER (driver.longhorn.io) assumes the ap-tools stack.
  # Velero still installs and does object backups without it, so warn loudly rather than fail.
  if ! kubectl get csidriver "$VSC_DRIVER" &>/dev/null; then
      echo "  WARNING: CSI driver '$VSC_DRIVER' is not registered in this cluster (default assumes Longhorn"
      echo "  installed by ap-tools). CSI volume snapshots WILL FAIL until VSC_DRIVER/VSC_NAME are set to an"
      echo "  installed CSI driver ('kubectl get csidrivers'). Object/resource backups are unaffected."
  fi

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

  # Create S3 credentials file in the script's private temp dir (0700), mode 0600,
  # instead of a fixed world-guessable /tmp path (RK-8). Removed on any exit via the trap.
  echo "  Creating Velero S3 credentials..."
  local velero_creds="$TMP_DIR/credentials-velero"
  ( umask 077; cat > "$velero_creds" <<CREDEOF
[default]
aws_access_key_id=${VELERO_S3_ACCESS_KEY}
aws_secret_access_key=${VELERO_S3_SECRET_KEY}
CREDEOF
  )

  # Install Velero into the cluster
  echo "  Installing Velero server into the cluster..."
  velero install \
    --provider aws \
    --plugins velero/velero-plugin-for-aws:${VELERO_AWS_PLUGIN_VERSION} \
    --bucket ${VELERO_BUCKET} \
    --backup-location-config \
      region=us-east-1,s3ForcePathStyle=true,s3Url=${VELERO_S3_URL},checksumAlgorithm="",insecureSkipTLSVerify=true \
    --secret-file "$velero_creds" \
    --features=EnableCSI \
    --use-node-agent \
    --use-volume-snapshots=true \
    --wait

  # Clean up credentials file
  rm -f "$velero_creds"

  # Verify installation
  echo "  Verifying Velero installation..."
  # Hard-fail: a scheduled backup against a broken Velero deployment is worse than no install.
  if ! check_namespace_pods_ready "velero"; then
      echo "Error: Velero pods did not become ready within the timeout."
      echo "  Inspect with 'kubectl get pods -n velero' and re-run '$SCRIPT_NAME install velero'."
      exit 1
  fi

  # Create scheduled backup (RK-4: guarded so 'install velero' is re-runnable -
  # 'velero schedule create' hard-fails when the schedule already exists)
  if velero schedule get daily-full-backup &>/dev/null; then
      echo "  Schedule 'daily-full-backup' already exists; leaving it in place."
      echo "  (To apply changed schedule settings: 'velero schedule delete daily-full-backup --confirm' and re-run.)"
  else
      echo "  Creating scheduled backup '${VELERO_BACKUP_SCHEDULE}'..."
      velero schedule create daily-full-backup \
        --schedule="${VELERO_BACKUP_SCHEDULE}" \
        --ttl ${VELERO_BACKUP_TTL} \
        --snapshot-move-data \
        --include-cluster-resources=true \
        --include-namespaces ${VELERO_BACKUP_NAMESPACES}
  fi

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

  # RK-11: the default PROMETHEUS_STORAGE_CLASS ('longhorn') assumes the ap-tools stack.
  # Standalone clusters fail 10 minutes into the helm --wait on a Pending PVC instead.
  # Verify the StorageClass up front: fall back to the cluster default if the requested
  # one is missing, and fail fast when there is no default either.
  if ! kubectl get storageclass "$PROMETHEUS_STORAGE_CLASS" &>/dev/null; then
      local default_sc
      default_sc=$(kubectl get storageclass \
        -o jsonpath='{.items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")].metadata.name}' \
        2>/dev/null | awk '{print $1}')
      if [[ -n "$default_sc" ]]; then
          echo "  WARNING: StorageClass '$PROMETHEUS_STORAGE_CLASS' not found; using the cluster default '$default_sc' instead."
          PROMETHEUS_STORAGE_CLASS="$default_sc"
      else
          echo "Error: StorageClass '$PROMETHEUS_STORAGE_CLASS' not found and the cluster has no default StorageClass."
          echo "  Prometheus PVCs would stay Pending until the helm install times out (10m)."
          echo "  Set PROMETHEUS_STORAGE_CLASS to an existing StorageClass ('kubectl get storageclass')"
          echo "  or install a storage provisioner (e.g. INSTALL_LOCAL_PATH_PROVISIONER=true) first."
          exit 1
      fi
  fi

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

# rke2-killall.sh unmounts /run/k3s, kubelet's pods and the CNI namespaces, but not containerd's tmpmounts. One left
# behind (seen after an upgrade, now and then) is a mount point, so removing the data folder fails with "Device or
# resource busy": Rancher's uninstaller then skips its last steps and deletes itself, and this script's own removal
# fails too. So they're unmounted first, lazily if need be. Spec 11, U3.
unmount_containerd_tmpmounts () {
    local data=${RKE2_DATA:-default} mnt
    [[ "$data" == "default" ]] && data=/var/lib/rancher/rke2
    [[ "$data" == /* && "$data" != "/" ]] || return 0
    findmnt -rn -o TARGET 2>/dev/null | awk -v p="$data/agent/containerd/tmpmounts/" 'index($0, p) == 1' | sort -r | while read -r mnt; do
        echo "  Unmounting $mnt, left behind by containerd"
        umount -- "$mnt" 2>/dev/null || umount -l -- "$mnt" 2>/dev/null || echo "  WARNING: couldn't unmount $mnt"
    done || true
}

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
    unmount_containerd_tmpmounts
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
        # P4-08b: restore SELinux enforcing if the install fallback switched it
        if [[ "${RKE2I_SELINUX_WAS_ENFORCING:-false}" == "true" ]]; then
            echo "  Restoring SELinux to enforcing (RKE2_SELINUX_FALLBACK switched it to permissive)..."
            if [[ -f /etc/selinux/config ]]; then
                sed -i 's/^SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
            fi
            setenforce 1 2>/dev/null || true
        fi
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
            unmount_containerd_tmpmounts
            rm -rf -- "$RKE2_DATA"
        fi
    fi
    if [[ -n "$KUBELET_DATA" && "$KUBELET_DATA" != "default" ]]; then
        if [[ "$KUBELET_DATA" != /* || "$KUBELET_DATA" == "/" ]]; then
            echo "Refusing removal of dir KUBELET_DATA=$KUBELET_DATA"
        else
            # unmount projected/secret tmpfs mounts (best effort)
            find "$KUBELET_DATA" -type d -path '*kubernetes.io~*' -exec umount -lf {} \; 2>/dev/null || true
            # dead CSI FUSE globalmounts (Longhorn after the engine is gone) EIO on
            # traversal and can be absent from findmnt - unmount them explicitly
            # WITHOUT descending into them, or the rm below fails with I/O errors
            find "$KUBELET_DATA/plugins" -type d -name globalmount -prune -exec umount -lf {} \; 2>/dev/null || true
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
    # RK-14: regenerate the utility-images list from scratch each run instead of
    # appending to a previous run's list ('>>' growth across re-runs).
    : > $WORKING_DIR/rke2-utilities/images/utility-images.txt
    download_rke2_binaries
    if [[ ${PUSH_SAVE_VELERO,,} == "true" ]]; then
        download_velero
    fi
    if [[ ${PUSH_SAVE_MONITORING,,} == "true" ]]; then
        download_monitoring_charts
    fi
    download_upgrade_artifacts
    download_rke2_utilities
    download_selinux_policy_rpms
    create_save_archive
    echo "--- Finished save workflow"
    echo "  Copy the archive to an air-gapped host runing the same version of $OS_ID"
}

download_selinux_policy_rpms () {
    # P4-04: air-gapped installs are tar-method and cannot fetch the SELinux
    # policies, and uninstall removes both the policy RPMs and the Rancher repo
    # file - so an Enforcing host could never reinstall from its own bundle
    # without a manual RPM transfer. Bundle the policy RPMs on rpm-based hosts.
    if ! command -v dnf &>/dev/null; then
        echo "  Skipping SELinux policy RPM download (no dnf; no upstream rke2-selinux for this distro)."
        return 0
    fi
    local maj destdir
    maj=$(. /etc/os-release && echo "${VERSION_ID%%.*}")
    destdir="$WORKING_DIR/rke2-selinux-rpms"
    mkdir -p "$destdir"
    echo "  Downloading rke2-selinux + container-selinux RPMs (el$maj) into the bundle..."
    if ! dnf download --help &>/dev/null; then
        dnf install -y dnf-plugins-core >/dev/null || true
    fi
    # --resolve WITHOUT --alldeps: the offline install applies every RPM in this
    # dir, so it must hold only the policy packages + deps genuinely missing on
    # this host (same-OS save contract) - --alldeps pulled the full 126-package
    # transitive closure and would bulk-upgrade system libs on the target
    if dnf download --resolve --destdir "$destdir" \
        --repofrompath "rancher-rke2-common-save,https://rpm.rancher.io/rke2/stable/common/centos/${maj}/noarch" \
        --setopt=rancher-rke2-common-save.gpgcheck=0 \
        rke2-selinux container-selinux >/dev/null; then
        echo "  SELinux policy RPMs bundled: $(find "$destdir" -name '*.rpm' | wc -l) package(s)."
        return 0
    fi
    rm -rf "$destdir"
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        echo "Error: failed to download the rke2-selinux/container-selinux RPMs and this host is"
        echo "  SELinux-enforcing - the save bundle could not reinstall RKE2 on this host while"
        echo "  air-gapped. Fix repo access (rpm.rancher.io) and re-run save."
        exit 1
    fi
    echo "Warning: could not download the SELinux policy RPMs; the bundle will not self-serve"
    echo "  SELinux-enforcing air-gapped installs (manual RPM transfer would be required)."
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
    curl -sfL $DNSUTILS_URL -o $WORKING_DIR/rke2-utilities/dnsutils.yaml
    cat $WORKING_DIR/rke2-utilities/dnsutils.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    # Add Helm utility images (Longhorn, MetalLB, HAProxy) before saving the archive
    if [[ -f $WORKING_DIR/rke2-utilities/images/utility-images.txt ]]; then
        image_pull_push_check
        sort -u -o $WORKING_DIR/rke2-utilities/images/utility-images.txt $WORKING_DIR/rke2-utilities/images/utility-images.txt
        cd $WORKING_DIR/rke2-utilities
        ./image_pull_push.sh -f images/utility-images.txt save
        cd $base_dir
    fi
}

download_velero () {
    echo "  Downloading Velero CLI ${VELERO_VERSION}..."
    curl -fL https://github.com/vmware-tanzu/velero/releases/download/${VELERO_VERSION}/velero-${VELERO_VERSION}-linux-amd64.tar.gz \
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
    # NOTE: rke2-save-version.txt doubles as the air-gap sentinel - its presence in the
    # invocation directory is what flips later runs into AIR_GAPPED_MODE (not the tar.gz). It is written here for the
    # archive, then removed from this folder.
    cat > $base_dir/rke2-save-version.txt <<EOF
# RKE2 Installer Save Archive
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
# CNI Type: $CNI_TYPE
EOF
    generate_bundle_licenses
    echo "  Creating rke2 archive..."
    # RK-12: tar with explicit -C dirs so invocation by absolute path from another cwd
    # works (the script itself may live outside $base_dir). RK-14: write to a temp file
    # and mv into place so an interrupted save never leaves a truncated archive behind.
    local script_dir tmp_archive
    script_dir=$(cd "$(dirname "$0")" && pwd)
    tmp_archive="$base_dir/.rke2-save.tar.gz.partial"
    tar -czf "$tmp_archive" -C "$base_dir" rke2-install rke2-save-version.txt LICENSES -C "$script_dir" "$SCRIPT_NAME"
    mv -f "$tmp_archive" "$base_dir/rke2-save.tar.gz"
    # The copy inside the archive is the sentinel that matters. Left here, it would flip later runs in this folder
    # into air-gapped mode with no files to use, because cleanup removes the working directory.
    rm -f "$base_dir/rke2-save-version.txt"
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
        local container_images_tar
        if ! container_images_tar=$(select_newest "$WORKING_DIR"/rke2-utilities/container_images_*.tar.gz); then
            echo "Error: no container_images_*.tar.gz archive found in $WORKING_DIR/rke2-utilities."
            echo "  Re-run 'save' on a connected host to build a complete archive."
            exit 1
        fi
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f "$container_images_tar" push $REGISTRY_INFO $REG_USER $REG_PASS
    elif [[ $AIR_GAPPED_MODE -eq 0 ]]; then
        # RK-14: regenerate the image list from scratch each run instead of appending
        # to whatever a previous run left behind ('>>' growth).
        : > $WORKING_DIR/rke2-utilities/images/utility-images.txt
        if [[ ${INSTALL_LOCAL_PATH_PROVISIONER,,} == "true" ]]; then
            curl -sfL https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH_PROVISIONER_VERSION/deploy/local-path-storage.yaml -o $WORKING_DIR/rke2-utilities/local-path-storage.yaml
            cat $WORKING_DIR/rke2-utilities/local-path-storage.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        fi
        if [[ ${INSTALL_DNS_UTILITY,,} == "true" ]]; then
            curl -sfL $DNSUTILS_URL -o $WORKING_DIR/rke2-utilities/dnsutils.yaml
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
            curl -sfL https://github.com/rancher/system-upgrade-controller/releases/download/$SUC_VERSION/system-upgrade-controller.yaml -o $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml
        fi
        local suc_image
        suc_image=$(grep 'rancher/system-upgrade-controller' $WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml | awk '{print $2}') || true
        echo "$suc_image" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        suc_job_kubectl_image "$WORKING_DIR/rke2-utilities/system-upgrade-controller.yaml" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt || true
        echo "rancher/rke2-upgrade:${RKE2_VERSION//+/-}" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        local stable_tag
        stable_tag=$(rke2_upgrade_image_tag)
        echo "rancher/rke2-upgrade:$stable_tag" >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        image_pull_push_check
        sort -u -o $WORKING_DIR/rke2-utilities/images/utility-images.txt $WORKING_DIR/rke2-utilities/images/utility-images.txt
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
        # RK-14: these archives have fixed names - address them directly instead of
        # globbing, so stale/duplicate archives can never be picked nondeterministically.
        echo "  Pushing rke2 core images"
        local core_images_tar="$WORKING_DIR/rke2-core-images/rke2-core-images.tar.gz"
        if [[ ! -f "$core_images_tar" ]]; then
            echo "Error: $core_images_tar not found. Re-run 'save' to build a complete archive."
            exit 1
        fi
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f "$core_images_tar" push $REGISTRY_INFO $REG_USER $REG_PASS
        if [[ $CNI_NONE == "false" ]]; then
            echo "  Pushing rke2 cni images"
            local cni_images_tar="$WORKING_DIR/rke2-cni-images/rke2-$CNI_TYPE-images.tar.gz"
            if [[ ! -f "$cni_images_tar" ]]; then
                echo "Error: $cni_images_tar not found (CNI_TYPE=$CNI_TYPE). Re-run 'save' with the same CNI_TYPE."
                exit 1
            fi
            $WORKING_DIR/rke2-utilities/image_pull_push.sh -f "$cni_images_tar" push $REGISTRY_INFO $REG_USER $REG_PASS
        fi
    else
        echo "  Downloading and pushing rke2 core images"
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-core.linux-amd64.txt -o $WORKING_DIR/rke2-core-images/rke2-images-core.linux-amd64.txt
        image_pull_push_check
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-core-images/rke2-images-core.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS
        if [[ $CNI_NONE == "false" ]]; then
            echo "  Downloading and pushing rke2 cni images"
            curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-$CNI_TYPE.linux-amd64.txt -o $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE.linux-amd64.txt
            $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS
        fi
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
        # RK-8: never print the join token itself - point at the token file instead
        # (install logs are routinely captured by callers like ap-tools).
        local host_ip
        host_ip=$(hostname -I |awk '{print $1}') || true
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
            echo "token: <contents of $RKE2_DATA/server/node-token>"
            echo "----"
            echo "  For joining another server: './rke2_installer.sh join server -tls-san $TLS_SAN $TLS_SAN \$(sudo cat $RKE2_DATA/server/node-token)'."
            echo "  For joining an agent node: './rke2_installer.sh join agent $TLS_SAN \$(sudo cat $RKE2_DATA/server/node-token)'."
            echo "  Note: if using private registry, include -registry in the join command."
            echo "  After joining an agent, apply the worker role with 'kubectl label node <node name> node-role.kubernetes.io/worker=true'."
        else
            echo "  To join more nodes to this cluster use the following config:"
            echo "----"
            echo "server: https://$host_ip:9345"
            echo "token: <contents of $RKE2_DATA/server/node-token>"
            echo "----"
            echo "  For joining another server: './rke2_installer.sh join server $host_ip \$(sudo cat $RKE2_DATA/server/node-token)'."
            echo "  For joining an agent node: './rke2_installer.sh join agent $host_ip \$(sudo cat $RKE2_DATA/server/node-token)'."
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

select_newest () {
    # RK-14: deterministic archive selection. Prints the newest existing file among the
    # expanded glob args (by mtime); returns 1 if none exist; warns when several match
    # (previously an unquoted glob fed multiple paths into basename/tar and misparsed).
    local newest="" count=0 f
    for f in "$@"; do
        if [[ -f "$f" ]]; then
            count=$((count+1))
            if [[ -z "$newest" || "$f" -nt "$newest" ]]; then
                newest="$f"
            fi
        fi
    done
    if [[ $count -eq 0 ]]; then
        return 1
    fi
    if [[ $count -gt 1 ]]; then
        echo "  WARNING: $count archives match; using newest: $(basename "$newest")" >&2
    fi
    echo "$newest"
}

require_cmds () {
    # RK-9: verify required commands up front (minimal cloud images lack several of
    # these) instead of failing obscurely mid-install. Prints a per-distro install hint.
    local missing="" c
    for c in "$@"; do
        if ! command -v "$c" &>/dev/null; then
            missing="$missing $c"
        fi
    done
    if [[ -n "$missing" ]]; then
        echo "Error: required command(s) not found:$missing"
        case "$OS_ID" in
            ubuntu|debian)
                echo "  Install with: sudo apt-get update && sudo apt-get install -y$missing" ;;
            rhel|centos|rocky|almalinux|fedora)
                echo "  Install with: sudo dnf install -y$missing" ;;
            sles|opensuse-leap)
                echo "  Install with: sudo zypper install -y$missing" ;;
        esac
        exit 1
    fi
}

preflight_checks () {
    if [[ ! "$POD_WAIT_TIMEOUT" =~ ^[0-9]+$ || "$POD_WAIT_TIMEOUT" -lt 1 ]]; then
        echo "Error: POD_WAIT_TIMEOUT must be a whole number of seconds, 1 or more, not '$POD_WAIT_TIMEOUT'."
        exit 1
    fi
    local cmds="tar gzip awk sed grep"
    if [[ $AIR_GAPPED_MODE -eq 0 ]]; then
        cmds="$cmds curl"
    fi
    if [[ $REGISTRY_MODE -eq 1 ]]; then
        cmds="$cmds openssl"
    fi
    # The built-in ingress controller uses hostPorts, which the CNI's portmap plugin sets up with the host's iptables.
    # Without it the controller stays in ContainerCreating and the install times out. An agent can't tell whether its
    # cluster runs the ingress, so it only warns.
    if [[ ( $INSTALL_MODE -eq 1 && $INSTALL_TYPE == "rke2" ) || $JOIN_MODE -eq 1 ]]; then
        if [[ ${INSTALL_INGRESS,,} == "true" && $JOIN_TYPE != "agent" ]]; then
            cmds="$cmds iptables"
        elif ! command -v iptables >/dev/null 2>&1; then
            echo "  WARNING: iptables isn't installed. Pods that use a hostPort, such as the built-in ingress controller, can't start on this node without it."
        fi
    fi
    # shellcheck disable=SC2086
    require_cmds $cmds
}

# fetch_helper <dest> <url> <ref> [sha256]: a helper script at a given ref (spec 12, as Harbor does). A copy is reused
# only when the .ref file beside it names the same ref; any other copy is fetched again. A failed download or a
# checksum mismatch leaves no file behind.
fetch_helper () {
    local dest=$1 url=$2 ref=$3 sha=${4:-} ref_file
    ref_file="$(dirname "$dest")/.$(basename "$dest").ref"
    if [[ -s "$dest" && "$(cat "$ref_file" 2>/dev/null)" == "$ref" ]]; then
        return 0
    fi
    echo "  Downloading $(basename "$dest") ($ref)..."
    if ! curl -fsSL "$url" -o "$dest.tmp"; then
        rm -f "$dest.tmp"
        echo "Error: failed to download $url"
        return 1
    fi
    if [[ -n "$sha" ]] && ! echo "$sha  $dest.tmp" | sha256sum -c --status; then
        rm -f "$dest.tmp"
        echo "Error: $(basename "$dest") from $url doesn't match IMAGE_PULL_PUSH_SHA256."
        return 1
    fi
    mv "$dest.tmp" "$dest"
    chmod +x "$dest"
    printf '%s\n' "$ref" > "$ref_file"
}

image_pull_push_check () {
    local dest=$WORKING_DIR/rke2-utilities/image_pull_push.sh
    mkdir -p "$WORKING_DIR/rke2-utilities"
    # A bundle uses the copy it brought, and an air-gapped run must never reach the download
    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        [[ -s "$dest" ]] && return 0
        echo "Error: air-gapped, but $dest isn't here. Extract the whole rke2-save.tar.gz in this folder."
        exit 1
    fi
    fetch_helper "$dest" "$IMAGE_PULL_PUSH_URL" "$IMAGE_PULL_PUSH_REF" "$IMAGE_PULL_PUSH_SHA256" || exit 1
}

check_namespace_pods_ready() {
  # check_namespace_pods_ready [namespace]: kube-system by default. Deletes completed pods, then waits up to
  # POD_WAIT_TIMEOUT seconds for every pod to be ready. Readiness is checked before the deadline, so a namespace that
  # is ready at the deadline passes. On a timeout it names the pods that aren't ready in NOT_READY_PODS and on the
  # console, and returns 1 (matches the ap-tools copy); callers decide fail-hard vs warn-and-continue.
  local ns=${1:-"kube-system"} timeout_seconds=$POD_WAIT_TIMEOUT
  local start_time elapsed_time completed_pods pod_name pods not_ready list_error
  NOT_READY_PODS=""
  start_time=$(date +%s) || true
  while true; do
    completed_pods=$(kubectl get pods -n "$ns" --field-selector status.phase=Succeeded -o name 2>/dev/null) || true
    echo "  Checking pod status in $ns namespace..."
    for pod_name in $completed_pods; do
      kubectl delete -n "$ns" "$pod_name" --ignore-not-found
    done
    # A failed listing isn't a ready namespace. Only stdout is the listing: kubectl's stderr carries "No resources
    # found" and API discovery warnings, which aren't pods.
    list_error=""
    if pods=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null); then
      not_ready=$(awk 'NF {split($2, r, "/"); if (r[1] != r[2]) print}' <<< "$pods") || true
    else
      pods=$(kubectl get pods -n "$ns" --no-headers 2>&1 >/dev/null) || true
      list_error="the pods in $ns can't be listed: ${pods//$'\n'/ }"
      not_ready=$list_error
    fi
    if [[ -z "$not_ready" ]]; then
      break
    fi
    elapsed_time=$(($(date +%s) - start_time))
    if [ "$elapsed_time" -ge "$timeout_seconds" ]; then
      kubectl get pods -A || true
      if [[ -n "$list_error" ]]; then
        NOT_READY_PODS="($list_error)"
        echo "Error: after ${timeout_seconds}s (POD_WAIT_TIMEOUT), $list_error" >&2
      else
        NOT_READY_PODS=$(awk '{printf "%s%s (%s, %s)", sep, $1, $3, $2; sep = ", "}' <<< "$not_ready")
        local count
        count=$(wc -l <<< "$not_ready")
        if [[ $count -eq 1 ]]; then
          echo "Error: 1 pod in $ns wasn't ready after ${timeout_seconds}s (POD_WAIT_TIMEOUT):" >&2
        else
          echo "Error: $count pods in $ns weren't ready after ${timeout_seconds}s (POD_WAIT_TIMEOUT):" >&2
        fi
        awk '{printf "  %-60s %-6s %s, %s old\n", $1, $2, $3, $5}' <<< "$not_ready" >&2
      fi
      return 1
    fi
    if [[ -n "$list_error" ]]; then
      echo "  - Waiting: $list_error"
    else
      echo "  - Waiting on $(wc -l <<< "$not_ready") pods..."
    fi
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
    local GREEN NC
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

# When sourced by a test harness, stop here: only the functions above are wanted.
if [[ "${BASH_SOURCE[0]:-$0}" != "$0" ]]; then
  return 0
fi

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
        echo "Error: registry info must be a valid FQDN or IPv4 format. i.e. 'my.registry.com:443'."
        exit 1
    fi
    REG_FQDN=$(echo "$REGISTRY_INFO" | cut -d':' -f1)
    REG_PORT=$(echo "$REGISTRY_INFO" | cut -d':' -f2)
    if [[ ! ( "$REG_FQDN" =~ $fqdn_pattern || "$REG_FQDN" =~ $ipv4_pattern ) ]]; then
        echo "Error: Registry url must be a valid FQDN or IPv4 format. i.e. 'my.registry.com' or '192.168.1.50'."
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
if [[ -f $base_dir/rke2-save-version.txt ]]; then
    if [[ ${RKE2_FORCE_ONLINE,,} == "true" ]]; then
        echo "NOTE: rke2-save-version.txt is in $base_dir, but RKE2_FORCE_ONLINE=true: staying online."
    else
        AIR_GAPPED_MODE=1
        # An install, join or push from a bundle needs the bundle's files. Without them, say so now, instead of
        # failing later on a missing archive. uninstall and a rebuilding save don't need them.
        if [[ ( $INSTALL_MODE -eq 1 && $INSTALL_TYPE == "rke2" ) || $JOIN_MODE -eq 1 || ( $PUSH_MODE -eq 1 && $SAVE_MODE -eq 0 ) ]] \
           && [[ ! -f $WORKING_DIR/rke2-binaries/rke2.linux-amd64.tar.gz ]]; then
            echo "Error: $base_dir has rke2-save-version.txt, so this run is air-gapped, but there is no extracted bundle"
            echo "  in $WORKING_DIR. Extract rke2-save.tar.gz here again, delete the stale rke2-save-version.txt,"
            echo "  or set RKE2_FORCE_ONLINE=true to install online."
            exit 1
        fi
    fi
fi

os_check
preflight_checks
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