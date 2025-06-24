#!/bin/bash

# --- USER DEFINED VARIABLES SECTION --- #
DEBUG=true
K8S_DNS_UTILITY=true
DOCKER_UTILITY=true
DOCKER_BRIDGE_CIDR=172.30.0.1/16
ZIP_UTILITY=true
JQ_UTILITY=true

# Supply extra sysctl parameters if required by your application, note that standard kubernetes are already applied, including CIS if enabled
EXTRA_SYSCTL_PARAMS=(
  "fs.inotify.max_queued_events = 32768"
  "fs.inotify.max_user_instances = 1024"
  "fs.inotify.max_user_watches = 1048576"
)

# RKE2 Install Parameters (If INSTALL_INGRESS=false, then Metallb LoadBalancer will be installed)
RKE2_VERSION=v1.33.1+rke2r1
CNI_TYPE=canal
ENABLE_CIS=false
CLUSTER_CIDR=172.28.175.0/24
SERVICE_CIDR=172.28.176.0/24
INSTALL_INGRESS=false
METALLB_VERSION=v0.15.2
INSTALL_LOCALPATH_STORAGE=true
HELM_VERION=v3.18.2

# Helm Chart Parameters (Helm runs as "helm upgrade --install $CHART_NAME $OCI_URL --version $CHART_VERSION -n $NAMESPACE $CHART_INSTALL_ARGS")
CHART_NAME=native-edge-orchestrator
OCI_URL=oci://public.ecr.aws/dell/nativeedge/native-edge-orchestrator
CHART_VERSION=3.1.0-0-58
NAMESPACE=dell-automation
INGRESS_FQDN=rke2.local.edge
CHART_INSTALL_ARGS="--set global.ingress.fqdn=$INGRESS_FQDN --wait --timeout 60m"
pre_helm_install_cmds=(
  "kubectl create namespace $NAMESPACE"
  "kubectl label namespace $NAMESPACE hzp.iam.webhook/active="true" --overwrite"
)
post_helm_install_cmds=(
  "echo 'Dell Orchestrator URL: https://$INGRESS_FQDN'"
  "echo 'Dell Orchestrator Username: administrator'"
  "echo 'Dell Orchesator default password:' \$(kubectl -n \"$NAMESPACE\" get secret keycloak-secret -o jsonpath=\"{.data.security-admin-usr-pwd}\" | base64 --decode)"
)

# Offline Prep Parameters

OFFLINE_APT_PACKAGES=(zip jq open-iscsi zstd docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)

# --- INTERNAL VARIABLES (do not edit) --- #
base_dir=$(pwd)
os_release_version=$(lsb_release -ds |tail -1)
os_release_version_short=$(lsb_release -rs |tail -1)
mgmt_ip=$(hostname -I | awk '{print $1}')
mgmt_if=$(ip a |grep "$(hostname -I |awk '{print $1}')" | awk '{print $NF}')
user_name=$SUDO_USER
offline_prep_done=false

export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
export PATH=$PATH:/var/lib/rancher/rke2/bin

# --- FUNCTIONS --- #

# MENU FUNCTIONS #
function install_rke2() {
  check_os_version
  [ ! -f $base_dir/rke2-install-files/VERSION.txt ] || echo "Installing from offline package..."
  [ $ENABLE_CIS == false ] || echo "Installing RKE2 with CIS profile enabled"
  debug_run set_prereqs
  debug_run start_rke2_server
  check_namespace_pods_ready
  debug_run load_extra_images
  debug_run apply_services
  [ $INSTALL_LOCALPATH_STORAGE == false ] || check_namespace_pods_ready
  [ $INSTALL_INGRESS == true ] || check_namespace_pods_ready metallb-system
  debug_run set_service_config
  debug_run install_helm
  run_utilities
  echo "RKE2 installation workflow completed..."
  echo "Displaying cluster status..."
  kubectl get nodes -o wide
  kubectl get pods -A
  echo ""
  echo "Type: 'source ~/.bashrc' to enable kubectl in this shell session"
  #  add function to generate server join token and/or kube auth credentials
}

function uninstall_rke2() {
  echo "Uninstalling RKE2"
  debug_run /usr/local/bin/rke2-uninstall.sh
  rm -rf $base_dir/rke2-install-files
  rm -rf $base_dir/.kube
  rm -rf /root/.kube
  # Clean up the KUBECONFIG and PATH from the global environment if they were set here
  unset KUBECONFIG
  # Restore original PATH if possible, or just remove the RKE2 bin path
  PATH=$(echo $PATH | sed -e "s|:/var/lib/rancher/rke2/bin||g")
  echo "Completed..."
}

function rke2_offline_prep() {
  echo "Preparing an offline package"
  [ -d "$base_dir/rke2-install-files/apt-packages" ] || mkdir -p "$base_dir/rke2-install-files/apt-packages"
  debug_run apt_get_install dpkg-dev
  debug_run install_docker_utility
  cd $base_dir/rke2-install-files/apt-packages
  debug_run apt_download_packs
  debug_run download_service_images
  debug_run download_extra_binaries
  debug_run download_rke2_zst
  debug_run prepare_offline_package
  echo "Offline package generation completed..."
  echo "Upload rke2-offline-package.tar.gz to your airgapped system running $os_release_version"
}

function install_helm_chart() {
  echo "Installing Helm chart $CHART_NAME version $CHART_VERSION under namespace $NAMESPACE"
  local pre_install_cmds=$pre_helm_install_cmds
  run_helm_pre_install_cmds "${pre_install_cmds[@]}"
  debug_run start_helm_chart
  echo "Helm Chart finished, listing pods..."
  kubectl get pods -n $NAMESPACE
  local post_install_cmds=$post_helm_install_cmds
  run_helm_post_install_cmds "${post_install_cmds[@]}"
}


# --- Installation functions --- #

function load_extra_images() {
  if [ -f $base_dir/rke2-install-files/VERSION.txt ]; then
    echo "Loading utility and service images from offline package..."
    /var/lib/rancher/rke2/bin/ctr --address /run/k3s/containerd/containerd.sock --namespace k8s.io image import $base_dir/rke2-install-files/utility-images/utility_images.tar.gz
  fi
}

function run_utilities() {
  if [ $K8S_DNS_UTILITY == true ]; then
    echo "Installing K8s DNS Utility pod in default namespace..."
    debug_run install_k8s_dns_utility
    check_namespace_pods_ready default
    echo "Completed..."
    kubectl exec -i -t dnsutils -- nslookup kube-dns.kube-system.svc.cluster.local
    echo "Usage example: kubectl exec -i -t dnsutils -- nslookup <FQDN>"
  fi
  if [ -f $base_dir/rke2-install-files/VERSION.txt ]; then
    echo "deb [trusted=yes] file:$base_dir/rke2-install-files/apt-packages ./" | tee -a /etc/apt/sources.list.d/extra-packages.list
    echo "Backing up original apt sources for offline installation..."
    mv /etc/apt/sources.list /etc/apt/sources.list.bak
    [ $os_release_version_short = "22.04" ] || mv /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.bak
    [ ! -f /etc/apt/sources.list.d/docker.list ] || mv /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.list.bak
  fi
  if [ $DOCKER_UTILITY == true ]; then
    echo "Installing Docker Utility..."
    debug_run install_docker_utility
    echo "Completed..."
    echo "Reload the shell to enable docker cli access or run as sudo/root user"
  fi
  if [ $ZIP_UTILITY == true ]; then
    echo "Installing zip utility..."
    debug_run apt_get_install zip
    echo "Completed..."
  fi
  if [ $JQ_UTILITY == true ]; then
    echo "Installing jq utility..."
    debug_run apt_get_install jq
    echo "Completed..."
  fi
  if [ -f $base_dir/rke2-install-files/VERSION.txt ]; then
    echo "Reverting apt sources..."
    mv /etc/apt/sources.list.bak /etc/apt/sources.list
    [ $os_release_version_short = "22.04" ] || mv /etc/apt/sources.list.d/ubuntu.sources.bak /etc/apt/sources.list.d/ubuntu.sources
    [ ! -f /etc/apt/sources.list.d/docker.list.bak ] || mv /etc/apt/sources.list.d/docker.list.bak /etc/apt/sources.list.d/docker.list
    rm /etc/apt/sources.list.d/extra-packages.list
  fi
}

function install_k8s_dns_utility() {
cat > $base_dir/rke2-install-files/dnsutils.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: dnsutils
  namespace: default
spec:
  containers:
  - name: dnsutils
    image: registry.k8s.io/e2e-test-images/agnhost:2.39
    imagePullPolicy: IfNotPresent
  restartPolicy: Always
EOF
kubectl apply -f $base_dir/rke2-install-files/dnsutils.yaml
}

function install_docker_utility() {
  if [ ! -f $base_dir/rke2-install-files/VERSION.txt ]; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  fi
  apt-get update
  create_bridge_json
  echo "" | DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  usermod -aG docker $user_name
}

function create_bridge_json () {
  echo "pre-creating docker bridge json..."
  mkdir -p /etc/docker
  cat <<EOF | tee /etc/docker/daemon.json > /dev/null
{
  "bip": "$DOCKER_BRIDGE_CIDR"
}
EOF
  echo "Created /etc/docker/daemon.json with bip: $DOCKER_BRIDGE_CIDR"
}

function set_prereqs() {
  mkdir -p /etc/rancher/rke2
  mkdir -p /var/lib/rancher/rke2/server/manifests
  [ -d "$base_dir/rke2-install-files" ] || mkdir -p "$base_dir/rke2-install-files"
  gen_modules_params
  gen_k8s_params
  gen_rke2_params
  gen_extra_sysctl_params
  gen_rke2_bootstrap
  gen_rke2_coredns_helmchartconfig
  gen_metallb_ipaddresspool
  gen_metallb_l2advertisement
  modprobe -a overlay br_netfilter
  systemctl restart systemd-sysctl
  if [ $? -ne 0 ]; then
    echo "Error: systemd-sysctl.service failed to restart. Exiting script."
    exit 1 
  else
    echo "systemd-sysctl.service restarted successfully."
  fi
  swapoff -a
  sed -i -e '/swap/d' /etc/fstab
  systemctl stop ufw
  systemctl disable ufw
}

function start_rke2_server() {
  echo "Installing RKE2 version $RKE2_VERSION..."
  if [ -f $base_dir/rke2-install-files/VERSION.txt ]; then
    cp $base_dir/rke2-install-files/*tar.zst /var/lib/rancher/rke2/agent/images/
    INSTALL_RKE2_ARTIFACT_PATH=$base_dir/rke2-install-files sh $base_dir/rke2-install-files/install.sh
  else
    curl -sfL https://get.rke2.io | sudo -E INSTALL_RKE2_VERSION="$RKE2_VERSION" sh -
  fi
  if [ $ENABLE_CIS == true ]; then
    echo "Copying CIS sysctl file to /etc/sysctl.d/60-rke2-cis.conf"
    cp -f /usr/local/share/rke2/rke2-cis-sysctl.conf /etc/sysctl.d/60-rke2-cis.conf
    useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
    systemctl restart systemd-sysctl
    if [ $? -ne 0 ]; then
      echo "Error: systemd-sysctl.service failed to restart. Exiting script."
      exit 1 
    else
      echo "systemd-sysctl.service restarted successfully."
    fi
  fi
  echo "Enabling and starting rke2-server service..."
  systemctl enable rke2-server.service
  systemctl start rke2-server.service
  if [ $? -ne 0 ]; then
    echo "Error: rke2-server.service failed to start. Exiting script."
    exit 1 
  else
    echo "rke2-server.service started successfully."
  fi
  echo "Waiting for pods to start..."
  sleep 15 
  mkdir -p /home/$user_name/.kube && mkdir -p /root/.kube
  cp /etc/rancher/rke2/rke2.yaml /home/$user_name/.kube/config && cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
  chown $user_name:$user_name /home/$user_name/.kube/config
  chmod 600 /home/$user_name/.kube/config &&chmod 600 /root/.kube/config
  echo "export KUBECONFIG=/home/$user_name/.kube/config" >> /home/$user_name/.bashrc
  echo "export PATH=\$PATH:/var/lib/rancher/rke2/bin" >> /home/$user_name/.bashrc
  echo 'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/var/lib/rancher/rke2/bin"' | sudo tee /etc/sudoers.d/rke2-path
}

function apply_services(){
  if [ $INSTALL_LOCALPATH_STORAGE == true ]; then
    gen_localpath_storage
    kubectl apply -f $base_dir/rke2-install-files/local-path-storage.yaml
  fi
  if [ $INSTALL_INGRESS == false ]; then
    if [ -f $base_dir/rke2-install-files/VERSION.txt ]; then
      kubectl apply -f $base_dir/rke2-install-files/extra-binaries/metallb-native.yaml
    else
      kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/$METALLB_VERSION/config/manifests/metallb-native.yaml
    fi
  fi
}

function set_service_config() {
  if [ $INSTALL_LOCALPATH_STORAGE == true ]; then
    kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
  fi
  if [ $INSTALL_INGRESS == false ]; then
    kubectl apply -f $base_dir/rke2-install-files/metallb-ipaddresspool.yaml
    kubectl apply -f $base_dir/rke2-install-files/metallb-l2advertisement.yaml
  fi
}

function install_helm() {
  if [ -f $base_dir/rke2-install-files/VERSION.txt ]; then
    tar xzvf $base_dir/rke2-install-files/extra-binaries/helm-$HELM_VERION-linux-amd64.tar.gz -C $base_dir/rke2-install-files/extra-binaries/
  else
    mkdir -p $base_dir/rke2-install-files/extra-binaries
    curl https://get.helm.sh/helm-$HELM_VERION-linux-amd64.tar.gz -o $base_dir/rke2-install-files/extra-binaries/helm-$HELM_VERION-linux-amd64.tar.gz
    tar xzvf $base_dir/rke2-install-files/extra-binaries/helm-$HELM_VERION-linux-amd64.tar.gz -C $base_dir/rke2-install-files/extra-binaries/
  fi
  cp $base_dir/rke2-install-files/extra-binaries/linux-amd64/helm /usr/local/bin/helm
}

function create_namespace() {
  kubectl create namespace $NAMESPACE
  kubectl label namespace $NAMESPACE hzp.iam.webhook/active="true" --overwrite
}

function start_helm_chart() {
  local helm_cmd="upgrade --install $CHART_NAME $OCI_URL --version $CHART_VERSION -n $NAMESPACE $CHART_INSTALL_ARGS"
  echo "Helm Command:"
  echo "helm $helm_cmd"
  helm $helm_cmd
  helm list -n $NAMESPACE
}

function run_helm_pre_install_cmds() {
  echo "Running pre install commands..."   
  for cmd in "${pre_helm_install_cmds[@]}"; do
    eval "$cmd"
  done
  if [ $ENABLE_CIS == true ]; then
    gen_cis_account_update
    echo "Running CIS service account patch for default account..."
    kubectl patch serviceaccount default -n $NAMESPACE -p "$(cat $base_dir/rke2-install-files/account_update.yaml)"
    echo "Completed..."
  fi
}

function run_helm_post_install_cmds() {
  echo "Running post install commands..."
  for cmd in "${post_helm_install_cmds[@]}"; do
    eval "$cmd"
  done
  echo "Completed..."
}

# --- Offline Prep functions --- #

function apt_download_packs () {
    echo "Downloading "${OFFLINE_APT_PACKAGES[*]}" ..."
    apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances --no-pre-depends ${OFFLINE_APT_PACKAGES[*]} | grep "^\w")
    dpkg-scanpackages -m . > Packages
    echo "Completed downloading..."
}

function download_service_images() {
  #Downloads container images for metallb, local-path-storage, dnsutils
    local images=(
        "rancher/local-path-provisioner:v0.0.31"
        "public.ecr.aws/docker/library/busybox:stable"
        "quay.io/metallb/speaker:$METALLB_VERSION"
        "quay.io/metallb/controller:$METALLB_VERSION"
        "registry.k8s.io/e2e-test-images/agnhost:2.39"
    )
    echo "Starting Docker image pull and save process..."
    [ -d "$base_dir/rke2-install-files/utility-images" ] || mkdir -p "$base_dir/rke2-install-files/utility-images"
    local output_dir="$base_dir/rke2-install-files/utility-images"
    # Loop through each image to pull them first, ensuring they are available locally
    for image in "${images[@]}"; do
        echo ""
        echo "Pulling image: $image..."
        if docker pull "$image"; then
            echo "Successfully pulled: $image"
        else
            echo "Error: Failed to pull image: $image. Skipping to next image."
            continue
        fi
    done
    echo "Image pull completed"
    # save all images to a single tar.gz
    local utility_images_filename="utility_images.tar.gz"
    local utility_images_save_path="$output_dir/$utility_images_filename"
    echo "Saving all pulled images to a single file: '$utility_images_filename'..."
    if docker save "${images[@]}" | gzip > "$utility_images_save_path"; then
        echo "Successfully saved all images to: $utility_images_save_path"
    else
        echo "Error: Failed to save all images to a single file."
        echo "Please check Docker daemon status and permissions."
    fi
    echo "Docker image pull and save process completed."
}

function download_extra_binaries() {
  echo "Downloading Helm $HELM_VERION..."
  mkdir -p $base_dir/rke2-install-files/extra-binaries
  cd $base_dir/rke2-install-files/extra-binaries
  curl -OL https://get.helm.sh/helm-$HELM_VERION-linux-amd64.tar.gz
  echo "Downloading MetalLB manifest version $METALLB_VERSION..."
  curl -OL https://raw.githubusercontent.com/metallb/metallb/$METALLB_VERSION/config/manifests/metallb-native.yaml
}

function download_rke2_zst() {
  echo "Downloading RKE2 air-gapped package..."
  if [[ $CNI_TYPE != "canal" && $CNI_TYPE != "calico" ]]; then
    echo "CNI must be either canal or calico"
    exit 1
  fi
  cd $base_dir/rke2-install-files
  # v1.33.1%2Brke2r1 | v1.33.1+rke2r1
  local translated_version=$(echo $RKE2_VERSION | sed 's/+/%2B/')
  curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/rke2-images-core.linux-amd64.tar.zst
  curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/rke2-images-core.linux-amd64.txt
  curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/rke2.linux-amd64.tar.gz
  curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/sha256sum-amd64.txt
  curl -sfL https://get.rke2.io --output install.sh
  # if cni = cannal
  if [[ $CNI_TYPE == "canal" ]]; then
    curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/rke2-images-canal.linux-amd64.tar.zst
    curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/rke2-images-canal.linux-amd64.txt
  fi
  # if cni = calico
  if [[ $CNI_TYPE == "calico" ]]; then
    curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/rke2-images-calico.linux-amd64.tar.zst
    curl -OL https://github.com/rancher/rke2/releases/download/$translated_version/rke2-images-calico.linux-amd64.txt
  fi
}

function prepare_offline_package() {
  echo "Generating offline archive..."
  cd $base_dir
  echo "Offline package generated on $(date) for $os_release_version and RKE2 version $RKE2_VERSION" | tee $base_dir/rke2-install-files/VERSION.txt
  tar czvf rke2-offline-package.tar.gz rke2-install-files/ install_rke2.sh
}

# --- GENERIC HELPER FUNCTIONS --- #

function apt_get_install() {
  echo "Installing $1..."
  apt-get update
  # Add a check for successful update before installing
  if [ $? -ne 0 ]; then
    echo "ERROR: apt-get update failed."
    return 1 # Indicate failure
  fi
  echo "" | DEBIAN_FRONTEND=noninteractive apt-get -y -qq install "$1"
  # Check for successful install
  if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install $1."
    return 1 # Indicate failure
  fi
  echo "$1 installed successfully."
  return 0 # Indicate success
}

function check_namespace_pods_ready() {
  local timeout_seconds=120
  local start_time=$(date +%s)
  local ns=$1
  if [ -z "$1" ]; then
    local ns="kube-system"
  fi
  while true; do
    local completed_pods=$(kubectl get pods -n $ns --field-selector status.phase=Succeeded -o name)
    echo "Checking pod status and removing Completed pods in $ns namespace..."
    for pod_name in $completed_pods; do
      kubectl delete -n $ns "$pod_name"
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
    echo "Wating on $current_pods_not_ready pods..."
    echo "Elapsed: ${elapsed_time}s/${timeout_seconds}s"
    sleep 10
  done
  echo "All pods are ready in $ns namespace!"
  return 0
}

function check_os_version() {
  if [[ $os_release_version_short = "22.04" || $os_release_version_short = "24.04" ]]; then
    return 0
  else
    echo "This script is only compatible with Ubuntu 22.04 and 24.04 server LTS."
    exit 1
  fi
}

function check_root_privileges() {
  if [[ $EUID != 0 ]]; then
    echo "This script must be run with sudo or as the root user."
    exit 1
  fi
}


function debug_run() {
  # Check the value of the global DEBUG variable
  if [ "$DEBUG" = "true" ]; then
    # If DEBUG is true, execute the command/function normally.
    # All stdout and stderr will be displayed to the console.
    echo "--- DEBUG: Running '$*' ---"
    "$@"
    local status=$? # Capture the exit status of the executed command
    echo "--- DEBUG: Finished '$*' with status $status ---"
    return $status # Return the original command's exit status
  else
    echo "Running '$*'..."
    # If DEBUG is false, execute the command/function and redirect
    # all standard output (1) and standard error (2) to /dev/null.
    # This effectively suppresses all output.
    "$@" > /dev/null 2>&1
    return $? # Return the original command's exit status
  fi
}

# --- FILE GENERATION FUNCTIONS --- #

function gen_modules_params() {
  cat > /etc/modules-load.d/40-k8s.conf <<EOF
overlay
br_netfilter
EOF
}

function gen_k8s_params() {
  echo "Generating /etc/sysctl.d/40-k8s.conf"
  cat > /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
}

function gen_rke2_params() {
  echo "Generating /etc/sysctl.d/50-rke2-config.conf"
  cat > /etc/sysctl.d/rke2-cis.conf <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.printk = 3 4 1 3
EOF
}


function gen_extra_sysctl_params() {
    echo "Checking global EXTRA_SYSCTL_PARAMS list..."
    # Check if the global list is empty
    if [ ${#EXTRA_SYSCTL_PARAMS[@]} -eq 0 ]; then
        echo "Global EXTRA_SYSCTL_PARAMS list is empty. No configuration file will be generated."
        return 0 # Return 0 for success as it's an expected condition
    fi
    local config_file="/etc/sysctl.d/30-extra.conf"
    echo "Generating ${config_file}"
    # Loop through each parameter in the global array and append to the file
    for param in "${EXTRA_SYSCTL_PARAMS[@]}"; do
        echo "$param" >> "${config_file}"
    done
}

function gen_rke2_bootstrap() {
  echo "Generating /etc/rancher/rke2/config.yaml"
  cat > /etc/rancher/rke2/config.yaml <<EOF
cni: "$CNI_TYPE"
write-kubeconfig-mode: "0600"
service-node-port-range: "443-40000"
cluster-cidr: "$CLUSTER_CIDR"
service-cidr: "$SERVICE_CIDR"
etcd-extra-env:
  - "ETCD_AUTO_COMPACTION_RETENTION=72h"
  - "ETCD_AUTO_COMPACTION_MODE=periodic"
kubelet-arg:
  - "max-pods=200"
  - "resolv-conf=/run/systemd/resolve/resolv.conf"
kube-apiserver-arg:
  - "audit-log-path=/var/log/rke2-apiserver-audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=10"
  - "audit-log-maxsize=200"
  - "service-cluster-ip-range=$SERVICE_CIDR"
EOF
if [ $INSTALL_INGRESS == false ]; then
  cat >> /etc/rancher/rke2/config.yaml <<EOF
disable:
  - rke2-ingress-nginx
EOF
fi
if [ $ENABLE_CIS == true ]; then
  cat >> /etc/rancher/rke2/config.yaml <<EOF
profile: "cis"
EOF
fi
}

function gen_cis_account_update() {
  echo "Generating $base_dir/rke2-install-files/account_update.yaml"
  cat > $base_dir/rke2-install-files/account_update.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
automountServiceAccountToken: false
EOF
}

function gen_rke2_coredns_helmchartconfig() {
  echo "Generating /var/lib/rancher/rke2/server/manifests/rke2-coredns-helmchartconfig.yaml"
  cat > /var/lib/rancher/rke2/server/manifests/rke2-coredns-helmchartconfig.yaml <<EOF
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

function gen_metallb_ipaddresspool() {
  echo "Generating $base_dir/rke2-install-files/metallb-ipaddresspool.yaml"
  cat > $base_dir/rke2-install-files/metallb-ipaddresspool.yaml <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: default
  namespace: metallb-system
spec:
  addresses:
  - $mgmt_ip/32
EOF
}

function gen_metallb_l2advertisement() {
  echo "Generating $base_dir/rke2-install-files/metallb-l2advertisement.yaml"
  cat > $base_dir/rke2-install-files/metallb-l2advertisement.yaml <<EOF
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  namespace: metallb-system
  name: default
spec:
  ipAddressPools:
  - default
  interfaces:
  - $mgmt_if
EOF
}

function gen_localpath_storage(){
  echo "Generating $base_dir/rke2-install-files/local-path-storage.yaml"
  cat > $base_dir/rke2-install-files/local-path-storage.yaml <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: local-path-storage

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: local-path-provisioner-service-account
  namespace: local-path-storage

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: local-path-provisioner-role
  namespace: local-path-storage
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: local-path-provisioner-role
rules:
  - apiGroups: [""]
    resources: ["nodes", "persistentvolumeclaims", "configmaps", "pods", "pods/log"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: local-path-provisioner-bind
  namespace: local-path-storage
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: local-path-provisioner-role
subjects:
  - kind: ServiceAccount
    name: local-path-provisioner-service-account
    namespace: local-path-storage

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: local-path-provisioner-bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: local-path-provisioner-role
subjects:
  - kind: ServiceAccount
    name: local-path-provisioner-service-account
    namespace: local-path-storage

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: local-path-provisioner
  namespace: local-path-storage
spec:
  replicas: 1
  selector:
    matchLabels:
      app: local-path-provisioner
  template:
    metadata:
      labels:
        app: local-path-provisioner
    spec:
      serviceAccountName: local-path-provisioner-service-account
      containers:
        - name: local-path-provisioner
          image: rancher/local-path-provisioner:v0.0.31
          imagePullPolicy: IfNotPresent
          command:
            - local-path-provisioner
            - --debug
            - start
            - --config
            - /etc/config/config.json
          volumeMounts:
            - name: config-volume
              mountPath: /etc/config/
          env:
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: CONFIG_MOUNT_PATH
              value: /etc/config/
      volumes:
        - name: config-volume
          configMap:
            name: local-path-config

---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-path
provisioner: rancher.io/local-path
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete

---
kind: ConfigMap
apiVersion: v1
metadata:
  name: local-path-config
  namespace: local-path-storage
data:
  config.json: |-
    {
            "nodePathMap":[
            {
                    "node":"DEFAULT_PATH_FOR_NON_LISTED_NODES",
                    "paths":["/opt/local-path-provisioner"]
            }
            ]
    }
  setup: |-
    #!/bin/sh
    set -eu
    mkdir -m 0777 -p "\$VOL_DIR"
  teardown: |-
    #!/bin/sh
    set -eu
    rm -rf "\$VOL_DIR"
  helperPod.yaml: |-
    apiVersion: v1
    kind: Pod
    metadata:
      name: helper-pod
    spec:
      priorityClassName: system-node-critical
      tolerations:
        - key: node.kubernetes.io/disk-pressure
          operator: Exists
          effect: NoSchedule
      containers:
      - name: helper-pod
        image: public.ecr.aws/docker/library/busybox:stable
        imagePullPolicy: IfNotPresent
EOF
}


# --- Main Menu function --- #

function help {
  echo "########################################################################"
  echo "###                     Ubuntu Devapps RKE2 Installer                ###"
  echo "########################################################################"
  echo "Usage: $0 [parameter]"
  echo ""
  echo "[Parameters]            | [Description]"                   
  echo "help                    | Display this help message"
  echo "install-server          | Installs RKE2 from the internet or offline package"
  echo "uninstall-server        | Uninstalls RKE2"
  echo "offline-prep            | Prepares an offline package"
  echo "install-helm-chart      | Installs helm chart from variables"
}

# Start CLI Wrapper
while [[ $# -gt 0 ]]; do
  case "$1" in
    help)
      help
      exit 0
      ;;
    install-server)
      check_root_privileges
      echo "###########################################"
      echo "###  RKE2 Cluster Installation Started  ###"
      echo "###########################################"
      install_rke2
      exit 0
      ;;
    uninstall-server)
      check_root_privileges
      echo "############################################"
      echo "###  RKE2 Cluster Uninstallation Started ###"
      echo "############################################"
      uninstall_rke2
      exit 0
      ;;
    offline-prep)
      check_root_privileges
      echo "##########################################"
      echo "###  RKE2 Offline preparation Started  ###"
      echo "##########################################"
      rke2_offline_prep
      exit 0
      ;;
    install-helm-chart)
      check_root_privileges
      echo "###################################################################"
      echo "###  Helm Chart Installation Started ###"
      echo "###################################################################"
      install_helm_chart
      exit 0
      ;;

    *)
      echo "Invalid option: $1"
      help
      exit 1
      ;;
  esac
  shift
done

help
# End CLI Wrapper