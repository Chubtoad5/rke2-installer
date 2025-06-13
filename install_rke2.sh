#!/bin/bash

# USER DEFINED VARIABLES
DEBUG=false
AIRGAPPED=false
RKE2_VERSION=v1.30.13+rke2r1
CNI_TYPE=canal
CLUSTER_CIDR=172.28.175.0/24
SERVICE_CIDR=172.28.176.0/24
INSTALL_INGRESS=false
INSTALL_LOCALPATH_STORAGE=true

METALLB_VERSION=v0.15.2
HELM_VERION=v3.12.3
NAMESPACE=dell-automation
CHART_NAME=native-edge-orchestrator
OCI_URL=oci://public.ecr.aws/dell/nativeedge/native-edge-orchestrator
CHART_VERSION=3.1.0-0-58
INGRESS_FQDN=$(hostname).local.edge
TIMEOUT=60m

# INTERNAL VARIABLES (do not edit)
base_dir=$(pwd)
os_release_version=$(lsb_release -ds |tail -1)
os_release_version_short=$(lsb_release -rs |tail -1)
mgmt_ip=$(hostname -I | awk '{print $1}')
mgmt_if=$(ip a |grep "$(hostname -I |awk '{print $1}')" | awk '{print $NF}')
user_name=$SUDO_USER
offline_prep_done=false

# FUNCTIONS
function install_rke2() {
  check_os_version
  if [ "$AIRGAPPED" = "true" ]; then
    # add check for airgapped packages
    echo "Installing RKE2 from airgapped packages"
  else
    echo "Installing RKE2 from the internet"
  fi
  debug_run set_prereqs
  debug_run start_rke2_server
  check_namespace_pods_ready
  debug_run apply_services
  if [ $INSTALL_LOCALPATH_STORAGE == true ]; then
    check_namespace_pods_ready
  fi
  if [ $INSTALL_INGRESS == false ]; then
      check_namespace_pods_ready metallb-system
  fi
  debug_run set_service_config
  debug_run install_helm
  echo "RKE2 installation workflow completed..."
  echo "Displaying cluster status..."
  kubectl get nodes -o wide
  kubectl get pods -A
  #  add function to generate server join token and/or kube auth credentials
}

function uninstall_rke2() {
  echo "Uninstalling RKE2"
  debug_run /usr/local/bin/rke2-uninstall.sh
  rm -rf $base_dir/rke2-install-files
  rm -rf $base_dir/.kube
  rm -rf /root/.kube
  echo "Completed..."
}

function rke2_offline_prep() {
  echo "Preparing an offline package"
}

function install_helm_chart() {
  echo "Installing Helm chart $CHART_NAME version $CHART_VERSION under namespace $NAMESPACE"
  create_namespace
  start_helm_chart
  check_namespace_pods_ready $NAMESPACE
  get_dell_orch_details
}
function set_prereqs() {
  mkdir -p /etc/rancher/rke2
  mkdir -p /var/lib/rancher/rke2/server/manifests
  mkdir -p $base_dir/rke2-install-files
  gen_modules_params
  gen_k8s_params
  gen_rke2_cis_params
  gen_dell_orch_params
  gen_rke2_bootstrap
  gen_rke2_coredns_helmchartconfig
  gen_metallb_ipaddresspool
  gen_metallb_l2advertisement
  modprobe -a overlay br_netfilter
  sysctl --system
  swapoff -a
  sed -i -e '/swap/d' /etc/fstab
  systemctl stop ufw
  systemctl disable ufw
}

function start_rke2_server() {
  curl -sfL https://get.rke2.io | sudo -E INSTALL_RKE2_VERSION="$RKE2_VERSION" sh -
  systemctl enable rke2-server.service
  echo "Starting rke2-server service..."
  systemctl start rke2-server.service
  echo "Waiting for pods to start..."
  sleep 15
  mkdir -p /home/$user_name/.kube && mkdir -p /root/.kube
  cp /etc/rancher/rke2/rke2.yaml /home/$user_name/.kube/config && cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
  chown $user_name:$user_name /home/$user_name/.kube/config
  chmod 600 /home/$user_name/.kube/config && chmod 600 /root/.kube/config
  echo "export KUBECONFIG=/home/$user_name/.kube/config" >> /home/$user_name/.bashrc
  echo 'export PATH=$PATH:/var/lib/rancher/rke2/bin' >> /home/$user_name/.bashrc
  source /home/$user_name/.bashrc
  echo 'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/var/lib/rancher/rke2/bin"' | sudo tee /etc/sudoers.d/rke2-path
}

function apply_services(){
  if [ $INSTALL_LOCALPATH_STORAGE == true ]; then
    kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
  fi
  if [ $INSTALL_INGRESS == false ]; then
    kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/$METALLB_VERSION/config/manifests/metallb-native.yaml
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
  curl https://get.helm.sh/helm-$HELM_VERION-linux-amd64.tar.gz -o $base_dir/rke2-install-files/helm-$HELM_VERION-linux-amd64.tar.gz
  tar xzvf $base_dir/rke2-install-files/helm-$HELM_VERION-linux-amd64.tar.gz -C $base_dir/rke2-install-files/
  cp $base_dir/rke2-install-files/linux-amd64/helm /usr/local/bin/helm
}

function create_namespace() {
  kubectl create namespace $NAMESPACE
  kubectl label namespace $NAMESPACE $NAMESPACE.iam.webhook/active="true" --overwrite
}

function start_helm_chart() {
  local helm_cmd="upgrade --install $CHART_NAME $OCI_URL --version $CHART_VERSION -n $NAMESPACE --set global.ingress.fqdn=$ORCHESTRATOR_FQDN --wait --timeout $TIMEOUT"
  echo "Helm Command:"
  echo "helm $helm_cmd"
  helm $helm_cmd
}

function get_dell_orch_details() {
  local default_passwd=$(kubectl -n $NAMESPACE get secret keycloak-secret -o jsonpath="{.data.security-admin-usr-pwd}" | base64 --decode)
  local dell_orch_url="https://$INGRESS_FQDN"
  helm list -n $NAMESPACE  
  echo "Dell Orchestrator URL: $dell_orch_url"
  echo "Default Password: $default_passwd"
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

function gen_modules_params() {
  cat > /etc/modules-load.d/k8s.conf <<EOF
overlay
br_netfilter
EOF
}

function gen_k8s_params() {
  cat > /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
}

function gen_rke2_cis_params() {
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

function gen_dell_orch_params() {
  cat > /etc/sysctl.d/dell-orchestrator.conf <<EOF
fs.inotify.max_queued_events = 32768
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 1048576
EOF
}
function gen_rke2_bootstrap() {
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
}

function gen_rke2_coredns_helmchartconfig() {
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

function help {
  echo "########################################################################"
  echo "###                     Ubuntu Devapps RKE2 Installer                ###"
  echo "########################################################################"
  echo "Usage: $0 [parameter]"
  echo ""
  echo "[Parameters]            | [Description]"                   
  echo "help                    | Display this help message"
  echo "install-server          | Installs RKE2 from the internet"
  echo "uninstall-server        | Uninstalls RKE2"
  echo "offline-prep            | Prepares an offline package"
  echo "install-helm-chart      | Installs helm chart from variables"
}

#Start CLI Wrapper
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
#End CLI Wrapper