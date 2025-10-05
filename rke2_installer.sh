#!/bin/bash

# --- Script Configuration - DO NOT EDIT --- #
set -o errexit
set -o nounset
set -o pipefail

# --- USER DEFINED VARIABLES ---#
RKE2_VERSION=v1.32.5+rke2r1
CNI_TYPE=canal
ENABLE_CIS=false
CLUSTER_CIDR=10.42.0.0/16
SERVICE_CIDR=10.43.0.0/16
MAX_PODS=110
INSTALL_INGRESS=true
INSTALL_SERVICELB=true
INSTALL_LOCAL_PATH_PROVISIONER=true
LOCAL_PATH_PROVISIONER_VERSION=v0.0.32
INSTALL_DNS_UTILITY=true
DEBUG=1

# --- INTERNAL VARIABLES - DO NOT EDIT --- #
user_name=$SUDO_USER
SCRIPT_NAME=$(basename "$0")
AIR_GAPPED_MODE=0
SAVE_MODE=0
PUSH_MODE=0
INSTALL_MODE=0
TLS_SAN_MODE=0
TLS_SAN=""
UNINSTALL_MODE=0
JOIN_MODE=0
JOIN_TYPE="server"
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
fqdn_pattern='^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
ipv4_pattern='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

# --- USAGE FUNCTION --- #

usage() {
    cat << EOF
Usage: $SCRIPT_NAME [install] [unintall] [save] [push] [join [server|agent] server-fqdn join-token-string] [tls-san [server-fqdn-ip]] [registry [registry:port username password]]

- This script must be run with root privileges.
- At least one parameter of [install], [uninstall], [save], [push], or [join] must be specified. 
- When [push] is specified, [registry:port username password] must be provided. The correct project path must exist on the registry (i.e. my.registry.com:443/rancher). See README.md for details.
- When [registry [registry:port username password]] is specified with [install] or [join], rke2 will use the private registry as a mirror to pull images.
- When [join] is specified, an install type, [server-fqdn] and [join-token-string] must be provided from an existing cluster. (Comming soon!)
- When [tls-san] is specified, install and join operations will add the [server-fqdn-ip] as the tls-san of the server configuration.
- To change the default install configuration, edit $SCRIPT_NAME USER DEFINED VARIABLES before running. See README.md for details.

Commands:
  install   : Installs rke2 and dependencies from the internet as a single-node untainted server.
              If a version file is detected in the directory, rke2 will be installed from offline tar package.
  uninstall : Uninstalls rke2 from the host.
  save      : Prepares an offline tar package with all rke2 install files and dependencies.
  push      : Pushes rke2 images to the specified registry. If a on offline tar package is not found, it will first pull from the internet.
  join      : Joins the host to an existing cluster as a [server] or [agent]. [join-token-string] must be specified.

Examples:
  Install rke2 fron the internet or offline package if it exists:          
  sudo ./$SCRIPT_NAME install

  Install rke2 fron the internet or offline package if it exists, and push the rke2 images to a registry, using it as a mirror:
  sudo ./$SCRIPT_NAME install push my.registry.com:443 myusername mypassword

  Install rke2 fron the internet or offline package if it exists, and uses a private registry with existing images a mirror:
  sudo ./$SCRIPT_NAME install registry:port username password

  Push images to a private registry from an offline tar package if it exists, or pull from the internet, but do not install rke2:
  sudo ./$SCRIPT_NAME push registry:port username password

  Join the host to an existing cluster as a agent node:
  sudo ./$SCRIPT_NAME join agent [join-token-string]

  Create an offline tar package for installing rke2 later in an air-gapped environment:
  sudo ./$SCRIPT_NAME save

  Uninstall rke2 instance from the host:
  sudo ./$SCRIPT_NAME uninstall

EOF
    exit 1
}

# --- Start Argument parsing and validation --- #

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with root privileges."
   echo "Type './$SCRIPT_NAME -h' for help."
   exit 1
fi

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
        join)
            JOIN_MODE=1
            JOIN_TYPE="${2:-}"
            JOIN_SERVER_FQDN="${3:-}"
            JOIN_TOKEN="${4:-}"
            if [[ -z "$JOIN_TYPE" || "$JOIN_TYPE" != "agent" && "$JOIN_TYPE" != "server" ]]; then
                echo "Error: 'join' command requires a join type. Format: join [server|agent] [join-token-string]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            if [[ -z "$JOIN_SERVER_FQDN" ]]; then
                echo "Error: 'join' command requires a server fqdn/ip. Format: join [server|agent] [join-token-string]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            if [[ -z "$JOIN_TOKEN" ]]; then
                echo "Error: 'join' command requires a join token. Format: join [server|agent] [join-token-string]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            shift
            shift
            shift
            shift
            ;;
        tls-san)
            TLS_SAN_MODE=1
            TLS_SAN="${2:-}"
            if [[ -z "$TLS_SAN" ]]; then
                echo "Error: 'tls-san' command requires a server fqdn/ip. Format: tls-san [server-fqdn-ip]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
            shift
            shift
            ;;
        registry)
            REGISTRY_MODE=1
            REGISTRY_INFO="$1"
            REG_USER="${2:-}"
            REG_PASS="${3:-}"
            if [[ -z "$REG_USER" || -z "$REG_PASS" ]]; then
                echo "Error: Registry info requires a username and password. Format: registry [registry:port username password]"
                echo "Type './$SCRIPT_NAME -h' for help."
                exit 1
            fi
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

# Run validation to ensure the correct arguments and modes have been passed.

# Verify uninstall is not used with any other mode
if [[ "$UNINSTALL_MODE" == "1" ]]; then
    if [[ "$INSTALL_MODE" == "1" || "$SAVE_MODE" == "1" || "$PUSH_MODE" == "1" || "$JOIN_MODE" == "1" || "$REGISTRY_MODE" == "1" ]]; then
        echo "Error:'uninstall' command cannot be used with other commands."
        echo "Type './$SCRIPT_NAME -h' for help."
        exit 1
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
        echo "Error: 'push' command requires registry config. Format: push registry [registry:port] [username] [password]"
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

# Verify REGISTRY_MODE is used with one of PUSH_MODE, INSTALL_MODE or JOIN_MODE
if [[ "$REGISTRY_MODE" == "1" && "$PUSH_MODE" != "1" && "$INSTALL_MODE" != "1" && "$JOIN_MODE" != "1" ]]; then
    echo "Error: 'Registry config must be used with either 'push', 'join', or 'install'."
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

# Verify AIR_GAPPED_MODE based on rke-save.tar.gz file presence
[[ ! -f $base_dir/rke2-save.tar.gz ]] || AIR_GAPPED_MODE=1

# Displays the parsed and validated arguments
display_args() {
    echo "---"
    echo "Arguments parsed successfully, script will run with:"
    echo "AIR_GAPPED_MODE: $AIR_GAPPED_MODE"
    echo "INSTALL_MODE: $INSTALL_MODE"
    echo "TLS_SAN_MODE: $TLS_SAN_MODE"
    echo "TLS_SAN: $TLS_SAN"
    echo "UNINSTALL_MODE: $UNINSTALL_MODE"
    echo "SAVE_MODE: $SAVE_MODE"
    echo "JOIN_MODE: $JOIN_MODE"
    echo "JOIN_TYPE: $JOIN_TYPE"
    echo "JOIN_SERVER_FQDN: $JOIN_SERVER_FQDN"
    echo "JOIN_TOKEN: $JOIN_TOKEN"
    echo "PUSH_MODE: $PUSH_MODE"
    echo "REGISTRY_MODE: $REGISTRY_MODE"
    echo "REGISTRY_INFO: $REGISTRY_INFO"
    echo "REG_FQDN: $REG_FQDN"
    echo "REG_PORT: $REG_PORT"
    echo "REG_USER: $REG_USER"
    echo "REG_PASS: $REG_PASS"
    echo "---"
}
# --- End of Argument Parsing --- #

# -- Install & Join Definitions -- #

run_install () {
    if [[ $INSTALL_MODE -eq 1 ]]; then
        create_config_files
        create_registry_config
        install_rke2_binaries
        config_host_settings
        start_rke2_service
        apply_utilities
    fi
    if [[ $JOIN_MODE -eq 1 && $JOIN_TYPE == "agent" ]]; then
        create_agent_join_config
        create_registry_config
        install_rke2_binaries
        config_host_settings
        start_rke2_service
    fi
    if [[ $JOIN_MODE -eq 1 && $JOIN_TYPE == "server" ]]; then
        create_server_join_config
        create_registry_config
        install_rke2_binaries
        config_host_settings
        start_rke2_service
    fi
}

start_rke2_service () {
    if [[ $JOIN_TYPE == "agent" ]]; then
        systemctl enable rke2-agent.service
        echo "Starting rke2 service, this may take several minutes..."
        systemctl start rke2-agent.service
    else
        systemctl enable rke2-server.service
        echo "Starting rke2 service, this may take several minutes..."
        systemctl start rke2-server.service
    fi
    if [ $? -ne 0 ]; then
        echo "Error: rke2 service failed to start. Exiting script."
        exit 1 
    else
        echo "rke2 service started successfully."
    fi
    if [[ $JOIN_TYPE == "agent" ]]; then
        echo "Agent install completed, check the status with 'kubectl get nodes' and 'kubectl get pods -A' on the server for details."
    else
        echo "Waiting for pods to start..."
        sleep 15
        mkdir -p /root/.kube
        cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
        chmod 600 /root/.kube/config
        if [[ -n "$user_name" ]]; then
            mkdir -p /home/$user_name/.kube
            cp /etc/rancher/rke2/rke2.yaml /home/$user_name/.kube/config
            chown $user_name:$user_name /home/$user_name/.kube/config
            chmod 600 /home/$user_name/.kube/config
            echo "export KUBECONFIG=/home/$user_name/.kube/config" >> /home/$user_name/.bashrc
            echo "export PATH=\$PATH:/var/lib/rancher/rke2/bin" >> /home/$user_name/.bashrc
            echo 'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/var/lib/rancher/rke2/bin"' | sudo tee /etc/sudoers.d/rke2-path
        fi
        export KUBECONFIG=/home/$user_name/.kube/config
        export PATH=$PATH:/var/lib/rancher/rke2/bin
        check_namespace_pods_ready
    fi
}

install_rke2_binaries () {
    echo "Installing RKE2 binaries..."
    if [[ "$AIR_GAPPED_MODE" -eq 1 ]]; then
        echo "extracting rke2-core-images archive..."
        tar -xzf $WORKING_DIR/rke2-core-images/rke2-core-images.tar.gz -C $WORKING_DIR/rke2-core-images
        mv $WORKING_DIR/rke2-core-images/images/rke2-images-core.linux-amd64.tar.gz $WORKING_DIR/rke2-binaries
        cp $WORKING_DIR/rke2-binaries/rke2-images-core.linux-amd64.tar.gz /var/lib/rancher/rke2/agent/images
        rm -rf $WORKING_DIR/rke2-core-images/images
        echo "extracting rke2-cni-images archive..."
        tar -xzf $WORKING_DIR/rke2-cni-images/rke2-$CNI_TYPE-images.tar.gz -C $WORKING_DIR/rke2-cni-images
        mv $WORKING_DIR/rke2-cni-images/images/rke2-images-$CNI_TYPE.linux-amd64.tar.gz $WORKING_DIR/rke2-binaries
        cp $WORKING_DIR/rke2-binaries/rke2-images-$CNI_TYPE.linux-amd64.tar.gz /var/lib/rancher/rke2/agent/images
        rm -rf $WORKING_DIR/rke2-cni-images/images
        if [[ $REGISTRY_MODE -eq 0 ]]; then
            echo "extracting rke2-utilities archive..."
            tar -xzf $WORKING_DIR/rke2-utilities/container_images_*.tar.gz -C $WORKING_DIR/rke2-utilities
            cp $WORKING_DIR/rke2-utilities/images/images.tar.gz /var/lib/rancher/rke2/agent/images
            rm -rf $WORKING_DIR/rke2-utilities/images
        fi
        INSTALL_RKE2_ARTIFACT_PATH="$WORKING_DIR/rke2-binaries" INSTALL_RKE2_VERSION="$RKE2_VERSION" INSTALL_RKE2_TYPE="$JOIN_TYPE" sh $WORKING_DIR/rke2-binaries/install.sh
    else
        curl -sfL https://get.rke2.io | sudo -E INSTALL_RKE2_VERSION="$RKE2_VERSION" INSTALL_RKE2_TYPE="$JOIN_TYPE" INSTALL_RKE2_METHOD="tar" sh -
    fi
}

create_registry_config () {
    if [[ "$REGISTRY_MODE" -eq 1 ]]; then
        echo "Configuring private registry for RKE2..."
        CERTS_DIR="/etc/rancher/rke2/certs.d/${REG_FQDN}:${REG_PORT}"
        mkdir -p "$CERTS_DIR"
        if openssl s_client -showcerts -connect "$REGISTRY_INFO" < /dev/null 2>/dev/null | openssl x509 -outform PEM > "$CERTS_DIR/ca.crt"; then
            echo "Certificate saved to $CERTS_DIR."
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
  ${REG_FQDN}:${REG_PORT}:
    endpoint:
      - "https://${REG_FQDN}:${REG_PORT}"
EOF
        if [[ $INSTALL_DNS_UTILITY == "true" ]]; then
            cat >> /etc/rancher/rke2/registries.yaml <<EOF
  registry.k8s.io:
    endpoint:
      - "https://${REG_FQDN}:${REG_PORT}"
EOF
        fi
        echo "Private registry configuration written to /etc/rancher/rke2/registries.yaml"
    else
        echo "Private registry not enabled. Skipping registry configuration."
    fi
}

create_agent_join_config () {
    echo "Generating /etc/rancher/rke2/config.yaml for agent"
    cat > /etc/rancher/rke2/config.yaml <<EOF
server: https://${JOIN_SERVER_FQDN}:9345
token: "$JOIN_TOKEN"
EOF
    if [ $ENABLE_CIS == true ]; then
        cat >> /etc/rancher/rke2/config.yaml <<EOF
profile: "cis"
EOF
    fi
}

create_server_join_config () {
    echo "Generating /etc/rancher/rke2/config.yaml for server join"
    cat > /etc/rancher/rke2/config.yaml <<EOF
server: https://${JOIN_SERVER_FQDN}:9345
token: "$JOIN_TOKEN"
write-kubeconfig-mode: "0600"
service-node-port-range: "443-40000"
cluster-cidr: "$CLUSTER_CIDR"
service-cidr: "$SERVICE_CIDR"
etcd-extra-env:
  - "ETCD_AUTO_COMPACTION_RETENTION=72h"
  - "ETCD_AUTO_COMPACTION_MODE=periodic"
kubelet-arg:
  - "max-pods=$MAX_PODS"
  - "resolv-conf=/run/systemd/resolve/resolv.conf"
kube-apiserver-arg:
  - "audit-log-path=/var/log/rke2-apiserver-audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=10"
  - "audit-log-maxsize=200"
EOF
    if [ $ENABLE_CIS == true ]; then
        cat >> /etc/rancher/rke2/config.yaml <<EOF
profile: "cis"
EOF
    fi
    if [[ $TLS_SAN_MODE -eq 1 ]]; then
        cat >> /etc/rancher/rke2/config.yaml <<EOF
tls-sans:
  - "$TLS_SAN"
EOF
    fi
}

create_config_files () {
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
  - "max-pods=$MAX_PODS"
  - "resolv-conf=/run/systemd/resolve/resolv.conf"
kube-apiserver-arg:
  - "audit-log-path=/var/log/rke2-apiserver-audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=10"
  - "audit-log-maxsize=200"
EOF
    if [ $INSTALL_INGRESS == false ]; then
        cat >> /etc/rancher/rke2/config.yaml <<EOF
disable:
  - rke2-ingress-nginx
EOF
    fi
    if [[ $INSTALL_SERVICELB == true ]]; then
        cat >> /etc/rancher/rke2/config.yaml <<EOF
enable-servicelb: $INSTALL_SERVICELB
EOF
    fi
    if [[ $TLS_SAN_MODE -eq 1 ]]; then
        cat >> /etc/rancher/rke2/config.yaml <<EOF
tls-san:
  - "$TLS_SAN"
EOF
    fi
    if [ $ENABLE_CIS == true ]; then
        cat >> /etc/rancher/rke2/config.yaml <<EOF
profile: "cis"
EOF
        echo "Generating $WORKING_DIR/rke-utilities/account_update.yaml"
        cat > $WORKING_DIR/rke-utilities/account_update.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
automountServiceAccountToken: false
EOF
    fi
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

config_host_settings () {
    echo "Enabling overlay and br_netfilter modules..."
    cat > /etc/modules-load.d/40-k8s.conf <<EOF
overlay
br_netfilter
EOF
    modprobe -a overlay br_netfilter
    echo "Disabling swap space and ufw..."
    swapoff -a
    sed -i -e '/swap/d' /etc/fstab
    systemctl stop ufw
    systemctl disable ufw
    echo "Enabling k8s sysctl parameters..."
    cat > /etc/sysctl.d/40-k8s.conf <<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
    if [[ $ENABLE_CIS == true ]]; then
        echo "Enabling CIS host parameters..."
        cp -f /usr/local/share/rke2/rke2-cis-sysctl.conf /etc/sysctl.d/60-rke2-cis.conf
        useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
    fi
    systemctl restart systemd-sysctl
    if [ $? -ne 0 ]; then
        echo "Error: systemd-sysctl.service failed to restart."
        exit 1 
    else
        echo "systemd-sysctl.service restarted successfully."
    fi
}

apply_utilities () {
    if [ $ENABLE_CIS == true ]; then
        for namespace in $(kubectl get namespaces -A -o=jsonpath="{.items[*]['metadata.name']}"); do
            echo -n "Patching namespace $namespace - "
            kubectl patch serviceaccount default -n ${namespace} -p "$(cat $WORKING_DIR/rke2-utilities/account_update.yaml)"
        done
    fi
    if [[ $INSTALL_LOCAL_PATH_PROVISIONER == "true" ]]; then
        # need to add check for registry and update yaml path
        if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
            kubectl apply -f $WORKING_DIR/rke2-utilities/local-path-storage.yaml
        else
            kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH_PROVISIONER_VERSION/deploy/local-path-storage.yaml
        fi
        check_namespace_pods_ready local-path-storage
        kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
    fi
    if [[ $INSTALL_DNS_UTILITY == "true" ]]; then
        # need to add check for registry and update yaml path
        if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
            kubectl apply -f $WORKING_DIR/rke2-utilities/dnsutils.yaml
        else
            kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml
        fi
        check_namespace_pods_ready default
    fi
}

# -- Uninstall Definitions -- #

uninstall_rke2() {
    if [[ $UNINSTALL_MODE -eq 1 ]]; then
        echo "Uninstalling RKE2..."
        [ ! -f "/usr/local/bin/rke2-uninstall.sh" ] || /usr/local/bin/rke2-uninstall.sh
        # rm -rf $base_dir/rke2-install-files
        [ ! -d "/home/$user_name/.kube" ] || rm -rf /home/$user_name/.kube
        [  ! -d "/root/.kube" ] || rm -rf /root/.kube
        # Clean up the KUBECONFIG and PATH from the global environment if they were set here
        unset KUBECONFIG
        # Restore original PATH if possible, or just remove the RKE2 bin path
        PATH=$(echo $PATH | sed -e "s|:/var/lib/rancher/rke2/bin||g")
        [ ! -d "$WORKING_DIR" ] || rm -rf "$WORKING_DIR"
        echo "Completed..."
        exit 0
    fi
}

# -- Save Definitions -- #

run_save () {
    if [[ $SAVE_MODE -eq 1 ]]; then
        echo "--- Running save workflow ---"
        download_rke2_binaries
        download_rke2_utilities
        create_save_archive
        echo "--- Finished save workflow ---"
        echo "Copy the archive to an air-gapped host runing the same version of $os_id"
    fi 
}

download_rke2_binaries () {
    echo "Downloading RKE2 images and binaries..."
    # Download RKE2 binaries and images
    echo "Downloading core rke2 files for $RKE2_VERSION..."
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-core.linux-amd64.tar.gz -o $WORKING_DIR/rke2-core-images/images/rke2-images-core.linux-amd64.tar.gz
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-core.linux-amd64.txt -o $WORKING_DIR/rke2-core-images/images/rke2-images-core.linux-amd64.txt
    echo "creating rke2-core-images archive..."
    cd $WORKING_DIR/rke2-core-images
    tar czf rke2-core-images.tar.gz --remove-files images
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2.linux-amd64.tar.gz -o $WORKING_DIR/rke2-binaries/rke2.linux-amd64.tar.gz
    curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/sha256sum-amd64.txt -o $WORKING_DIR/rke2-binaries/sha256sum-amd64.txt
    curl -sfL https://get.rke2.io --output $WORKING_DIR/rke2-binaries/install.sh
    if [[ $CNI_NONE == "false" ]]; then
        echo "Downloading CNI rke2 files for $CNI_TYPE..."
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-$CNI_TYPE.linux-amd64.tar.gz -o $WORKING_DIR/rke2-cni-images/images/rke2-images-$CNI_TYPE.linux-amd64.tar.gz
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-$CNI_TYPE.linux-amd64.txt -o $WORKING_DIR/rke2-cni-images/images/rke2-images-$CNI_TYPE.linux-amd64.txt
        echo "creating rke2-cni-images archive..."
        cd $WORKING_DIR/rke2-cni-images
        tar czf rke2-$CNI_TYPE-images.tar.gz --remove-files images
    fi
    cd $base_dir
}

download_rke2_utilities () {
    # check if local_path_provisioner should be downloaded
    echo "Checking if RKE2 utility download is required..."
    if [[ $INSTALL_LOCAL_PATH_PROVISIONER == "true" ]]; then
        echo "Downloading local-path-provisioner manifest..."
        curl -sfL https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH_PROVISIONER_VERSION/deploy/local-path-storage.yaml -o $WORKING_DIR/rke2-utilities/local-path-storage.yaml
        cat $WORKING_DIR/rke2-utilities/local-path-storage.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' > $WORKING_DIR/rke2-utilities/images/utility-images.txt
    fi
    # Download k8s dns utils regardless so docker binaries get saved by image_pull_push.sh
    echo "Downloading k8s dns utils manifest..."
    curl -sfL https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml -o $WORKING_DIR/rke2-utilities/dnsutils.yaml
    cat $WORKING_DIR/rke2-utilities/dnsutils.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
    if [[ -f $WORKING_DIR/rke2-utilities/images/utility-images.txt ]]; then
        image_pull_push_check
        echo "Running image_pull_push utility script for utility images..."
        cd $WORKING_DIR/rke2-utilities
        ./image_pull_push.sh -f images/utility-images.txt save
        cd $base_dir
    fi
}

create_save_archive () {
    # saves downloaded files into rke2-save.tar.gz
    echo "Creating final archive..."
    tar -czf rke2-save.tar.gz rke2-install rke2_installer.sh
    echo "Air-gapped archive 'rke2-save.tar.gz' created."
}

# -- Push Definitions -- #
run_push () {
    # Run push workflow if set to 1
    if [[ $PUSH_MODE -eq 1 ]]; then
        echo "--- Running push workflow ---"
        push_utility_images
        push_rke2_images
        echo "--- Finished push workflow ---"
    fi 
}

push_utility_images () {
    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        echo "Pushing utility images..."
        local container_images_tar=$(basename $WORKING_DIR/rke2-utilities/container_images*.tar.gz)
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-utilities/$container_images_tar push $REGISTRY_INFO $REG_USER $REG_PASS
    elif [[ $AIR_GAPPED_MODE -eq 0 ]]; then
        if [[ $INSTALL_LOCAL_PATH_PROVISIONER == "true" ]]; then
            echo "Downloading Local Path Provisioner manifest..."
            curl -sfL https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH_PROVISIONER_VERSION/deploy/local-path-storage.yaml -o $WORKING_DIR/rke2-utilities/local-path-storage.yaml
            cat $WORKING_DIR/rke2-utilities/local-path-storage.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' > $WORKING_DIR/rke2-utilities/images/utility-images.txt
        fi
        if [[ $INSTALL_DNS_UTILITY == "true" ]]; then
            echo "Downloading k8s dns utils manifest..."
            curl -sfL https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml -o $WORKING_DIR/rke2-utilities/dnsutils.yaml
            cat $WORKING_DIR/rke2-utilities/dnsutils.yaml |grep image: |cut -d: -f2-3 | awk '{sub(/^ /, ""); print}' >> $WORKING_DIR/rke2-utilities/images/utility-images.txt
        fi
        image_pull_push_check
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-utilities/images/utility-images.txt push $REGISTRY_INFO $REG_USER $REG_PASS
    else
        echo "No utility images to push..."
    fi
}

push_rke2_images () {
    if [[ $AIR_GAPPED_MODE -eq 1 ]]; then
        echo "Pushing rke2 core images..."
        local container_images_tar=$(basename $WORKING_DIR/rke2-core-images/*.tar.gz)
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-core-images/$container_images_tar push $REGISTRY_INFO $REG_USER $REG_PASS
        echo "Pushing rke2 cni images..."
        local container_images_tar=$(basename $WORKING_DIR/rke2-cni-images/*.tar.gz)
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-cni-images/$container_images_tar push $REGISTRY_INFO $REG_USER $REG_PASS
    else
        echo "Downloading and pushing rke2 core images..."
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-core.linux-amd64.txt -o $WORKING_DIR/rke2-core-images/rke2-images-core.linux-amd64.txt
        image_pull_push_check
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-core-images/rke2-images-core.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS
        echo "Downloading and pushing rke2 cni images..."
        curl -sfL https://github.com/rancher/rke2/releases/download/$TRANSLATED_VERSION/rke2-images-$CNI_TYPE.linux-amd64.txt -o $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE.linux-amd64.txt
        $WORKING_DIR/rke2-utilities/image_pull_push.sh -f $WORKING_DIR/rke2-cni-images/rke2-images-$CNI_TYPE.linux-amd64.txt push $REGISTRY_INFO $REG_USER $REG_PASS
    fi
}

# --- Helper Functions --- #

runtime_outputs () {
    if [[ $PUSH_MODE -eq 1 ]]; then
        echo "----"
        echo "Push to external registry $REG_FQDN completed, check the registry to confirm images are present"
    fi
    if [[ $SAVE_MODE -eq 1 ]]; then
        echo "----"
        echo "Air-gapped archive 'rke2-save.tar.gz' created."
        echo "Copy the archive to an air-gapped host runing the same version of $os_id and extract it with 'tar -xzf rke2-save.tar.gz'."
    fi
    if [[ $INSTALL_MODE -eq 1 ]]; then
        local join_token=$(cat /var/lib/rancher/rke2/server/node-token)
        local host_ip=$(hostname -I |awk '{print $1}')
        echo "----"
        echo "RKE2 Server installed successfully."
        echo "Verify API is reachable at:"
        echo "https://$host_ip:6443"
        if [[ $TLS_SAN_MODE -eq 1 ]]; then
            echo "https://$TLS_SAN:6443"
        fi
        echo "Join token stored in: /var/lib/rancher/rke2/server/node-token"
        if [[ $TLS_SAN_MODE -eq 1 ]]; then
            echo "To join more nodes to this cluster use the following config:"
            echo "----"
            echo "server: https://$TLS_SAN:9345"
            echo "token: $join_token"
            echo "----"
        else
            echo "To join more nodes to this cluster use the following config:"
            echo "----"
            echo "server: https://$host_ip:9345"
            echo "token: $join_token"
            echo "----"
        fi
        echo "Kube config stored in: /etc/rancher/rke2/rke2.yaml and coppied to /home/$user_name/.kube/config"
        echo "Run 'source ~/.bashrc' to enable Kubectl on this shell session."
    fi
    if [[ $JOIN_MODE -eq 1 ]]; then
        if [[ $JOIN_TYPE == "server" ]]; then
            echo "Server join completed, check the status with 'kubectl get nodes' and 'kubectl get pods -A' on the server for details."
            echo "kube config stored in: /etc/rancher/rke2/rke2.yaml and coppied to /home/$user_name/.kube/config"
            echo "Run 'source ~/.bashrc' to enable Kubectl on this shell session."
        else
            echo "Agent install completed, check the status with 'kubectl get nodes' and 'kubectl get pods -A' on the server for details."
        fi
    fi
}

create_working_dir () {
    # check for rke2-install directory and supporting directories, then create them
    [ -d "$WORKING_DIR" ] || mkdir -p "$WORKING_DIR"
    [ -d "$WORKING_DIR/rke2-core-images/images" ] || mkdir -p "$WORKING_DIR/rke2-core-images/images"
    [ -d "$WORKING_DIR/rke2-cni-images/images" ] || mkdir -p "$WORKING_DIR/rke2-cni-images/images"
    [ -d "$WORKING_DIR/rke2-binaries" ] || mkdir -p "$WORKING_DIR/rke2-binaries"
    [ -d "$WORKING_DIR/rke2-utilities/images" ] || mkdir -p "$WORKING_DIR/rke2-utilities/images"
    [ -d "/var/lib/rancher/rke2/agent/images" ] || mkdir -p "/var/lib/rancher/rke2/agent/images"
    [ -d "/etc/rancher/rke2" ] || mkdir -p "/etc/rancher/rke2"
    [ -d "/var/lib/rancher/rke2/server/manifests" ] || mkdir -p "/var/lib/rancher/rke2/server/manifests"
}


os_check () {
    # Get OS information from /etc/os-release
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        echo "OS type is: $ID"
        os_id="$ID"
    else
        echo "Unknown or unsupported OS $os_id."
        exit 1
    fi
    if [[ ! "$os_id" =~ ^(ubuntu|debian|rhel|centos|rocky|almalinux|fedora|sles|opensuse-leap)$ ]]; then
        echo "Unknown or unsupported OS $os_id."
        exit 1
    fi
}

rke2_version_and_cni_check () {
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
}

image_pull_push_check () {
    if [[ ! -f $WORKING_DIR/rke2-utilities/image_pull_push.sh ]]; then
        echo "Downloading image_pull_push.sh..."
        curl -sfL https://github.com/Chubtoad5/images-pull-push/raw/refs/heads/main/image_pull_push.sh  -o $WORKING_DIR/rke2-utilities/image_pull_push.sh
        chmod +x $WORKING_DIR/rke2-utilities/image_pull_push.sh
    fi
}

check_namespace_pods_ready() {
  # Run this function as 'check_namespace_pods_ready $namespace', no argument will default to kube-system
  # checks status of pods, deletes any completed pods, and loops until all pods are ready or 120s has elapsed
  local timeout_seconds=120
  local start_time=$(date +%s)
  local ns=${1:-"kube-system"}
  while true; do
    local completed_pods=$(kubectl get pods -n $ns --field-selector status.phase=Succeeded -o name)
    echo "Checking pod status and removing Completed pods in $ns namespace..."
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
    echo "Wating on $current_pods_not_ready pods..."
    echo "Elapsed: ${elapsed_time}s/${timeout_seconds}s"
    sleep 10
  done
  echo "All pods are ready in $ns namespace!"
  return 0
}

run_debug() {
  # Use this to hide the output of functions or helper scripts when they are not needed.
  # Check the value of the global DEBUG variable
  if [ "$DEBUG" = "1" ]; then
    # If DEBUG is 1, execute the command/function normally.
    # All stdout and stderr will be displayed to the console.
    local GREEN=$(tput setaf 2)
    local RED=$(tput setaf 1)
    local NC=$(tput sgr0) # No Color (reset)
    # Unicode symbols
    local CHECKMARK='\u2714'
    local CROSSMARK='\u2717'
    # --- Argument Assignments ---
    local SUCCESS_MSG=${2:-"Success"} # Use provided message or default
    local ERROR_MSG=${3:-"Error"}     # Use provided message or default
    echo "--- Running '$*' with DEBUG enabled---"
    "$@"
    local status=$? # Capture the exit status of the executed command
    if [ "$status" -eq 0 ]; then
        # Success case (status is 0)
        echo -e "--- DEBUG: Finished '$*' ${GREEN}${CHECKMARK} ${SUCCESS_MSG}${NC} ---"
    else
        # Error case (status is non-zero)
        echo -e "--- DEBUG: Finished '$*' ${RED}${CROSSMARK} ${ERROR_MSG}${NC} ---" >&2 # Print errors to stderr
    fi
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

cleanup () {
    if [[ $INSTALL_MODE -eq 1 || $JOIN_MODE -eq 1 ]]; then
        echo "Installation detected, no cleanup required..."
    else
        echo "Cleaning up..."
        rm -rf "$WORKING_DIR"
    fi
}

# --- Main Script Execution --- #
os_check
run_debug display_args
run_debug uninstall_rke2
rke2_version_and_cni_check
create_working_dir
run_debug run_save
run_debug run_push
run_debug run_install
cleanup
runtime_outputs

echo "--- RKE2 installer script complete ---"