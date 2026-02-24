# RKE2 Manual Installation Guide

A step-by-step guide for manually installing RKE2 (Rancher Kubernetes Engine 2) on Linux systems. This guide covers online installations, offline/air-gapped deployments, multi-node clusters, and optional components.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Part 1: Online Installation](#part-1-online-installation)
  - [Step 1 — Prepare the Host](#step-1--prepare-the-host)
  - [Step 2 — Configure RKE2](#step-2--configure-rke2)
  - [Step 3 — Install and Start RKE2](#step-3--install-and-start-rke2)
  - [Step 4 — Set Up kubectl Access](#step-4--set-up-kubectl-access)
  - [Step 5 — Verify the Cluster](#step-5--verify-the-cluster)
- [Part 2: Optional Components](#part-2-optional-components)
  - [NGINX Ingress Controller](#nginx-ingress-controller)
  - [Klipper LoadBalancer](#klipper-loadbalancer)
  - [Local Path Provisioner (Storage)](#local-path-provisioner-storage)
  - [DNS Utility Pod](#dns-utility-pod)
  - [CIS Hardening](#cis-hardening)
  - [Velero Backup](#velero-backup)
  - [Monitoring Stack](#monitoring-stack)
- [Part 3: Multi-Node Clusters](#part-3-multi-node-clusters)
  - [Finding the Join Token](#finding-the-join-token)
  - [Joining a Worker (Agent) Node](#joining-a-worker-agent-node)
  - [Joining an Additional Server Node](#joining-an-additional-server-node)
  - [Control-Plane Tainting](#control-plane-tainting)
- [Part 4: Offline and Air-Gapped Installation](#part-4-offline-and-air-gapped-installation)
  - [Step 1 — Download Everything on an Online Machine](#step-1--download-everything-on-an-online-machine)
  - [Step 2 — Transfer Files to the Air-Gapped Host](#step-2--transfer-files-to-the-air-gapped-host)
  - [Step 3 — Install from Local Files](#step-3--install-from-local-files)
  - [Air-Gapped Optional Components](#air-gapped-optional-components)
- [Part 5: Private Registry (Mirror)](#part-5-private-registry-mirror)
  - [Pushing Images to a Registry](#pushing-images-to-a-registry)
  - [Installing with a Registry Mirror](#installing-with-a-registry-mirror)
  - [Registry Configuration Details](#registry-configuration-details)
- [Part 6: TLS SAN Configuration](#part-6-tls-san-configuration)
- [Part 7: Uninstalling RKE2](#part-7-uninstalling-rke2)
- [Appendix: Configuration Reference](#appendix-configuration-reference)

---

## Prerequisites

- **Operating System** (one of):
  - Ubuntu / Debian
  - RHEL / CentOS / Rocky Linux / AlmaLinux / Fedora
  - SLES / OpenSUSE Leap
- **Root access** (all commands must be run as root or with `sudo`)
- **Valid hostname** — must be lowercase alphanumeric with hyphens only (DNS-1123 format)
- **Internet access** (for online installation) or pre-downloaded files (for air-gapped)
- Architecture: **x86_64 (amd64)**

---

## Part 1: Online Installation

This section walks through a standard single-node RKE2 server installation with internet access.

### Step 1 — Prepare the Host

RKE2 requires several system-level settings. Run the following as root.

#### Load required kernel modules

```bash
cat > /etc/modules-load.d/40-k8s.conf <<EOF
overlay
br_netfilter
dm_crypt
nfs
EOF

modprobe -a overlay br_netfilter dm_crypt nfs
```

#### Disable swap

```bash
swapoff -a
sed -i -e '/swap/d' /etc/fstab
```

#### Set kernel network parameters

```bash
cat > /etc/sysctl.d/40-k8s.conf <<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF

systemctl restart systemd-sysctl
```

#### Disable the host firewall

RKE2 manages its own network rules. Disable the native firewall to avoid conflicts.

**Ubuntu/Debian:**
```bash
ufw disable
```

**RHEL/CentOS/Rocky/AlmaLinux/Fedora:**
```bash
systemctl stop firewalld
systemctl disable firewalld
```

**SLES/OpenSUSE:**
```bash
systemctl stop firewalld
systemctl disable firewalld
# If using SuSEfirewall2 instead:
# systemctl stop SuSEfirewall2 && systemctl disable SuSEfirewall2
```

#### Configure NetworkManager (if active)

If your system uses NetworkManager, tell it to ignore CNI-managed interfaces:

```bash
cat > /etc/NetworkManager/conf.d/rke2-canal.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:flannel*;interface-name:cali*;interface-name:tunl*;interface-name:vxlan.calico;interface-name:vxlan-v6.calico;interface-name:wireguard.cali;interface-name:wg-v6.cali
EOF

systemctl restart NetworkManager
```

#### Disable multipath (if present)

```bash
systemctl stop multipathd.service 2>/dev/null || true
systemctl disable multipathd.service 2>/dev/null || true
systemctl mask multipathd.service 2>/dev/null || true
systemctl stop multipathd.socket 2>/dev/null || true
systemctl disable multipathd.socket 2>/dev/null || true
systemctl mask multipathd.socket 2>/dev/null || true
```

### Step 2 — Configure RKE2

Create the RKE2 configuration directory and config file:

```bash
mkdir -p /etc/rancher/rke2
mkdir -p /var/lib/rancher/rke2/server/manifests
```

Create the main configuration file. Adjust the values to match your environment:

```bash
cat > /etc/rancher/rke2/config.yaml <<EOF
cni: "canal"
write-kubeconfig-mode: "0600"
service-node-port-range: "443-40000"
cluster-cidr: "10.42.0.0/16"
service-cidr: "10.43.0.0/16"
advertise-address: "<YOUR_NODE_IP>"
node-ip: "<YOUR_NODE_IP>"
etcd-extra-env:
  - "ETCD_AUTO_COMPACTION_RETENTION=72h"
  - "ETCD_AUTO_COMPACTION_MODE=periodic"
kube-apiserver-arg:
  - "audit-log-path=/var/log/rke2-apiserver-audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=10"
  - "audit-log-maxsize=200"
kubelet-arg:
  - "max-pods=110"
  - "resolv-conf=/etc/resolv.conf"
EOF
```

> **Note:** Replace `<YOUR_NODE_IP>` with the management IP of this node. You can find it with `hostname -I | awk '{print $1}'`.

> **Note on resolv-conf:** If `/etc/resolv.conf` is a symlink to `/run/systemd/resolve/stub-resolv.conf`, use `/run/systemd/resolve/resolv.conf` instead to avoid DNS loops.

**Available CNI options:** `canal` (default), `calico`, `cilium`, or `none`

#### Configure CoreDNS

Create a CoreDNS HelmChartConfig to customize DNS behavior:

```bash
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
```

### Step 3 — Install and Start RKE2

Install the RKE2 binaries:

```bash
curl -sfL https://get.rke2.io | INSTALL_RKE2_VERSION="v1.32.5+rke2r1" INSTALL_RKE2_METHOD="tar" sh -
```

> Change the version string as needed. Check the [RKE2 releases page](https://github.com/rancher/rke2/releases) for available versions.

Enable and start the RKE2 server service:

```bash
systemctl enable rke2-server.service
systemctl start rke2-server.service
```

> The first start may take several minutes as RKE2 downloads and starts all required containers.

### Step 4 — Set Up kubectl Access

After the service starts, configure `kubectl` access:

```bash
# Wait a moment for the cluster to initialize
sleep 15

# Set up kubeconfig for root
mkdir -p /root/.kube
cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
chmod 600 /root/.kube/config
export KUBECONFIG=/root/.kube/config

# Set up kubeconfig for your regular user (optional)
mkdir -p /home/<YOUR_USER>/.kube
cp /etc/rancher/rke2/rke2.yaml /home/<YOUR_USER>/.kube/config
chown <YOUR_USER>:<YOUR_USER> /home/<YOUR_USER>/.kube/config
chmod 600 /home/<YOUR_USER>/.kube/config

# Add RKE2 binaries to PATH and create symlinks
export PATH=$PATH:/var/lib/rancher/rke2/bin
ln -sf /var/lib/rancher/rke2/bin/kubectl /usr/bin/kubectl
ln -sf /var/lib/rancher/rke2/bin/ctr /usr/bin/ctr
ln -sf /var/lib/rancher/rke2/bin/crictl /usr/bin/crictl
```

### Step 5 — Verify the Cluster

```bash
kubectl get nodes
kubectl get pods -A
```

All pods should reach a `Running` state within a few minutes. Your single-node RKE2 cluster is now ready.

---

## Part 2: Optional Components

### NGINX Ingress Controller

RKE2 bundles an NGINX ingress controller that is **enabled by default**. No extra steps are needed.

To **disable** it, add this to your `/etc/rancher/rke2/config.yaml` **before** starting RKE2:

```yaml
disable:
  - rke2-ingress-nginx
```

### Klipper LoadBalancer

Klipper is the RKE2 built-in service LoadBalancer. It allows `LoadBalancer`-type services to receive an external IP on bare-metal hosts. It is **enabled by default**.

To **enable** it explicitly, add this to your config:

```yaml
enable-servicelb: true
```

If you are using an external load balancer (e.g., MetalLB), omit this setting or set it to `false`.

### Local Path Provisioner (Storage)

The Rancher local-path-provisioner gives your cluster a default `StorageClass` backed by node-local disk. Persistent volume data is stored under `/opt/local-path-provisioner` by default.

**Install:**

```bash
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.32/deploy/local-path-storage.yaml
```

Wait for the pod to be ready:

```bash
kubectl get pods -n local-path-storage
```

Set it as the default storage class:

```bash
kubectl patch storageclass local-path \
  -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

### DNS Utility Pod

A convenience pod for testing DNS resolution inside the cluster:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml
```

Test with:

```bash
kubectl exec -it dnsutils -- nslookup kubernetes.default
```

### CIS Hardening

The CIS (Center for Internet Security) Kubernetes hardening profile adds additional security controls. To enable it:

1. Add the CIS profile to your `/etc/rancher/rke2/config.yaml` **before** starting RKE2:

```yaml
profile: "cis"
```

2. Apply the CIS sysctl parameters:

```bash
cp -f /usr/local/share/rke2/rke2-cis-sysctl.conf /etc/sysctl.d/60-rke2-cis.conf
systemctl restart systemd-sysctl
```

3. Create the required `etcd` system user:

```bash
useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
```

4. After the cluster is running, patch all namespace service accounts to disable auto-mount of tokens:

```bash
for namespace in $(kubectl get namespaces -o jsonpath="{.items[*].metadata.name}"); do
  kubectl patch serviceaccount default -n "$namespace" -p '{"automountServiceAccountToken": false}'
done
```

### Velero Backup

Velero provides cluster backup and restore using an S3-compatible object store and CSI volume snapshots.

#### Prerequisites

- An S3-compatible object store (MinIO, Ceph RGW, AWS S3, etc.)
- A pre-created S3 bucket (e.g., `velero`)
- A CSI driver (e.g., Longhorn) installed in the cluster for volume snapshots
- The RKE2 snapshot controller must be running (provided by RKE2 by default)

#### Install Velero CLI

```bash
VELERO_VERSION="v1.17.1"
curl -L "https://github.com/vmware-tanzu/velero/releases/download/${VELERO_VERSION}/velero-${VELERO_VERSION}-linux-amd64.tar.gz" \
  -o "velero-${VELERO_VERSION}-linux-amd64.tar.gz"
tar -xzf "velero-${VELERO_VERSION}-linux-amd64.tar.gz"
mv "velero-${VELERO_VERSION}-linux-amd64/velero" /usr/local/bin/velero
rm -rf "velero-${VELERO_VERSION}-linux-amd64"
velero version --client-only
```

#### Verify the Snapshot Controller

```bash
kubectl get pods -n kube-system | grep snapshot-controller
```

If no snapshot controller is running, check your RKE2 version. It should be included by default.

#### Create a VolumeSnapshotClass

```bash
cat <<EOF | kubectl apply -f -
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: longhorn-snapshot-vsc
  labels:
    velero.io/csi-volumesnapshot-class: "true"
driver: driver.longhorn.io
deletionPolicy: Delete
parameters:
  type: snap
EOF
```

> Replace `driver.longhorn.io` with your CSI driver if not using Longhorn.

#### Create S3 Credentials

```bash
cat > /tmp/credentials-velero <<EOF
[default]
aws_access_key_id=<YOUR_ACCESS_KEY>
aws_secret_access_key=<YOUR_SECRET_KEY>
EOF
```

#### Install Velero Server

```bash
velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.13.0 \
  --bucket velero \
  --backup-location-config \
    region=us-east-1,s3ForcePathStyle=true,s3Url=https://s3.example.com:8333,checksumAlgorithm="",insecureSkipTLSVerify=true \
  --secret-file /tmp/credentials-velero \
  --features=EnableCSI \
  --use-node-agent \
  --use-volume-snapshots=true \
  --wait

rm -f /tmp/credentials-velero
```

> Replace the `--bucket`, `s3Url`, and credentials with your actual values.

#### Create a Scheduled Backup

```bash
velero schedule create daily-full-backup \
  --schedule="0 2 * * *" \
  --ttl 720h \
  --snapshot-move-data \
  --include-cluster-resources=true \
  --include-namespaces default
```

> Adjust `--include-namespaces` to list the namespaces you want backed up (comma-separated).

#### Verify

```bash
velero backup-location get          # Should show 'Available'
velero schedule get                 # Should show 'daily-full-backup'
kubectl get pods -n velero          # Velero server + node-agent pods
```

#### Common Velero Operations

```bash
# Manual backup
velero backup create manual-backup --from-schedule daily-full-backup --wait

# List backups
velero backup get

# Describe a backup
velero backup describe <backup-name> --details

# Restore from a backup
velero restore create --from-backup <backup-name> --wait
```

### Monitoring Stack

Installs kube-prometheus-stack and Fluent Bit to ship metrics and logs to an **external** monitoring host running Grafana, Loki, and Prometheus.

> Grafana is **not** deployed in-cluster. It runs on the external monitoring host.

#### Prerequisites

- An external host running Loki, Grafana, and Prometheus with remote-write enabled
- A StorageClass that supports `ReadWriteOnce` PVCs (e.g., Longhorn)
- Helm 3 installed (the steps below cover installing it)

#### Install Helm

```bash
HELM_VERSION="3.12.0"
curl -fsSLo "/tmp/helm-v${HELM_VERSION}-linux-amd64.tar.gz" \
  "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz"
tar -xzf "/tmp/helm-v${HELM_VERSION}-linux-amd64.tar.gz" -C /tmp
mv /tmp/linux-amd64/helm /usr/bin/helm
rm -rf /tmp/linux-amd64
```

#### Add Helm Repositories

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
```

#### Create the Monitoring Namespace

```bash
kubectl create namespace monitoring
```

#### Install kube-prometheus-stack

Create a values file. Replace `<MONITORING_HOST>` and `<CLUSTER_NAME>` with your values:

```bash
cat > /tmp/prom-values.yaml <<EOF
grafana:
  enabled: false

prometheus:
  prometheusSpec:
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: longhorn
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 50Gi
    retention: 48h
    retentionSize: "45GB"
    externalLabels:
      cluster: "<CLUSTER_NAME>"
    remoteWrite:
      - url: "http://<MONITORING_HOST>:9090/api/v1/write"
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
EOF

helm upgrade --install kube-prometheus-stack \
  prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --values /tmp/prom-values.yaml \
  --version 69.8.0 \
  --wait --timeout 10m

rm -f /tmp/prom-values.yaml
```

#### Install Fluent Bit

Create a values file. Replace `<MONITORING_HOST>` and `<CLUSTER_NAME>` with your values:

```bash
cat > /tmp/fb-values.yaml <<'FBEOF'
kind: DaemonSet

image:
  repository: cr.fluentbit.io/fluent/fluent-bit
  tag: "4.2.2"

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
        Add     cluster <CLUSTER_NAME>

    [FILTER]
        Name    modify
        Match   host.*
        Add     cluster <CLUSTER_NAME>

  outputs: |
    [OUTPUT]
        Name                 loki
        Match                kube.*
        Host                 <MONITORING_HOST>
        Port                 3100
        Labels               job=fluent-bit, cluster=<CLUSTER_NAME>
        Label_Keys           $kubernetes['namespace_name'],$kubernetes['container_name']
        Remove_Keys          kubernetes,stream
        Auto_Kubernetes_Labels Off
        Line_Format          json
        Retry_Limit          5

    [OUTPUT]
        Name                 loki
        Match                host.*
        Host                 <MONITORING_HOST>
        Port                 3100
        Labels               job=fluent-bit-systemd, cluster=<CLUSTER_NAME>
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

helm upgrade --install fluent-bit \
  fluent/fluent-bit \
  --namespace monitoring \
  --values /tmp/fb-values.yaml \
  --version 0.55.0 \
  --wait --timeout 5m

rm -f /tmp/fb-values.yaml
```

> **Important:** Before running the `helm` commands, replace all occurrences of `<MONITORING_HOST>` and `<CLUSTER_NAME>` in the values files with your actual monitoring host IP/FQDN and desired cluster label.

#### Verify Monitoring

```bash
kubectl -n monitoring get pods
kubectl -n monitoring get servicemonitors

# Verify data is flowing to the external host
curl -s http://<MONITORING_HOST>:3100/loki/api/v1/labels
curl -s http://<MONITORING_HOST>:9090/api/v1/label/__name__/values | grep -c .
```

#### Recommended Grafana Dashboards

Import these dashboards on your external Grafana instance:

| Dashboard ID | Description |
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

---

## Part 3: Multi-Node Clusters

After the first server node is installed, you can join additional nodes as workers (agents) or as additional control-plane servers.

### Finding the Join Token

On the **first server node**, retrieve the join token:

```bash
cat /var/lib/rancher/rke2/server/node-token
```

> If you used a custom `data-dir`, the token is at `<data-dir>/server/node-token`.

You will also need the server's IP address or FQDN (reachable on port 9345).

### Joining a Worker (Agent) Node

On the **new agent node**, perform the host preparation steps from [Step 1](#step-1--prepare-the-host), then:

1. Create the RKE2 config directory:

```bash
mkdir -p /etc/rancher/rke2
```

2. Create the agent configuration:

```bash
cat > /etc/rancher/rke2/config.yaml <<EOF
server: https://<SERVER_FQDN_OR_IP>:9345
token: "<JOIN_TOKEN>"
node-ip: "<AGENT_NODE_IP>"
kubelet-arg:
  - "max-pods=110"
  - "resolv-conf=/etc/resolv.conf"
node-label:
  - "node-role.kubernetes.io/worker=true"
EOF
```

3. Install RKE2 as an agent:

```bash
curl -sfL https://get.rke2.io | INSTALL_RKE2_VERSION="v1.32.5+rke2r1" INSTALL_RKE2_TYPE="agent" INSTALL_RKE2_METHOD="tar" sh -
```

4. Start the agent service:

```bash
systemctl enable rke2-agent.service
systemctl start rke2-agent.service
```

5. Verify on the **server node**:

```bash
kubectl get nodes
```

### Joining an Additional Server Node

On the **new server node**, perform the host preparation steps from [Step 1](#step-1--prepare-the-host), then:

1. Create the RKE2 config directory:

```bash
mkdir -p /etc/rancher/rke2
mkdir -p /var/lib/rancher/rke2/server/manifests
```

2. Create the server join configuration:

```bash
cat > /etc/rancher/rke2/config.yaml <<EOF
server: https://<FIRST_SERVER_FQDN_OR_IP>:9345
token: "<JOIN_TOKEN>"
write-kubeconfig-mode: "0600"
service-node-port-range: "443-40000"
cluster-cidr: "10.42.0.0/16"
service-cidr: "10.43.0.0/16"
advertise-address: "<THIS_NODE_IP>"
node-ip: "<THIS_NODE_IP>"
etcd-extra-env:
  - "ETCD_AUTO_COMPACTION_RETENTION=72h"
  - "ETCD_AUTO_COMPACTION_MODE=periodic"
kube-apiserver-arg:
  - "audit-log-path=/var/log/rke2-apiserver-audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=10"
  - "audit-log-maxsize=200"
kubelet-arg:
  - "max-pods=110"
  - "resolv-conf=/etc/resolv.conf"
EOF
```

3. Install and start RKE2 as a server:

```bash
curl -sfL https://get.rke2.io | INSTALL_RKE2_VERSION="v1.32.5+rke2r1" INSTALL_RKE2_METHOD="tar" sh -
systemctl enable rke2-server.service
systemctl start rke2-server.service
```

4. Set up kubectl access (same as [Step 4](#step-4--set-up-kubectl-access)).

### Control-Plane Tainting

For multi-node clusters, you typically want workloads to run only on agent nodes. To taint the control-plane node(s), add this to the **server** config before starting RKE2:

```yaml
node-taint:
  - "node-role.kubernetes.io/control-plane:NoSchedule"
```

This prevents regular workloads from being scheduled on server nodes.

---

## Part 4: Offline and Air-Gapped Installation

When the target host has no internet access, you must download all required files on a connected machine first, then transfer them.

### Step 1 — Download Everything on an Online Machine

On a machine with internet access and the **same OS** as the target:

#### Download RKE2 Binaries and Images

```bash
RKE2_VERSION="v1.32.5+rke2r1"
# The download URL uses '+' replaced by '%2B'
TRANSLATED_VERSION=$(echo "$RKE2_VERSION" | sed 's/+/%2B/g')
CNI_TYPE="canal"  # Match your chosen CNI

mkdir -p rke2-offline/{binaries,core-images,cni-images}

# Core binaries and installer
curl -sfL "https://github.com/rancher/rke2/releases/download/${TRANSLATED_VERSION}/rke2.linux-amd64.tar.gz" \
  -o rke2-offline/binaries/rke2.linux-amd64.tar.gz
curl -sfL "https://github.com/rancher/rke2/releases/download/${TRANSLATED_VERSION}/sha256sum-amd64.txt" \
  -o rke2-offline/binaries/sha256sum-amd64.txt
curl -sfL https://get.rke2.io -o rke2-offline/binaries/install.sh
chmod +x rke2-offline/binaries/install.sh

# Core container images
curl -sfL "https://github.com/rancher/rke2/releases/download/${TRANSLATED_VERSION}/rke2-images-core.linux-amd64.tar.gz" \
  -o rke2-offline/core-images/rke2-images-core.linux-amd64.tar.gz

# CNI container images
curl -sfL "https://github.com/rancher/rke2/releases/download/${TRANSLATED_VERSION}/rke2-images-${CNI_TYPE}.linux-amd64.tar.gz" \
  -o rke2-offline/cni-images/rke2-images-${CNI_TYPE}.linux-amd64.tar.gz
```

#### Download Optional Component Files

```bash
# Local path provisioner manifest
curl -sfL "https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.32/deploy/local-path-storage.yaml" \
  -o rke2-offline/local-path-storage.yaml

# DNS utility manifest
curl -sfL "https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/admin/dns/dnsutils.yaml" \
  -o rke2-offline/dnsutils.yaml

# Velero CLI
VELERO_VERSION="v1.17.1"
curl -L "https://github.com/vmware-tanzu/velero/releases/download/${VELERO_VERSION}/velero-${VELERO_VERSION}-linux-amd64.tar.gz" \
  -o rke2-offline/velero-${VELERO_VERSION}-linux-amd64.tar.gz

# Helm binary
HELM_VERSION="3.12.0"
curl -fsSLo "rke2-offline/helm-v${HELM_VERSION}-linux-amd64.tar.gz" \
  "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz"

# Monitoring Helm charts (requires helm to be installed on the download machine)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
helm pull prometheus-community/kube-prometheus-stack --version 69.8.0 -d rke2-offline/
helm pull fluent/fluent-bit --version 0.55.0 -d rke2-offline/
```

#### Create the Archive

```bash
tar -czf rke2-save.tar.gz rke2-offline/
```

### Step 2 — Transfer Files to the Air-Gapped Host

```bash
scp rke2-save.tar.gz user@air-gapped-host:~/
```

### Step 3 — Install from Local Files

On the air-gapped host:

```bash
tar -xzf rke2-save.tar.gz
cd rke2-offline
```

1. Perform all host preparation from [Step 1](#step-1--prepare-the-host).

2. Create the RKE2 config file as described in [Step 2](#step-2--configure-rke2).

3. Copy image archives to the RKE2 agent images directory:

```bash
mkdir -p /var/lib/rancher/rke2/agent/images
cp core-images/rke2-images-core.linux-amd64.tar.gz /var/lib/rancher/rke2/agent/images/
cp cni-images/rke2-images-canal.linux-amd64.tar.gz /var/lib/rancher/rke2/agent/images/
```

4. Install RKE2 from local binaries:

```bash
INSTALL_RKE2_ARTIFACT_PATH="$(pwd)/binaries" \
  INSTALL_RKE2_VERSION="v1.32.5+rke2r1" \
  sh binaries/install.sh
```

5. Start RKE2:

```bash
systemctl enable rke2-server.service
systemctl start rke2-server.service
```

6. Set up kubectl access as described in [Step 4](#step-4--set-up-kubectl-access).

### Air-Gapped Optional Components

- **Local Path Provisioner:** Use the local manifest file instead of the URL:
  ```bash
  kubectl apply -f rke2-offline/local-path-storage.yaml
  ```

- **DNS Utility:** Use the local manifest:
  ```bash
  kubectl apply -f rke2-offline/dnsutils.yaml
  ```

- **Velero:** Install the CLI from the local tarball, then proceed with the Velero install steps. The `velero install` command will pull images from your private registry if configured.

- **Monitoring:** Install Helm from the local tarball, then use the local chart `.tgz` files instead of the remote Helm repos:
  ```bash
  # Install Helm
  tar -xzf rke2-offline/helm-v3.12.0-linux-amd64.tar.gz -C /tmp
  mv /tmp/linux-amd64/helm /usr/bin/helm

  # Install kube-prometheus-stack from local chart
  helm upgrade --install kube-prometheus-stack \
    rke2-offline/kube-prometheus-stack-69.8.0.tgz \
    --namespace monitoring --create-namespace \
    --values /tmp/prom-values.yaml \
    --wait --timeout 10m

  # Install Fluent Bit from local chart
  helm upgrade --install fluent-bit \
    rke2-offline/fluent-bit-0.55.0.tgz \
    --namespace monitoring \
    --values /tmp/fb-values.yaml \
    --wait --timeout 5m
  ```

---

## Part 5: Private Registry (Mirror)

You can push all RKE2 and component images to a private OCI registry, then configure RKE2 to pull from it instead of the public internet. This is useful for air-gapped environments or for centralized image management.

> **Prerequisite:** The `/rancher` project path must pre-exist on the target registry (e.g., `my.registry.com:443/rancher`).

### Pushing Images to a Registry

To push images, you need a tool that can pull from public registries and push to your private registry. The rke2-installer project includes `image_pull_push.sh` for this purpose, but you can also use tools like `skopeo` or `crane`.

The images that need to be pushed include:
- **RKE2 core images** (listed in `rke2-images-core.linux-amd64.txt` from the RKE2 release)
- **RKE2 CNI images** (listed in `rke2-images-<cni>.linux-amd64.txt`)
- **Utility images** (local-path-provisioner, dnsutils)
- **Velero images** (if using Velero): `velero/velero:<version>`, `velero/velero-plugin-for-aws:<version>`
- **Monitoring images** (if using monitoring): extracted from the Helm chart templates

### Installing with a Registry Mirror

Configure RKE2 to use your private registry as a pull-through mirror.

1. Retrieve the registry's TLS certificate:

```bash
REGISTRY="my.registry.com"
REGISTRY_PORT="443"
CERTS_DIR="/etc/rancher/rke2/certs.d/${REGISTRY}:${REGISTRY_PORT}"
mkdir -p "$CERTS_DIR"

openssl s_client -showcerts -connect "${REGISTRY}:${REGISTRY_PORT}" < /dev/null 2>/dev/null \
  | openssl x509 -outform PEM > "$CERTS_DIR/ca.crt"
```

2. Create the registries configuration:

```bash
cat > /etc/rancher/rke2/registries.yaml <<EOF
configs:
  ${REGISTRY}:${REGISTRY_PORT}:
    auth:
      username: "<REGISTRY_USERNAME>"
      password: "<REGISTRY_PASSWORD>"
    tls:
      ca_file: "${CERTS_DIR}/ca.crt"
mirrors:
  docker.io:
    endpoint:
      - "https://${REGISTRY}:${REGISTRY_PORT}"
  quay.io:
    endpoint:
      - "https://${REGISTRY}:${REGISTRY_PORT}"
  registry.k8s.io:
    endpoint:
      - "https://${REGISTRY}:${REGISTRY_PORT}"
  cr.fluentbit.io:
    endpoint:
      - "https://${REGISTRY}:${REGISTRY_PORT}"
  ${REGISTRY}:${REGISTRY_PORT}:
    endpoint:
      - "https://${REGISTRY}:${REGISTRY_PORT}"
EOF
```

3. Start (or restart) RKE2. It will now pull images from your private registry.

### Registry Configuration Details

The `registries.yaml` file configures mirrors for all common upstream registries:

| Upstream Registry | Used By |
|---|---|
| `docker.io` | RKE2 core images, Velero |
| `quay.io` | Some RKE2 components |
| `registry.k8s.io` | Kubernetes system images |
| `cr.fluentbit.io` | Fluent Bit (monitoring) |

---

## Part 6: TLS SAN Configuration

If you access the Kubernetes API through a load balancer, DNS name, or any address other than the node's primary IP, add it as a TLS SAN (Subject Alternative Name).

Add the following to your `/etc/rancher/rke2/config.yaml` **before** starting RKE2:

```yaml
tls-san:
  - "my.rke2-cluster.lab"
```

You can add multiple entries:

```yaml
tls-san:
  - "my.rke2-cluster.lab"
  - "192.168.1.100"
```

This applies to both the initial server install and server join configurations.

---

## Part 7: Uninstalling RKE2

RKE2 provides a built-in uninstall script:

```bash
# For server nodes
/usr/local/bin/rke2-uninstall.sh

# For agent nodes
/usr/local/bin/rke2-agent-uninstall.sh
```

After running the uninstall script, clean up any remaining files:

```bash
# Remove kubeconfig
rm -rf /root/.kube
rm -rf /home/<YOUR_USER>/.kube

# Remove command symlinks
rm -f /usr/bin/kubectl /usr/bin/ctr /usr/bin/crictl

# Unset environment
unset KUBECONFIG
```

If you used custom data paths, remove those directories as well:

```bash
# Only if you used non-default paths — adjust as needed
# rm -rf /custom/rke2/data
# rm -rf /custom/kubelet/data
# rm -rf /custom/pvc/data
```

---

## Appendix: Configuration Reference

### RKE2 config.yaml Options Used in This Guide

| Setting | Description |
|---|---|
| `cni` | CNI plugin: `canal`, `calico`, `cilium`, or `none` |
| `write-kubeconfig-mode` | File permissions for the generated kubeconfig |
| `service-node-port-range` | Range for NodePort services |
| `cluster-cidr` | Pod network CIDR (default: `10.42.0.0/16`) |
| `service-cidr` | Service network CIDR (default: `10.43.0.0/16`) |
| `advertise-address` | IP address the API server advertises |
| `node-ip` | IP address used for inter-node communication |
| `data-dir` | Custom data directory (default: `/var/lib/rancher/rke2`) |
| `server` | URL of the server to join (`https://<server>:9345`) |
| `token` | Shared secret for joining a cluster |
| `tls-san` | Additional SANs for the API server certificate |
| `node-taint` | Taints to apply to the node |
| `node-label` | Labels to apply to the node |
| `disable` | List of built-in components to disable |
| `enable-servicelb` | Enable the Klipper service LoadBalancer |
| `profile` | Security profile (e.g., `cis`) |
| `etcd-extra-env` | Extra environment variables for etcd |
| `kube-apiserver-arg` | Extra arguments for the API server |
| `kubelet-arg` | Extra arguments for the kubelet |

### Custom Data Paths

You can change where RKE2 stores its data by adding these to your config:

```yaml
# Custom RKE2 data directory (default: /var/lib/rancher/rke2)
data-dir: "/mnt/data/rke2"

# Custom kubelet root directory
kubelet-arg:
  - "root-dir=/mnt/data/kubelet"
```

Make sure the directories exist before starting RKE2:

```bash
mkdir -p /mnt/data/rke2
mkdir -p /mnt/data/kubelet
```

### Environment Variables for RKE2 Installer

When using the `curl | sh` install method, these environment variables control behavior:

| Variable | Description |
|---|---|
| `INSTALL_RKE2_VERSION` | RKE2 version to install |
| `INSTALL_RKE2_TYPE` | Node type: empty for server, `agent` for agent |
| `INSTALL_RKE2_METHOD` | Install method: `tar` (recommended) |
| `INSTALL_RKE2_ARTIFACT_PATH` | Local path for offline binary installation |
