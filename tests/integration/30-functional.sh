#!/bin/bash
# What a cluster is for, on a throwaway host, as root, from the repo root (spec 09's C2, in the chubtoad-automation project):
# the default install with local-path and the DNS utility, a pod with a volume, a Service by name, a request through the
# ingress, a changed config refused without RKE2_RECONFIGURE, -tls-san for a DNS name with certificate checks on, Calico as
# well as Canal, then a push to a registry and an install from it. Runs after 20-day2.sh, which leaves the host uninstalled.
# The DNS name and the registry come from CI's lab run (CI_SUPPORT_DNS_NAME, CI_SUPPORT_REGISTRY and an account of this
# job's own); without them those parts are skipped. Test pods use busybox, so nothing here installs a tool on the host.
set -uo pipefail
REPO=$PWD
fail=0
ok()   { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; fail=1; }
skip() { echo "SKIP  $1"; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
cp "$REPO/rke2_installer.sh" .; chmod +x rke2_installer.sh
IP=${CI_CLONE_IP:-$(hostname -I | awk '{print $1}')}
unset INSTALL_LOCAL_PATH_PROVISIONER INSTALL_DNS_UTILITY CNI_TYPE MAX_PODS
export DEBUG=0
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml"
show() { tail -8 "$W/o" | cut -c1-170; }
# events: the namespace's latest events, so a pod that never started says why (an image pull refused, a volume not bound)
events() { $K get events -n "${1:-ci-c2}" --sort-by=.lastTimestamp 2>/dev/null | tail -6 | cut -c1-200; }
ready() { for _ in $(seq 1 60); do $K get nodes --no-headers 2>/dev/null | grep -qw Ready && return 0; sleep 5; done; return 1; }
# within <seconds> <command...>: true once the command is, checking every 3 seconds
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
. /etc/os-release
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then export RKE2_SELINUX_FALLBACK=permissive; fi
# 10-lifecycle.sh installs iptables where it's missing. Run alone, do it here.
if ! command -v iptables >/dev/null 2>&1; then
  case "$ID" in
    ubuntu|debian) DEBIAN_FRONTEND=noninteractive apt-get install -y iptables >/dev/null 2>&1 ;;
    sles|opensuse-leap) zypper --non-interactive install -y iptables >/dev/null 2>&1 ;;
    *) dnf install -y iptables >/dev/null 2>&1 ;;
  esac
fi
# workload: a pod that writes to a local-path volume, one that reads it back, and a web app behind a Service and an Ingress.
workload() {
  $K create namespace ci-c2 >/dev/null 2>&1
  $K apply -n ci-c2 -f - > "$W/k" 2>&1 <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: data }
spec: { accessModes: [ReadWriteOnce], storageClassName: local-path, resources: { requests: { storage: 64Mi } } }
---
apiVersion: v1
kind: Pod
metadata: { name: writer }
spec:
  restartPolicy: Never
  containers:
    - { name: w, image: busybox:1.36, command: [sh, -c, "echo ci-c2-volume > /data/f && sync"], volumeMounts: [{ name: d, mountPath: /data }] }
  volumes: [{ name: d, persistentVolumeClaim: { claimName: data } }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: web }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec:
      containers:
        - name: web
          image: busybox:1.36
          command: [sh, -c, "mkdir -p /www && echo ci-c2-web > /www/index.html && exec httpd -f -p 8080 -h /www"]
          ports: [{ containerPort: 8080 }]
---
apiVersion: v1
kind: Service
metadata: { name: web }
spec: { selector: { app: web }, ports: [{ port: 80, targetPort: 8080 }] }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: { name: web }
spec:
  ingressClassName: nginx
  rules:
    - host: web.ci.test
      http: { paths: [{ path: /, pathType: Prefix, backend: { service: { name: web, port: { number: 80 } } } }] }
EOF
}
pod_done() { [ "$($K get pod -n ci-c2 "$1" -o jsonpath='{.status.phase}' 2>/dev/null)" = Succeeded ]; }
web_ok() { [ "$(curl -s -m 5 -H 'Host: web.ci.test' "http://$IP/")" = ci-c2-web ]; }
dns_ok() { $K exec -n default dnsutils -- nslookup web.ci-c2.svc.cluster.local 2>/dev/null | grep -q "^Name:"; }
pod_end() { [[ "$($K get pod -n ci-c2 "$1" -o jsonpath='{.status.phase}' 2>/dev/null)" =~ ^(Succeeded|Failed)$ ]]; }
# A pod that fetches the app through its Service's name. Not "kubectl run -i": a pod that quick can end before kubectl
# attaches, and its output is lost.
svc_ok() {
  $K delete pod -n ci-c2 "probe$1" --ignore-not-found >/dev/null 2>&1
  $K run -n ci-c2 "probe$1" --restart=Never --image=busybox:1.36 -- sh -c 'for i in 1 2 3 4 5 6; do wget -qO- -T 5 http://web.ci-c2 && exit 0; sleep 5; done; exit 1' >/dev/null 2>&1
  within 120 pod_end "probe$1" && [ "$($K logs -n ci-c2 "probe$1" 2>/dev/null)" = ci-c2-web ]
}

echo "=== The default install: Canal, local-path and the DNS utility"
./rke2_installer.sh install > "$W/o" 2>&1 && ok "install" || { bad "install"; show; }
ready && ok "the node is Ready" || bad "the node isn't Ready"
$K get storageclass local-path >/dev/null 2>&1 && ok "the local-path StorageClass is there" || bad "no local-path StorageClass"
$K wait -n default --for=condition=Ready pod/dnsutils --timeout=300s >/dev/null 2>&1 && ok "the DNS utility pod is ready" || bad "the DNS utility pod isn't ready"
workload && ok "apply the test workload" || { bad "apply the test workload"; tail -5 "$W/k"; }
within 300 pod_done writer && ok "a pod writes to a local-path volume" || { bad "the writer pod: $($K get pod -n ci-c2 writer --no-headers 2>&1)"; events; events local-path-storage; }
$K run -n ci-c2 reader --restart=Never --image=busybox:1.36 --overrides='{"spec":{"containers":[{"name":"reader","image":"busybox:1.36","command":["cat","/data/f"],"volumeMounts":[{"name":"d","mountPath":"/data"}]}],"volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"data"}}]}}' >/dev/null 2>&1
within 180 pod_done reader && [ "$($K logs -n ci-c2 reader 2>/dev/null)" = ci-c2-volume ] && ok "another pod reads the file back from the volume" \
  || { bad "the reader pod: $($K logs -n ci-c2 reader 2>&1 | tail -1)"; events; }
$K wait -n ci-c2 --for=condition=Available deployment/web --timeout=300s >/dev/null 2>&1 && ok "the web app is up" || { bad "the web app isn't up"; events; }
within 60 dns_ok && ok "the cluster DNS resolves a Service by name" || bad "nslookup web.ci-c2.svc.cluster.local failed"
svc_ok a && ok "a pod reaches the Service by name" || bad "a pod can't reach http://web.ci-c2"
within 180 web_ok && ok "a request through the ingress reaches the app" || bad "the ingress: '$(curl -s -m 5 -H 'Host: web.ci.test' "http://$IP/" | head -c 120)'"

echo "=== A changed config is refused without RKE2_RECONFIGURE"
sum=$(md5sum < /etc/rancher/rke2/config.yaml)
if MAX_PODS=120 ./rke2_installer.sh install > "$W/o" 2>&1; then bad "a changed config was applied without RKE2_RECONFIGURE"
elif grep -q "RKE2_RECONFIGURE=true" "$W/o" && [ "$(md5sum < /etc/rancher/rke2/config.yaml)" = "$sum" ]; then
  ok "a changed config is refused, names RKE2_RECONFIGURE, and leaves config.yaml alone"
else bad "the refusal is wrong"; show; fi
systemctl is-active -q rke2-server && ok "rke2-server stayed up" || bad "rke2-server is down"

echo "=== -tls-san for a name in DNS, with certificate checks on"
if [ -z "${CI_SUPPORT_DNS_NAME:-}" ]; then
  skip "the -tls-san check: no CI_SUPPORT_DNS_NAME (CI's lab runs give one)"
else
  N=$CI_SUPPORT_DNS_NAME
  [ "$(getent hosts "$N" | awk '{print $1}')" = "$IP" ] && ok "this host resolves $N to itself" || bad "$N resolves to '$(getent hosts "$N")'"
  out=$($K --server "https://$N:6443" get --raw /readyz 2>&1)
  [[ "$out" == *x509* || "$out" == *certificate* ]] && ok "before -tls-san, the API by that name fails its certificate check" || bad "before -tls-san: $out"
  RKE2_RECONFIGURE=true ./rke2_installer.sh install -tls-san "$N" > "$W/o" 2>&1 && ok "re-run with -tls-san and RKE2_RECONFIGURE=true" || { bad "re-run with -tls-san"; show; }
  ready && within 120 sh -c "$K --server https://$N:6443 get --raw /readyz >/dev/null 2>&1" \
    && ok "the API answers by name, with its certificate checked" || bad "by name after -tls-san: $($K --server "https://$N:6443" get --raw /readyz 2>&1 | tail -1)"
  within 120 web_ok && ok "the workload survived the restart" || bad "the ingress after the restart"
fi
./rke2_installer.sh uninstall > "$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; show; }

echo "=== Calico"
CNI_TYPE=calico ./rke2_installer.sh install > "$W/o" 2>&1 && ok "install with CNI_TYPE=calico" || { bad "install with CNI_TYPE=calico"; show; }
ready && ok "the node is Ready" || bad "the node isn't Ready"
$K get pods -A --no-headers 2>/dev/null | grep -q calico-node && ok "Calico runs" || bad "no calico-node pod"
# The ingress controller's admission webhook can still be starting: give the apply a minute.
within 60 workload && ok "apply the test workload on Calico" || { bad "apply the test workload on Calico"; tail -5 "$W/k"; }
$K wait -n ci-c2 --for=condition=Available deployment/web --timeout=300s >/dev/null 2>&1 && ok "the web app is up on Calico" || { bad "the web app isn't up on Calico"; events; }
svc_ok b && ok "a pod reaches the Service by name on Calico" || bad "a pod can't reach the Service on Calico"
within 180 web_ok && ok "the ingress works on Calico" || bad "the ingress on Calico"
./rke2_installer.sh uninstall > "$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; show; }

echo "=== Push to a registry, then install from it"
if [ -z "${CI_SUPPORT_REGISTRY:-}" ]; then
  skip "the registry checks: no CI_SUPPORT_REGISTRY (CI's lab runs give one)"
else
  R=$CI_SUPPORT_REGISTRY RU=$CI_SUPPORT_REGISTRY_USER RP=$CI_SUPPORT_REGISTRY_PASSWORD
  h() { curl -sk -m 20 -u "$RU:$RP" -H 'Content-Type: application/json' "$@"; }
  # images-pull-push keeps each image's path, so Harbor needs a project per namespace: rke2's push also carries the
  # monitoring and Velero images. library comes with Harbor. A namespace added to push's lists shows up below as a
  # failed push that names the image.
  for p in rancher e2e-test-images bats fluent grafana ingress-nginx kiwigrid kube-state-metrics prometheus prometheus-operator velero; do
    c=$(h -o /dev/null -w '%{http_code}' -X POST "https://$R/api/v2.0/projects" -d "{\"project_name\":\"$p\",\"metadata\":{\"public\":\"false\"}}")
    [[ "$c" == 201 || "$c" == 409 ]] || bad "create Harbor project $p: $c"
  done
  ./rke2_installer.sh push -registry "$R" "$RU" "$RP" > "$W/o" 2>&1 && ok "push to the registry" || { bad "push to the registry"; show; }
  n=$(h "https://$R/api/v2.0/projects/rancher" | grep -o '"repo_count":[0-9]*' | cut -d: -f2)
  [ "${n:-0}" -ge 10 ] && ok "the registry has $n rancher repositories" || bad "the registry has ${n:-no} rancher repositories"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  ./rke2_installer.sh install -registry "$R" "$RU" "$RP" > "$W/o" 2>&1 && ok "install from the registry" || { bad "install from the registry"; show; }
  ready && ok "the node is Ready" || bad "the node isn't Ready"
  grep -q "https://$R" /etc/rancher/rke2/registries.yaml && ok "registries.yaml points docker.io at the registry" || bad "registries.yaml doesn't name the registry"
  # Harbor's own log: this job's account pulled the cluster's images. The account is this job's alone, so other distros'
  # pulls don't count, and containerd's fallback to the public registries can't pass for it.
  pulls() { h "https://$R/api/v2.0/auditlog-exts?page_size=100&q=operation%3Dpull%2Cusername%3D$RU%2Cop_time%3D%5B$since~$(date -u +%Y-%m-%dT%H:%M:%SZ)%5D" \
    | grep -o '"resource":"rancher/[^"@:]*' | sort -u | wc -l; }
  n=$(pulls)
  [ "$n" -ge 5 ] && ok "Harbor's audit log has pulls of $n rancher images by this job's account" || bad "Harbor's audit log has pulls of $n rancher images by this job's account"
  ./rke2_installer.sh uninstall > "$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; show; }
fi
systemctl is-active --quiet rke2-server && bad "rke2-server is still running" || ok "rke2-server is gone"
echo "=== exit $fail"; exit $fail
