#!/bin/bash
# Spec 29: the RKE2 versions this release supports, fresh installs only, no upgrades (the upgrade chain between minors is
# a one-time bench in the spec that adds each minor, never CI). On a throwaway host, as root, from the repo root. Runs
# after 30-functional.sh, which leaves the host uninstalled.
#
# Each 'verified' version in tests/rke2-versions.conf (today v1.35.10) is installed from a save bundle: the node is Ready,
# every pod is ready, CoreDNS answers as kube-dns, and a request reaches an app through the built-in ingress. Then
# INSTALL_INGRESS=false: no ingress controller, and nothing answers on 80 or 443. The default (v1.36.6) is covered by
# 10-30, so for it only a bundle's 1.36 cases run: INSTALL_INGRESS=false turns off Traefik (R17), and
# INGRESS_CONTROLLER=ingress-nginx installs from the bundle's own ingress-nginx images and serves the nginx class (R20, R24).
# The bundles come from GitHub, so they don't count against Docker Hub's pull limit; the test app is busybox.
set -uo pipefail
REPO=$PWD
fail=0
ok()   { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; fail=1; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
IP=${CI_CLONE_IP:-$(hostname -I | awk '{print $1}')}
unset RKE2_VERSION INGRESS_CONTROLLER INSTALL_INGRESS CNI_TYPE
# A smaller bundle and install: no Velero or monitoring images, no local-path or DNS utility.
export DEBUG=0 PUSH_SAVE_VELERO=false PUSH_SAVE_MONITORING=false INSTALL_LOCAL_PATH_PROVISIONER=false INSTALL_DNS_UTILITY=false
K="/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml"
. /etc/os-release
if [[ "$ID" =~ ^(sles|opensuse-leap)$ && "$(getenforce 2>/dev/null)" == Enforcing ]]; then export RKE2_SELINUX_FALLBACK=permissive; fi
if ! command -v iptables >/dev/null 2>&1; then
  case "$ID" in
    ubuntu|debian) DEBIAN_FRONTEND=noninteractive apt-get install -y iptables >/dev/null 2>&1 ;;
    sles|opensuse-leap) zypper --non-interactive install -y iptables >/dev/null 2>&1 ;;
    *) dnf install -y iptables >/dev/null 2>&1 ;;
  esac
fi
show() { tail -8 "$1" | cut -c1-170; }
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
ready() { $K get nodes --no-headers 2>/dev/null | grep -qw Ready; }
pods_up() { local all; all=$($K get pods -A --no-headers 2>/dev/null) || return 1; [ -n "$all" ] && ! grep -vqE 'Running|Completed' <<< "$all"; }
not_up() { $K get pods -A --no-headers 2>/dev/null | grep -vE 'Running|Completed' | head -4 | awk '{print $2, $4}' | tr '\n' ';'; }
dns_ok() { [ -n "$($K -n kube-system get endpoints kube-dns -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)" ]; }
ingress_pods() { $K get pods -A --no-headers 2>/dev/null | grep -E 'traefik|ingress-nginx-controller' | grep -v helm-install; }
# port_closed <port>: nothing answers on this host's address (a hostPort is DNAT in iptables, so ss can't see it)
port_closed() { local c; c=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "$1://$IP/" 2>/dev/null); [ "$c" = 000 ]; }
web_ok() { [ "$(curl -s -m 5 -H 'Host: web.ci.test' "http://$IP/")" = ci-v-web ]; }
# app <ingress class>: a web app behind a Service and an Ingress of that class
app() {
  $K create namespace ci-v >/dev/null 2>&1
  $K apply -n ci-v -f - > "$W/k" 2>&1 <<EOF
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
          command: [sh, -c, "mkdir -p /www && echo ci-v-web > /www/index.html && exec httpd -f -p 8080 -h /www"]
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
  ingressClassName: $1
  rules:
    - host: web.ci.test
      http: { paths: [{ path: /, pathType: Prefix, backend: { service: { name: web, port: { number: 80 } } } }] }
EOF
}
# bundle <version>: save a bundle for it, and unpack it in $W/<version>/ag
bundle() {
  local d="$W/$1"
  mkdir -p "$d/save" "$d/ag"; cp "$REPO/rke2_installer.sh" "$d/save/"
  if (cd "$d/save" && RKE2_VERSION=$1 ./rke2_installer.sh save > o 2>&1) && [ -s "$d/save/rke2-save.tar.gz" ]; then
    ok "save a bundle for $1 ($(du -h "$d/save/rke2-save.tar.gz" | cut -f1))"
  else
    bad "save a bundle for $1"; show "$d/save/o"; return 1
  fi
  tar -xzf "$d/save/rke2-save.tar.gz" -C "$d/ag" && rm -f "$d/save/rke2-save.tar.gz"
  grep -qx "# RKE2 Version: $1" "$d/ag/rke2-save-version.txt" && ok "the bundle says it is for $1" || bad "the bundle's version: $(grep 'RKE2 Version' "$d/ag/rke2-save-version.txt")"
}
# from_bundle <version> <label> [settings...]: install from the bundle with no RKE2_VERSION set (it comes from the bundle)
from_bundle() {
  local v=$1 label=$2; shift 2
  if (cd "$W/$v/ag" && env "$@" ./rke2_installer.sh install > o 2>&1); then ok "$v, $label: install from the bundle"
  else bad "$v, $label: install from the bundle"; show "$W/$v/ag/o"; return 1; fi
  grep -q "RKE2_VERSION: $v" "$W/$v/ag/o" && ok "$v, $label: it took $v from the bundle" || bad "$v, $label: the run's RKE2_VERSION isn't $v"
  within 300 ready && ok "$v, $label: the node is Ready" || bad "$v, $label: the node isn't Ready"
  [ "$($K get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}' 2>/dev/null)" = "$v" ] && ok "$v, $label: the node runs $v" \
    || bad "$v, $label: the node runs $($K get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}' 2>&1)"
}
off_checks() { # off_checks <version>: INSTALL_INGRESS=false
  local v=$1
  within 300 pods_up && ok "$v, ingress off: every pod is ready" || bad "$v, ingress off: pods not ready: $(not_up)"
  sleep 30
  [ -z "$(ingress_pods)" ] && ok "$v, ingress off: no ingress controller runs" || bad "$v, ingress off: $(ingress_pods | awk '{print $2}' | tr '\n' ' ')"
  port_closed http && port_closed https && ok "$v, ingress off: nothing answers on 80 or 443" || bad "$v, ingress off: something answers on 80 or 443"
}
uninstall() { # uninstall <version>
  (cd "$W/$1/ag" && ./rke2_installer.sh uninstall > o 2>&1) && ok "$1: uninstall" || { bad "$1: uninstall"; show "$W/$1/ag/o"; }
  systemctl is-active --quiet rke2-server && bad "$1: rke2-server is still running" || true
}

conf="$REPO/tests/rke2-versions.conf"
default=$(grep '|default$' "$conf" | cut -d'|' -f1)
verified=$(grep '|verified$' "$conf" | cut -d'|' -f1)
[ -n "$default" ] && ok "versions: default $default; verified: $(echo $verified)" || bad "no default in $conf"

for v in $verified; do
  echo "=== $v (verified): fresh install from a bundle, then with the ingress off"
  bundle "$v" || continue
  from_bundle "$v" "default ingress" || { uninstall "$v"; continue; }
  within 300 pods_up && ok "$v: every pod is ready" || bad "$v: pods not ready: $(not_up)"
  within 120 dns_ok && ok "$v: CoreDNS answers as kube-dns" || bad "$v: the kube-dns Service has no endpoints"
  ic=nginx; grep -q 'v1\.3[6-9]' <<< "$v" && ic=traefik
  within 60 app "$ic" && ok "$v: an app behind an Ingress of class $ic" || { bad "$v: apply the app"; tail -3 "$W/k"; }
  $K wait -n ci-v --for=condition=Available deployment/web --timeout=300s >/dev/null 2>&1 || bad "$v: the app isn't up"
  within 180 web_ok && ok "$v: a request through the ingress reaches the app" || bad "$v: the ingress: '$(curl -s -m 5 -H 'Host: web.ci.test' "http://$IP/" | head -c 100)'"
  uninstall "$v"
  from_bundle "$v" "ingress off" INSTALL_INGRESS=false && off_checks "$v"
  uninstall "$v"
done

echo "=== $default (the default) from a bundle: INSTALL_INGRESS=false (R17), INGRESS_CONTROLLER=ingress-nginx (R20, R24)"
if bundle "$default"; then
  tar -tzf "$W/$default/ag/rke2-install/rke2-ingress-images/rke2-ingress-nginx-images.tar.gz" 2>/dev/null | grep -q 'rke2-images-ingress-nginx.linux-amd64.tar.gz' \
    && ok "$default: the bundle carries ingress-nginx's images" || bad "$default: the bundle has no ingress-nginx images"
  if from_bundle "$default" "ingress off" INSTALL_INGRESS=false; then
    off_checks "$default"
    grep -qx '  - rke2-traefik' /etc/rancher/rke2/config.yaml && ok "$default, ingress off: config.yaml disables rke2-traefik" || bad "$default, ingress off: config.yaml doesn't disable rke2-traefik"
  fi
  uninstall "$default"
  if from_bundle "$default" "ingress-nginx" INGRESS_CONTROLLER=ingress-nginx; then
    grep -q 'deprecated' "$W/$default/ag/o" && ok "$default, ingress-nginx: the install warns it's deprecated" || bad "$default, ingress-nginx: no deprecation warning"
    [ -f /var/lib/rancher/rke2/agent/images/rke2-images-ingress-nginx.linux-amd64.tar.gz ] && ok "$default, ingress-nginx: its images went into agent/images" || bad "$default, ingress-nginx: its images aren't in agent/images"
    within 300 pods_up && ok "$default, ingress-nginx: every pod is ready" || bad "$default, ingress-nginx: pods not ready: $(not_up)"
    ingress_pods | grep -q ingress-nginx-controller && ok "$default, ingress-nginx: the ingress-nginx controller runs" || bad "$default, ingress-nginx: no ingress-nginx controller"
    ! ingress_pods | grep -q traefik && ok "$default, ingress-nginx: Traefik doesn't" || bad "$default, ingress-nginx: Traefik runs too"
    # Its images came from the bundle: the controller's image was already there, not pulled
    ev=$($K get events -A --field-selector reason=Pulling --no-headers 2>/dev/null | grep -E 'nginx-ingress-controller|kube-webhook-certgen')
    [ -z "$ev" ] && ok "$default, ingress-nginx: none of its images was pulled from a registry" || bad "$default, ingress-nginx: pulled: $(cut -c1-160 <<< "$ev" | head -2)"
    within 60 app nginx && ok "$default, ingress-nginx: an app behind an Ingress of class nginx" || { bad "$default, ingress-nginx: apply the app"; tail -3 "$W/k"; }
    $K wait -n ci-v --for=condition=Available deployment/web --timeout=300s >/dev/null 2>&1 || bad "$default, ingress-nginx: the app isn't up"
    within 180 web_ok && ok "$default, ingress-nginx: a request through the ingress reaches the app" || bad "$default, ingress-nginx: the ingress: '$(curl -s -m 5 -H 'Host: web.ci.test' "http://$IP/" | head -c 100)'"
  fi
  uninstall "$default"
fi
systemctl is-active --quiet rke2-server && bad "rke2-server is still running" || ok "rke2-server is gone"
echo "=== exit $fail"; exit $fail
