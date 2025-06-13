# rke2-installer
Simple RKE2 installer for Ubuntu based systems

## Key Features
- Installs a Rancher RKE2 cluster as a single-node control-plane,etcd,master, allowing workloads to be scheduled
- When nginx-ingress is not installed, a MetalLB LoadBalancer will be installed instead
- Rancher's local-path-storage manifest will be applied by default, unless disabled
- Supports installing and uninstalling the RKE2 server
- Supports installing a user defined helm chart
- Supports offline package preparation (Comming soon!)
- install-helm-chart function currently defaults to installing Dell Automation Platform

## Installation and Usage
- Download install_rke2.sh
```
chmod +x install_rke2.sh
```
- (Optional) edit install_rke2.sh variables in USER DEFINED VARIABLES section
- Run script as sudo or root user
```
sudo ./install_rke2.sh [parameter]

[Parameters]            | [Description]
help                    | Display this help message
install-server          | Installs RKE2 from the internet
uninstall-server        | Uninstalls RKE2
offline-prep            | Prepares an offline package
install-helm-chart      | Installs helm chart from variables
```

## Coming soon
- host resource and connectivty pre-checks
- better CIS hardening
- DNS troubleshooting utility
- AIRGAPPED installation logic
- Offline package generation
