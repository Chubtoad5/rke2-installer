# rke2-installer
Simple RKE2 installer for Ubuntu based systems

## Key Features
- Installs a Rancher RKE2 cluster as a server or agent
- Supports joining an existing RKE2 cluster that was created from this script
- Supports offline-bundle creation for air-gapped deployment
- Supports pulling images localy and pushing images to a target OCI registry
- Supports Ingress, Klipper LB, Local Path Storage
- Supports installing K8s DNS utility
- Supports tls-SAN
- Supports CIS hardening profile, including host hardening configuration
- Supports uninstalling the agent/server running on the local host

## Installation and Usage
- Download rke2_installer.sh and make it executable
```
git clone https://github.com/Chubtoad5/rke2-installer.git
cd rke2-installer
```
```
chmod +x rke2_installer.sh
```
- (Optional) edit rke2_installer.sh variables in USER DEFINED VARIABLES section
- Run script as sudo or root user
```
Usage: $SCRIPT_NAME [install] [unintall] [save] [push] [join [server|agent] server-fqdn join-token-string] [registry:port username password] [tls-san [server-fqdn-ip]] 

- This script must be run with root privileges.
- At least one parameter of [install], [uninstall], [save], [push], or [join] must be specified. 
- When [push] is specified, [registry:port username password] must be provided. The correct project path must exist on the registry (i.e. my.registry.com:443/rancher). See README.md for details.
- When [registry:port username password] is specified with [install] or [join], rke2 will use the private registry as a mirror to pull images.
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
```

## Coming Soon
- Upgrade to new RKE2 version