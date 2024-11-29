# How to deploy on LXD

This guide goes shows you how to deploy Charmed OpenSearch on [LXD](https://ubuntu.com/server/docs/lxd-containers), Canonical’s lightweight container hypervisor.

## Prerequisites

* Charmed OpenSearch VM Revision 108+
* Fulfil the [system requirements](/t/14565)

## Summary
* [Configure LXD](#configure-lxd)
* [Prepare Juju](#prepare-juju)
* [Deploy OpenSearch](#deploy-opensearch)

---

## Configure LXD

This subsection assumes you are running on a fresh Ubuntu installation. In this case, we need to either install or refresh the current LXD snap and initialize it.

### Install

LXD is pre-installed on Ubuntu images. You can verify if you have it install with the command `which lxd`. 

If not installed, the `lxd` package can be installed using

```shell
sudo snap install lxd --channel=latest/stable  # latest stable will settle for 5.21+ version
```

### Refresh and initialize

Once installed, refresh the `lxd` snap:

```shell
sudo snap refresh lxd --channel=latest/stable  # latest stable will settle for 5.21+ version
lxd 5.21.1-2d13beb from Canonical✓ refreshed
```

Initialize your setup. In the steps below, LXD is initialized to the "dir" storage backend. We can keep that or selecting any other option. IPv6 is disabled.

```shell
sudo lxd init

Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (lvm, powerflex, zfs, btrfs, ceph, dir) [default=zfs]: dir
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: none
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]: 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:
```

## Prepare Juju

Once LXD is ready, we can move on and prepare Juju. First, install juju's latest v3:

```shell
sudo snap install juju --classic --channel=3/stable
```

### Make LXD accessible to your local user

Run the following commands to create a new group for LXD and add your current user to it:

```shell
sudo newgrp lxd
sudo usermod -a -G lxd $USER
```

Now, log out and log back in.

### Sysctl configuration

Before bootstrapping Juju controllers, we need to enforce the sysconfigs that OpenSearch demands. Some of these settings must be applied within the container, others must be set directly on the host.

On the host machine, add the settings below to a config file:
```shell
sudo tee /etc/sysctl.d/opensearch.conf <<EOF
vm.swappiness = 0
vm.max_map_count = 262144
net.ipv4.tcp_retries2 = 5
EOF
```
Now, apply the new settings:
```shell
sudo sysctl -p /etc/sysctl.d/opensearch.conf
```

### Bootstrap

Create the juju controller using the [bootstrap](https://juju.is/docs/juju/manage-controllers#heading--bootstrap-a-controller) command:

```shell
juju bootstrap localhost
```

### Configure sysctl for each model

Configure cloud-init to set sysctl on each new container deployed. First, add the configurations to a cloud-init user data file:

```shell
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'echo', 'vm.max_map_count=262144', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'vm.swappiness=0', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'net.ipv4.tcp_retries2=5', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'fs.file-max=1048576', '>>', '/etc/sysctl.conf' ]
    - [ 'sysctl', '-p' ]
EOF
```

Now, there are two options to set it as configuration: (1) set the cloud-init as a default and to be used by every new model created after that; or (2) set it as a model config for the target model. The latter will be explained in the next section.

To set the cloud-init script above as default, use the [`model-defaults`](https://juju.is/docs/juju/juju-model-defaults) command:

```
juju model-defaults --file=./cloudinit-userdata.yaml
```

### Add model

Add a model for the OpenSearch deployment, for example:
```
juju add-model opensearch
```

Confirm the cloud-init script is configured on this new model:
```
juju model-config cloudinit-userdata
postruncmd:
  - [ 'echo', 'vm.max_map_count=262144', '>>', '/etc/sysctl.conf' ]
  - [ 'echo', 'vm.swappiness=0', '>>', '/etc/sysctl.conf' ]
  - [ 'echo', 'net.ipv4.tcp_retries2=5', '>>', '/etc/sysctl.conf' ]
  - [ 'echo', 'fs.file-max=1048576', '>>', '/etc/sysctl.conf' ]
  - [ 'sysctl', '-p' ]
```

If the script above is not available, follow section "Configure sysctl for each model" to create the cloud-init script correctly and set it for this model:
```
juju model-config --file=./cloudinit-userdata.yaml
```


## Deploy OpenSearch

[note]
**Note:** Charmed OpenSearch supports performance profile. It is recommended in a single host deployment with LXD to use the testing profile, which will only consume 1G RAM per container.
[/note]

To deploy OpenSearch, run
```shell
juju deploy opensearch --channel 2/edge
```

For more information about deploying OpenSearch, see our [tutorial](https://discourse.charmhub.io/t/topic/9716).