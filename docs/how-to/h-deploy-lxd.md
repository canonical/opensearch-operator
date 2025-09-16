# How to deploy on LXD

This guide summarizes how to set up your machine and deploy Charmed OpenSearch on [LXD](https://ubuntu.com/server/docs/lxd-containers), Canonical’s lightweight container hypervisor.

If you are a beginner to OpenSearch or Juju and are looking for a more comprehensive walkthrough of these steps, refer instead to the [Tutorial](/t/9722).

## Prerequisites
**Juju `v.3.5.3+`**: Install Juju, but do not bootstrap anything yet. 

> See also: [How to install Juju](https://documentation.ubuntu.com/juju/3.6/howto/manage-juju/#install-juju)
  
**LXD `v6.1+`**: Install and initialize LXD. 
> See also: [FIrst steps with LXD](https://documentation.ubuntu.com/lxd/en/latest/tutorial/first_steps/#install-and-initialize-lxd)

**System requirements**: Check that you fulfill the rest of the software and hardware requirements in the [system requirements page](/t/14565).

---

## Disable IPv6 on LXD

Juju does not support IPv6 addresses with LXD. To set the network bridge to have no IPv6 addresses, run the following command after initializing LXD:
```
lxc network set lxdbr0 ipv6.address none
```

See [The LXD cloud and Juju](https://documentation.ubuntu.com/juju/3.6/reference/cloud/list-of-supported-clouds/the-lxd-cloud-and-juju/#supported-constraints) for more information.

## Sysctl configuration

Before bootstrapping Juju controllers, sysconfigs required by OpenSearch must be enforced. This entails modifying some kernel parameters on the host machine, and creating a configuration file to apply the same configuration in any new container that gets deployed.

[note]
The following instructions will modify your kernel parameters. You can later reset them either manually or by rebooting.

To take note of the original values, run
```shell
sudo sysctl -a | grep -E 'swappiness|max_map_count|tcp_retries2'
```
[/note]

### Configure sysctl on the host machine
On the **host** machine, add the settings below to a config file:
```shell
sudo tee /etc/sysctl.d/opensearch.conf <<EOF
vm.swappiness = 0
vm.max_map_count = 262144
net.ipv4.tcp_retries2 = 5
EOF
```
Then, apply the new settings:
```shell
sudo sysctl -p /etc/sysctl.d/opensearch.conf
```

Now you can bootstrap a Juju controller:

```shell
juju bootstrap localhost
```

### Configure sysctl for new containers

Configure `cloud-init` to set sysctl on each new container that gets deployed. 

First, add the configurations to a `cloud-init` user data file:

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

Now, there are two options to apply this  `cloud-init` configuration: set as the default config to be used by every new model created after that, or set it as a config for a target model.

To set the `cloud-init` script above as **default for all models**, use the [`model-defaults`](https://juju.is/docs/juju/juju-model-defaults) command:

```
juju model-defaults --file=./cloudinit-userdata.yaml
```

To set the `cloud-init` script **for a particular model**, use the [`model-config`](https://juju.is/docs/juju/juju-model-config) command:
```
juju model-config --file=./cloudinit-userdata.yaml --model <model_name>
```

## Deploy OpenSearch

Create a model if you haven't already:
```
juju add-model <model_name>
```
In a single host deployment with LXD, we recommend using the `testing` profile, which will only consume 1G RAM per container.

To deploy OpenSearch with the testing profile, run
```shell
juju deploy opensearch