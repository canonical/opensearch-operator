## Setting up your environment

### Minimum requirements

Before we start, make sure your machine meets the following requirements:

- Ubuntu 20.04 (Focal) or later.
- 16GB of RAM.
- 4 CPU cores.
- At least 20GB of available storage.
- Access to the internet for downloading the required snaps and charms.

For a complete list of OpenSearch system requirements, please read the [Opensearch Documentation](https://opensearch.org/docs/2.4/install-and-configure/install-opensearch/index/).

### Prepare LXD

The simplest way to get started with Charmed OpenSearch is to set up a local LXD cloud. LXD is a system container and virtual machine manager that comes pre-installed on Ubuntu. Juju interfaces with LXD to control the containers on which Charmed OpenSearch runs. While this tutorial covers some of the basics of using LXD, you can [learn more about LXD here](https://linuxcontainers.org/lxd/getting-started-cli/).

Verify that LXD is installed by entering `which lxd` into the command line. This will output:

```bash
/snap/bin/lxd
```

Although LXD is already installed, we need to run `lxd init` to perform post-installation tasks. For this tutorial the default parameters are preferred and the network bridge should be set to have no IPv6 addresses, since Juju does not support IPv6 addresses with LXD:

```bash
lxd init --auto
lxc network set lxdbr0 ipv6.address none
```

You can list all LXD containers by entering the command `lxc list` in to the command line. Although at this point in the tutorial none should exist and you'll only see this as output:

```bash
+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

### Install and prepare Juju

Juju is an Operator Lifecycle Manager (OLM) for clouds, bare metal, LXD or Kubernetes. We will be using it to deploy and manage Charmed OpenSearch. As with LXD, Juju is installed using a snap package:

```bash
sudo snap install juju --classic
```

To list the clouds available to juju run the following command:

```bash
juju clouds
```

The output will most likely look as follows:

```bash
Clouds available on the client:
Cloud      Regions  Default    Type  Credentials  Source    Description
localhost  1        localhost  lxd   1            built-in  LXD Container Hypervisor
```

Juju already has a built-in knowledge of LXD and how it works, so there is no additional setup or configuration needed. A controller will be used to deploy and control Charmed OpenSearch. Run the following command to bootstrap a Juju controller named ‘opensearch-demo’ on LXD. This bootstrapping processes can take several minutes depending on your system resources:

```bash
juju bootstrap localhost opensearch-demo
```

The Juju controller should exist within an LXD container. You can verify this by entering the command `lxc list`; you should see the following:

```bash
+---------------+---------+-----------------------+------+-----------+-----------+
|     NAME      |  STATE  |         IPV4          | IPV6 |   TYPE    | SNAPSHOTS |
+---------------+---------+-----------------------+------+-----------+-----------+
| juju-<id>     | RUNNING | 10.105.164.235 (eth0) |      | CONTAINER | 0         |
+---------------+---------+-----------------------+------+-----------+-----------+
```

where `<id>` is a unique combination of numbers and letters such as `9d7e4e-0`

The controller can hold multiple models. In each model, we deploy charmed applications. Set up a specific model for this tutorial, named ‘tutorial’:

```bash
juju add-model tutorial
```

You can now view the model you created above by entering the command `juju status` into the command line. You should see the following:

```bash
Model    Controller         Cloud/Region         Version  SLA          Timestamp
tutorial opensearch-demo    localhost/localhost  2.9.37   unsupported  23:20:53Z

Model "admin/tutorial" is empty.
```

### Setting Kernel Parameters

Before deploying Charmed OpenSearch, we need to set some [kernel parameters](https://www.kernel.org/doc/Documentation/sysctl/vm.txt). These are necessary requirements for OpenSearch to function correctly, and because we're using LXD containers to deploy our charm, and containers share a kernel with their host, we need to set these kernel parameters on the host machine.

First, we need to get the current parameters of the kernel because we will need to reset them after the tutorial (although rebooting your machine will also do the trick). We're only changing three specific parameters, so we're filtering the output for those three parameters:

```bash
sudo sysctl -a | grep -E 'swappiness|max_map_count|tcp_retries2'
```

This command should return something like the following:

```bash
net.ipv4.tcp_retries2 = 15
vm.max_map_count = 262144
vm.swappiness = 60
```

Note these variables so we can reset them later. Not doing so may cause some system instability. Set the kernel parameters to the new recommended values like so:

```bash
sudo sysctl -w vm.max_map_count=262144 vm.swappiness=0 net.ipv4.tcp_retries2=5
```

Please note that these values reset on system reboot, so if you complete this tutorial in multiple stages, you'll need to set these values each time you restart your computer.

### Setting Kernel Parameters as Juju Model Parameters

You also need to set the juju model config to include these parameters, which you do like so:

```bash
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
    - [ 'sysctl', '-w', 'vm.swappiness=0' ]
    - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
EOF
juju model-config ./cloudinit-userdata.yaml
```

## Next Steps

The next stage in this tutorial is about deploying the OpenSearch charm, and can be found [here](./tutorial-deploy-opensearch.md).
