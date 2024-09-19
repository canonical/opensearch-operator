> [Charmed OpenSearch Tutorial](/t/9722) >  1. Set up the environment

# Set up the environment

In this step, we will set up a development environment with the required components for deploying Charmed OpenSearch.

[note]
Before you start, make sure your machine meets the [minimum system requirements](/t/14565).
[/note]

## Summary
* [Set up LXD](#heading--set-up-lxd)
* [Set up Juju](#heading--set-up-juju)
* [Set kernel parameters](#heading--kernel-parameters)

---

<a href="#heading--set-up-lxd"><h2 id="heading--set-up-lxd"> Set up LXD </h2></a>

The simplest way to get started with Charmed OpenSearch is to set up a local LXD cloud. [LXD](https://documentation.ubuntu.com/lxd/en/latest/) is a system container and virtual machine manager that comes pre-installed on Ubuntu. Juju interfaces with LXD to control the containers on which Charmed OpenSearch runs.

Verify if your Ubuntu system already has LXD installed with the command `which lxd`. If there is no output, then install LXD with

```shell
sudo snap install lxd
```

After installation, `lxd init` is run to perform post-installation tasks. For this tutorial, the default parameters are preferred and the network bridge should be set to have no IPv6 addresses since Juju does not support IPv6 addresses with LXD:

```shell
lxd init --auto
lxc network set lxdbr0 ipv6.address none
```

You can list all LXD containers by executing the command `lxc list`. At this point in the tutorial, none should exist, so you'll only see this as output:

```shell
+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

<a href="#heading--set-up-juju"><h2 id="heading--set-up-juju"> Set up Juju </h2></a>

[Juju](https://juju.is/docs/juju) is an Operator Lifecycle Manager (OLM) for clouds, bare metal, LXD or Kubernetes. We will be using it to deploy and manage Charmed OpenSearch. 

As with LXD, Juju is installed using a snap package:

```shell
sudo snap install juju --channel 3.4/stable --classic
```

Juju already has a built-in knowledge of LXD and how it works, so there is no additional setup or configuration needed, however,  because Juju 3.x is a [strictly confined snap](https://snapcraft.io/docs/classic-confinement), and is not allowed to create a `~/.local/share` directory, we need to create it manually.

```shell
mkdir -p ~/.local/share
```

To list the clouds available to Juju, run the following command:

```shell
juju clouds
```

The output will look as follows:

```shell
Clouds available on the client:
Cloud      Regions  Default    Type  Credentials  Source    Description
localhost  1        localhost  lxd   1            built-in  LXD Container Hypervisor
```

Notice that Juju already has a built-in knowledge of LXD and how it works, so there is no need for additional setup. A controller will be used to deploy and control Charmed OpenSearch. 

Run the following command to bootstrap a Juju controller named `opensearch-demo` on LXD:

```shell
juju bootstrap localhost opensearch-demo
```

This bootstrapping process can take several minutes depending on your system resources.

The Juju controller exists within an LXD container. You can verify this by entering the command `lxc list`.

This will output the following:

```shell
+---------------+---------+-----------------------+------+-----------+-----------+
|     NAME      |  STATE  |         IPV4          | IPV6 |   TYPE    | SNAPSHOTS |
+---------------+---------+-----------------------+------+-----------+-----------+
| juju-<id>     | RUNNING | 10.105.164.235 (eth0) |      | CONTAINER | 0         |
+---------------+---------+-----------------------+------+-----------+-----------+
```

where `<id>` is a unique combination of numbers and letters such as `9d7e4e-0`

Set up a unique model for this tutorial named `tutorial`:

```shell
juju add-model tutorial
```

You can now view the model you created above by entering the command `juju status` into the command line. You should see the following:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.5.3    unsupported  11:26:13Z
```

<a href="#heading--kernel-parameters"><h2 id="heading--kernel-parameters"> Set kernel parameters </h2></a>

Before deploying Charmed OpenSearch, we need to set some [kernel parameters](https://www.kernel.org/doc/Documentation/sysctl/vm.txt). These are requirements for OpenSearch to function correctly. 

Since we are using LXD containers to deploy our charm, and containers share a kernel with their host, we need to set these kernel parameters on the host machine. We will save the default values, change them to the optimal values for OpenSearch, and add the parameters to the Juju model's configuration.

### Get default values

First, we need to make note of the current parameters of the kernel because we will need to reset them after the tutorial (although rebooting your machine will also do the trick). 

Let's run `sysctl` and filter the output for the three specific parameters that we will be changing:

```shell
sudo sysctl -a | grep -E 'swappiness|max_map_count|tcp_retries2'
```

This command should return something like the following:

```shell
net.ipv4.tcp_retries2 = 15
vm.max_map_count = 262144
vm.swappiness = 60
```

Make note of the above variables so that you can reset them later to their original values. Using the host machine outside of this tutorial without resetting these kernel parameters manually or rebooting may have an impact on the host machine's performance.

### Set parameters on the host machine

Set the kernel parameters to the recommended values for OpenSearch with the following commands:

```shell
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT

sudo sysctl -p
```

Please note that these values reset on system reboot, so if you complete this tutorial in multiple stages, you'll need to set these values again each time you restart your host machine.

### Add parameters to Juju model config

You also need to set the Juju model configuration to include these parameters. 

To do so, run the following commands:

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

juju model-config --file=./cloudinit-userdata.yaml
```

>**Next step:** [2. Deploy OpenSearch](/t/9716).