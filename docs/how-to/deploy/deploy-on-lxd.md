---
myst:
  html_meta:
    description: "Deploy Charmed OpenSearch on LXD containers with Juju, including prerequisites, sysctl configuration, and bootstrap steps."
---

<!-- vale off -->
(how-to-deploy-lxd)=
<!-- vale on -->
# How to deploy on LXD

This guide shows how to deploy Charmed OpenSearch on
[LXD](https://ubuntu.com/server/docs/lxd-containers), Canonical’s lightweight container hypervisor.

For a comprehensive step-by-step walkthrough, refer to the [Tutorial](tutorial-index).

## Prerequisites

* **Juju 3.5.3+** — installed but not yet bootstrapped.
  See [How to install Juju](https://documentation.ubuntu.com/juju/3.6/howto/manage-juju/#install-juju).
* **LXD 6.1+** — installed and initialised.
  See [First steps with LXD](https://documentation.ubuntu.com/lxd/latest/tutorial/first_steps/#install-lxd-using-snap).
* Hardware and software prerequisites as described in the
  [system requirements](reference-system-requirements).

## Disable IPv6 on LXD

Juju does not support IPv6 with LXD. After initialising LXD, disable IPv6 on the default bridge:

```shell
lxc network set lxdbr0 ipv6.address none
```

See [The LXD cloud and Juju](https://canonical.com/juju/docs/juju-cli/3.6/reference/cloud/list-of-supported-clouds/lxd/#constraints) for more information.

## Configure sysctl

OpenSearch requires specific kernel parameters. These must be set on the host
and propagated to every new LXD container.

````{note}
The following instructions modify kernel parameters. To record original values
before making changes:

```shell
sudo sysctl -a | grep -E 'swappiness|max_map_count|tcp_retries2'
```
````

### On the host machine

Create a sysctl configuration file:

```shell
sudo tee /etc/sysctl.d/opensearch.conf <<EOF
vm.swappiness = 0
vm.max_map_count = 262144
net.ipv4.tcp_retries2 = 5
EOF
```

Apply the settings:

```shell
sudo sysctl -p /etc/sysctl.d/opensearch.conf
```

### Bootstrap the Juju controller

```shell
juju bootstrap localhost
```

### For new containers

Configure `cloud-init` so that each new container inherits the required sysctl settings.

Create a user data file:

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

To apply as the **default for all new models**:

```shell
juju model-defaults --file=./cloudinit-userdata.yaml
```

To apply **for a specific model only**:

```shell
juju model-config --file=./cloudinit-userdata.yaml --model <model-name>
```

## Deploy OpenSearch

Create a Juju model:

```shell
juju add-model <model-name>
```

For a single-host LXD deployment, the `testing` profile is recommended (1 GB RAM per container):

```shell
juju deploy opensearch --config profile=testing
```

```{note}
Charmed OpenSearch requires TLS to function.
After deploying, proceed to [manage TLS encryption](how-to-enable-tls-encryption).
```
