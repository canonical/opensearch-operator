---
myst:
  html_meta:
    description: "Deploy Charmed OpenSearch on LXD containers with Juju, including prerequisites, kernel parameter configuration, and deployment steps."
---

<!-- vale off -->
(how-to-deploy-lxd)=
<!-- vale on -->
# How to deploy on LXD

This guide shows how to deploy Charmed OpenSearch on
[LXD](https://ubuntu.com/server/docs/lxd-containers), Canonical's lightweight container hypervisor.

## Prerequisites

To deploy Charmed OpenSearch on LXD using Juju, you need:

* LXD 6.1+
* Juju 3.5.3+
* Hardware that meets the [system requirements](reference-system-requirements)

For additional guidance, see the [Environment setup](tutorial-1-set-up-the-environment) stage of our tutorial or the documentation for [LXD](https://canonical.com/lxd/docs/latest/tutorial/first_steps/#install-lxd-using-snap) and [Juju](https://canonical.com/juju/docs/juju-cli/3.6/howto/manage-juju/#install-juju) respectively.

## Prepare the environment

Configure the environment so that Charmed OpenSearch runs correctly on LXD:

* Disable IPv6 on LXD
* Configure kernel parameters
  * On the host
  * For new containers

### Disable IPv6 on LXD

Juju does not support IPv6 with LXD. After initializing LXD, disable IPv6 on the default bridge:

```shell
lxc network set lxdbr0 ipv6.address none
```

See [The LXD cloud and Juju](https://canonical.com/juju/docs/juju-cli/3.6/reference/cloud/list-of-supported-clouds/lxd/#constraints) for more information.

### Configure kernel parameters on the host

OpenSearch requires specific kernel parameters to be set on the host
and propagated to every new LXD container:

* `vm.swappiness = 0`
* `vm.max_map_count = 262144`
* `net.ipv4.tcp_retries2 = 5`

See [System requirements](reference-system-requirements) for the full list of required
kernel parameters and their purpose.

To see the current kernel parameter values before making changes:

```shell
sudo sysctl -a | grep -E 'swappiness|max_map_count|tcp_retries2'
```

On the host machine, create a sysctl configuration file:

```shell
sudo tee /etc/sysctl.d/opensearch.conf <<EOF
vm.swappiness = 0
vm.max_map_count = 262144
net.ipv4.tcp_retries2 = 5
EOF
```

Then, apply the settings:

```shell
sudo sysctl -p /etc/sysctl.d/opensearch.conf
```

#### Configure kernel parameters for new containers

Configure `cloud-init` so that each new container inherits the required sysctl settings.

Create a cloud-init user-data file:

```shell
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'echo', 'vm.max_map_count=262144', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'vm.swappiness=0', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'net.ipv4.tcp_retries2=5', '>>', '/etc/sysctl.conf' ]
    - [ 'sysctl', '-p' ]
EOF
```

To apply this as the **default** for **all new Juju models**:

```shell
juju model-defaults --file=./cloudinit-userdata.yaml
```

To apply this as the **default** for a **specific existing model**:

```shell
juju model-config --file=./cloudinit-userdata.yaml --model <model-name>
```

## Deploy OpenSearch

To deploy a single unit of Charmed OpenSearch for testing:

```shell
juju deploy opensearch
```

By default, the charm uses the `testing` profile, which is optimized for development and testing with lightweight workloads.

To deploy a multi-unit application with the `production` profile:

```shell
juju deploy opensearch -n 3 --config profile=production
```

See [How to optimize cluster performance with profiles](how-to-optimize-cluster-performance) for details on the available profiles.

Check the deployment status:

```shell
juju status
```

You should see the `opensearch` application in a blocked state with the message `Missing TLS relation with this cluster`.
Charmed OpenSearch requires TLS encryption. To complete the setup, continue with [How to manage TLS encryption](how-to-enable-tls-encryption).
