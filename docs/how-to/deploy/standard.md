---
myst:
  html_meta:
    description: "Deploy Charmed OpenSearch on LXD virtual machines or on Kubernetes with Juju, including prerequisites, kernel tuning, and bootstrap steps."
---

<!-- vale off -->
(how-to-deploy-standard)=
<!-- vale on -->

# How to deploy Charmed OpenSearch

This guide walks you through deploying Charmed OpenSearch,
covering both the **IAAS/VM** charm (`opensearch`) and the **Kubernetes** charm (`opensearch-k8s`).

If you are new to OpenSearch or Juju and are looking for a more comprehensive
walkthrough of these steps, see the [Tutorial](tutorial-index).

For large, multi-application deployments, see the
the [Launch a large deployment](how-to-deploy-large) guide instead.

## Prerequisites

Check that you fulfill the hardware requirements in the
[system requirements page](reference-system-requirements).

Before continuing, decide whether you are going to use a machine (VM)-based or
a Kubernetes environment for this deployment. Use the tabs below to switch between the two substrates.
The instructions will update accordingly.

`````{tab-set}
:sync-group: substrate

````{tab-item} VM
:sync: vm

To deploy Charmed OpenSearch using Juju in machine/VM environment, you need:

* **Juju `3.6+` (latest LTS)** -- Canonical's orchestration engine (see [How to install Juju](https://canonical.com/juju/docs/juju-cli/3.6/howto/manage-juju/#install-juju))
* **LXD `v6.1+`** -- Canonical's lightweight container hypervisor (see [LXD tutorial](https://canonical.com/lxd/docs/latest/tutorial/first_steps/#install-lxd-using-snap)).
````

````{tab-item} K8s
:sync: k8s

To deploy Charmed OpenSearch using Juju in K8s environment, you need:

* **Juju `3.6+` (latest LTS)** -- Canonical's orchestration engine (see [How to install Juju](https://canonical.com/juju/docs/juju-cli/3.6/howto/manage-juju/#install-juju))
* **Kubernetes `v1.29+` cluster**, for example:
  * [Canonical Kubernetes](https://documentation.ubuntu.com/canonical-kubernetes/latest/) with the following features enabled:
    * `local-storage`
    * `load-balancer`
  * [MicroK8s](https://canonical.com/microk8s/docs/getting-started) with the following add-ons:
    * `hostpath-storage`
    * `dns`
    * `metallb`

````

`````

## Prepare the substrate

Prepare the environment for Charmed OpenSearch deployment:

`````{tab-set}
:sync-group: substrate

````{tab-item} VM
:sync: vm

**Disable IPv6 on LXD**

Juju does not support IPv6 addresses with LXD. To set the network bridge to have no IPv6
addresses, run the following command after initializing LXD:

```shell
lxc network set lxdbr0 ipv6.address none
```

See [The LXD cloud and Juju](https://canonical.com/juju/docs/juju-cli/3.6/reference/cloud/list-of-supported-clouds/lxd/#constraints)
for more information.
````

````{tab-item} K8s
:sync: k8s

**Check the storage class**

Charmed OpenSearch K8s requests two persistent volumes per unit. Confirm that your
cluster has a default storage class that can satisfy them:

```shell
kubectl get storageclass
```

At least one entry must be marked as `(default)`. If none is, either mark one as default
or pass an explicit storage class at [deploy time](#deploy-opensearch).
````

`````

## Kernel parameter configuration

OpenSearch relies on a number of kernel parameters that are not set to suitable values by
default. How and where you apply them depends on the substrate.

````{note}
The following instructions modify kernel parameters. You can later reset them either
manually or by rebooting.

To take note of the current values before changing them:

```shell
sudo sysctl -a | grep -E 'swappiness|max_map_count|file-max'
```
````

`````{tab-set}
:sync-group: substrate

````{tab-item} VM
:sync: vm

Before bootstrapping Juju controllers, the sysctl settings required by OpenSearch must be
enforced. This entails modifying some kernel parameters on the host machine, and creating
a configuration file to apply the same configuration in any new container that gets
deployed.

The `net.ipv4.tcp_retries2` parameter is set automatically by the charm and does not
need to be configured manually.

**Configure sysctl on the host machine**

On the **host** machine, run the following command to add the settings to a config file:

```shell
sudo tee /etc/sysctl.d/opensearch.conf <<EOF
vm.swappiness = 0
vm.max_map_count = 262144
fs.file-max = 1048576
EOF
```

Then, apply the new settings:

```shell
sudo sysctl -p /etc/sysctl.d/opensearch.conf
```

**Configure sysctl for new containers**

Configure `cloud-init` to set sysctl on each new container that gets deployed.

First, add the configurations to a `cloud-init` user data file:

```shell
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'echo', 'vm.max_map_count=262144', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'vm.swappiness=0', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'fs.file-max=1048576', '>>', '/etc/sysctl.conf' ]
    - [ 'sysctl', '-p' ]
EOF
```

There are two ways to apply this `cloud-init` configuration.

To set the `cloud-init` script above as **default for all models**, use the
[`model-defaults`](https://canonical.com/juju/docs/juju-cli/3.6/reference/juju-cli/list-of-juju-cli-commands/model-defaults/) command:

```shell
juju model-defaults --file=./cloudinit-userdata.yaml
```

To set the `cloud-init` script **for a particular model**, use the
[`model-config`](https://canonical.com/juju/docs/juju-cli/3.6/reference/juju-cli/list-of-juju-cli-commands/model-config/) command:

```shell
juju model-config --file=./cloudinit-userdata.yaml --model <model-name>
```
````

````{tab-item} K8s
:sync: k8s

On Kubernetes, kernel parameters are applied per **worker node**, not per container:
`vm.max_map_count`, `vm.swappiness`, and `fs.file-max` are node-wide settings that the
workload pods inherit from the host they are scheduled on.

**Configure sysctl on each Kubernetes node**

On **each node** that may run OpenSearch pods, run the following command to add the settings to a config file:

```shell
sudo tee /etc/sysctl.d/opensearch.conf <<EOF
vm.swappiness = 0
vm.max_map_count = 262144
fs.file-max = 1048576
EOF
```

Then, apply the new settings:

```shell
sudo sysctl -p /etc/sysctl.d/opensearch.conf
```

```{note}
If your nodes are managed by a cloud provider, prefer the provider's node configuration
mechanism (for example, a node bootstrap script or a machine image) so the settings
survive node replacement.
```

<!--**Configure `net.ipv4.tcp_retries2`**

Unlike the parameters above, `net.ipv4.tcp_retries2` is scoped to the **pod's network
namespace** rather than the host, so setting it on the node has no effect on the
workload.

To configure it, deploy the
[`data-platform-k8s-mutator`](https://github.com/canonical/data-platform-k8s-mutator)
charm alongside OpenSearch in the same Kubernetes cluster. The mutator applies the
required sysctl value to the OpenSearch workload pods.

```{note}
This step is optional but recommended for production deployments. Without it, OpenSearch
nodes take longer to detect and recover from network partitions.
``` -->

<!-- TODO: Add the concrete `juju deploy data-platform-k8s-mutator` invocation and any
required configuration options once the charm's interface is finalised. -->
````

`````

## Bootstrap a Juju controller

Make sure your cloud is registered with Juju:

```shell
juju list-clouds
```

```{note}
See also: [How to manage clouds](https://canonical.com/juju/docs/juju-cli/latest/howto/manage-clouds/)
in the Juju documentation.
```

Bootstrap a new controller:

```shell
juju bootstrap <cloud> <controller-name>
```

Or switch to an existing one:

```shell
juju switch <controller-name>
```

`````{tab-set}
:sync-group: substrate

````{tab-item} VM
:sync: vm

Make sure that the controller's back-end cloud is **not** Kubernetes-based.
````

````{tab-item} K8s
:sync: k8s

Make sure that the controller's back-end cloud **is** Kubernetes-based.
````

`````

## Create a model

Create a model if you haven't already:

```shell
juju add-model <model-name>
```

Check that the model is of the expected type:

```shell
juju show-model
```

The output includes a `type` field.

`````{tab-set}
:sync-group: substrate

````{tab-item} VM
:sync: vm

The type must **not** be `caas`.
````

````{tab-item} K8s
:sync: k8s

The type must be `caas`.
````

`````

(deploy-opensearch)=
## Deploy OpenSearch

`````{tab-set}
:sync-group: substrate

````{tab-item} VM
:sync: vm

In a single-host deployment with LXD, we recommend using the default `testing`
[profile](how-to-optimize-cluster-performance), which only consumes 1 GB of RAM per
container.

To deploy OpenSearch:

```shell
juju deploy opensearch -n 3
```

For production deployments, set the `production` profile explicitly:

```shell
juju deploy opensearch -n 3 --config profile=production
```
````

````{tab-item} K8s
:sync: k8s

The Kubernetes charm requires the `--trust` flag, which grants it the permissions it needs
to manage Kubernetes resources such as Services and StatefulSets on your behalf.

In a single-host K8s cluster, we recommend using the default `testing`
[profile](how-to-optimize-cluster-performance), which only consumes 1 GB of RAM per pod.

To deploy OpenSearch:

```shell
juju deploy opensearch-k8s -n 3 --trust
```

If your cluster has no default storage class, or you want to pin the charm to a specific
one, pass the storage constraints explicitly:

```shell
juju deploy opensearch-k8s -n 3 --trust \
  --storage opensearch-data=<storage_class>,10G \
  --storage opensearch-logs=<storage_class>,2G
```

For production deployments, set the `production` profile explicitly:

```shell
juju deploy opensearch-k8s -n 3 --trust --config profile=production
```

```{note}
The charm pulls a pinned OpenSearch workload from a
[charmed-opensearch-rock](https://github.com/canonical/charmed-opensearch-rock/pkgs/container/charmed-opensearch)
OCI image rather than from a snap.
The image is published together with the charm revision,
so no additional resource needs to be specified at deploy time.
```
````

`````

## Check the deployment

To check the current status of the application:

```shell
juju status
```

You should see the OpenSearch application in a blocked state with the message
`Missing TLS relation with this cluster`. Charmed OpenSearch requires TLS encryption
to start, on both the HTTP and Transport layers.

## Next steps

* [Enable TLS encryption](how-to-enable-tls-encryption)
* [Launch a large deployment](how-to-deploy-large)
* [Integrate with an application](how-to-integrate-with-an-application)
* [Scale horizontally](how-to-scale-horizontally)
* [Enable monitoring](how-to-monitoring)
