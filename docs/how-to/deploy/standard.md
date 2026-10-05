---
myst:
  html_meta:
    description: Deploy Charmed OpenSearch on LXD virtual machines or on Kubernetes with Juju, including prerequisites, kernel tuning, and bootstrap steps.
---

<!-- vale off -->

(how-to-deploy-standard)=

<!-- vale on -->

# How to deploy Charmed OpenSearch

This guide walks you through deploying Charmed OpenSearch, covering both the **IAAS/VM** charm (`opensearch`) and the
**Kubernetes** charm (`opensearch-k8s`).

If you are new to OpenSearch or Juju and are looking for a more comprehensive walkthrough of these steps, see the
[Tutorial](tutorial-index).

For large, multi-application deployments, see the [Launch a large deployment](how-to-deploy-large) guide instead.

## Prerequisites

Check that you fulfill the hardware requirements in the [system requirements page](reference-system-requirements).

Before continuing, decide whether you are going to use a machine (VM)-based or a Kubernetes environment for this
deployment. Use the tabs below to switch between the two substrates. The instructions will update accordingly.

`````{tab-set}
---
sync-group: substrate
---
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
---
sync-group: substrate
---
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
cluster has a storage class that can satisfy them:

```shell
kubectl get storageclass
```

The bootstrap and model-creation commands below assume a suitable class is marked `(default)`.
If there is none, configure storage for the Juju controller before bootstrapping and
[operator storage](https://canonical.com/juju/docs/juju-cli/3.6/reference/cloud/list-of-supported-clouds/microk8s/#models)
for the workload model before creating it. For OpenSearch volumes, you can use an existing
Juju storage pool at [deploy time](#deploy-opensearch), but a workload pool alone does not
provide storage for the controller or Juju operators.
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
---
sync-group: substrate
---
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

If you are reusing an existing model, select it before running the remaining commands:

```shell
juju switch <controller-name>:<model-name>
```

Check that the model is of the expected type:

```shell
juju show-model <model-name>
```

The output includes a `model-type` field (distinct from the cloud's `type` field).

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

The `model-type` must **not** be `caas`.
````

````{tab-item} K8s
:sync: k8s

The `model-type` must be `caas`.
````

`````

## Kernel parameter configuration

OpenSearch relies on a number of kernel parameters that are not set to suitable values by default. Configure them before
deploying OpenSearch. How and where you apply them depends on the substrate.

````{note}
To take note of the current values before changing them:

```shell
sudo sysctl -a | grep -E 'swappiness|max_map_count|file-max'
```

The settings below are saved in `/etc/sysctl.d/opensearch.conf` and persist across
reboots. To restore the previous values, remove or update that file and reset the
parameters manually, or reboot after removing the file.
````

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

Configure the required kernel settings on the host machine, then configure the workload
model to apply them to new containers. You can do this after bootstrapping a controller,
but before deploying OpenSearch.

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

Create a `cloud-init` user data file to set sysctl on new containers:

```shell
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
    - echo 'vm.swappiness=0' >> /etc/sysctl.conf
    - echo 'fs.file-max=1048576' >> /etc/sysctl.conf
    - sysctl -p
EOF
```

```{note}
Keep each `postruncmd` entry as a **string**. Cloud-init runs string entries through a
shell, so the `>>` redirection works. Entries written as a YAML list are passed straight to
`execve(3)` with no shell, so `>>` would become a literal argument to `echo` instead of
appending to the file.
```

Apply it to the **existing model** before deploying OpenSearch, so the settings are
included when Juju provisions its machines. Changing model configuration does not
retroactively run `cloud-init` on existing machines:

```shell
juju model-config --file=./cloudinit-userdata.yaml --model <model-name>
```

For models you create **in the future**, you can instead set this as a default on the
selected controller using
[`juju model-defaults`](https://canonical.com/juju/docs/juju-cli/3.6/reference/juju-cli/list-of-juju-cli-commands/model-defaults/)
*before* creating those models. Defaults do not change the model created above:

```shell
juju model-defaults --file=./cloudinit-userdata.yaml
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

**Configure `net.ipv4.tcp_retries2` (optional)**

This setting belongs to each pod's network namespace, so the node settings above do not
change it. The Kubernetes-only
[`data-platform-k8s-mutator`](https://github.com/canonical/data-platform-k8s-mutator)
is a containerized admission webhook, not a Juju charm. It sets
`net.ipv4.tcp_retries2=5` on newly created OpenSearch workloads.

For this optional tuning, [allow the unsafe sysctl](https://github.com/canonical/data-platform-k8s-mutator#prerequisites)
on every node that may run OpenSearch pods (`--allowed-unsafe-sysctls=net.ipv4.tcp_retries2`)
and restart its kubelet. Ensure the cluster supports admission webhooks. Follow the
[mutator quick start](https://github.com/canonical/data-platform-k8s-mutator#quick-start)
to build the rock with Rockcraft and publish its image to a registry reachable by the
cluster. Then, from the mutator repository root, run **before deploying OpenSearch**:

```shell
uv run python -m scripts.bootstrap_webhook --namespace webhooks \
  --image <cluster-accessible-image> --target-container-names opensearch \
  --target-namespaces <model-kubernetes-namespace>
```

Find the model's Kubernetes namespace with `kubectl get namespaces`; `webhooks` is the
mutator's own namespace. The script generates and applies the Kubernetes manifests.
Without the mutator, OpenSearch still deploys, but its pods retain their default
`tcp_retries2` value and may take longer to detect and recover from network partitions.
We recommend this tuning for production deployments.
````

`````

(deploy-opensearch)=

## Deploy OpenSearch

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

In a single-host deployment with LXD, we recommend using the default `testing`
[profile](how-to-optimize-cluster-performance), which sets the JVM heap size to 1 GB per
container.

To deploy OpenSearch, choose one of the following commands:

```shell
juju deploy opensearch --channel=2/stable -n 3
```

For production deployments, meet the [profile's resource and node-role requirements](how-to-optimize-cluster-performance)
before setting `production` explicitly. Three units can cover both cluster-manager and data
roles when the roles are combined, but each node still needs sufficient resources.

```shell
juju deploy opensearch --channel=2/stable -n 3 --config profile=production
```
````

````{tab-item} K8s
:sync: k8s

The Kubernetes charm requires the `--trust` flag to access the model's cloud credentials
and manage Kubernetes resources such as Services and StatefulSets on your behalf.

In a single-host K8s cluster, we recommend using the default `testing`
[profile](how-to-optimize-cluster-performance), which sets the JVM heap size to 1 GB per pod.

To deploy OpenSearch, choose one of the following commands. Each deploys the
`opensearch-k8s` charm as an application named `opensearch`, the same name used by
the VM charm:

```shell
juju deploy opensearch-k8s opensearch --channel=2/edge -n 3 --trust
```

To use a specific Kubernetes storage class for both OpenSearch volumes, first ensure
an existing Juju `kubernetes` storage pool in this model selects that class and can
provision both volumes. Find available pools with `juju storage-pools`. Pass the **pool
name**, not the Kubernetes storage class, to `--storage`:

```shell
juju deploy opensearch-k8s opensearch --channel=2/edge -n 3 --trust \
  --storage opensearch-data=<juju-storage-pool>,10G \
  --storage opensearch-logs=<juju-storage-pool>,2G
```

For production deployments, meet the [profile's resource and node-role requirements](how-to-optimize-cluster-performance)
before setting `production` explicitly. Three pods can cover both cluster-manager and data
roles when the roles are combined, but each pod still needs sufficient resources.

```shell
juju deploy opensearch-k8s opensearch --channel=2/edge -n 3 --trust --config profile=production
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

Once the units have been provisioned and the other prerequisites are met, the `opensearch` application should become
`blocked` with a `Missing TLS relation with this cluster` message. If provisioning or storage is still pending,
`juju status` may show a different state first. Charmed OpenSearch requires TLS encryption to start, on both the HTTP
and Transport layers.

## Next steps

- [Enable TLS encryption](how-to-enable-tls-encryption)
- [Launch a large deployment](how-to-deploy-large)
- [Integrate with an application](how-to-integrate-with-an-application)
- [Scale horizontally](how-to-scale-horizontally)
- [Enable monitoring](how-to-monitoring)
