---
myst:
  html_meta:
    description: Deploy large-scale Charmed OpenSearch clusters on VMs or Kubernetes with node roles, data tiers, and production configurations for high-performance workloads.
---

(how-to-deploy-large)=

# How to launch a large deployment

This guide shows how to deploy a multi-application OpenSearch cluster using Juju, with dedicated node roles for
scalability and fault tolerance. It covers both the **VM** charm (`opensearch`) and the **Kubernetes** charm
(`opensearch-k8s`).

All applications in this example are deployed in the same Juju model, using the same substrate — for Kubernetes, within
a single Kubernetes cluster. The applications are integrated to form a single OpenSearch cluster.

For background on node roles, data tiers, and the main orchestrator pattern, see
[Node roles and cluster topology](explanation-node-roles).

## Prerequisites

Complete the preparation steps in the [standard deployment guide](how-to-deploy-standard) — substrate preparation,
controller and model setup, kernel parameter configuration, and the optional TCP retries tuning — then return here
before deploying OpenSearch.

The Kubernetes charm requires the `--trust` flag to access the model's cloud credentials and manage Kubernetes resources
on your behalf.

## Node roles

Roles are assigned at the Juju application level (all units in an application share the same roles). If no roles are
configured, the charm auto-assigns: `data`, `ingest`, `ml`, `cluster_manager`.

To set roles at deploy time:

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

```shell
juju deploy opensearch -n 3 --config roles="cluster_manager,data,ml" --channel 2/stable
```
````

````{tab-item} K8s
:sync: k8s

```shell
juju deploy opensearch-k8s opensearch -n 3 --config roles="cluster_manager,data,ml" --channel 2/edge --trust
```
````

`````

To change roles after deployment (triggers a rolling restart):

```shell
juju config opensearch roles="cluster_manager,data,ml"
```

```{note}
The `cluster_manager` role cannot be removed. In a large deployment, the `data` role can be removed only if another
application still holds it. See [Node roles and cluster topology](explanation-node-roles) for details.
```

## Deploy the cluster applications

A large deployment consists of multiple Juju applications integrated together, each configured with specific node roles.
See [Node roles and cluster topology](explanation-node-roles) for an explanation of the main orchestrator, failover, and
data-node pattern.

```{caution}
The examples below use the `testing` profile (sets the JVM heap size to 1 GB per node), which is suited to development
and testing. For production, deploy each application with `--config profile=production` (JVM heap set to 50% of RAM,
capped at 31 GB) and sufficient resources.
See [How to optimize cluster performance with profiles](how-to-optimize-cluster-performance)
for details on the available profiles.
```

```{note}
**Two critical configuration rules for large deployments:**

1. All applications must share the same `cluster_name` value.
   A mismatch prevents applications from forming a cluster.
2. Set `init_hold=true` on every application **except** the main orchestrator.
   This prevents non-orchestrator applications from starting before integration.
```

See [Node roles and cluster topology](explanation-node-roles) for details on why these rules are required.

### 1. Deploy the main orchestrator

Deploy the `main` application:

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

```shell
juju deploy -n 3 \
    opensearch main \
    --config cluster_name="app" \
    --channel 2/stable
```
````

````{tab-item} K8s
:sync: k8s

```shell
juju deploy -n 3 \
    opensearch-k8s main \
    --config cluster_name="app" \
    --channel 2/edge \
    --trust
```
````

`````

Since no roles are specified, the charm auto-assigns all default roles.

### 2. Deploy a failover application (recommended)

The failover application takes over orchestration if the `main` app fails or is removed:

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

```shell
juju deploy -n 3 \
    opensearch failover \
    --config cluster_name="app" \
    --config init_hold="true" \
    --config roles="cluster_manager" \
    --channel 2/stable
```
````

````{tab-item} K8s
:sync: k8s

```shell
juju deploy -n 3 \
    opensearch-k8s failover \
    --config cluster_name="app" \
    --config init_hold="true" \
    --config roles="cluster_manager" \
    --channel 2/edge \
    --trust
```
````

`````

### 3. Deploy data nodes

Deploy an application with `data.hot` roles:

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

```shell
juju deploy -n 3 \
    opensearch data-hot \
    --config cluster_name="app" \
    --config roles="data.hot" \
    --config init_hold="true" \
    --channel 2/stable
```
````

````{tab-item} K8s
:sync: k8s

```shell
juju deploy -n 3 \
    opensearch-k8s data-hot \
    --config cluster_name="app" \
    --config roles="data.hot" \
    --config init_hold="true" \
    --channel 2/edge \
    --trust
```
````

`````

### 4. Deploy TLS certificates

Deploy a TLS certificate provider:

```shell
juju deploy self-signed-certificates
```

Track deployment progress:

```shell
juju status --watch 1s
```

At this point, once the units have been provisioned, `main` will show `blocked` (missing TLS), while `failover` and
`data-hot` will show `blocked` (waiting for peer cluster relation).

## Configure TLS encryption

Charmed OpenSearch requires TLS. Integrate `self-signed-certificates` with all OpenSearch applications:

```shell
juju integrate self-signed-certificates main
juju integrate self-signed-certificates failover
juju integrate self-signed-certificates data-hot
```

The `main` app will become `active` once TLS is configured. The other apps remain `blocked` until the peer-cluster
relations are added in the next step.

## Form the OpenSearch cluster

Integrate the applications via the peer-cluster relations to form a single OpenSearch cluster:

```shell
juju integrate main:peer-cluster-orchestrator failover:peer-cluster
juju integrate main:peer-cluster-orchestrator data-hot:peer-cluster
juju integrate failover:peer-cluster-orchestrator data-hot:peer-cluster
```

```{note}
On Kubernetes, nodes identify and communicate with each other using their internal service FQDNs, not pod IPs.
```

The `main` application orchestrates cluster formation. Track progress with:

```shell
juju status --watch 1s
```

Once all applications show `active`, the cluster is fully formed and operational.

```{caution}
The cluster will not come online if no `data` nodes are available.
Ensure `data` nodes are deployed and ready before forming the cluster.
```

## Next steps

- [Manage TLS encryption](how-to-enable-tls-encryption) — configure and rotate TLS certificates.
- [Enable monitoring (COS)](how-to-monitoring) — observe the cluster.
- [Scale a cluster horizontally](how-to-scale-horizontally) — adjust cluster size.
