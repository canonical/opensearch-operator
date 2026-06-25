---
myst:
  html_meta:
    description: "Deploy large-scale Charmed OpenSearch clusters with node roles, data tiers, and production configurations for high-performance workloads."
---

(how-to-deploy-large)=
# How to launch a large deployment

This guide shows how to deploy a multi-application OpenSearch cluster using Juju,
with dedicated node roles for scalability and fault tolerance.

## Node roles overview

In a large deployment, nodes are assigned
[roles](https://opensearch.org/docs/latest/tuning-your-cluster/) at the Juju application level
(all units in an application share the same roles). The two essential roles are:

- `cluster_manager` — handles cluster-wide operations (index creation, shard management, rebalancing). One node is elected master among all `cluster_manager`-eligible nodes.
- `data` — stores indexed data and performs search/indexing operations.

Data nodes can optionally be classified into tiers for
[index lifecycle management](https://opensearch.org/docs/latest/im-plugin/ism/index/):
`data.hot`, `data.warm`, `data.cold`.

### Set roles

If no roles are configured, the charm auto-assigns: `data`, `ingest`, `ml`, `cluster_manager`.

To set roles at deploy time:

```shell
juju deploy opensearch -n 3 --config roles="cluster_manager,data,ml"
```

To change roles after deployment (triggers a rolling restart):

```shell
juju config opensearch roles="cluster_manager,data,ml"
```

```{note}
Removal of the `cluster_manager` or `data` roles is not supported.
```

## Deploy the cluster applications

A large deployment consists of multiple Juju applications integrated together,
each configured with specific node roles.

```{caution}
The examples below use the `testing` profile (1 GB RAM per node) for a single-host LXD environment.
For production, use `production` (50% of RAM, up to 32 GB) or `staging` (25% of RAM, up to 32 GB).
```

```{important}
**Two critical configuration rules for large deployments:**

1. All applications must share the same `cluster_name` value.
   A mismatch prevents applications from forming a cluster.
2. Set `init_hold=true` on every application **except** the main orchestrator.
   This prevents non-orchestrator applications from starting before integration.
```

### 1. Deploy the main orchestrator

```shell
juju deploy -n 3 \
    opensearch main \
    --config cluster_name="app" \
    --channel 2/edge \
    --config profile="testing"
```

Since no roles are specified, the charm auto-assigns all default roles.

### 2. Deploy a failover application (recommended)

The failover application takes over orchestration if the `main` app fails or is removed:

```shell
juju deploy -n 3 \
    opensearch failover \
    --config cluster_name="app" \
    --config init_hold="true" \
    --config roles="cluster_manager" \
    --channel 2/edge \
    --config profile="testing"
```

### 3. Deploy data nodes

Deploy an application with `data.hot` roles:

```shell
juju deploy -n 3 \
    opensearch data-hot \
    --config cluster_name="app" \
    --config roles="data.hot" \
    --config init_hold="true" \
    --channel 2/edge \
    --config profile="testing"
```

### 4. Deploy TLS certificates

```shell
juju deploy self-signed-certificates
```

Track deployment progress:

```shell
juju status --watch 1s
```

At this point, `main` will show `blocked` (missing TLS), while `failover` and `data-hot`
will show `blocked` (waiting for peer cluster relation).

## Configure TLS encryption

Charmed OpenSearch requires TLS. Integrate `self-signed-certificates` with all OpenSearch applications:

```shell
juju integrate self-signed-certificates main
juju integrate self-signed-certificates failover
juju integrate self-signed-certificates data-hot
```

The `main` app will become `active` once TLS is configured.
The other apps remain `blocked` until the peer-cluster relations are added in the next step.

## Form the OpenSearch cluster

Integrate the applications via the peer-cluster relations:

```shell
juju integrate main:peer-cluster-orchestrator failover:peer-cluster
juju integrate main:peer-cluster-orchestrator data-hot:peer-cluster
juju integrate failover:peer-cluster-orchestrator data-hot:peer-cluster
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
