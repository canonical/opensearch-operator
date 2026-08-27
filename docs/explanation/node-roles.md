---
myst:
  html_meta:
    description: "Understand OpenSearch node roles, data tiers, and large deployment topology with the main orchestrator pattern in Charmed OpenSearch."
---

(explanation-node-roles)=
# Node roles and cluster topology

OpenSearch clusters are made up of nodes, each assigned one or more **roles** that determine
what work the node performs. In Charmed OpenSearch, roles are assigned at the
Juju **application** level — all units within an application share the same set of roles.
This page explains the available roles, how they interact, and how multiple applications
combine to form a large deployment.

(explanation-node-roles-available)=
## Available node roles

OpenSearch supports the following built-in roles, all of which can be used in Charmed OpenSearch:

| Role | Description |
| :--- | :--- |
| `cluster_manager` | Handles cluster-wide operations: creating and deleting indices, managing shard allocation, and rebalancing data. One node is elected **cluster manager** among all `cluster_manager`-eligible nodes. |
| `data` | Stores indexed data and performs search and indexing operations. Data nodes hold the shards that contain the indexed documents. |
| `data.hot` | A data tier for time-series data that receives the most recent, most frequently queried data. |
| `data.warm` | A data tier for data that is queried less frequently but still needs to be searchable. |
| `data.cold` | A data tier for infrequently accessed data, stored on less expensive hardware. |
| `ingest` | Pre-processes documents before they are indexed (pipelines, transformations). |
| `coordinating` | Routes requests to the appropriate data nodes and aggregates results. Does not hold data. |
| `voting_only` | Participates in cluster manager election but is never eligible to become the cluster manager node itself. |
| `ml` | Runs machine learning tasks such as model training and inference. |

Data nodes can optionally be classified into **tiers** (`data.hot`, `data.warm`, `data.cold`)
to support [index lifecycle management](https://opensearch.org/docs/latest/im-plugin/ism/index/)
policies that move data between tiers as it ages.

## Auto-generated roles

When the `roles` configuration option is left empty, the charm automatically assigns the
following roles to all nodes in the application:

```python
["data", "ingest", "ml", "cluster_manager"]
```

This means a single-application deployment can handle all functions — cluster management,
data storage, ingestion, and machine learning — without any additional configuration.

## Setting roles

Roles can be set at deployment time or changed later via configuration:

```shell
# At deployment time
juju deploy opensearch -n 3 --config roles="cluster_manager,data,ml"

# After deployment (triggers a rolling restart)
juju config opensearch roles="cluster_manager,data,ml"
```

```{note}
Removal of the `cluster_manager` or `data` roles is not supported.
These roles are essential for cluster operation and data availability.
```

## Large deployments

For production workloads, a single application is often insufficient. Charmed OpenSearch
supports **large deployments** — a single OpenSearch cluster composed of multiple Juju
applications, each configured with specific node roles. This topology allows you to
scale different node types independently and provides fault tolerance.

### The main orchestrator pattern

A large deployment consists of three types of applications:

1. **Main orchestrator** — the primary application that bootstraps the cluster.
   It has `init_hold=false` (the default) and is responsible for generating the cluster UUID,
   initialising the security index, and sharing admin certificates with other applications.
   When no roles are explicitly set, it receives all auto-generated roles.

2. **Failover orchestrator** (recommended) — a dedicated `cluster_manager` application that
   takes over orchestration if the main orchestrator fails or is removed.
   It must have `init_hold=true` to prevent it from starting before being integrated
   with the main orchestrator.

3. **Data applications** — applications with `data`-tier roles (e.g. `data.hot`, `data.warm`)
   that store and process data. They also require `init_hold=true`.

### Critical configuration rules

Two configuration options are essential for large deployments:

- **`cluster_name`**: All applications must share the same `cluster_name` value.
  A mismatch prevents applications from forming a cluster. If left unset on the main
  orchestrator, a name is auto-generated and inherited by other applications via the
  peer-cluster relation.

- **`init_hold`**: Must be set to `true` on every application **except** the main orchestrator.
  This prevents non-orchestrator applications from starting before they are integrated with
  the main orchestrator, which would cause them to fail (they cannot reach the cluster
  to obtain admin certificates and cluster metadata).

### Cluster formation

The applications are connected via the **peer-cluster** relations:

```shell
juju integrate main:peer-cluster-orchestrator failover:peer-cluster
juju integrate main:peer-cluster-orchestrator data-hot:peer-cluster
juju integrate failover:peer-cluster-orchestrator data-hot:peer-cluster
```

Once these relations are established, the main orchestrator shares the cluster UUID,
admin certificates, and security configuration with the other applications. The other
applications then start and join the cluster.

### Integrations and the main orchestrator

In a large deployment, integrations with external charms (e.g. SMTP, JWT, OAuth) must
target the **main orchestrator** application, not the data or failover applications.
The main orchestrator is responsible for distributing configuration to the rest of the
cluster. If integrated with the wrong application, the charm will enter a `blocked` state.

You can identify the main orchestrator by inspecting the `integrations` section of
`juju status` — look for the application providing the `peer-cluster-orchestrator` endpoint.

## See also

* [How to launch a large deployment](how-to-deploy-large) — step-by-step deployment guide.
* [Performance profiles](explanation-performance-profiles) — resource tuning for different deployment sizes.
* [Cluster health and scaling](explanation-cluster-health) — understanding cluster health states.
