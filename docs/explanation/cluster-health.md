---
myst:
  html_meta:
    description: "Understand OpenSearch cluster health states (green, yellow, red), how they map to Juju status, and safe scaling practices in Charmed OpenSearch."
---

(explanation-cluster-health)=
# Cluster health and scaling

OpenSearch reports cluster health as a single status that summarises the state of shard
allocation across all nodes. Charmed OpenSearch reflects this health in the Juju application
status, making it visible without querying the OpenSearch API directly. Understanding these
health states is essential for safe scaling operations — particularly when removing nodes.

## Cluster health states

The OpenSearch [cluster health API](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-health/)
returns one of three states:

| State | Meaning | Scaling down safe? |
| :--- | :--- | :--- |
| **`green`** | All primary and replica shards are allocated. The cluster is fully healthy. | Likely safe — but verify the target node does not hold a primary shard of an unreplicated index. |
| **`yellow`** | All primary shards are allocated, but some replica shards are **unassigned**. The cluster is functional but lacks full redundancy. | **May not be safe** — removing a node could lose the only copy of a primary shard if replicas are unavailable. |
| **`red`** | Some primary shards are **unassigned**. Data is missing. | **Not safe** — do not remove nodes. Add units to restore health first. |

### How health maps to Juju status

The charm reflects cluster health in the application status:

- **`active`** — the cluster is healthy (equivalent to `green`).
- **`blocked`** — the cluster has issues (equivalent to `yellow` or `red`). The status
  message describes the problem, e.g. *"1 or more 'replica' shards are not assigned,
  please scale your application up"*.

This means you can use `juju status` as a quick health check without querying the
OpenSearch API directly.

## Shard allocation

To understand why health states matter for scaling, it helps to understand shard allocation:

- Each index is divided into **shards**. Each shard has a **primary** copy and zero or more
  **replica** copies distributed across nodes.
- When a node is removed, its shards must be **reallocated** to remaining nodes. If a primary
  shard's node is removed and no replica is available, the shard becomes unassigned (health
  turns `red`).
- If replicas are available, OpenSearch promotes a replica to primary and creates new replicas
  on remaining nodes (health may temporarily drop to `yellow`).

You can inspect shard allocation with:

```shell
curl --cacert cert.pem -k -XGET "https://<unit-ip>:9200/_cat/shards" -u admin:<password>
```

And explain why a shard is unassigned with:

```shell
curl --cacert cert.pem -k -XGET "https://<unit-ip>:9200/_cluster/allocation/explain" -u admin:<password>
```

## Safe scaling practices

**Adding nodes** is always safe. New units automatically join the cluster and start receiving
shard allocations. No additional configuration is required.

**Removing nodes** requires caution:

1. **Check health first** — confirm the cluster is `green` (or at minimum `yellow` with
   sufficient replicas) before removing any unit.
2. **Remove one unit at a time** — never remove multiple units in a single command.
   After each removal, wait for the cluster to rebalance and return to `green` before
   removing the next unit.
3. **Monitor after removal** — the charm may reconfigure and restart another unit to
   balance node roles. Wait for the application to fully stabilise before proceeding.

```{note}
In highly available deployments, **do not scale below 3 nodes**.
```

### Reactive blocking

The charm **reactively** (not proactively) blocks unsafe removals. This means it does not
know in advance whether removing a specific unit will put the cluster in a `red` state.
If health degrades to `red` after a removal, the charm will block further removals to give
you the opportunity to scale back up.

## See also

* [How to scale down safely](how-to-scale-horizontally) — step-by-step scaling guide.
* [Node roles and cluster topology](explanation-node-roles) — how node roles affect scaling.
* [Performance profiles](explanation-performance-profiles) — resource requirements for different deployment sizes.
