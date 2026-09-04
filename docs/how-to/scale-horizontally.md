---
myst:
  html_meta:
    description: "Scale Charmed OpenSearch clusters horizontally by adding or removing units, safely and without data loss."
---

(how-to-scale-horizontally)=
# How to scale a cluster horizontally

This guide shows how to remove nodes from a Charmed OpenSearch cluster
without data loss or availability disruption.

For a hands-on example, see [Tutorial: Scale horizontally](tutorial-6-scale-horizontally).

```{warning}
* **Never remove multiple units in a single command.** Remove one unit at a time.
* In highly available deployments, **do not scale below 3 nodes**.
```

## Scale up

To add nodes to the cluster, run:

```shell
juju add-unit opensearch -n <number-of-units>
```

Monitor the new units joining the cluster:

```shell
watch juju status
```

New units automatically join the cluster and start receiving shard allocations.
No additional configuration is required.

## Scale down

Before removing a node, verify the cluster is healthy.

### Via Juju

The charm reflects cluster health in the application status on a best-effort basis:

* `active` — the cluster is healthy
* `maintenance` — shards are still initializing or relocating
* `waiting` — the charm is waiting for an operation to complete
* `blocked` — the cluster has issues (the message describes the problem)

Run `juju status` and make sure the application is `active` before proceeding.
A `maintenance` or `waiting` status does not necessarily mean something is wrong, but it
does indicate that now is not the best time to scale down — wait for the cluster to settle.

For example, the following output shows an application blocked because replica shards
cannot be assigned:

```text
App         Version  Status   Scale  Charm       Channel   Rev  Exposed  Message
opensearch           blocked      1  opensearch  2/stable  344  no       1 or more 'replica' shards are not assigned, please scale your application up.

Unit           Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*  active    idle   1        10.95.38.230    9200/tcp
```

For an explanation of how each health state maps to a Juju status, see
[Cluster health and scaling](explanation-cluster-health).
The OpenSearch health API is the source of truth, so use the check below to confirm.

### Via the OpenSearch health API

For more detail, query the
[cluster health API](https://opensearch.org/docs/2.19/api-reference/cluster-api/cluster-health/).

First, retrieve the admin credentials and the CA certificate:

```shell
juju run opensearch/leader get-password
```

The `get-password` action returns the admin password and the CA certificate chain.
Save the CA certificate to a file (e.g. `cert.pem`) to use with `curl`.

(scale-cluster-health-status)=
### Interpret cluster health

The cluster health API returns `green`, `yellow`, or `red`.
For a detailed explanation of what each state means and how it maps to Juju status,
see [Cluster health and scaling](explanation-cluster-health).

**`green`** — Scaling down is likely safe.

Verify the target node does not hold a primary shard of an unreplicated index:

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cat/shards" -u admin:<password>
```

If it does, [re-route](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-reroute/) the shard to another node first.

**`yellow`** — Scaling down **may not be safe**. Some replica shards are unassigned.

Investigate with the
[cluster allocation explain API](https://opensearch.org/docs/2.19/api-reference/cluster-api/cluster-allocation/):

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cluster/allocation/explain" -u admin:<password>
```

Depending on the cause, the resolution may be scaling up, adding storage to existing nodes, or
[re-routing](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-reroute/) the
affected shard to another node. The most common fix is to scale up to restore green health
before scaling down:

```shell
juju add-unit opensearch -n 1
```

**`red`** — Scaling down **is not safe**. At least one primary shard is unassigned.

Do not add units before you know why. Adding capacity only helps for some causes, and an
empty node cannot recreate data that no longer exists. Diagnose the cause first:

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cluster/allocation/explain" -u admin:<password>
```

Then act on what the output reports:

| Cause | Resolution |
| :--- | :--- |
| Too little disk space, or too few suitable nodes | Scale up, or add storage to existing nodes. |
| Allocation rules prevent the shard from being placed | Correct the allocation rules. |
| `no_valid_shard_copy` — no valid copy of the primary shard exists on any available node | Recover the failed node, or [restore a snapshot](how-to-restore-a-local-backup). Adding units will not help. |

Where the cause is capacity or topology, scale up:

```shell
juju add-unit opensearch -n 1
```

```{note}
If health becomes `red` after removing a unit, the charm blocks further removal
to give you the opportunity to scale back up.
```

### Remove one unit

Once health is confirmed green, remove **a single unit**:

```shell
juju remove-unit opensearch/<unit-id>
```

Monitor progress:

```shell
juju status --watch 1s
```

```{note}
The charm does not know in advance whether a removal will degrade cluster health.
Always verify health after each removal before proceeding.
```

### Verify and repeat

After removal, OpenSearch reallocates the departed node's shards across the remaining nodes.
If the removed node was `cluster_manager`-eligible, the charm also updates the cluster's voting
configuration and a new cluster manager is elected.

Wait for the application to fully stabilise (`active/idle`), then
[check cluster health](#scale-cluster-health-status) again.

Repeat the removal step for each additional unit you need to remove.

## Next steps

* [Optimize cluster performance with profiles](how-to-optimize-cluster-performance) — tune resource allocation for the new cluster size.
* [Upgrade, rollback, and recover](how-to-minor-upgrade) — upgrade the cluster after scaling.
