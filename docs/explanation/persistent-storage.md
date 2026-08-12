---
myst:
  html_meta:
    description: "Understand persistent storage, disk reuse risks, dangling indices, and last-resort coordination-metadata recovery in Charmed OpenSearch."
---

(explanation-persistent-storage)=
# Persistent storage and disk recovery

Charmed OpenSearch stores data and cluster metadata on Juju-managed storage volumes.
In some scenarios — such as disaster recovery, cluster migration, or hardware replacement —
you may need to reuse disks that already contain data from a previous OpenSearch cluster.
This page explains the concepts behind disk reuse, the risks involved, and the mechanisms
OpenSearch provides for detecting and recovering existing data.

## Why disk reuse is risky

When a disk that previously belonged to an OpenSearch cluster is attached to a new node,
the disk contains not only indexed data but also **cluster metadata** — the cluster UUID,
node identity, and references to peer nodes. If this metadata does not match the current
cluster, the node may fail to start or may behave unpredictably.

```{caution}
Reusing disks may cause older data to override existing or newer data.
Make sure the disks and their contents are known before proceeding.
```

## Prefer snapshot and restore

Moving data between clusters by reattaching disks is **not** a general-purpose migration
path. The only supported, data-safe way to move data between clusters is to
[create a backup](how-to-create-a-backup) of the source cluster and
[restore or migrate](how-to-migrate-a-cluster) it into the target cluster.

Reusing a disk from a different cluster involves editing the node's on-disk
**coordination metadata** — the cluster UUID and voting configuration used to elect a
cluster manager. This is a last resort for disaster recovery, valid only when the source
cluster is permanently gone (for example, after losing a majority of
`cluster_manager`-eligible nodes, or after a brutal cluster decommission) **and** no viable
snapshot exists to restore from instead.

## How OpenSearch detects existing data

OpenSearch provides two mechanisms for interacting with data on an attached disk:

### The `/_dangling` API

When a node starts with a disk that contains index data not known to the current cluster,
those indices are called **dangling indices**. The
[dangling indices API](https://opensearch.org/docs/latest/api-reference/index-apis/dangling-index/)
allows you to list, import, or delete them.

```{caution}
The dangling indices API cannot guarantee that the imported data accurately represents
the latest state of the data when the index was still part of the original cluster.
```

### The `opensearch-node` CLI

The `opensearch-node` command-line tool performs **coordination-metadata surgery** on a
stopped node's disk: it edits the cluster UUID and voting configuration directly on disk,
bypassing the normal cluster-formation and consensus protocol. It is **not** a
general-purpose way to migrate disks between clusters.

```{danger}
`detach-cluster` and `unsafe-bootstrap` are last-resort disaster-recovery commands.
OpenSearch warns that they can cause **arbitrary data loss**, because the node running the
command may not hold the most recent cluster metadata. Only use them after the **permanent**
loss of a majority (or all) of the `cluster_manager`-eligible nodes in a cluster, or after a
brutal cluster decommission, and only when no viable snapshot recovery exists.
A success message from either command does not mean no data was lost — always audit the
data after recovery.
```

Two subcommands are relevant:

- **`detach-cluster`** — resets the cluster UUID on a surviving node so it can be adopted by
  a different cluster (for example, one freshly bootstrapped with `unsafe-bootstrap`).

- **`unsafe-bootstrap`** — creates a **new** cluster UUID and uses it to bootstrap a
  single surviving `cluster_manager`-eligible node into a brand new cluster, built from
  that node's own persisted metadata. This deliberately preserves the node's existing
  indices and metadata where possible, but data loss is still possible if that metadata is
  not the most up to date.

## Scenarios for disk reuse

There are three scenarios, each requiring a different approach:

### Same cluster — reattaching a detached volume

If a volume was previously used by a node in the same cluster and was detached (e.g. due
to a unit removal), it can be reattached to a new unit. The node rejoins the cluster
automatically with no metadata changes required — the cluster UUID and peer references
already match.

### Different cluster — attaching to an existing cluster (last resort)

When a disk from a different cluster is attached to a new unit in an existing cluster,
the node holds stale metadata referencing the old cluster UUID. The node will fail to join
because it cannot reach its old peers. This is only appropriate if the source cluster is
permanently gone and no viable snapshot exists to restore from instead — in that case, the
last-resort `detach-cluster` tool can be run to discard the stale metadata so the node can
join the new cluster.

### Different cluster — bootstrapping a new cluster (last resort)

When a disk from a different cluster is used to seed a brand new single-node deployment,
the node will fail to start because it is trying to load its original metadata and cannot
reach any of its old peers. Again, this only makes sense if the source cluster is
permanently gone and no viable snapshot exists — in that case, the last-resort
`unsafe-bootstrap` tool can be run to reset the cluster metadata, after which a new cluster
UUID is assigned and the node starts fresh.

## See also

* [How to back up and restore](how-to-guides-back-up-and-restore-index) — the preferred, data-safe way to move data between clusters.
* [How to manage persistent storage](how-to-persistent-storage) — step-by-step guide, including the last-resort disaster-recovery procedure.
* [Node roles and cluster topology](explanation-node-roles) — how nodes and clusters are structured.
