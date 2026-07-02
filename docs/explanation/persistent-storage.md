---
myst:
  html_meta:
    description: "Understand persistent storage, disk reuse risks, dangling indices, and metadata cleanup in Charmed OpenSearch."
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

The `opensearch-node` command-line tool allows operators to clean up portions of the
metadata on a used disk before re-attaching it to a cluster. Two subcommands are relevant:

- **`detach-cluster`** — removes stale cluster references (cluster UUID, peer node list)
  from the disk metadata. Used when attaching a disk from a different cluster to an
  existing cluster.

- **`unsafe-bootstrap`** — resets the cluster metadata entirely so that a new cluster UUID
  is assigned. Used when bootstrapping a brand new cluster from a disk that belonged to
  a previous cluster.

## Scenarios for disk reuse

There are three scenarios, each requiring a different approach:

### Same cluster — reattaching a detached volume

If a volume was previously used by a node in the same cluster and was detached (e.g. due
to a unit removal), it can be reattached to a new unit. The node rejoins the cluster
automatically with no metadata changes required — the cluster UUID and peer references
already match.

### Different cluster — attaching to an existing cluster

When a disk from a different cluster is attached to a new unit in an existing cluster,
the node holds stale metadata referencing the old cluster UUID. The node will fail to join
because it cannot reach its old peers. The `detach-cluster` tool must be run to remove
the stale metadata before the node can join the new cluster.

### Different cluster — bootstrapping a new cluster

When a disk from a different cluster is used to seed a brand new single-node deployment,
the node will fail to start because it is trying to load its original metadata and cannot
reach any of its old peers. The `unsafe-bootstrap` tool must be run to reset the cluster
metadata, after which a new cluster UUID is assigned and the node starts fresh.

## See also

* [How to manage persistent storage](how-to-persistent-storage) — step-by-step guide for reusing disks.
* [How to back up and restore](how-to-create-a-backup) — create backups before reusing disks.
* [Node roles and cluster topology](explanation-node-roles) — how nodes and clusters are structured.
