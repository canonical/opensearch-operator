---
myst:
  html_meta:
    description: "Reuse and recover OpenSearch data from Juju-managed disks containing existing cluster metadata and data."
---

(how-to-persistent-storage)=
# How to manage persistent storage

This guide shows how to reuse disks that contain data from a previous OpenSearch cluster.
For an explanation of the risks of disk reuse, dangling indices, and metadata cleanup,
see [Persistent storage and disk recovery](explanation-persistent-storage).

There are three scenarios:

* **Same cluster** — a detached volume is reattached to a new unit in the same cluster.
  The node rejoins automatically with no metadata changes required.
* **Different cluster (attach)** — a disk from a different cluster is attached to an existing
  cluster. The disk holds stale metadata referencing the old cluster UUID, so the
  `detach-cluster` tool must be run to discard that metadata before the node can join.
* **Different cluster (bootstrap)** — a disk from a different cluster is used to seed a brand
  new single-node deployment. The `unsafe-bootstrap` tool resets the cluster metadata so that
  a new cluster UUID is assigned and the node can start.

```{note}
These steps apply only to **persistent** disks under Juju management
(e.g. deployed using a persistent storage pool such as LXD ZFS or Btrfs).
Non-persistent storage (such as the default `rootfs` pool) is destroyed
when its unit is removed and cannot be reused.
Bringing external disks or volumes into Juju is not currently supported.
```

```{caution}
Back up your data before proceeding. Reusing disks may cause older data
to override newer data.
```

## Prerequisites

Ensure the disks are visible within Juju. List volumes with:

```shell
juju storage
```

For more details, see [Juju storage management](https://juju.is/docs/juju/manage-storage).

## Reuse a disk within the same cluster

If a volume is detached (visible via `juju storage` with status `detached`),
attach it to a new unit:

```shell
juju add-unit opensearch -n 1 --attach-storage opensearch-data/<id>
```

The new node will start with the existing data and rejoin the cluster automatically.

## Reuse a disk from a different cluster

When attaching a disk from a different cluster, the node holds stale metadata
referencing the old cluster UUID. You must clean this metadata manually.

### Attach to an existing cluster

Add a new unit with the used disk:

```shell
juju add-unit opensearch --attach-storage opensearch-data/<id>
```

The unit will fail to join. Confirm this is the expected UUID-mismatch error by inspecting the logs:

```text
CoordinationStateRejectedException: join validation on cluster state with a different cluster uuid
... rejecting
```

SSH into the unit and fix it:

```shell
juju ssh opensearch/<unit-id>
sudo systemctl stop snap.opensearch.daemon
```

Detach the node from its old cluster references:

```shell
sudo -u snap_daemon \
    OPENSEARCH_JAVA_HOME=/snap/opensearch/current/usr/lib/jvm/java-21-openjdk-amd64 \
    OPENSEARCH_PATH_CONF=/var/snap/opensearch/current/etc/opensearch \
    OPENSEARCH_HOME=/var/snap/opensearch/current/usr/share/opensearch \
    OPENSEARCH_LIB=/var/snap/opensearch/current/usr/share/opensearch/lib \
    OPENSEARCH_PATH_CERTS=/var/snap/opensearch/current/etc/opensearch/certificates \
    /snap/opensearch/current/usr/share/opensearch/bin/opensearch-node detach-cluster
```

Restart the service:

```shell
sudo systemctl start snap.opensearch.daemon
```

The node will join the cluster.

### Bootstrap a new cluster from a used disk

Deploy a new single-node cluster with the used disk:

```shell
juju deploy opensearch -n1 --attach-storage opensearch-data/<id>
```

The unit will fail to start. Confirm this is the expected error by inspecting the logs:

```text
ConfigurationRepository: Wait for cluster to be available
```

SSH in and fix it:

```shell
juju ssh opensearch/<unit-id>
sudo systemctl stop snap.opensearch.daemon
```

Run `unsafe-bootstrap` to reset cluster metadata:

```shell
sudo -u snap_daemon \
    OPENSEARCH_JAVA_HOME=/snap/opensearch/current/usr/lib/jvm/java-21-openjdk-amd64 \
    OPENSEARCH_PATH_CONF=/var/snap/opensearch/current/etc/opensearch \
    OPENSEARCH_HOME=/var/snap/opensearch/current/usr/share/opensearch \
    OPENSEARCH_LIB=/var/snap/opensearch/current/usr/share/opensearch/lib \
    OPENSEARCH_PATH_CERTS=/var/snap/opensearch/current/etc/opensearch/certificates \
    /snap/opensearch/current/usr/share/opensearch/bin/opensearch-node unsafe-bootstrap
```

Restart the service:

```shell
sudo systemctl start snap.opensearch.daemon
```

The cluster will form with a new UUID. You can then add more units (fresh or detached from another cluster).

## Recover dangling indices

After reattaching a used disk, check for indices that were not part of the current cluster
using the [dangling indices API](https://opensearch.org/docs/latest/api-reference/index-apis/dangling-index/).

```{caution}
The dangling indices API cannot guarantee that imported data represents the latest state
of the data when the index was still part of the original cluster.
```

## Expected result

After reusing a disk within the same cluster, the new unit rejoins automatically with existing
data. After `detach-cluster` or `unsafe-bootstrap`, the node joins the target cluster and
`juju status` shows the unit `active/idle`.

## Next steps

* [Back up and restore](how-to-guides-back-up-and-restore-index) — create backups before reusing disks.
* [Scale down safely](how-to-scale-horizontally) — safely remove units when reorganising storage.
