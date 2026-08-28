---
myst:
  html_meta:
    description: "Reuse and recover OpenSearch data from Juju-managed disks, including last-resort disaster-recovery metadata cleanup."
---

(how-to-persistent-storage)=
# How to manage persistent storage

This guide shows how to reuse disks that contain data from a previous OpenSearch cluster.
For an explanation of the risks of disk reuse, dangling indices, and metadata cleanup,
see [Persistent storage and disk recovery](explanation-persistent-storage).

```{note}
Prefer snapshot and restore whenever possible. The procedures on this page for reusing a
disk from a **different** cluster are last-resort disaster recovery, not a general-purpose
migration path. To move data between clusters, always try
[creating a backup](how-to-create-a-backup) and
[restoring or migrating it](how-to-migrate-a-cluster) first.
```

There are three scenarios:

* **Same cluster** (routine, safe) — a detached volume is reattached to a new unit in the
  same cluster. The node rejoins automatically with no metadata changes required.
* **Different cluster, attach** (last resort) — a disk from a different cluster is attached
  to an existing cluster. The disk holds stale metadata referencing the old cluster UUID.
  Only proceed if the source cluster is permanently gone and no viable snapshot exists —
  in that case, the last-resort `detach-cluster` tool discards that metadata so the node
  can join.
* **Different cluster, bootstrap** (last resort) — a disk from a different cluster is used
  to seed a brand new single-node deployment. Only proceed under the same conditions as
  above — the last-resort `unsafe-bootstrap` tool resets the cluster metadata so that a
  new cluster UUID is assigned and the node can start.

This guide applies only to **persistent** disks under Juju management
(e.g. deployed using a persistent storage pool such as LXD ZFS or Btrfs).
Non-persistent storage (such as the default `rootfs` pool) is destroyed
when its unit is removed and cannot be reused.
Bringing external disks or volumes into Juju is not currently supported.

```{caution}
Back up your data before proceeding. Reusing disks may cause older data
to override newer data.
```

## Prerequisites

Ensure the disks are visible within Juju. List volumes with:

```shell
juju storage
```

Note the Storage ID of a detached volume for use in the steps below:

```text
Unit          Storage ID         Type        Pool             Size     Status    Message
              opensearch-data/0  filesystem  opensearch-pool  2.0 GiB  detached
opensearch/1  opensearch-data/1  filesystem  opensearch-pool  2.0 GiB  attached
opensearch/2  opensearch-data/2  filesystem  opensearch-pool  2.0 GiB  attached
```

For more details, see [Juju storage management](https://juju.is/docs/juju/manage-storage).

## Reuse a disk within the same cluster

Attach the detached volume to a new unit:

```shell
juju add-unit opensearch --attach-storage opensearch-data/<id>
```

When the new unit shows `active/idle` in `juju status`, the node has rejoined the cluster
with the existing data. Re-running `juju storage` shows the reused volume as `attached`
to the new unit.

To confirm from OpenSearch's side, retrieve the admin password and CA certificate chain with
`juju run opensearch/leader get-password`, saving the chain to a file (e.g. `cert.pem`), and
list the cluster nodes:

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cat/nodes" -u admin:<password>
```

The new unit should appear in the output alongside the existing nodes. See
[mapping Juju units to OpenSearch nodes](cluster-health-mapping-nodes) for how to read this
output.

## Recover a disk from a different cluster (last resort)

When attaching a disk from a different cluster, the node holds stale metadata
referencing the old cluster UUID. The steps below perform coordination-metadata surgery on
that disk and are a **last resort** — use them only when the source cluster is permanently
gone and no viable snapshot exists to restore from instead.

```{caution}
`detach-cluster` and `unsafe-bootstrap` are last-resort disaster-recovery commands.
OpenSearch warns that they can cause **arbitrary data loss**, because the node running the
command may not hold the most recent cluster metadata. Only use them after the
**permanent** loss of a majority (or all) of the `cluster_manager`-eligible nodes in a
cluster, or after a brutal cluster decommission, and only when no viable snapshot recovery
exists. A success message from either command does not mean no data was lost.
```

Before proceeding, confirm all of the following:

* The source cluster (or the majority of its `cluster_manager`-eligible nodes) is
  permanently lost, decommissioned, or otherwise unrecoverable — not merely offline or
  repairable by moving its data path to healthy hardware.
* No usable snapshot exists to [restore or migrate](how-to-migrate-a-cluster) the data
  instead.
* All other nodes that were part of the old cluster are stopped, if any survive.
* If more than one node survives from the old cluster, `unsafe-bootstrap` should be run on
  the one reporting the highest `(term, version)` pair, since it holds the freshest
  metadata.

Both `detach-cluster` and `unsafe-bootstrap` (used below) prompt for interactive
confirmation (`Confirm [y/N]`) and print their own data-loss warning before making any
change.

### Attach to an existing cluster

Attach the used disk to a new unit:

```shell
juju add-unit opensearch --attach-storage opensearch-data/<id>
```

The unit will fail to join. Connect to it to confirm this is the expected UUID-mismatch
error and to run the remaining commands:

```shell
juju ssh opensearch/<unit-id>
```

All remaining commands in this section run **on the unit**, inside this session.

Inspect the logs:

```shell
sudo journalctl -u snap.opensearch.daemon -f
```

The unit repeatedly reports that it cannot join the cluster because of a UUID mismatch, similar to:

```text
CoordinationStateRejectedException: join validation on cluster state with a different cluster uuid
... rejecting
```

Press `Ctrl+C` to stop following the log, then stop the service:

```shell
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

To confirm, exit the unit session, retrieve the
admin password and CA certificate chain with `juju run opensearch/leader get-password`,
saving the chain to a file (e.g. `cert.pem`), and list the cluster nodes from the host with the
[CAT nodes API](https://opensearch.org/docs/2.19/api-reference/cat/cat-nodes/):

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cat/nodes" -u admin:<password>
```

The recovered node should appear in the output alongside the existing nodes. See
[mapping Juju units to OpenSearch nodes](cluster-health-mapping-nodes) for how to read this
output.

### Bootstrap a new cluster from a used disk

Deploy a new single-node cluster with the used disk:

```shell
juju deploy opensearch --attach-storage opensearch-data/<id>
```

The unit will fail to start. Connect to it to confirm this is the expected error and to run
the remaining commands:

```shell
juju ssh opensearch/<unit-id>
```

All remaining commands in this section run **on the unit**, inside this session.

Inspect the logs:

```shell
sudo journalctl -u snap.opensearch.daemon -f
```

The unit repeatedly reports that it is waiting for a cluster it cannot reach, similar to:

```text
ConfigurationRepository: Wait for cluster to be available
```

Press `Ctrl+C` to stop following the log, then stop the service:

```shell
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

The cluster will form with a new UUID.

To confirm, exit the unit session, retrieve the
admin password and CA certificate chain with `juju run opensearch/leader get-password`,
saving the chain to a file (e.g. `cert.pem`), and list the cluster nodes from the host with the
[CAT nodes API](https://opensearch.org/docs/2.19/api-reference/cat/cat-nodes/):

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cat/nodes" -u admin:<password>
```

The single bootstrapped node should be listed as the elected cluster manager (marked `*`). See
[mapping Juju units to OpenSearch nodes](cluster-health-mapping-nodes) for how to read this
output. You can then add more units (fresh or detached from another cluster).

## Recover dangling indices

After reattaching a used disk, check for indices that were not part of the current cluster
using the [dangling indices API](https://opensearch.org/docs/2.19/api-reference/index-apis/dangling-index/).

```{caution}
The dangling indices API cannot guarantee that imported data represents the latest state
of the data when the index was still part of the original cluster.
```

```{caution}
An `active/idle` status and a successful `detach-cluster` or `unsafe-bootstrap` message do
**not** mean no data was lost. Always audit the recovered indices and document counts, and
check for dangling indices, before treating the recovery as complete.
```

## Next steps

* [Back up and restore](how-to-guides-back-up-and-restore-index) — the preferred, data-safe way to move data between clusters; create backups before reusing disks.
* [Scale down safely](how-to-scale-horizontally) — safely remove units when reorganising storage.
