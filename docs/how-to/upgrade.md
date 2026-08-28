---
myst:
  html_meta:
    description: "Upgrade Charmed OpenSearch from one minor version to another, including pre-upgrade checks, in-place upgrades, health verification, and rollback procedures."
---

(how-to-guides-upgrade-index)=
# How to upgrade, rollback, and recover

This guide shows how to perform a minor revision upgrade of a Charmed OpenSearch deployment,
roll back if needed, and recover from a failed rollback.

(how-to-minor-upgrade)=
## Perform a minor upgrade

A minor upgrade is an upgrade from one minor version to another:
OpenSearch `X.Y` -> OpenSearch `X.Y+1`.
For example, from OpenSearch `2.15` to OpenSearch `2.16`.

This guide will walk you through the steps to upgrade your OpenSearch cluster,
including pre-upgrade checks, upgrading the OpenSearch cluster, preparing the application
for the in-place upgrade, initiating the upgrade, resuming the upgrade, and checking the cluster's health.

```{caution}
In large deployments, upgrades should follow a specific role-dependent order.
**Upgrade all applications without the `cluster_manager` role first, then upgrade applications
with the `cluster_manager` role.**
The steps below describe upgrading a single application.
In large deployments, repeat these steps for each application, following this order.
```

### Pre-upgrade checks

Before upgrading your OpenSearch cluster, ensure that you have completed the following steps:

1. **Backup your data**: Before upgrading, back up your data to prevent data loss in case of failure.
  For more information, see [How to create a backup](how-to-create-a-backup).
2. **Make sure not to perform any extraordinary operations**: Avoid performing any concurrent operations
  on the cluster during the upgrade process. This can lead to an inconsistent state of the cluster.
  This includes:
    - Adding or removing units
    - Creating or destroying new relations
    - Changes in workload configuration
    - Upgrading other connected/related/integrated applications simultaneously
    - Backup / restore of snapshots

### Upgrade the OpenSearch cluster

To upgrade your OpenSearch cluster, follow these steps:

1. Collect all necessary pre-upgrade information.
  It will be required for the rollback (if requested). **Do NOT skip this step**.
2. (optional) Scale-up: The new sacrificial unit will be the first to be updated,
  and will simplify the rollback procedure in the case of an upgrade failure.
3. Prepare the "Charmed OpenSearch" Juju application for the in-place upgrade.
  See the step description below for all the technical details the charm executes.
4. Upgrade: Only one app unit will be upgraded once started.
  In case of failure, roll back with `juju refresh`.
5. Resume upgrade: The upgrade can be resumed if the upgrade of the first unit is successful.
  All units in an app will be upgraded sequentially from the highest to lowest unit number.
6. (optional) Scale back: Remove no longer necessary units created in step 2 (if any).
7. Post-upgrade check: Ensure all units are in the proper state and the cluster is healthy.

#### Collect all necessary pre-upgrade information

The first step is to record the revision of the running application,
as a safety measure for a rollback action.
To accomplish this, run the `juju status` command and look for the deployed
Charmed OpenSearch revision in the command output, e.g.:

```text
Model  Controller           Cloud/Region         Version  SLA          Timestamp
dev    localhost-localhost  localhost/localhost  3.6.25   unsupported  10:16:46+01:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/stable       144  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   0        10.214.176.180  9200/tcp
opensearch/1                 active    idle   1        10.214.176.220  9200/tcp
opensearch/2*                active    idle   2        10.214.176.175  9200/tcp
self-signed-certificates/0*  active    idle   3        10.214.176.31

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.180  juju-0c35d2-0  ubuntu@24.04      Running
1        started  10.214.176.220  juju-0c35d2-1  ubuntu@24.04      Running
2        started  10.214.176.175  juju-0c35d2-2  ubuntu@24.04      Running
3        started  10.214.176.31   juju-0c35d2-3  ubuntu@24.04      Running
```

For this example, the current revision is **144** for OpenSearch.

```{note}
Make sure to store the revision number in case of rollback.
If the deployment is of a local charm, save a copy of the current `.charm` file.
```

#### Scale-up (optional)

Optionally, it is recommended to scale the application up by one unit before upgrading.

The new unit will be the first one to be updated, and it will assert that the upgrade is possible.
In the event of a failure, an extra unit simplifies manual recovery without disrupting service.

```shell
juju add-unit opensearch
```

Wait for the new unit to be up and ready.

### Prepare the application for the in-place upgrade

1. **IMPORTANT:** Create a backup of your cluster

Refer to [How to create a backup](how-to-create-a-backup).

2. Perform the `pre-upgrade-check` action

After the application has settled, it's necessary to run the `pre-upgrade-check` action against the leader unit:

```shell
juju run opensearch/leader pre-upgrade-check
```

The output should be similar to the following:

```text
Running operation 1 with 1 task
  - task 2 on unit-opensearch-2

Waiting for task 2...
result: Charm is ready for upgrade
```

The action will ensure and check the health of OpenSearch and determine if the charm
is well prepared to start an upgrade procedure.

### Initiate the upgrade

```{caution}
Charmed OpenSearch supports performance profiles with different RAM consumption:

* `production`: JVM heap set to 50% of the available RAM, capped at 31 GB
* `testing`: JVM heap fixed at ~1 GB of RAM

If the charm is running on a revision prior to `185`, the `testing` profile is the default.
Ensure it is set before upgrading, then switch to a profile that suits your use case.
See [How to optimize cluster performance with profiles](how-to-optimize-cluster-performance).
```

Use the `juju refresh` command to trigger the charm upgrade process.
You have control over what upgrade you want to apply:

- You can upgrade the charm to the latest revision available in the charm store for a specific channel,
  in this case, the stable channel:

    ```shell
    # If your charm is running a revision prior to 185, then set the profile explicitly:
    juju refresh opensearch --channel 2/stable --config profile="testing"

    # Otherwise, just refresh
    juju refresh opensearch --channel 2/stable
    ```

- You can also upgrade the charm to a specific revision:

    ```shell
    juju refresh opensearch --revision 145
    ```

- Or you can upgrade the charm using a local charm file:

    ```shell
    juju refresh opensearch --path /path/to/your/charm/file.charm
    ```

The OpenSearch upgrade will execute only on the highest ordinal unit. For the running example,
the `juju status` output will look similar to:

```text
Model  Controller           Cloud/Region         Version  SLA          Timestamp
dev    localhost-localhost  localhost/localhost  3.6.25   unsupported  10:29:07+01:00

App                       Version  Status   Scale  Charm        Channel   Rev  Exposed  Message
opensearch                         blocked      4  opensearch   2/stable  145  no       Upgrading. Verify highest unit is healthy & run `resume-upgrade` action. To rollback, `juju refresh` to last revision
self-signed-certificates           active       1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   0        10.214.176.180  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated)
opensearch/1                 active    idle   1        10.214.176.220  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated)
opensearch/2*                active    idle   2        10.214.176.175  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated)
opensearch/3                 active    idle   4        10.214.176.7    9200/tcp  OpenSearch 2.16.0 running; Snap rev 57
self-signed-certificates/0*  active    idle   3        10.214.176.31
```

The highest unit (`opensearch/3`) is upgraded first. The application shows `blocked` with a message
instructing you to verify the upgraded unit and run `resume-upgrade`.

```{note}
The unit should recover shortly after, but the time can vary depending on the amount of data
written to the cluster while the unit was not part of the cluster. Be patient with large installations.
```

### Resume the upgrade

After the first unit is upgraded, the charm will set the unit upgrade state as completed.
If deemed necessary, you can further assert the success of the upgrade.
If the unit is healthy within the cluster, the next step is to resume the upgrade process by running:

```shell
juju run opensearch/leader resume-upgrade
```

The `resume-upgrade` action will roll out the OpenSearch upgrade for the remaining units in the application.
The action will be executed sequentially from the highest unit number to the lowest.

Once all units are upgraded, the application status will return to `active`, all units will
show `active`/`idle`, and the version messages will disappear. The `Rev` column in the
`juju status` output will reflect the new charm revision.

### Rollback (optional)

In case of a failed upgrade, you might potentially be able to rollback to the previous revision.
To do so, follow the [Perform a minor rollback](how-to-minor-rollback) section below.

### Scale-back (optional)

If you scaled up the application in step 2, you can now scale it back down to the original number of units:

```shell
juju remove-unit opensearch/<highest unit number>
```

### Check the cluster health

First, check the units have settled as `active`/`idle` in `juju status`,
with the newer revision number in the `Rev` column. All unit messages should be empty
(no version or upgrade messages).

Check the cluster is healthy. OpenSearch's upstream documentation
[suggests the following check](https://opensearch.org/docs/latest/install-and-configure/upgrade-opensearch/rolling-upgrade/).

First, retrieve the admin credentials and the CA certificate chain:

```shell
juju run opensearch/leader get-password
```

Save the `ca-chain` value to a file (e.g. `cert.pem`) to use with `curl`:

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cluster/health?pretty" -u admin:<password>
```

The response should look similar to the following example:

```json
{
  "cluster_name" : "opensearch-wvmy",
  "status" : "green",
  "timed_out" : false,
  "number_of_nodes" : 3,
  "number_of_data_nodes" : 3,
  "discovered_master" : true,
  "discovered_cluster_manager" : true,
  "active_primary_shards" : 5,
  "active_shards" : 15,
  "relocating_shards" : 0,
  "initializing_shards" : 0,
  "unassigned_shards" : 0,
  "delayed_unassigned_shards" : 0,
  "number_of_pending_tasks" : 0,
  "number_of_in_flight_fetch" : 0,
  "task_max_waiting_in_queue_millis" : 0,
  "active_shards_percent_as_number" : 100.0
}
```

(how-to-minor-rollback)=
## Perform a minor rollback

```{caution}
OpenSearch does not support downgrading.
For more information, please refer to the upstream
[OpenSearch documentation about rolling upgrades](https://docs.opensearch.org/latest/migrate-or-upgrade/rolling-upgrade/#preparing-to-upgrade).
```

While rolling back a charm revision that does not change the underlying OpenSearch version is a safe operation, it is important to note that rolling back in Charmed OpenSearch is a best-effort process to restore the cluster to a previous revision. If the OpenSearch workload version is different, it does not guarantee that the cluster will be rolled back to a previous version. 

After a `juju refresh`, if there are any version incompatibilities in charm revisions,
their dependencies, or any other unexpected failure in the upgrade process,
the process will be halted and enter a failure state.

Even if the underlying OpenSearch cluster continues to work, it's important to roll back the charm to
a previous revision so that an update can be attempted after further inspection of the failure.

### Pre-rollback checks

To execute a rollback we take the same procedure as the upgrade, the difference being
the charm revision to upgrade to. As an example follow up
[the minor upgrades guide](how-to-minor-upgrade).

```{note}
Do **not** run `pre-upgrade-check` before a rollback. The action refuses to run while an
upgrade is in progress and fails with `Upgrade already in progress`. Because a rollback only
happens mid-upgrade, the action can never succeed at this point.

The charm runs the equivalent checks itself: after `juju refresh`, it detects the rollback
and re-enables shard allocation without requiring the action.
```

Before rolling back, check `juju status`. The application will show `blocked` with a message like
`Upgrading. Verify highest unit is healthy & run \`resume-upgrade\` action. To rollback, \`juju refresh\` to last revision`.
The unit messages will show which units have already been upgraded (newer OpenSearch version)
and which are still on the old version (marked `(outdated)`). Note the current charm revision
from the `Rev` column — in this example, it is **145**.

### Rollback the charm

```{caution}
Do not trigger a rollback during a running upgrade action.
It may cause an unpredictable OpenSearch state.
```

```{caution}
Rollbacks in Charmed OpenSearch are a best-effort process. It is recommended to perform a backup and restore to a new deployment with the desired OpenSearch version instead of performing a rollback. Rollbacks carry the potential of *data loss* and *downtime*.
```

#### Rollback a charm revision with the same workload version

You can initiate the rollback by running the `refresh` command with the revision of
the charm you want to rollback to. For example, to rollback to revision **144**, run:

```shell
juju refresh opensearch --revision=144
```

When deploying from a local charm file, you must have the previous revision's `.charm` file.
Then, run:

```shell
juju refresh opensearch --path=<path-to-charm-file>
```

After the refresh command, the Juju controller revision for the application will be
back in sync with the running OpenSearch revision. `juju status` will show the application
`active` with the previous revision number in the `Rev` column (e.g. **144**), and all units
`active`/`idle` with no messages.

#### Rollback a charm revision with a different workload version

If you roll back to a charm revision with a different workload version, the process will roll back the charm code and then make a best-effort attempt to roll back the workload, since OpenSearch does not support downgrades.

##### If the rollback between the versions is possible

In this case, both the charm code and the workload will be rolled back to the previous version. However, because rollback is a risky operation, rolling back the workload requires manual intervention. The charm will enter a `blocked` state and display a message instructing you to run the `force-refresh-start` action with `check-compatibility=false` to continue the best-effort workload rollback:

```text
Model    Controller           Cloud/Region         Version  SLA          Timestamp
testing  localhost-localhost  localhost/localhost  3.6.25   unsupported  08:36:09+01:00

App                       Version  Status   Scale  Charm       Channel  Rev  Exposed  Message
opensearch                         blocked      3  opensearch            2  no       Upgrading. Verify highest unit is healthy & run `resume-upgrade` action.
self-signed-certificates           active       1  self-signed-certificates  1/stable  586  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   1        10.149.40.7     9200/tcp  OpenSearch 2.18.0 running; Snap rev 66
opensearch/1                 active    idle   2        10.149.40.93    9200/tcp  OpenSearch 2.18.0 running; Snap rev 66
opensearch/2*                blocked   idle   3        10.149.40.126   9200/tcp  Rollback incompatible. Run 'juju run <unit> force-refresh-start' with `check-compatibility` set to false to override
self-signed-certificates/0*  active    idle   0        10.149.40.252
```

Run the action on the blocked unit:

```shell
juju run opensearch/<unit-id> force-refresh-start check-compatibility=false
```

##### If the rollback between the versions is not possible

In this case, the charm code will be rolled back, but the OpenSearch workload will remain on the newer version. The charm will enter a `blocked` state and display a message instructing you to either refresh to a charm revision with the same workload version or perform a backup and restore to a new deployment:

```text
Model    Controller           Cloud/Region         Version  SLA          Timestamp
testing  localhost-localhost  localhost/localhost  3.6.25   unsupported  08:03:52+01:00

App                       Version  Status   Scale  Charm       Channel  Rev  Exposed  Message
opensearch                         blocked      3  opensearch            17  no       Upgrading. Verify highest unit is healthy & run `resume-upgrade` action.
self-signed-certificates           active       1  self-signed-certificates  1/stable  586  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/6*                active    idle   7        10.149.40.239   9200/tcp  OpenSearch 2.17.0 running; Snap rev 58
opensearch/7                 active    idle   8        10.149.40.64    9200/tcp  OpenSearch 2.17.0 running; Snap rev 58
opensearch/8                 blocked   idle   9        10.149.40.31    9200/tcp  Rollback unsupported. Refresh to a newer revision or consult the recovery documentation
self-signed-certificates/0*  active    idle   0        10.149.40.55
```

### Check the cluster's health

Once the charm is rolled back, it is important to check the cluster's health to ensure it is healthy.
OpenSearch's upstream documentation
[suggests the following check](https://opensearch.org/docs/latest/install-and-configure/upgrade-opensearch/rolling-upgrade/):

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cluster/health?pretty" -u admin:<password>
```

The response should look similar to the following example:

```json
{
  "cluster_name" : "opensearch-7ngj",
  "status" : "green",
  "timed_out" : false,
  "number_of_nodes" : 3,
  "number_of_data_nodes" : 3,
  "discovered_master" : true,
  "discovered_cluster_manager" : true,
  "active_primary_shards" : 5,
  "active_shards" : 15,
  "relocating_shards" : 0,
  "initializing_shards" : 0,
  "unassigned_shards" : 0,
  "delayed_unassigned_shards" : 0,
  "number_of_pending_tasks" : 0,
  "number_of_in_flight_fetch" : 0,
  "task_max_waiting_in_queue_millis" : 0,
  "active_shards_percent_as_number" : 100.0
}
```

(how-to-recover-rollback)=
## Recovering from a rollback

OpenSearch does not support downgrades.
Running `juju refresh` to a previous revision may cause OpenSearch to fail to start.
In that case, manual recovery is required.
Follow the steps in this section to restore the cluster to a healthy state.

For more information, please refer to the upstream
[OpenSearch documentation about rolling upgrades](https://docs.opensearch.org/latest/migrate-or-upgrade/rolling-upgrade/#preparing-to-upgrade).

### Check Juju status

First, check Juju model status:

```shell
juju status
```

The rolled back unit may appear stuck displaying the status `Waiting for OpenSearch to start...`:

```text
Model  Controller           Cloud/Region         Version  SLA          Timestamp
test   localhost-localhost  localhost/localhost  3.6.25   unsupported  01:32:11+01:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/stable       168  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  264  no

Unit                         Workload  Agent      Machine  Public address  Ports     Message
opensearch/0*                active    idle       0        10.45.114.156   9200/tcp
opensearch/1                 active    idle       1        10.45.114.208   9200/tcp
opensearch/2                 waiting   executing  2        10.45.114.147   9200/tcp  Waiting for OpenSearch to start...
self-signed-certificates/0*  active    idle       3        10.45.114.124
```

Note the blocked unit; in this example, it is `opensearch/2`.
This unit will not recover automatically, and additional steps are required to replace it.

### Check cluster health

Retrieve the cluster health using the `cert.pem` and `<password>` obtained above:

```shell
curl --cacert cert.pem -X GET "https://<unit-ip>:9200/_cluster/health?pretty" -u admin:<password>
```

If the cluster health is red, one or more primary shards cannot be allocated.
Allocation explanations will identify any indices that exist only on the rolled back unit
which has left the cluster.
As the departed unit will not rejoin, these indices cannot be recovered and must be removed.

Identify the problematic index from the output of:

```shell
curl --cacert cert.pem -X GET "https://<unit-ip>:9200/_cluster/allocation/explain?pretty" -u admin:<password>
```

For example, in the following output, `index1` cannot be recovered as its current state is
`unassigned` with the reason `NODE_LEFT`:

```json
{
  "index": "index1",
  "shard": 0,
  "primary": true,
  "current_state": "unassigned",
  "unassigned_info": {
    "reason": "NODE_LEFT",
    "at": "2025-11-27T08:40:43.653Z",
    "details": "node_left [NKDiDmZ7TOShHAW32rcleg]",
    "last_allocation_status": "no_valid_shard_copy"
  },
  "can_allocate": "no_valid_shard_copy",
  "allocate_explanation": "cannot allocate because a previous copy of the primary shard existed but can no longer be found on the nodes in the cluster",
  "node_allocation_decisions": [
    {
      "node_id": "WxxsBtxITtab58q078TdEg",
      "node_name": "opensearch-1.4c1",
      "transport_address": "10.45.114.208:9300",
      "node_attributes": {
        "app_id": "39b6cdac-c195-466d-8537-e4a1f41fafd0/opensearch",
        "shard_indexing_pressure_enabled": "true"
      },
      "node_decision": "no",
      "store": {
        "found": false
      }
    },
    {
      "node_id": "XnZt4LqwSTu79M7neGxkoQ",
      "node_name": "opensearch-0.4c1",
      "transport_address": "10.45.114.156:9300",
      "node_attributes": {
        "shard_indexing_pressure_enabled": "true",
        "app_id": "39b6cdac-c195-466d-8537-e4a1f41fafd0/opensearch"
      },
      "node_decision": "no",
      "store": {
        "found": false
      }
    }
  ]
}
```

Delete the problematic index identified in the previous step:

```{warning}
If you do not have a snapshot containing this index, the data will be lost!
```

```shell
curl --cacert cert.pem -X DELETE "https://<unit-ip>:9200/index1" -u admin:<password>
```

After deleting any orphaned indices, verify that the cluster returns to green or yellow health:

```shell
curl --cacert cert.pem -X GET "https://<unit-ip>:9200/_cluster/health?pretty" -u admin:<password>
```

### Set allocation settings

During the upgrade process, the routing allocation setting may be restricted to `primaries`.
Restore normal allocation by enabling all routing:

```shell
curl --cacert cert.pem -X PUT "https://<unit-ip>:9200/_cluster/settings" -H 'Content-Type: application/json' -u admin:<password> -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": "all"
  }
}
'
```

### Add a new unit

While optional, it is highly advisable to add a replacement unit to restore the application to its original scale:

```shell
juju add-unit opensearch -n 1
```

### Remove rolled back unit

Remove the rolled back unit:

```shell
juju remove-unit opensearch/2
```

Where `opensearch/2` is the name of the unit that was rolled back and blocked earlier.

### Remove lock

If the replacement unit appears stuck displaying the status message
`Requesting lock on operation: start`, check if the departed unit still hold the lock:

```text
GET /.charm_node_lock/_doc/0
```

Example response:

```json
{
  "_index": ".charm_node_lock",
  "_id": "0",
  "_version": 3,
  "_seq_no": 28,
  "_primary_term": 1,
  "found": true,
  "_source": {
    "unit-name": "opensearch-2.4c1"
  }
}
```

If the departed unit holds the lock, delete the lock document:

```shell
curl --cacert cert.pem -X DELETE "https://<unit-ip>:9200/.charm_node_lock/_doc/0?refresh=true" -u admin:<password>
```

Wait for the replacement unit to start and join the cluster. `juju status` should show all
units `active`/`idle` with no messages, and the application `active` with the original scale
restored.

### Verify new unit has joined the cluster

List the nodes in the current cluster:

```shell
curl --cacert cert.pem -X GET "https://<unit-ip>:9200/_cat/nodes" -u admin:<password>
```

Confirm that the new node is present in the output, which will look similar to the following:

```text
10.45.114.228 35 86  6 0.43 0.69 0.95 dim cluster_manager,data,ingest,ml - opensearch-3.4c1
10.45.114.156 32 86 11 0.43 0.69 0.95 dim cluster_manager,data,ingest,ml * opensearch-0.4c1
10.45.114.208 45 86 11 0.43 0.69 0.95 dim cluster_manager,data,ingest,ml - opensearch-1.4c1
```

Finally, confirm the cluster is healthy again — the cluster health API should return `green`:

```shell
curl --cacert cert.pem -XGET "https://<unit-ip>:9200/_cluster/health?pretty" -u admin:<password>
```

## Next steps

* [Back up and restore](how-to-guides-back-up-and-restore-index) — create a backup after upgrading.
* [Scale down safely](how-to-scale-horizontally) — adjust cluster size if needed.
