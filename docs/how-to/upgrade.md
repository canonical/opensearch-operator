---
myst:
  html_meta:
    description: "Upgrade Charmed OpenSearch from one minor version to another, including pre-upgrade checks, in-place upgrades, health verification, and rollback procedures."
---

(how-to-guides-upgrade-index)=
# How to upgrade revision

This guide shows how to perform a minor upgrade of a Charmed OpenSearch deployment and, if needed,
how to roll back to the previous revision.

(how-to-minor-upgrade)=
## Perform a minor upgrade

A minor upgrade is an upgrade from one minor version to another:
OpenSearch `X.Y` -> OpenSearch `X.Y+1`.
For example, from OpenSearch `2.14` to OpenSearch `2.15`.

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
  All units in an app will be executed sequentially from the highest to lowest unit number.
6. (optional) Scale back: Remove no longer necessary units created in step 2 (if any).
7. Post-upgrade check: Ensure all units are in the proper state and the cluster is healthy.

#### Collect all necessary pre-upgrade information

The first step is to record the revision of the running application,
as a safety measure for a rollback action.
To accomplish this, run the `juju status` command and look for the deployed
Charmed OpenSearch revision in the command output, e.g.:

```shell
Model  Controller   Cloud/Region         Version  SLA          Timestamp
dev    development  localhost/localhost  3.5.3    unsupported  10:16:46Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/edge         144  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   0        10.214.176.180  9200/tcp
opensearch/1                 active    idle   1        10.214.176.220  9200/tcp
opensearch/2*                active    idle   2        10.214.176.175  9200/tcp
self-signed-certificates/0*  active    idle   3        10.214.176.31

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.180  juju-0c35d2-0  ubuntu@22.04      Running
1        started  10.214.176.220  juju-0c35d2-1  ubuntu@22.04      Running
2        started  10.214.176.175  juju-0c35d2-2  ubuntu@22.04      Running
3        started  10.214.176.31   juju-0c35d2-3  ubuntu@22.04      Running
```

For this example, the current revision is **144** for OpenSearch.

```{note}
Make sure to store the revision number in case of rollback.
If the deployment is of a local charm, save a copy of the current `.charm` file.
```

#### Scale-up (optional)

Optionally, it is recommended to scale the application up by one unit before upgrading.

The new unit will be the first one to be updated, and it will assert that the upgrade is possible.

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

The output should be the following:

```shell

Running operation 1 with 1 task
  - task 2 on unit-opensearch-2

Waiting for task 2...
result: Charm is ready for upgrade

```

The action will ensure and check the health of OpenSearch and determine if the charm
is well prepared to start an upgrade procedure.

### Initiate the upgrade

```{caution}
**Caution**: Charmed OpenSearch supports performance profiles and will have
different RAM consumption according to the profile chosen:

* `production`: consumes 50% of the RAM available, up to 32G
* `staging`: consumes 25% of the RAM available, up to 32G
* `testing`: consumes 1G of RAM

In case your charm is running on revision prior to `185`, the `testing` profile will be your default value. Ensure you have it set at upgrade and then feel free to switch to another profile that is more suitable to your use-case.

```

Use the `juju refresh` command to trigger the charm upgrade process.
You have control over what upgrade you want to apply:

- You can upgrade the charm to the latest revision available in the charm store for a specific channel,
  in this case, the edge channel:

    ```shell
    # If your charm is running a revision prior to 185, then set the profile explicitly:
    juju refresh opensearch --channel 2/edge --config profile="testing"

    # Otherwise, just refresh
    juju refresh opensearch --channel 2/edge
    ```

- You can also upgrade the charm to a specific revision:

    ```shell
    juju refresh opensearch --revision 145
    ```

- Or you can upgrade the charm using a local charm file:

    ```shell
    juju refresh opensearch --path /path/to/your/charm/file.charm
    ```

The OpenSearch upgrade will execute only on the highest ordinal unit, for the running example
OpenSearch, the `juju status` will look as follows:

```shell
Model  Controller   Cloud/Region         Version  SLA          Timestamp
dev    development  localhost/localhost  3.5.3    unsupported  10:29:07Z

App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         blocked      4  opensearch                2/edge         145  no       Upgrading. Verify highest unit is healthy & run `resume-upgrade` action. To rollback, `juju refresh` to last revision
self-signed-certificates           active       1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   0        10.214.176.180  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated); Charmed operator 1+e686854
opensearch/1                 active    idle   1        10.214.176.220  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated); Charmed operator 1+e686854
opensearch/2*                active    idle   2        10.214.176.175  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated); Charmed operator 1+e686854
opensearch/3                 active    idle   4        10.214.176.7    9200/tcp  OpenSearch 2.16.0 running; Snap rev 57; Charmed operator 1+e686854
self-signed-certificates/0*  active    idle   3        10.214.176.31

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.180  juju-0c35d2-0  ubuntu@22.04      Running
1        started  10.214.176.220  juju-0c35d2-1  ubuntu@22.04      Running
2        started  10.214.176.175  juju-0c35d2-2  ubuntu@22.04      Running
3        started  10.214.176.31   juju-0c35d2-3  ubuntu@22.04      Running
4        started  10.214.176.7    juju-0c35d2-4  ubuntu@22.04      Running
    
```

```{note}
The unit should recover shortly after, but the time can vary depending on the amount of data
written to the cluster while the unit was not part of the cluster. Please be patient with the huge installations.
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

After every unit is upgraded, its status will be set to `active/idle` and its message will indicate
the new version of OpenSearch running on the unit. The `juju status` output will look as follows:

```shell
Model  Controller   Cloud/Region         Version  SLA          Timestamp
dev    development  localhost/localhost  3.5.3    unsupported  10:39:06Z

App                       Version  Status       Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         maintenance      4  opensearch                2/edge         145  no       Upgrading. To rollback, `juju refresh` to the previous revision
self-signed-certificates           active           1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent      Machine  Public address  Ports     Message
opensearch/0                 active    idle       0        10.214.176.180  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated); Charmed operator 1+e686854
opensearch/1                 waiting   executing  1        10.214.176.220  9200/tcp  Waiting for OpenSearch to start...
opensearch/2*                active    idle       2        10.214.176.175  9200/tcp  OpenSearch 2.16.0 running; Snap rev 57; Charmed operator 1+e686854
opensearch/3                 active    idle       4        10.214.176.7    9200/tcp  OpenSearch 2.16.0 running; Snap rev 57; Charmed operator 1+e686854
self-signed-certificates/0*  active    idle       3        10.214.176.31

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.180  juju-0c35d2-0  ubuntu@22.04      Running
1        started  10.214.176.220  juju-0c35d2-1  ubuntu@22.04      Running
2        started  10.214.176.175  juju-0c35d2-2  ubuntu@22.04      Running
3        started  10.214.176.31   juju-0c35d2-3  ubuntu@22.04      Running
4        started  10.214.176.7    juju-0c35d2-4  ubuntu@22.04      Running
```

Once all units are upgraded, the application status will be set to `active`
and the message indicating the new version of OpenSearch running on the units will disappear.

```shell
Model  Controller   Cloud/Region         Version  SLA          Timestamp
dev    development  localhost/localhost  3.5.3    unsupported  10:43:41Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      4  opensearch                2/edge         145  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   0        10.214.176.180  9200/tcp
opensearch/1                 active    idle   1        10.214.176.220  9200/tcp
opensearch/2*                active    idle   2        10.214.176.175  9200/tcp
opensearch/3                 active    idle   4        10.214.176.7    9200/tcp
self-signed-certificates/0*  active    idle   3        10.214.176.31

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.180  juju-0c35d2-0  ubuntu@22.04      Running
1        started  10.214.176.220  juju-0c35d2-1  ubuntu@22.04      Running
2        started  10.214.176.175  juju-0c35d2-2  ubuntu@22.04      Running
3        started  10.214.176.31   juju-0c35d2-3  ubuntu@22.04      Running
4        started  10.214.176.7    juju-0c35d2-4  ubuntu@22.04      Running
```

Notice the `Rev` column in the `juju status` output.
The revision number should reflect the new revision of the application.

### Rollback (optional)

In case of a failed upgrade, you might potentially be able to rollback to the previous revision.
To do so, follow the [Perform a minor rollback](how-to-minor-rollback) section below.

### Scale-back (optional)

If you scaled up the application in step 2, you can now scale it back down to the original number of units:

```shell
juju remove-unit opensearch/<highest unit number>
```

### Check the cluster health

First, check the units have settled as `active/idle` state on `juju status`,
with the newer revision number:

```shell
Model  Controller   Cloud/Region         Version  SLA          Timestamp
dev    development  localhost/localhost  3.5.3    unsupported  10:45:39Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/edge         145  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   0        10.214.176.180  9200/tcp
opensearch/1                 active    idle   1        10.214.176.220  9200/tcp
opensearch/2*                active    idle   2        10.214.176.175  9200/tcp
self-signed-certificates/0*  active    idle   3        10.214.176.31

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.180  juju-0c35d2-0  ubuntu@22.04      Running
1        started  10.214.176.220  juju-0c35d2-1  ubuntu@22.04      Running
2        started  10.214.176.175  juju-0c35d2-2  ubuntu@22.04      Running
3        started  10.214.176.31   juju-0c35d2-3  ubuntu@22.04      Running
```

Check the cluster is healthy. OpenSearch's upstream documentation
[suggests the following check](https://opensearch.org/docs/latest/install-and-configure/upgrade-opensearch/rolling-upgrade/):

```shell
GET "/_cluster/health?pretty"
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

This guide describes how to roll back a minor version of OpenSearch.
This is useful when an upgrade fails and you need to roll back to the previous version.

```{note}
OpenSearch does not support downgrading to a previous major version.
For more information, please refer to the upstream
[OpenSearch documentation about rolling upgrades](https://docs.opensearch.org/latest/migrate-or-upgrade/rolling-upgrade/#preparing-to-upgrade).
```

After a `juju refresh`, if there are any version incompatibilities in charm revisions,
its dependencies, or any other unexpected failure in the upgrade process,
the process will be halted and enter a failure state.

Even if the underlying OpenSearch cluster continues to work, it's important to roll back the charm to
a previous revision so that an update can be attempted after further inspection of the failure.

### Pre-rollback checks

To execute a rollback we take the same procedure as the upgrade, the difference being
the charm revision to upgrade to. As an example follow up
the [Perform a minor upgrade](how-to-minor-upgrade) section above.

It is important to run the `pre-upgrade-checks` action to ensure the cluster is in a healthy state
before the rollback. This action will check the cluster health and the status of the upgrade.

```shell
juju run opensearch/leader pre-upgrade-check
```

Once the pre-upgrade checks are complete, and you get the `Charm is ready for upgrade` message,
you can proceed with the rollback.

For example, here is the status of the OpenSearch cluster after upgrading one unit to revision 145:

```shell
Model  Controller   Cloud/Region         Version  SLA          Timestamp
dev    development  localhost/localhost  3.5.3    unsupported  12:24:17Z

App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         blocked      3  opensearch                2/edge         145  no       Upgrading. Verify highest unit is healthy & run `resume-upgrade` action. To rollback, `juju refresh` to la
st revision
self-signed-certificates           active       1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*                active    idle   0        10.214.176.187  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated); Charmed operator 1+e686854
opensearch/1                 active    idle   1        10.214.176.197  9200/tcp  OpenSearch 2.15.0 running; Snap rev 56 (outdated); Charmed operator 1+e686854
opensearch/2                 active    idle   2        10.214.176.222  9200/tcp  OpenSearch 2.16.0 running; Snap rev 57; Charmed operator 1+e686854
self-signed-certificates/0*  active    idle   3        10.214.176.93

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.187  juju-dd97d9-0  ubuntu@22.04      Running
1        started  10.214.176.197  juju-dd97d9-1  ubuntu@22.04      Running
2        started  10.214.176.222  juju-dd97d9-2  ubuntu@22.04      Running
3        started  10.214.176.93   juju-dd97d9-3  ubuntu@22.04      Running
```

Notice that the OpenSearch charm is at revision **145**.

### Rollback the charm

```{caution}
**Caution**:  Do not trigger rollback during the running upgrade action.
It may cause an unpredictable OpenSearch state. 
```

You can initiate the rollback by running the `refresh` command with the revision of
the charm you want to rollback to. For example, to rollback to revision **144**, run:

```shell
juju refresh opensearch --revision=144
```

When deploying from a local charm file, you must have the previous revision's `.charm` file.
Then, run:

```shell
juju refresh opensearch --path=<path_to_charm_file>
```

After the refresh command, the Juju controller revision for the application will be
back in sync with the running OpenSearch revision.

```shell
Model  Controller   Cloud/Region         Version  SLA          Timestamp
dev    development  localhost/localhost  3.5.3    unsupported  12:27:02Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/edge         144  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*                active    idle   0        10.214.176.187  9200/tcp
opensearch/1                 active    idle   1        10.214.176.197  9200/tcp
opensearch/2                 active    idle   2        10.214.176.222  9200/tcp
self-signed-certificates/0*  active    idle   3        10.214.176.93

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.214.176.187  juju-dd97d9-0  ubuntu@22.04      Running
1        started  10.214.176.197  juju-dd97d9-1  ubuntu@22.04      Running
2        started  10.214.176.222  juju-dd97d9-2  ubuntu@22.04      Running
3        started  10.214.176.93   juju-dd97d9-3  ubuntu@22.04      Running
```

Notice that the OpenSearch charm is now at revision **144**.

### Check the cluster's health

Once the charm is rolled back, it is important to check the cluster's health to ensure it is healthy.
OpenSearch's upstream documentation
[suggests the following check](https://opensearch.org/docs/latest/install-and-configure/upgrade-opensearch/rolling-upgrade/):

```shell
GET "/_cluster/health?pretty"
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
