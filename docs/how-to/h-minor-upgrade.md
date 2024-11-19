# How to perform a minor upgrade
**Example**: OpenSearch X.Y -> OpenSearch X.Y+1

<!-- Brief intro about what this guide explains -->
This guide explains how to perform a minor upgrade of the OpenSearch cluster deployed with the Charmed OpenSearch operator. A minor upgrade is an upgrade from one minor version to another, for example, from OpenSearch 2.14 to OpenSearch 2.15. 

This guide will walk you through the steps to upgrade your OpenSearch cluster, including pre-upgrade checks, upgrading the OpenSearch cluster, preparing the application for the in-place upgrade, initiating the upgrade, resuming the upgrade, and checking the cluster's health.

## Summary
  - [Pre-upgrade checks](#pre-upgrade-checks)
  - [Upgrade the OpenSearch cluster](#upgrade-the-opensearch-cluster)
    - [Collect all necessary pre-upgrade information](#collect-all-necessary-pre-upgrade-information)
    - [Scale-up (optional)](#scale-up-optional)
  - [Prepare the application for the in-place upgrade](#prepare-the-application-for-the-in-place-upgrade)
  - [Initiate the upgrade](#initiate-the-upgrade)
  - [Resume upgrade](#resume-upgrade)
  - [Rollback (optional)](#rollback-optional)
  - [Scale-back (optional)](#scale-back-optional)
  - [Check the cluster health](#check-the-cluster-health)

---

## Pre-upgrade checks
Before upgrading your OpenSearch cluster, ensure that you have completed the following steps:

1. **Backup your data**: Before upgrading, back up your data to prevent data loss in case of failure. For more information, see [Hot to create a backup](/t/14098).
2. **Make sure not to perform any extraordinary operations**: Avoid performing any concurrent operations on the cluster during the upgrade process. This can lead to an inconsistent state of the cluster. This includes:
    - Adding or removing units
    - Creating or destroying new relations
    - Changes in workload configuration
    - Upgrading other connected/related/integrated applications simultaneously
    - Backup / restore of snapshots

## Upgrade the OpenSearch cluster

To upgrade your OpenSearch cluster, follow these steps:
1. Collect all necessary pre-upgrade information. It will be required for the rollback (if requested). **Do NOT skip this step**.
2. (optional) Scale-up: The new sacrificial unit will be the first to be updated, and will simplify the rollback procedure in case of the upgrade failure.
3. Prepare the “Charmed OpenSearch” Juju application for the in-place upgrade. See the step description below for all the technical details the charm executes.
4. Upgrade: Only one app unit will be upgraded once started. In case of failure, roll back with juju refresh.
5. Resume upgrade: The upgrade can be resumed if the upgrade of the first unit is successful. All units in an app will be executed sequentially from the highest to lowest unit number.
6. (optional) Consider [rolling back](/t/14142) in case of disaster. Please [inform and include us](https://app.element.io/#/room/#charmhub-data-platform:ubuntu.com) in your case scenario troubleshooting to trace the source of the issue and prevent it in the future.
7. (optional) Scale back: Remove no longer necessary units created in step 2 (if any).
8. Post-upgrade check: Ensure all units are in the proper state and the cluster is healthy.


### Collect all necessary pre-upgrade information

The first step is to record the revision of the running application, as a safety measure for a rollback action. To accomplish this,  run the `juju status` command and look for the deployed Charmed OpenSearch revision in the command output, e.g.:

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

[note] Make sure to store the revision number in case of rollback. If the deployment is of a local charm, save a copy of the current `.charm` file. [/note]

### Scale-up (optional)

Optionally, it is recommended to scale the application up by one unit before upgrading.

The new unit will be the first one to be updated, and it will assert that the upgrade is possible. In case of failure, having the extra unit will ease the rollback procedure, without disrupting service -more in [Minor rollback how-to](/t/14142).

```shell
juju add-unit opensearch
```

Wait for the new unit to be up and ready.

## Prepare the application for the in-place upgrade

1. **IMPORTANT:** Create a backup of your cluster

Refer to [How to create a backup](/t/14098).

2. Perform the `pre-upgrade-check` action

After the application has settled, it’s necessary to run the `pre-upgrade-check` action against the leader unit:

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

The action will ensure and check the health of OpenSearch and determine if the charm is well prepared to start an upgrade procedure.

## Initiate the upgrade

[note type="caution"]
**Caution**: Charmed OpenSearch supports performance profiles and will have different RAM consumption according to the profile chosen:

* `production`: consumes 50% of the RAM available, up to 32G
* `staging`: consumes 25% of the RAM available, up to 32G
* `testing`: consumes 1G of RAM

In case your charm is running on revision prior to `185`, the `testing` profile will be your default value. Ensure you have it set at upgrade and then feel free to switch to another profile that is more suitable to your use-case.

[/note]

Use the juju refresh command to trigger the charm upgrade process. You have control over what upgrade you want to apply:
- You can upgrade the charm to the latest revision available in the charm store for a specific channel, in this case, the edge channel:

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


The OpenSearch upgrade will execute only on the highest ordinal unit, for the running example OpenSearch, the juju status will look as follows:

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

[note] The unit should recover shortly after, but the time can vary depending on the amount of data written to the cluster while the unit was not part of the cluster. Please be patient with the huge installations. [/note]

## Resume upgrade

After the first unit is upgraded, the charm will set the unit upgrade state as completed. If deemed necessary, you can further assert the success of the upgrade. If the unit is healthy within the cluster, the next step is to resume the upgrade process by running:

```shell
juju run opensearch/leader resume-upgrade
```

The `resume-upgrade` action will roll out the OpenSearch upgrade for the remaining units in the application. The action will be executed sequentially from the highest unit number to the lowest.

After every unit is upgraded, its status will be set to `active/idle` and its message will indicate the new version of OpenSearch running on the unit. The juju status output will look as follows: 

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

Once all units are upgraded, the application status will be set to `active` and the message indicating the new version of OpenSearch running on the units will disappear. 

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

Notice the `Rev` column in the `juju status` output. The revision number should reflect the new revision of the application.

## Rollback (optional)

In case of a failed upgrade, you can roll back to the previous revision. To do so, follow the guide [How to perform a minor rollback](/t/14142).

## Scale-back (optional)

If you scaled up the application in step 2, you can now scale it back down to the original number of units:

```shell
juju remove-unit opensearch/<highest unit number>
```

## Check the cluster health

First, check the units have settled as `active/idle” state on juju status, with the newer revision number:

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

Check the cluster is healthy. OpenSearch’s upstream documentation [suggests the following check](https://opensearch.org/docs/latest/install-and-configure/upgrade-opensearch/rolling-upgrade/):

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