# How to perform a minor rollback

This guide describes how to roll back a minor version of OpenSearch. This is useful when an upgrade fails and you need to roll back to the previous version.

>OpenSearch does not support downgrading to a previous major version. For more information, please refer to the upstream [OpenSearch documentation about rolling upgrades](https://opensearch.org/docs/latest/install-and-configure/upgrade-opensearch/rolling-upgrade/#preparing-to-upgrade).

After a `juju refresh`, if there are any version incompatibilities in charm revisions, its dependencies, or any other unexpected failure in the upgrade process, the process will be halted and enter a failure state.

Even if the underlying OpenSearch cluster continues to work, it’s important to roll back the charm to 
a previous revision so that an update can be attempted after further inspection of the failure.

## Summary
  - [Summary](#summary)
  - [Pre-rollback checks](#pre-rollback-checks)
  - [Rollback the charm](#rollback-the-charm)
  - [Check the cluster's health](#check-the-clusters-health)

---

## Pre-rollback checks

To execute a rollback we take the same procedure as the upgrade, the difference being the charm revision to upgrade to. As an example follow up [the minor upgrades guide](/t/14141).

It is important to run the `pre-upgrade-checks` action to ensure the cluster is in a healthy state before the rollback. This action will check the cluster health and the status of the upgrade.

```shell
juju run opensearch/leader pre-upgrade-check
```

Once the pre-upgrade checks are complete, and you get the `Charm is ready for upgrade` message, you can proceed with the rollback.

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

## Rollback the charm

[note type="caution"]
**Caution**:  Do not trigger rollback during the running upgrade action. It may cause an unpredictable OpenSearch state. 
[/note]


You can initiate the rollback by running the `refresh` command with the revision of the charm you want to rollback to. For example, to rollback to revision **144**, run:

```shell
juju refresh opensearch --revision=144
```

When deploying from a local charm file, you must have the previous revision’s .charm file. Then, run:

```shell
juju refresh opensearch --path=<path_to_charm_file>
```

After the refresh command, the juju controller revision for the application will be back in sync with the running OpenSearch revision.

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

## Check the cluster's health

Once the charm is rolled back, it is important to check the cluster’s health to ensure it is healthy. OpenSearch’s upstream documentation [suggests the following check](https://opensearch.org/docs/latest/install-and-configure/upgrade-opensearch/rolling-upgrade/):

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