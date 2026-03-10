---
myst:
  html_meta:
    description: "Roll back a failed Charmed OpenSearch minor upgrade to restore stability and investigate upgrade failures safely."
---

(how-to-minor-rollback)=
# How to perform a minor rollback

```{caution}
OpenSearch does not support downgrading.
For more information, please refer to the upstream
[OpenSearch documentation about rolling upgrades](https://docs.opensearch.org/latest/migrate-or-upgrade/rolling-upgrade/#preparing-to-upgrade).
```

While rollbacking a charm revision that does not change the underlying OpenSearch version is a safe operation, it is important to note that rollbacking in Charmed OpenSearch is a best-effort process to restore the cluster to a previous revision. If the OpenSearch workload version is different, it does not guarantee that the cluster will be rolled back to a previous version. 

After a `juju refresh`, if there are any version incompatibilities in charm revisions,
its dependencies, or any other unexpected failure in the upgrade process,
the process will be halted and enter a failure state.

Even if the underlying OpenSearch cluster continues to work, it’s important to roll back the charm to
a previous revision so that an update can be attempted after further inspection of the failure.

## Pre-rollback checks

To execute a rollback we take the same procedure as the upgrade, the difference being
the charm revision to upgrade to. As an example follow up
[the minor upgrades guide](how-to-minor-upgrade).

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

## Rollback the charm

```{caution}
**Caution**:  Do not trigger rollback during the running upgrade action.
It may cause an unpredictable OpenSearch state. 
```

```{caution}
**Caution**:  Rollbacks in Charmed OpenSearch are a best-effort process. It is recommended to perform a backup and restore to a new deployment with the desired OpenSearch version instead of performing a rollback. Rollbacks carry the potential of *data loss* and *downtime*.
```

### Rollback a charm revision with the same workload version

You can initiate the rollback by running the `refresh` command with the revision of
the charm you want to rollback to. For example, to rollback to revision **144**, run:

```shell
juju refresh opensearch --revision=144
```

When deploying from a local charm file, you must have the previous revision’s `.charm` file.
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

### Rollback a charm revision with a different workload version
If the charm revision you are rolling back to has a different workload version, the rollback process will attempt to roll back the workload version as well. However, since OpenSearch does not support downgrading, the rollback process will rollback the charm code then attempt a best-effort rollback of the OpenSearch workload. 

This is a dangerous operation that may lead to an unhealthy OpenSearch cluster. It is recommended to instead perform a backup and restore of the cluster to a new deployment with the desired OpenSearch version.

We do not recommend performing a rollback to a charm revision with a different OpenSearch version. However, if you choose to proceed, you can follow the same steps as rolling back to a charm revision with the same workload version. There are two possible outcomes after the rollback:
#### It is possible to perform a best-effort rollback between the two workload revisions
In this case both the charm code and the workload will be rolled back to the previous version. However, since this is rollback is a dangerous operation, manual intervention is required to rollback the workload version. The charm will be blocked and a message will be displayed indicating that you need to run the `force-refresh-start` action with the `check-compatibility=false` to continue with the best-effort rollback of the workload version. 
```shell
Model    Controller  Cloud/Region         Version  SLA          Timestamp
testing  lxd         localhost/localhost  3.6.14   unsupported  08:36:09Z

App                       Version  Status   Scale  Charm                     Channel   Rev  Exposed  Message
opensearch                         blocked      3  opensearch                            2  no       Upgrading. Verify highest unit is healthy & run `resume-upgrade` action.
self-signed-certificates           active       1  self-signed-certificates  1/stable  586  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0                 active    idle   1        10.149.40.7     9200/tcp  OpenSearch 2.18.0 running; Snap rev 66; Charmed operator 1+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-...
opensearch/1                 active    idle   2        10.149.40.93    9200/tcp  OpenSearch 2.18.0 running; Snap rev 66; Charmed operator 1+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-...
opensearch/2*                blocked   idle   3        10.149.40.126   9200/tcp  Rollback incompatible. Run 'juju run <unit> force-refresh-start' with `check-compatibility` set to false to override ...
self-signed-certificates/0*  active    idle   0        10.149.40.252

Machine  State    Address        Inst id        Base          AZ   Message
0        started  10.149.40.252  juju-f44a9a-0  ubuntu@24.04  xof  Running
1        started  10.149.40.7    juju-f44a9a-1  ubuntu@24.04  xof  Running
2        started  10.149.40.93   juju-f44a9a-2  ubuntu@24.04  xof  Running
3        started  10.149.40.126  juju-f44a9a-3  ubuntu@24.04  xof  Running
```
#### It is not possible to perform a rollback between the two workload revisions 
In this case, the charm code will be rolled back but the OpenSearch workload will remain in the newer version. The charm will be blocked and a message will be displayed indicating that you need to refresh back to a charm revision with the same workload version or perform a backup and restore to a new deployment.

```shell
Model    Controller  Cloud/Region         Version  SLA          Timestamp
testing  lxd         localhost/localhost  3.6.14   unsupported  08:03:52Z

App                       Version  Status   Scale  Charm                     Channel   Rev  Exposed  Message
opensearch                         blocked      3  opensearch                           17  no       Upgrading. Verify highest unit is healthy & run `resume-upgrade` action.
self-signed-certificates           active       1  self-signed-certificates  1/stable  586  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/6*                active    idle   7        10.149.40.239   9200/tcp  OpenSearch 2.17.0 running; Snap rev 58; Charmed operator 1+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-...
opensearch/7                 active    idle   8        10.149.40.64    9200/tcp  OpenSearch 2.17.0 running; Snap rev 58; Charmed operator 1+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-dirty+530fe10bb-...
opensearch/8                 blocked   idle   9        10.149.40.31    9200/tcp  Rollback unsupported. Refresh to a newer revision or consult the recovery documentation
self-signed-certificates/0*  active    idle   0        10.149.40.55

Machine  State    Address        Inst id        Base          AZ   Message
0        started  10.149.40.55   juju-0bfd52-0  ubuntu@24.04  xof  Running
7        started  10.149.40.239  juju-0bfd52-7  ubuntu@24.04  xof  Running
8        started  10.149.40.64   juju-0bfd52-8  ubuntu@24.04  xof  Running
9        started  10.149.40.31   juju-0bfd52-9  ubuntu@24.04  xof  Running
```

## Check the cluster's health

Once the charm is rolled back, it is important to check the cluster’s health to ensure it is healthy.
OpenSearch’s upstream documentation
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
