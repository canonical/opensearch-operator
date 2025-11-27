(how-to-recover-rollback)=
## Recovering from a Rollback

OpenSearch does not support rolling back to a previous version. If a unit has already been upgraded, performing `juju refresh` to a previous revision will result in OpenSearch failing to start on that unit. In this situation, a manual recovery is required. This section describes how to restore the cluster to a healthy, operable state.

For more information, please refer to the upstream
[OpenSearch documentation about rolling upgrades](https://docs.opensearch.org/latest/migrate-or-upgrade/rolling-upgrade/#preparing-to-upgrade).

### Unit Waiting to Start
After running `juju refresh`, the rolled back unit may appear stuck displaying the status `Waiting for OpenSearch to start...`:

```
App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/stable       168  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  264  no

Unit                         Workload  Agent      Machine  Public address  Ports     Message
opensearch/0*                active    idle       0        10.45.114.156   9200/tcp
opensearch/1                 active    idle       1        10.45.114.208   9200/tcp
opensearch/2                 waiting   executing  2        10.45.114.147   9200/tcp  Waiting for OpenSearch to start...
self-signed-certificates/0*  active    idle       3        10.45.114.124

Machine  State    Address        Inst id        Base          AZ  Message
0        started  10.45.114.156  juju-1fafd0-0  ubuntu@22.04      Running
1        started  10.45.114.208  juju-1fafd0-1  ubuntu@22.04      Running
2        started  10.45.114.147  juju-1fafd0-2  ubuntu@22.04      Running
3        started  10.45.114.124  juju-1fafd0-3  ubuntu@22.04      Running
```

This unit will not recover automatically and additional steps are required to replace it.

### Check Cluster Health
Retrieve the cluster health:

```
GET _cluster/health?pretty
```

If the cluster health is red, one or more primary shards cannot be allocated. Allocation explanations will identify any indices that exist only on the rolled back unit which has left the cluster. As the departed unit will not rejoin, these indices cannot be recovered and must be removed.

Identify the problematic index from the output of:

```
GET _cluster/allocation/explain?pretty
```

For example, in the following output, `index1` cannot be recovered as its current state is `unassigned` with the reason `NODE_LEFT`:

```
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

Delete the index. Replace `index1` with the name of the index identified in the previous step:

```
DELETE /index1
```

After deleting any orphaned indices, verify that the cluster returns to green or yellow health:

```
GET _cluster/health?pretty
```

### Set Allocation Settings
During the upgrade process, the routing allocation setting may be restriced to `primaries`. Restore normal allocation by enabling all routing:

```
PUT _cluster/settings
{
  "persistent": {
    "cluster.routing.allocation.enable": "all"
  }
}
```

### Add a New Unit
Add a replacement unit to restore the desired scale for your application:

```
juju add-unit opensearch -n 1
```

### Remove Rolled Back Unit
Remove the rolled back unit. Replace `opensearch/2` with the unit that was rolled back:

```
juju remove-unit opensearch/2
```

### Remove Lock
If the replacement unit appears stuck displaying the status message `Requesting lock on operation: start`, check if the departed unit still hold the lock:

```
GET /.charm_node_lock/_doc/0

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

```
DELETE /.charm_node_lock/_doc/0?refresh=true
```

Wait for the replacement unit to start and join the cluster.

```
App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/stable       168  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  264  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*                active    idle   0        10.45.114.156   9200/tcp
opensearch/1                 active    idle   1        10.45.114.208   9200/tcp
opensearch/3                 active    idle   4        10.45.114.228   9200/tcp
self-signed-certificates/0*  active    idle   3        10.45.114.124

Machine  State    Address        Inst id        Base          AZ  Message
0        started  10.45.114.156  juju-1fafd0-0  ubuntu@22.04      Running
1        started  10.45.114.208  juju-1fafd0-1  ubuntu@22.04      Running
3        started  10.45.114.124  juju-1fafd0-3  ubuntu@22.04      Running
4        started  10.45.114.228  juju-1fafd0-4  ubuntu@22.04      Running
```

### Verify New Unit Has Joined the Cluster
List the nodes in the current cluster:

```
GET _cat/nodes
```

Confirm that the new node is present in the output, which will look similar to the following:

```
10.45.114.228 35 86  6 0.43 0.69 0.95 dim cluster_manager,data,ingest,ml - opensearch-3.4c1
10.45.114.156 32 86 11 0.43 0.69 0.95 dim cluster_manager,data,ingest,ml * opensearch-0.4c1
10.45.114.208 45 86 11 0.43 0.69 0.95 dim cluster_manager,data,ingest,ml - opensearch-1.4c1
```
