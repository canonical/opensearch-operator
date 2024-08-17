>[Charmed OpenSearch Tutorial](/t/9722) > 6. Scale horizontally

# Scale Charmed OpenSearch horizontally

After having indexed some data in our previous section, let's take a look at the status of our charm:

```shell
juju status --color
```

This should result in the following output (notice the `blocked` status and application message):

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.4.4    unsupported  17:16:43+02:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      1  opensearch                2/edge         117  no       
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no       

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*                active    idle   0        10.121.127.140  9200/tcp  
self-signed-certificates/0*  active    idle   1        10.121.127.164            

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.121.127.140  juju-454312-0  ubuntu@22.04      Running
1        started  10.121.127.164  juju-454312-1  ubuntu@22.04      Running
```

Out of curiosity, let's take a look at the health of the current 1 node OpenSearch cluster:

```shell
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/_cluster/health
```

You should get a similar output to the following:

```json
{
  "cluster_name": "opensearch-tutorial",
  "status": "yellow",
  "timed_out": false,
  "number_of_nodes": 1,
  "number_of_data_nodes": 1,
  "discovered_master": true,
  "discovered_cluster_manager": true,
  "active_primary_shards": 3,
  "active_shards": 3,
  "relocating_shards": 0,
  "initializing_shards": 0,
  "unassigned_shards": 1,
  "delayed_unassigned_shards": 0,
  "number_of_pending_tasks": 0,
  "number_of_in_flight_fetch": 0,
  "task_max_waiting_in_queue_millis": 0,
  "active_shards_percent_as_number": 75
}
```

You'll notice 2 things:
- The `status` of the cluster is `yellow`
- The `unassigned_shards` is `1`

This means that one of our replica shards could not be assigned to a node, which is normal since we only have a single OpenSearch node.

In order to have a healthy cluster `"status": "green"` we need to scale our cluster up (horizontally).

You could also list the shards in your cluster and visualize which one is not assigned.

```shell
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/_cat/shards
```

Which should result in the following output:

```shell
.opensearch-observability 0 p STARTED     0   208b 10.111.61.68 opensearch-0
albums                    0 p STARTED     4 10.6kb 10.111.61.68 opensearch-0
albums                    0 r UNASSIGNED
.opendistro_security      0 p STARTED    10 68.4kb 10.111.61.68 opensearch-0
```
## Add node
You can add two additional nodes to your deployed OpenSearch application with the following command:

```shell
juju add-unit opensearch -n 2
```

You can now watch the new units join the cluster with: `watch -c juju status --color`. It usually takes a few minutes for the new nodes to be added to the cluster formation. You’ll know that all three nodes are ready when `watch -c juju status --color` reports:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.4.4    unsupported  17:28:02+02:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/edge         117  no       
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no       

Unit                         Workload  Agent      Machine  Public address  Ports     Message
opensearch/0*                active    idle       0        10.121.127.140  9200/tcp  
opensearch/1                 active    idle       3        10.121.127.126  9200/tcp  
opensearch/2                 active    executing  4        10.121.127.102  9200/tcp  
self-signed-certificates/0*  active    idle       1        10.121.127.164            

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.121.127.140  juju-454312-0  ubuntu@22.04      Running
1        started  10.121.127.164  juju-454312-1  ubuntu@22.04      Running
3        started  10.121.127.126  juju-454312-3  ubuntu@22.04      Running
4        started  10.121.127.102  juju-454312-4  ubuntu@22.04      Running
```

You will now notice that the application message regarding unassigned replica shards disappeared from the output of `juju status`.

You can trust that Charmed OpenSearch added these nodes correctly, and that your replica shard is now assigned to a new node. But if you want to verify that your data is correctly replicated, feel free to run the above command accessing the endpoint `/_cluster/health` and see if `"status": "green"`.

You can also query the shards as shown previously:

```shell
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/_cat/shards
```

Which should result in the following output:

```shell
.opensearch-observability 0 r STARTED  0   208b 10.111.61.76 opensearch-1
.opensearch-observability 0 r STARTED  0   208b 10.111.61.79 opensearch-2
.opensearch-observability 0 p STARTED  0   208b 10.111.61.68 opensearch-0
albums                    0 r STARTED  4 10.6kb 10.111.61.76 opensearch-1
albums                    0 p STARTED  4 10.6kb 10.111.61.68 opensearch-0
.opendistro_security      0 r STARTED 10 68.4kb 10.111.61.76 opensearch-1
.opendistro_security      0 r STARTED 10 68.4kb 10.111.61.79 opensearch-2
.opendistro_security      0 p STARTED 10 68.4kb 10.111.61.68 opensearch-0
```

## Remove nodes
[note type="caution"]
**Note:** Refer to [safe-horizontal-scaling guide](/t/10994) to understand how to safely remove units in a production environment.
[/note]

[note type="caution"]
**Warning:** In highly available deployment, only scaling down to 3 nodes is safe. If only 2 nodes are online, neither can be unavailable nor removed. The service will become **unavailable** and **data may be lost**  if scaling below 2 nodes.
[/note]

Removing a unit from the Juju application scales down your OpenSearch cluster by one node. Before we scale down the nodes we no longer need, list all the units with `juju status`. Here you will see three units / nodes: `opensearch/0`, `opensearch/1`, and `opensearch/2`. To remove the unit `opensearch/2` run:

```shell
juju remove-unit opensearch/2
```

You’ll know that the node was successfully removed when `watch -c juju status --color` reports:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.4.4    unsupported  17:30:45+02:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      2  opensearch                2/edge         117  no       
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no       

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*                active    idle   0        10.121.127.140  9200/tcp  
opensearch/1                 active    idle   3        10.121.127.126  9200/tcp  
self-signed-certificates/0*  active    idle   1        10.121.127.164            

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.121.127.140  juju-454312-0  ubuntu@22.04      Running
1        started  10.121.127.164  juju-454312-1  ubuntu@22.04      Running
3        started  10.121.127.126  juju-454312-3  ubuntu@22.04      Running
```

>**Next step**: [7. Clean up the environment](/t/9726).