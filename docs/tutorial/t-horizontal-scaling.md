## Horizontally Scale Charmed OpenSearch

After having indexed some data in our previous section, let's take a look at the status of our charm:

```bash
juju status --color
```

Which should result in the following output (notice the `blocked` status and application message):

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  14:52:07Z

App                        Version  Status   Scale  Charm                      Channel  Rev  Exposed  Message
opensearch                          blocked      1  opensearch                 edge      21  no       1 or more 'replica' shards are not assigned, please scale your application up.
tls-certificates-operator           active       1  tls-certificates-operator  stable    22  no
```

Out of curiosity, let's take a look at the health of the current 1 node OpenSearch cluster:

```bash
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

```bash
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/_cat/shards
```

Which should result in the following output:

```
.opensearch-observability 0 p STARTED     0   208b 10.111.61.68 opensearch-0
albums                    0 p STARTED     4 10.6kb 10.111.61.68 opensearch-0
albums                    0 r UNASSIGNED
.opendistro_security      0 p STARTED    10 68.4kb 10.111.61.68 opensearch-0
```

You can add two additional nodes to your deployed OpenSearch application with the following command:

```bash
juju add-unit opensearch -n 2
```

You can now watch the new units join the cluster with: `watch -c juju status --color`. It usually takes a few minutes for the new nodes to be added to the cluster formation. You’ll know that all three nodes are ready when `watch -c juju status --color` reports:

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:46:15Z

App                        Version  Status  Scale  Charm                      Channel  Rev  Exposed  Message
data-integrator                     active      1  data-integrator            edge      11  no
opensearch                          active      3  opensearch                 edge      22  no
tls-certificates-operator           active      1  tls-certificates-operator  stable    22  no

Unit                          Workload  Agent  Machine  Public address  Ports  Message
data-integrator/0*            active    idle   2        10.180.162.96
opensearch/0*                 active    idle   0        10.180.162.97
opensearch/1                  active    idle   3        10.180.162.177
opensearch/2                  active    idle   4        10.180.162.142
tls-certificates-operator/0*  active    idle   1        10.180.162.44

Machine  State    Address         Inst id        Series  AZ  Message
0        started  10.180.162.97   juju-3305a8-0  jammy       Running
1        started  10.180.162.44   juju-3305a8-1  jammy       Running
2        started  10.180.162.96   juju-3305a8-2  jammy       Running
3        started  10.180.162.177  juju-3305a8-3  jammy       Running
4        started  10.180.162.142  juju-3305a8-4  jammy       Running
```

You will now notice that the application message regarding unassigned replica shards disappeared from the output of `juju status`.

You can trust that Charmed OpenSearch added these nodes correctly, and that your replica shard is now assigned to a new node. But if you want to verify that your data is correctly replicated, feel free to run the above command accessing the endpoint `/_cluster/health` and see if `"status": "green"`.

You can also query the shards as shown previously:

```bash
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/_cat/shards
```

Which should result in the following output:

```
.opensearch-observability 0 r STARTED  0   208b 10.111.61.76 opensearch-1
.opensearch-observability 0 r STARTED  0   208b 10.111.61.79 opensearch-2
.opensearch-observability 0 p STARTED  0   208b 10.111.61.68 opensearch-0
albums                    0 r STARTED  4 10.6kb 10.111.61.76 opensearch-1
albums                    0 p STARTED  4 10.6kb 10.111.61.68 opensearch-0
.opendistro_security      0 r STARTED 10 68.4kb 10.111.61.76 opensearch-1
.opendistro_security      0 r STARTED 10 68.4kb 10.111.61.79 opensearch-2
.opendistro_security      0 p STARTED 10 68.4kb 10.111.61.68 opensearch-0
```

### Removing Nodes

Removing a unit from the Juju application scales down your OpenSearch cluster by one node. Before we scale down the nodes we no longer need, list all the units with `juju status`. Here you will see three units / nodes: `opensearch/0`, `opensearch/1`, and `opensearch/2`. To remove the unit `opensearch/2` run:

```bash
juju remove-unit opensearch/2
```

You’ll know that the node was successfully removed when `watch -c juju status --color` reports:

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:51:30Z

App                        Version  Status  Scale  Charm                      Channel  Rev  Exposed  Message
data-integrator                     active      1  data-integrator            edge      11  no
opensearch                          active      2  opensearch                 edge      22  no
tls-certificates-operator           active      1  tls-certificates-operator  stable    22  no

Unit                          Workload  Agent  Machine  Public address  Ports  Message
data-integrator/0*            active    idle   2        10.180.162.96
opensearch/0*                 active    idle   0        10.180.162.97
opensearch/1                  active    idle   3        10.180.162.177
tls-certificates-operator/0*  active    idle   1        10.180.162.44

Machine  State    Address         Inst id        Series  AZ  Message
0        started  10.180.162.97   juju-3305a8-0  jammy       Running
1        started  10.180.162.44   juju-3305a8-1  jammy       Running
2        started  10.180.162.96   juju-3305a8-2  jammy       Running
3        started  10.180.162.177  juju-3305a8-3  jammy       Running
```

---

## Next Steps

The next stage in this tutorial is about removing the OpenSearch charm and tearing down your Juju deployment, and can be found [here](/t/charmed-opensearch-tutorial-teardown/9726).

