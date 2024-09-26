>[Charmed OpenSearch Tutorial](/t/9722) > 6. Scale horizontally

# Scale Charmed OpenSearch horizontally

After having indexed some data in our previous section, let's take a look at the status of our charm:

```shell
juju status
```
The output should look similar to the following:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.5.3    unsupported  13:57:38Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
data-integrator                    active      1  data-integrator           latest/edge     59  no
opensearch                         active      3  opensearch                2/beta         117  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
data-integrator/0*           active    idle   4        10.95.38.22
opensearch/0*                active    idle   0        10.95.38.94     9200/tcp
opensearch/1                 active    idle   1        10.95.38.139    9200/tcp
opensearch/2                 active    idle   2        10.95.38.212    9200/tcp
self-signed-certificates/0*  active    idle   3        10.95.38.54

Machine  State    Address       Inst id        Base          AZ  Message
0        started  10.95.38.94   juju-be3883-0  ubuntu@22.04      Running
1        started  10.95.38.139  juju-be3883-1  ubuntu@22.04      Running
2        started  10.95.38.212  juju-be3883-2  ubuntu@22.04      Running
3        started  10.95.38.54   juju-be3883-3  ubuntu@22.04      Running
4        started  10.95.38.22   juju-be3883-4  ubuntu@22.04      Running

Integration provider                   Requirer                               Interface              Type     Message
data-integrator:data-integrator-peers  data-integrator:data-integrator-peers  data-integrator-peers  peer
opensearch:node-lock-fallback          opensearch:node-lock-fallback          node_lock_fallback     peer
opensearch:opensearch-client           data-integrator:opensearch             opensearch_client      regular
opensearch:opensearch-peers            opensearch:opensearch-peers            opensearch_peers       peer
opensearch:upgrade-version-a           opensearch:upgrade-version-a           upgrade                peer
self-signed-certificates:certificates  opensearch:certificates                tls-certificates       regular
```

## Add node
You can add two additional nodes to your deployed OpenSearch application with the following command:

```shell
juju add-unit opensearch -n 1
```

Where `-n 1` specifies the number of units to add. In this case, we are adding one unit to the OpenSearch application. You can add more units by changing the number after `-n`.

You can now watch the new units join the cluster with: `juju status --watch 1s`. It usually takes a few minutes for the new nodes to be added to the cluster formation. You’ll know that all three nodes are ready when `juju status --watch 1s` reports:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.5.3    unsupported  14:02:18Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
data-integrator                    active      1  data-integrator           latest/edge     59  no
opensearch                         active      4  opensearch                2/beta         117  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
data-integrator/0*           active    idle   4        10.95.38.22
opensearch/0*                active    idle   0        10.95.38.94     9200/tcp
opensearch/1                 active    idle   1        10.95.38.139    9200/tcp
opensearch/2                 active    idle   2        10.95.38.212    9200/tcp
opensearch/3                 active    idle   5        10.95.38.39     9200/tcp
self-signed-certificates/0*  active    idle   3        10.95.38.54

Machine  State    Address       Inst id        Base          AZ  Message
0        started  10.95.38.94   juju-be3883-0  ubuntu@22.04      Running
1        started  10.95.38.139  juju-be3883-1  ubuntu@22.04      Running
2        started  10.95.38.212  juju-be3883-2  ubuntu@22.04      Running
3        started  10.95.38.54   juju-be3883-3  ubuntu@22.04      Running
4        started  10.95.38.22   juju-be3883-4  ubuntu@22.04      Running
5        started  10.95.38.39   juju-be3883-5  ubuntu@22.04      Running
```


You can trust that Charmed OpenSearch added these nodes correctly, and that your replica shards are all assigned. But if you want to verify that your data is correctly replicated, you can also query the shards with the following command:

```shell
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/_cat/shards
```

Which should result in the following output:

```shell
test-index                       0 r STARTED  0    208b 10.95.38.94  opensearch-0.0f3
test-index                       0 p STARTED  0    208b 10.95.38.139 opensearch-1.0f3
.plugins-ml-config               0 r STARTED  1   3.9kb 10.95.38.94  opensearch-0.0f3
.plugins-ml-config               0 r STARTED  1   3.9kb 10.95.38.139 opensearch-1.0f3
.plugins-ml-config               0 p STARTED  1   3.9kb 10.95.38.212 opensearch-2.0f3
.opensearch-observability        0 r STARTED  0    208b 10.95.38.94  opensearch-0.0f3
.opensearch-observability        0 p STARTED  0    208b 10.95.38.139 opensearch-1.0f3
.opensearch-observability        0 r STARTED  0    208b 10.95.38.212 opensearch-2.0f3
albums                           0 r STARTED  4  10.7kb 10.95.38.139 opensearch-1.0f3
albums                           0 p STARTED  4  10.7kb 10.95.38.212 opensearch-2.0f3
.opensearch-sap-log-types-config 0 r STARTED            10.95.38.94  opensearch-0.0f3
.opensearch-sap-log-types-config 0 r STARTED            10.95.38.139 opensearch-1.0f3
.opensearch-sap-log-types-config 0 p STARTED            10.95.38.212 opensearch-2.0f3
.opendistro_security             0 r STARTED 10  54.2kb 10.95.38.94  opensearch-0.0f3
.opendistro_security             0 r STARTED 10  54.2kb 10.95.38.139 opensearch-1.0f3
.opendistro_security             0 p STARTED 10 155.1kb 10.95.38.212 opensearch-2.0f3
.charm_node_lock                 0 r STARTED  1   3.8kb 10.95.38.94  opensearch-0.0f3
.charm_node_lock                 0 r STARTED  1   6.9kb 10.95.38.139 opensearch-1.0f3
.charm_node_lock                 0 p STARTED  1  11.8kb 10.95.38.212 opensearch-2.0f3
```

Notice that the shards are distributed across all nodes.


## Remove nodes
[note type="caution"]
**Note:** Refer to [safe-horizontal-scaling guide](/t/10994) to understand how to safely remove units in a production environment.
[/note]

[note type="caution"]
**Warning:** In highly available deployment, only scaling down to 3 nodes is safe. If only 2 nodes are online, neither can be unavailable nor removed. The service will become **unavailable** and **data may be lost**  if scaling below 2 nodes.
[/note]

Removing a unit from the Juju application scales down your OpenSearch cluster by one node. Before we scale down the nodes we no longer need, list all the units with `juju status`. Here you will see four units / nodes: `opensearch/0`, `opensearch/1`, `opensearch/2`, `opensearch/3`. To remove the unit `opensearch/3` run:

```shell
juju remove-unit opensearch/3
```

You’ll know that the node was successfully removed when `juju status --watch 1s` reports:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.5.3    unsupported  14:05:58Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
data-integrator                    active      1  data-integrator           latest/edge     59  no
opensearch                         active      3  opensearch                2/beta         117  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
data-integrator/0*           active    idle   4        10.95.38.22
opensearch/0*                active    idle   0        10.95.38.94     9200/tcp
opensearch/1                 active    idle   1        10.95.38.139    9200/tcp
opensearch/2                 active    idle   2        10.95.38.212    9200/tcp
self-signed-certificates/0*  active    idle   3        10.95.38.54

Machine  State    Address       Inst id        Base          AZ  Message
0        started  10.95.38.94   juju-be3883-0  ubuntu@22.04      Running
1        started  10.95.38.139  juju-be3883-1  ubuntu@22.04      Running
2        started  10.95.38.212  juju-be3883-2  ubuntu@22.04      Running
3        started  10.95.38.54   juju-be3883-3  ubuntu@22.04      Running
4        started  10.95.38.22   juju-be3883-4  ubuntu@22.04      Running
```

>**Next step**: [7. Clean up the environment](/t/9726).