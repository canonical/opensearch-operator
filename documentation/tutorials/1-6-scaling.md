## Horizontally Scale Charmed OpenSearch

You can add two additional nodes to your deployed OpenSearch application with:

```bash
juju add-unit opensearch -n 2
```

You can now watch the new units join the cluster with: `watch -c juju status --color`. It usually takes a few minutes for the new nodes to be added to the cluster formation. You’ll know that all three nodes are ready when `watch -c juju status --color` reports:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  14:42:04Z

App                        Version  Status  Scale  Charm                      Channel   Rev  Exposed  Message
data-integrator                     active      1  data-integrator            edge      3    no
opensearch                          active      3  opensearch                 dpe/edge  96   no
tls-certificates-operator           active      1  tls-certificates-operator  beta      22   no

Unit                          Workload  Agent  Machine  Public address  Ports      Message
data-integrator/0*            active    idle   5        10.23.62.216               received opensearch credentials
opensearch/0*                 active    idle   0        10.23.62.156
opensearch/1                  active    idle   3        10.23.62.55
opensearch/2                  active    idle   2        10.23.62.243
tls-certificates-operator/0*  active    idle   1        10.137.5.33

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
3        started  10.23.62.55   juju-d35d30-3  jammy       Running
2        started  10.23.62.243  juju-d35d30-2  jammy       Running
5        started  10.23.62.216  juju-d35d30-5  jammy       Running
```

You can trust that Charmed OpenSearch added these replicas correctly, but if you want to verify that your data is correctly replicated, feel free to run the above commands on all the replicas. To view the cluster settings yourself, send a `GET` request (in the same way as before) to the endpoint `_cluster/settings`.

### Remove nodes

Removing a unit from the Juju application scales down your OpenSearch cluster by one node. Before we scale down the nodes we no longer need, list all the units with `juju status`. Here you will see three units / nodes: `opensearch/0`, `opensearch/1`, and `opensearch/2`. To remove the unit `opensearch/2` run:

```bash
juju remove-unit opensearch/2
```

You’ll know that the node was successfully removed when `watch -c juju status --color` reports:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  14:42:04Z

App                        Version  Status  Scale  Charm                      Channel   Rev  Exposed  Message
data-integrator                     active      1  data-integrator            edge      3    no
opensearch                          active      2  opensearch                 dpe/edge  21   no
tls-certificates-operator           active      1  tls-certificates-operator  stable      22   no

Unit                          Workload  Agent  Machine  Public address  Ports      Message
data-integrator/0*            active    idle   5        10.23.62.216               received opensearch credentials
opensearch/0*                 active    idle   0        10.23.62.156
opensearch/1                  active    idle   3        10.23.62.55
tls-certificates-operator/0*  active    idle   1        10.137.5.33

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
3        started  10.23.62.55   juju-d35d30-3  jammy       Running
5        started  10.23.62.216  juju-d35d30-5  jammy       Running
```

---

## Next Steps

The next stage in this tutorial is about removing the OpenSearch charm and tearing down your Juju deployment, and can be found [here](./tutorial-teardown.md).
