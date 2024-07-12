## How to safely scale-down 

Horizontal scale down (removal of units) is a common process that administrators occasionally do, but one that requires special care in order to prevent data loss and keep the deployment of the application highly available.

(for more details on how to horizontally scale down / up please refer to [this page](https://discourse.charmhub.io/t/charmed-opensearch-tutorial-horizontal-scaling/9720))

----
**Note: Do not remove multiple units at the same time.**  You should only remove one unit at a time to be able to control and react to the health of your cluster.
Though we implement rolling units removal, the internal state of OpenSearch is only reflected reactively, meaning the charm does **not** know **beforehand** whether a certain removal will put the cluster in a `red` (some primary shards are unassigned) or `yellow` (some replica shards are unassigned) – (you can read more about the cluster health in the [OpenSearch official documentation](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-health/)).

----------

### Steps to follow when scaling down:
Here we detail the steps that an administrator must follow in order to guarantee the safety of the process:

#### 1. Before scaling down:
You should make sure that removing nodes is a safe operation to do. For that, check the health of the cluster: the charm will usually reflect the current health of the cluster on the application status, i.e:
 
```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:46:15Z

App                        Version  Status  Scale  Charm                      Channel  Rev  Exposed  Message
data-integrator                     active      1  data-integrator            edge      11  no
opensearch                          blocked     2  opensearch                 edge      22  no       1 or more 'replica' shards are not assigned, please scale your application up.
tls-certificates-operator           active      1  tls-certificates-operator  stable    22  no
```
You can also manually verify it by using the [OpenSearch health api](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-health/).

**Reminder:** in order to authenticate your requests to the REST API, you need to [retrieve the admin user's credentials](https://discourse.charmhub.io/t/charmed-opensearch-tutorial-user-management/9728). You can run the following command:
```
juju run-action opensearch/leader get-password --wait

> unit-opensearch-0:
    results:
        ca-chain: |-
             <certificate>
        username: admin
        password: admin_password
``` 

If the cluster health is:
- **`green`:** the scale down **may** be safe to do: it is imperative to check whether the node targeted for removal does not hold a primary shard of an index with no replicas! You can see this by making the following request and seeing which primary shards are allocated to the said node. 
  ```
   curl -k -XGET https://admin:admin_pasword@10.180.162.96:9200/_cat/shards
   ```
  It is in general a bad idea to disable replication for indices, but if that's the case: please [re-route](https://www.elastic.co/guide/en/elasticsearch/reference/7.10/cluster-reroute.html) the said shard manually to another node. 
- **`yellow`:** scaling down may **not** be a good idea. This means that some replica shards are `unassigned` - you can visualize that by using the cat api. i.e:
   ```
   curl -k -XGET https://10.180.162.96:9200/_cat/shards -u admin:admin_password
   ```
  A general good course of action here would be the opposite, to scale up / add a unit to have a `green` state where all primary and replica shards are well assigned. 

  Regardless, you **should investigate** why is your cluster in a `yellow` state.
You can make the following call to have an explanation:
  ```
   curl -k -XGET "https://10.180.162.96:9200/_cluster/allocation/explain?filter_path=index,shard,primary,**.node_name,**.node_decision,**.decider,**.decision,**.*explanation,**.unassigned_info,**.*delay"  -u admin:admin_password
   ``` 
   And react accordingly, such as horizontally scaling up or adding more storage to the existing nodes or perhaps [manually re-route](https://www.elastic.co/guide/en/elasticsearch/reference/7.10/cluster-reroute.html) the said shard manually to another node.

- **`red`:** scaling down **is definitely not** a good idea, as some primary shards are not assigned. The course of action to follow here would be to add units to the cluster.

**Note:** You'll notice we did not use the certificates to authenticate the curl requests above, in a real world example you should always make sure you verify your requests with the TLS certificates received from the `get-password` action.
i.e:
```
curl --cacert cert.pem -XGET https://admin:admin_password@10.180.162.96:9200/_cluster/health
``` 

#### 2. Scaling down / remove unit:
Now that you made sure that removing a unit may be safe to do.  **ONLY remove 1 unit at a time.**

You can run the following command (change the unit name to the one you're targeting):
```
juju remove-unit opensearch/2
```

Make sure you monitor the status of the application using: `watch -c juju status --color`.

#### 3. After scale down:
After removing a unit, depending on the roles of the said unit, the charm may reconfigure and restart a unit to balance the node roles. (you should see this by monitoring the juju status: `watch -c juju status --color`)

Please make sure you wait for all the application to stabilize, before you consider removing further units.

**Now, you should check the health of the cluster as detailed previously and react accordingly.**

**Note**: If after a scale down the health color is red: the charm will attempt to block the removal of the node, giving the administrator the opportunity to scale up / add units.