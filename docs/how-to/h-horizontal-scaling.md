# How to safely scale down 

This page outlines the general steps to follow when scaling down Charmed OpenSearch in order to prevent data loss and ensure the deployment remains highly available

To see an example of scaling down a real deployment scenario, check the following page from the Charmed OpenSearch Tutorial: [6. Scale horizontally](/t/9720).

[note type="caution"]
**Warning:**
* The following steps are for removing one single Juju unit (node). This may be repeated as many times as necessary, but **never remove multiple units in the same command.** 
* In highly available deployments, **it is not safe to scale below 3 nodes**. 
[/note]

## Summary
* [1. Check cluster health before scaling down](#1-check-cluster-health-before-scaling-down)
  * [Via Juju](#via-juju)
  * [Via the OpenSearch health API](#via-the-opensearch-health-api)
  * [Cluster health statuses](#cluster-health-statuses)
* [2. Scale down one unit](#2-scale-down-one-unit)
* [3. Repeat cluster health check](#3-repeat-cluster-health-check)

---

## 1. Check cluster health before scaling down

First of all, make sure that removing nodes is a safe operation to do. For that, check the health of the cluster. This can be done via Juju or via the OpenSearch API.

### Via Juju

The charm will reflect the current health of the cluster on the application status. This will display an `active` status when the cluster is in good health, and a `blocked` status along with an informative message when the cluster is not in good health.  

Below is a sample output of the command `juju status --watch 1s` when the cluster is not healthy enough for scaling down. 
 
```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.5.3    unsupported  14:29:04Z

App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
data-integrator                    active       1  data-integrator           latest/edge     59  no
opensearch                         blocked      1  opensearch                2/beta         117  no       1 or more 'replica' shards are not assigned, please scale your application up.
self-signed-certificates           active       1  self-signed-certificates  latest/stable  155  no

Unit                         Workload  Agent  Machine  Public address  Ports     Message
data-integrator/0*           active    idle   2        10.95.38.174
opensearch/0*                active    idle   1        10.95.38.230    9200/tcp
self-signed-certificates/0*  active    idle   0        10.95.38.94

Machine  State    Address       Inst id        Base          AZ  Message
0        started  10.95.38.94   juju-4dad5c-0  ubuntu@22.04      Running
1        started  10.95.38.230  juju-4dad5c-1  ubuntu@22.04      Running
2        started  10.95.38.174  juju-4dad5c-2  ubuntu@22.04      Running
```
In this case, the cluster is not in good health because the status is `blocked`, and the message says `1 or more 'replica' shards are not assigned, please scale your application up`.

### Via the OpenSearch health API

To monitor the health more precisely, you can use the [OpenSearch health API](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-health/).

In order to authenticate your requests to the REST API, you need to [retrieve the admin user's credentials](/t/9728). 

To get the admin user credentials, run the following command:
```shell
juju run opensearch/leader get-password

> unit-opensearch-0:
    results:
        ca-chain: |-
             <certificate>
        username: admin
        password: admin_password
``` 

### Cluster health statuses

A cluster health may return `green`, `yellow`, or `red`.

#### `green`

 :green_circle: Scaling down might be safe to do. This is roughly equivalent to an `active` juju status.

It is imperative to check whether the node targeted for removal does not hold a primary shard of an index with no replicas. You can see this by making the following request and seeing which primary shards are allocated to a given node:

```shell
curl --cacert cert.pem -k -XGET https://admin:admin_pasword@10.180.162.96:9200/_cat/shards
```
It is generally not recommended to disable replication for indices, but if that's the case: [re-route](https://www.elastic.co/guide/en/elasticsearch/reference/7.10/cluster-reroute.html) the said shard manually to another node.

#### `yellow` 

:yellow_circle: Scaling down **might not be safe** to do. This is roughly equivalent to a `blocked` juju status.

This means that some replica shards are `unassigned`. You can visualize that by using the cat API as shown below.

```shell
curl --cacert cert.pem -k -XGET https://10.180.162.96:9200/_cat/shards -u admin:admin_password
```
A general good course of action here would be to scale up (add a unit) to have a `green` state where all primary and replica shards are well assigned. 

To investigate why is your cluster in a `yellow` state. You can make the following call to have an explanation:

```shell
curl --cacert cert.pem -k -XGET "https://10.180.162.96:9200/_cluster/allocation/explain?filter_path=index,shard,primary,**.node_name,**.node_decision,**.decider,**.decision,**.*explanation,**.unassigned_info,**.*delay"  -u admin:admin_password
``` 
<!-- What can we expect as an output?-->
Depending on the output, there may be a different course of action. For example: scaling up, adding more storage to the existing nodes, or perhaps [manually re-route](https://www.elastic.co/guide/en/elasticsearch/reference/7.10/cluster-reroute.html) the relevant shard manually to another node.

To scale up by one unit, run the following command:
```shell
juju add-unit -n 1
```

#### `red`  

:red_circle: Scaling down **is definitely not safe** to do, as some primary shards are not assigned. This is roughly equivalent to a `blocked` juju status.

The course of action to follow here is to add units to the cluster. To scale up by one unit, run the following command:
```shell
juju add-unit -n 1
```

[note]
**Note**: If the health color is `red` after removing a unit, the charm will attempt to block the removal of the node, giving the administrator the opportunity to scale up (add units).
[/note]

<!-- TODO: clarify
**Note:** You'll notice we did not use the certificates to authenticate the curl requests above, in a real world example you should always make sure you verify your requests with the TLS certificates received from the `get-password` action.
i.e:
```
curl --cacert cert.pem -XGET https://admin:admin_password@10.180.162.96:9200/_cluster/health
``` 
-->
## 2. Scale down one unit

Once you made sure that removing a unit is safe to do, you can proceed to removing **a single unit**. It is unsafe to remove more than one unit at a time.

[note]
**Note:** Although we implement a rolling units removal, the internal state of OpenSearch is only reflected reactively. This means the charm **does not know in advance** whether a certain removal will put the cluster in a `red` (some primary shards are unassigned) or `yellow` (some replica shards are unassigned).

Read more about cluster health in the official [OpenSearch documentation](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-health/).
[/note]

To remove one unit of the `opensearch` application, run the following command:
```shell
juju remove-unit opensearch/<unit-id>
```

Make sure you monitor the status of the application using: `juju status --watch 1s`.

## 3. Repeat cluster health check

After removing **one unit**, depending on the roles of the said unit, the charm may reconfigure and restart a unit to balance the node roles. You can monitor this with `juju status --watch 1s`.
<!-- what happens to each role?-->

Make sure you wait for the whole application to stabilize before you consider removing further units.

Once the application is stable, check the health of the cluster as detailed in the section [Understand the meaning of the cluster status](#cluster-health-statuses) and react accordingly.