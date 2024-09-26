# How to recover from attached storage

This document describes the steps needed to reuse disks that contain data and metadata of an OpenSearch cluster.

[note] This document's steps can only be applied for disks under Juju management. It is not currently supported to bring external disks or volumes into Juju. [/note]

## Summary
  - [Introduction](#introduction)
    - [Pre-requisites](#pre-requisites)
  - [Re-using Disks Use-Cases](#re-using-disks-use-cases)
    - [Same Cluster Scenario](#same-cluster-scenario)
    - [Different Cluster Scenarios](#different-cluster-scenarios)
      - [Reusing a disk in a different cluster](#reusing-a-disk-in-a-different-cluster)
      - [Bootstrapping from a *used disk*](#bootstrapping-from-a-used-disk)
  - [Dangling Indices](#dangling-indices)

---

[note type="caution"] **Make sure you have safely backed up your data, the steps described here may potentially cause data loss** [/note]

## Introduction

This document will describe the different steps needed to bring disks that have previously being used by OpenSearch, and hence still hold data and metadata of that cluster; and how to reuse these disks. These disks will be named across this document as *used disks*. 

The document is intended for cases where a quick recovery is needed. However, it is important to understand that reusing disks may cause older data to override existing / newer data.  Make sure the disks and their content are known before proceeding with any of the steps described below.

### Pre-requisites

Before starting, make sure that the disks are visible within Juju. For the reminder of the document, the following deployment will be used as example:

```
$ juju status
Model       Controller           Cloud/Region         Version  SLA          Timestamp
opensearch  localhost-localhost  localhost/localhost  3.5.3    unsupported  16:46:04Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/edge         164  no       
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no       

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*                active    idle   1        10.81.173.18    9200/tcp  
opensearch/1                 active    idle   2        10.81.173.167   9200/tcp  
opensearch/2                 active    idle   3        10.81.173.48    9200/tcp  
self-signed-certificates/0*  active    idle   0        10.81.173.30              

Machine  State    Address        Inst id        Base          AZ  Message
0        started  10.81.173.30   juju-e7601c-0  ubuntu@22.04      Running
1        started  10.81.173.18   juju-e7601c-1  ubuntu@22.04      Running
2        started  10.81.173.167  juju-e7601c-2  ubuntu@22.04      Running
3        started  10.81.173.48   juju-e7601c-3  ubuntu@22.04      Running
```

Volumes can be listed with:

```
$ juju storage
Unit          Storage ID         Type        Pool             Size     Status    Message
opensearch/0  opensearch-data/0  filesystem  opensearch-pool  2.0 GiB  attached  
opensearch/1  opensearch-data/1  filesystem  opensearch-pool  2.0 GiB  attached  
opensearch/2  opensearch-data/2  filesystem  opensearch-pool  2.0 GiB  attached 
```

For more details, [refer to Juju storage management documentation](https://juju.is/docs/juju/manage-storage).


## Re-using Disks Use-Cases

OpenSearch does have a set of APIs and mechanisms to detect the existence of previous data on a given node and how to interact with that data. Most notable mechanisms are: (i) the `/_dangling` API, [as described in the upstream docs](https://opensearch.org/docs/latest/api-reference/index-apis/dangling-index/); and (ii) the `opensearch-node` CLI that allows operators to clean up portions of the metadata in the *used disk* before re-attaching to the cluster.

The cases can be broken down into two groups: reusing disks from older nodes but the **same cluster** or reusing disks from **another cluster**. They will be named *same cluster* and *other cluster* scenarios.

The following scenarios will be considered:

1) Same cluster: reusing disks from another node
2) Other cluster: bootstrapping a new cluster with an used disk
3) Other cluster: attaching an used disk from another cluster to an existing cluster

The main concern in these cases is the management of the cluster metadata and the status of the previous indices.

### Same Cluster Scenario

We can check which volumes are currently available to be reattached:
```
$ juju storage
Unit          Storage ID         Type        Pool             Size     Status    Message
              opensearch-data/0  filesystem  opensearch-pool  2.0 GiB  detached  
opensearch/1  opensearch-data/1  filesystem  opensearch-pool  2.0 GiB  attached  
opensearch/2  opensearch-data/2  filesystem  opensearch-pool  2.0 GiB  attached
```

To reuse a given disk within the same cluster, it is enough to spin up a new node and attach that volume:

```
$ juju add-unit opensearch -n 1 --attach-storage opensearch-data/0
```

The node will eventually come up:
```
$ juju status
Model       Controller           Cloud/Region         Version  SLA          Timestamp
opensearch  localhost-localhost  localhost/localhost  3.5.3    unsupported  16:51:39Z

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      3  opensearch                2/edge         164  no       
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no       

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/1*                active    idle   2        10.81.173.167   9200/tcp  
opensearch/2                 active    idle   3        10.81.173.48    9200/tcp  
opensearch/3                 active    idle   4        10.81.173.102   9200/tcp  
self-signed-certificates/0*  active    idle   0        10.81.173.30              

Machine  State    Address        Inst id        Base          AZ  Message
0        started  10.81.173.30   juju-e7601c-0  ubuntu@22.04      Running
2        started  10.81.173.167  juju-e7601c-2  ubuntu@22.04      Running
3        started  10.81.173.48   juju-e7601c-3  ubuntu@22.04      Running
4        started  10.81.173.102  juju-e7601c-4  ubuntu@22.04      Running
```

The new node will have `opensearch-data/0` successfully attached:
```
$ juju storage
Unit          Storage ID         Type        Pool             Size     Status    Message
opensearch/1  opensearch-data/1  filesystem  opensearch-pool  2.0 GiB  attached  
opensearch/2  opensearch-data/2  filesystem  opensearch-pool  2.0 GiB  attached  
opensearch/3  opensearch-data/0  filesystem  opensearch-pool  2.0 GiB  attached
```

Finally, the node will show up on the cluster status:
```
$ curl -sk -u admin:$PASSWORD https://$IP:9200/_cat/nodes
10.81.173.102 15 98 16 3.75 5.59 4.99 dim cluster_manager,data,ingest,ml - opensearch-3.f1a
10.81.173.48  20 98 16 3.75 5.59 4.99 dim cluster_manager,data,ingest,ml - opensearch-2.f1a
10.81.173.167 29 98 16 3.75 5.59 4.99 dim cluster_manager,data,ingest,ml * opensearch-1.f1a
```

### Different Cluster Scenarios

In these cases, the cluster has been removed and the application will be redeployed reusing these disks in part or in total. In all of the following cases, the `opensearch-node` CLI will be needed to clean up portions of the metadata.

#### Reusing a disk in a *different cluster*

To reuse a disk from another cluster, add a new unit with the *used disk*:
```
$ juju add-unit opensearch --attach-storage opensearch-data/0
```

The deployment of this node will eventually stop its normal process and will be unable to proceed. That happens because the new unit holds old metadata, with reference to the *old cluster UUID*. To resolve that, access the unit:
```
$ juju ssh opensearch/0
```

Checking the logs, it is possible to see the unit is waiting for the cluster to become available and intermittently listing its last-known peers that are now unreachable. The following message on the logs will show up:
```
$ sudo journalctl -u snap.opensearch.daemon -f

...

Caused by: org.opensearch.cluster.coordination.CoordinationStateRejectedException: join validation on cluster state with a different cluster uuid K-LFo5AqQ--lamWCNc6ZsA than local cluster uuid gRaym5GmSUebyPO5o3Ay4w, rejecting
```

To remove the stale metadata, first, stop the service:
```
$ sudo systemctl stop snap.opensearch.daemon
```

Then, execute detach the node from its old references:
```
$ sudo -u snap_daemon \
	    OPENSEARCH_JAVA_HOME=/snap/opensearch/current/usr/lib/jvm/java-21-openjdk-amd64 \
	    OPENSEARCH_PATH_CONF=/var/snap/opensearch/current/etc/opensearch \
	    OPENSEARCH_HOME=/var/snap/opensearch/current/usr/share/opensearch \
	    OPENSEARCH_LIB=/var/snap/opensearch/current/usr/share/opensearch/lib \
	    OPENSEARCH_PATH_CERTS=/var/snap/opensearch/current/etc/opensearch/certificates \
	    /snap/opensearch/current/usr/share/opensearch/bin/opensearch-node detach-cluster
```

Restart the service:
```
$ sudo systemctl start snap.opensearch.daemon
```

The cluster will eventually add the new node.

#### Bootstrapping from a *used disk* 

To create a new cluster reusing one of the disks, first deploy a new OpenSearch cluster with one of the attached volumes:
```
$ juju deploy opensearch -n1 --attach-storage opensearch-data/XXX
```

The deployment will eventually stop its normal process and will be unable to proceed. That happens because the cluster is currently loading its original metadata and cannot reach out to any of its peers. To resolve that, access the unit:
```
$ juju ssh opensearch/0
```
Checking the logs, it is possible to see the unit is waiting for the cluster to become available and intermittently listing its last-known peers that are now unreachable. The following message on the logs will show up:
```
$ sudo journalctl -u snap.opensearch.daemon -f

...

Sep 09 10:33:55 juju-05dbd1-4 opensearch.daemon[8573]: [2024-09-09T10:33:55,415][INFO ][o.o.s.c.ConfigurationRepository] [opensearch-3.bf4] Wait for cluster to be available ... 
```

To remove the stale metadata, first, stop the service:
```
$ sudo systemctl stop snap.opensearch.daemon
```

Then, execute the unsafe-bootstrap to remove the stale metadata:
```
$ sudo -u snap_daemon \
	    OPENSEARCH_JAVA_HOME=/snap/opensearch/current/usr/lib/jvm/java-21-openjdk-amd64 \
	    OPENSEARCH_PATH_CONF=/var/snap/opensearch/current/etc/opensearch \
	    OPENSEARCH_HOME=/var/snap/opensearch/current/usr/share/opensearch \
	    OPENSEARCH_LIB=/var/snap/opensearch/current/usr/share/opensearch/lib \
	    OPENSEARCH_PATH_CERTS=/var/snap/opensearch/current/etc/opensearch/certificates \
	    /snap/opensearch/current/usr/share/opensearch/bin/opensearch-node unsafe-bootstrap
```

Restart the service:
```
$ sudo systemctl start snap.opensearch.daemon
```

The cluster will be correctly form a new UUID. It is possible to also add more units, either fresh ones or even units detached from another cluster, as explained on the previous section.



## Dangling Indices

Now, the *used disk*  is successfully mounted to the cluster. The next step is to check for indices that  did not exist in the cluster. That can be done using the `/_dangling` API. To understand n more details how to list and recover dangling indices, refer to the [OpenSearch documentation on this API](https://opensearch.org/docs/latest/api-reference/index-apis/dangling-index/).

[note type="caution"] **This API cannot offer any guarantees as to whether the imported data truly represents the latest state of the data when the index was still part of the cluster.** [/note]