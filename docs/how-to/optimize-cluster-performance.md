(how-to-optimize-cluster-performance)=
# How to optimize cluster performance with profiles

**Note:** Profile configuration is currently only available in the edge channel.

The charmed OpenSearch operator provides a way to tune the performance of deployed OpenSearch clusters through the `profile` configuration parameter. Profiles define resource requirements and tuning performance related parameters to suit different use cases. One of the said parameters would be the JVM allocated heap size for example.

Currently, the OpenSearch charm supports two profiles:

* **`testing`** – optimized for lightweight, development, or testing workloads.  
* **`production`** – optimized for production-grade, large-scale deployments.

By default:

* The **`testing`** profile is applied by default when deploying OpenSearch version 2\.  
* The **`production`** profile will become the default in the next stable release of OpenSearch version 3\.

## Deploy OpenSearch with the `testing` profile

```shell
juju deploy opensearch --channel=2/edge --config profile=testing
```

This command deploys OpenSearch with the testing profile, which applies the following requirements and constraints:

* Cluster can run with a **minimum of 1 node** (with both ClusterManager and Data roles).  
* **No strict memory requirements** are enforced.  
* JVM heap size (`-Xms` / `-Xmx`) is set to **1 GB by default**.

TLS is still required, as it is a first-class requirement for all OpenSearch deployments. 

For example, to deploy a self-signed certificates operator and integrate it with OpenSearch:

```shell
juju deploy self-signed-certificates --channel=latest/stable
juju integrate self-signed-certificates opensearch
```

After deployment, the application status should look similar to:

```
App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         active      1  opensearch                2/edge         274  no
self-signed-certificates           active      1  self-signed-certificates  latest/stable  264  no
```

If you inspect the logs using `juju debug-log --include opensearch/0 --level WARNING`  you will see a warning indicating that the **`testing` profile** is in use:

```shell
unit-opensearch-0: 07:42:00 WARNING unit.opensearch/0.juju-log opensearch-peers:1: Testing profile is used. This profile is not suitable for production use and should only be used for testing purposes.
```

## Deploy OpenSearch with the `production` profile

```shell
juju deploy opensearch --channel=2/edge --config profile=production
juju deploy self-signed-certificates --channel=latest/stable
juju integrate self-signed-certificates opensearch
```

When deploying with the **`production`** profile, OpenSearch enforces stricter constraints to ensure stability and performance. For example, if only a single node is deployed, the application will enter a blocked state:

```shell
App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
opensearch                         blocked      1  opensearch                                 1  no       At least 3 cluster manager nodes are required. Found only 1. - At least 3 data nodes are required. Found only 1.
```

The production profile has the following requirements and optimizations:

* **Minimum of 3 cluster manager nodes**.  
* **Minimum of 3 data nodes**.  
* **Recommended memory: 8 GB**.  
* JVM heap size (`-Xms` / `-Xmx`) is automatically set to **50% of available RAM**, with a minimum of 4 GB and a maximum of 31 GB.

**Important:** If any of these requirements are not met, the charm will remain in a **`blocked`** state until corrected.

## Update profile at runtime

The OpenSearch profile can be changed after deployment. The charm automatically detects the update and reconfigures the instance accordingly.

```shell
juju config opensearch profile=<profile name>testing
# or
juju config opensearch profile=production
```

## Profile comparison

**Note:** Both profiles enforce the same system prerequisites regarding swap that must be disabled and **vm.max\_map\_count \>= 262144**. The charm would guarantee the same high availability in both profiles.

| Feature / Setting  | `testing` Profile                           | `production` Profile                                     |
| :----------------- | :------------------------------------------ | :------------------------------------------------------- |
| Cluster size       | Minimum **1 node** (ClusterManager \+ Data) | Minimum **3 cluster manager nodes** and **3 data nodes** |
| Memory requirement | No enforced requirement                     | Recommended: **8 GB**                                    |
| JVM Heap size      | Fixed at **1 GB**                           | **50% of RAM**, min **4 GB**, max **31 GB**              |
| Default use case   | Development / testing / lightweight loads   | Production workloads and large deployments               |

