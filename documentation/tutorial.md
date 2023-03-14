# Charmed OpenSearch tutorial
The Charmed OpenSearch Operator delivers automated operations management from [day 0 to day 2](https://codilime.com/blog/day-0-day-1-day-2-the-software-lifecycle-in-the-cloud-age/) on the [OpenSearch](https://github.com/opensearch-project/OpenSearch/) document database. It is an open source, end-to-end, production-ready data platform running on [Juju](https://juju.is/). This tutorial will cover the following:

- [Charmed OpenSearch tutorial](#charmed-opensearch-tutorial)
  - [Setting up your environment](#setting-up-your-environment)
    - [Minimum requirements](#minimum-requirements)
    - [Prepare LXD](#prepare-lxd)
    - [Install and prepare Juju](#install-and-prepare-juju)
    - [Setting Kernel Parameters](#setting-kernel-parameters)
    - [Setting Kernel Parameters as Juju Model Parameters](#setting-kernel-parameters-as-juju-model-parameters)
  - [Deploy Charmed OpenSearch](#deploy-charmed-opensearch)
  - [Transport Layer Security (TLS)](#transport-layer-security-tls)
    - [Configure TLS](#configure-tls)
    - [Enable TLS](#enable-tls)
  - [Relations](#relations)
    - [Relate to OpenSearch](#relate-to-opensearch)
    - [Create and Access OpenSearch Indices](#create-and-access-opensearch-indices)
    - [Remove the user](#remove-the-user)
  - [Scale Charmed OpenSearch](#scale-charmed-opensearch)
    - [Remove replicas](#remove-replicas)
  - [Next Steps](#next-steps)
    - [Remove Charmed OpenSearch and Juju](#remove-charmed-opensearch-and-juju)
    - [License](#license)
    - [Trademark Notice](#trademark-notice)

This tutorial assumes a basic understanding of the following:

- Basic linux terminal commands.
- OpenSearch concepts such as indices and users.
  - To learn more about these concepts, visit the [OpenSearch Documentation](https://opensearch.org/docs/latest/)

---

## Setting up your environment

### Minimum requirements

Before we start, make sure your machine meets the following requirements:

- Ubuntu 20.04 (Focal) or later.
- 16GB of RAM.
- 4 CPU cores.
- At least 20GB of available storage.
- Access to the internet for downloading the required snaps and charms.

For a complete list of OpenSearch system requirements, please read the [Opensearch Documentation](https://opensearch.org/docs/2.4/install-and-configure/install-opensearch/index/).

### Prepare LXD

The simplest way to get started with Charmed OpenSearch is to set up a local LXD cloud. LXD is a system container and virtual machine manager that comes pre-installed on Ubuntu. Juju interfaces with LXD to control the containers on which Charmed OpenSearch runs. While this tutorial covers some of the basics of using LXD, you can [learn more about LXD here](https://linuxcontainers.org/lxd/getting-started-cli/).

Verify that LXD is installed by entering `which lxd` into the command line. This will output:

```bash
/snap/bin/lxd
```

Although LXD is already installed, we need to run `lxd init` to perform post-installation tasks. For this tutorial the default parameters are preferred and the network bridge should be set to have no IPv6 addresses, since Juju does not support IPv6 addresses with LXD:

```bash
lxd init --auto
lxc network set lxdbr0 ipv6.address none
```

You can list all LXD containers by entering the command `lxc list` in to the command line. Although at this point in the tutorial none should exist and you'll only see this as output:

```bash
+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

### Install and prepare Juju

Juju is an Operator Lifecycle Manager (OLM) for clouds, bare metal, LXD or Kubernetes. We will be using it to deploy and manage Charmed OpenSearch. As with LXD, Juju is installed using a snap package:

```bash
sudo snap install juju --classic
```

Juju already has a built-in knowledge of LXD and how it works, so there is no additional setup or configuration needed. A controller will be used to deploy and control Charmed OpenSearch. Run the following command to bootstrap a Juju controller named ‘opensearch-demo’ on LXD. This bootstrapping processes can take several minutes depending on your system resources:

```bash
juju bootstrap localhost opensearch-demo
```

The Juju controller should exist within an LXD container. You can verify this by entering the command `lxc list`; you should see the following:

```bash
+---------------+---------+-----------------------+------+-----------+-----------+
|     NAME      |  STATE  |         IPV4          | IPV6 |   TYPE    | SNAPSHOTS |
+---------------+---------+-----------------------+------+-----------+-----------+
| juju-<id>     | RUNNING | 10.105.164.235 (eth0) |      | CONTAINER | 0         |
+---------------+---------+-----------------------+------+-----------+-----------+
```

where `<id>` is a unique combination of numbers and letters such as `9d7e4e-0`

The controller can hold multiple models. In each model, we deploy charmed applications. Set up a specific model for this tutorial, named ‘tutorial’:

```bash
juju add-model tutorial
```

You can now view the model you created above by entering the command `juju status` into the command line. You should see the following:

```bash
Model    Controller         Cloud/Region         Version  SLA          Timestamp
tutorial opensearch-demo    localhost/localhost  2.9.37   unsupported  23:20:53Z

Model "admin/tutorial" is empty.
```

### Setting Kernel Parameters

Before deploying Charmed OpenSearch, we need to set some [kernel parameters](https://www.kernel.org/doc/Documentation/sysctl/vm.txt). These are necessary requirements for OpenSearch to function correctly, and because we're using LXD containers to deploy our charm, and containers share a kernel with their host, we need to set these kernel parameters on the host machine.

First, we need to get the current parameters of the kernel because we will need to reset them after the tutorial (although rebooting your machine will also do the trick). We're only changing three specific parameters, so we're filtering the output for those three parameters:

```bash
sudo sysctl -a | grep -E 'swappiness|max_map_count|tcp_retries2'
```

This command should return something like the following:

```bash
net.ipv4.tcp_retries2 = 15
vm.max_map_count = 262144
vm.swappiness = 60
```

Note these variables so we can reset them later. Not doing so may cause some system instability. Set the kernel parameters to the new recommended values like so:

```bash
sudo sysctl -w vm.max_map_count=262144 vm.swappiness=0 net.ipv4.tcp_retries2=5
```

Please note that these values reset on system reboot, so if you complete this tutorial in multiple stages, you'll need to set these values each time you restart your computer.

### Setting Kernel Parameters as Juju Model Parameters

You also need to set the juju model config to include these parameters, which you do like so:

```bash
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
    - [ 'sysctl', '-w', 'vm.swappiness=0' ]
    - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
EOF
juju model-config ./cloudinit-userdata.yaml
```

---

## Deploy Charmed OpenSearch

To deploy Charmed OpenSearch, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/opensearch?channel=edge) and deploy it to your model:

```bash
juju deploy opensearch --channel=edge
```

Juju will now fetch Charmed OpenSearch and begin deploying it to the LXD cloud. This process can take several minutes depending on your machine. You can track the progress by running:

```bash
juju status --watch=1s
```

This command is useful for checking the status of your Juju Model, including the applications and machines that it hosts. Some of the helpful information it displays include IP addresses, ports, state, etc. The output of this command updates once per second. When the application is ready, `juju status` will show:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  11:24:30Z

App         Version  Status   Scale  Charm       Channel   Rev  Exposed  Message
opensearch           blocked      1  opensearch  dpe/edge   96  no       Waiting for TLS to be fully configured...

Unit           Workload  Agent  Machine  Public address  Ports      Message
opensearch/0*  blocked   idle   0        10.23.62.156    27017/tcp  Waiting for TLS to be fully configured...

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
```

To exit the screen with `juju status --watch 1s`, enter `Ctrl+c`.

The status message `Waiting for TLS to be fully configured...` exists because Charmed OpenSearch requires TLS to be configured before use, to ensure data is transmitted securely. If you're seeing a status message like the following, [you need to set the correct kernel parameters to continue](#setting-kernel-parameters).

```bash
vm.swappiness should be 0 - net.ipv4.tcp_retries2 should be 5
```

---

## Transport Layer Security (TLS)

[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) is used to encrypt data exchanged between two applications; it secures data transmitted over the network. Typically, enabling TLS within a highly available database, and between a highly available database and client/server applications, requires domain-specific knowledge and a high level of expertise. Fortunately, the domain-specific knowledge has been encoded into Charmed OpenSearch. This means enabling TLS on Charmed Opensearch is easily available and requires minimal effort on your end.

TLS is enabled via relations, by relating Charmed OpenSearch to the [TLS Certificates Charm](https://charmhub.io/tls-certificates-operator). The TLS Certificates Charm centralises TLS certificate management in a consistent manner and handles providing, requesting, and renewing TLS certificates.

### Configure TLS

Before enabling TLS on Charmed OpenSearch we must first deploy the `TLS-certificates-operator` charm:

```bash
juju deploy tls-certificates-operator --channel=beta
```

Wait until the `tls-certificates-operator` is ready to be configured. When it is ready to be configured `juju status --watch 1s`. Will show:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  09:24:12Z

App                        Version  Status   Scale  Charm                      Channel  Rev  Exposed  Message
opensearch                          blocked      1  opensearch                 edge      11  no       Waiting for TLS to be fully configured...
tls-certificates-operator           blocked      1  tls-certificates-operator  beta      22  no       Configuration options missing: ['certificate', 'ca-certificate']

Unit                          Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*                 blocked   idle   0        10.137.5.232           Waiting for TLS to be fully configured...
tls-certificates-operator/0*  blocked   idle   1        10.137.5.33            Configuration options missing: ['certificate', 'ca-certificate']

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.137.5.232  juju-2f4c88-0  jammy       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
```

Now we can configure the TLS certificates. Configure the  `tls-certificates-operator` to use self signed certificates:

```bash
juju config tls-certificates-operator generate-self-signed-certificates="true" ca-common-name="Tutorial CA"
```
*Note: this tutorial uses [self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate); self-signed certificates should not be used in a production cluster. To set the correct certificates, see the [TLS operator documentation](https://github.com/canonical/tls-certificates-operator).*

### Enable TLS

After configuring the certificates `juju status` will show the status of `tls-certificates-operator` as active. To enable TLS on Charmed OpenSearch, relate the two applications:

```bash
juju relate tls-certificates-operator opensearch
```

The output of `juju status` should now resemble the following:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  09:24:12Z

App                        Version  Status  Scale  Charm                      Channel  Rev  Exposed  Message
opensearch                          active      1  opensearch                 edge      11  no
tls-certificates-operator           active      1  tls-certificates-operator  beta      22  no

Unit                          Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*                 active    idle   0        10.137.5.232
tls-certificates-operator/0*  active    idle   1        10.137.5.33

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.137.5.232  juju-2f4c88-0  jammy       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
```

---

## Relations
<!---Juju 3.0 uses integrations; I haven’t been able to find the docs for 2.9 --->
Relations, or what Juju documentation [describes as Integrations](https://juju.is/docs/sdk/integration), are the easiest way to connect to Charmed OpenSearch. Relations automatically create a username, password, and database for the desired user/application, as well as defining access permissions.

The best way to create a user and password for manual use (i.e. connecting to opensearch directly using `curl`, which is what we'll be doing later) is to add a relation between Charmed Opensearch and the [Data Integrator Charm](https://charmhub.io/data-integrator). This is a bare-bones charm that allows for central management of database users, providing support for different kinds of data platforms (e.g. MongoDB, MySQL, PostgreSQL, Kafka, etc) with a consistent, opinionated and robust user experience. In order to deploy the Data Integrator Charm we can use the command `juju deploy` we have learned above:

```bash
juju deploy data-integrator --channel=edge --config index-name=test-index --config extra-user-roles=admin
```

The expected output:

```bash
Located charm "data-integrator" in charm-hub...
Deploying "data-integrator" from charm-hub charm "data-integrator"...
```

Wait for the data-integrator charm to reach an active idle state, which shouldn't take too long.

### Relate to OpenSearch

Now that the Database Integrator Charm has been set up, we can relate it to Charmed OpenSearch. This will automatically create a username, password, and CA cert for the Database Integrator Charm. Relate the two applications with:

```bash
juju relate data-integrator opensearch
```

Wait for `juju status --watch 1s` to show:

```bash
ubuntu@ip-172-31-11-104:~/data-integrator$ juju status
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  10:32:09Z

App                        Version  Status  Scale  Charm                Channel   Rev  Exposed  Message
data-integrator                     active      1  data-integrator      edge       3   no
opensearch                          active      2  opensearch           dpe/edge   96  no
tls-certificates-operator           active      1  tls-certificates-operator  beta      22  no

Unit                          Workload  Agent  Machine  Public address  Ports      Message
data-integrator/0*            active    idle   5        10.23.62.216               received opensearch credentials
opensearch/0*                 active    idle   0        10.23.62.156
tls-certificates-operator/0*  active    idle   1        10.137.5.33

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
5        started  10.23.62.216  juju-d35d30-5  jammy       Running
```

To retrieve information such as the username, password, and database. Enter:

```bash
juju run-action data-integrator/leader get-credentials --wait
```

This should output something like: TODO VERIFY

```yaml
​​unit-data-integrator-0:
  UnitId: data-integrator/0
  id: "24"
  results:
    opensearch:
      index: test-index
      endpoints: 10.23.62.156
      password: VMnRws6BlojzDi5e1m2GVWOgJaoSs44d
      ca-cert: TODO ADD A CERT IN HERE
      username: relation-4
    ok: "True"
  status: completed
  timing:
    completed: 2022-12-06 10:33:24 +0000 UTC
    enqueued: 2022-12-06 10:33:20 +0000 UTC
    started: 2022-12-06 10:33:24 +0000 UTC
```

Save the ca-cert, username, and password, because you'll need them in the next section.

### Create and Access OpenSearch Indices

You can access the opensearch REST API any way you prefer, but in this tutorial we're going to use `curl`. Get the IP of an opensearch node from the output of `juju status` (any of the nodes should work fine), and store the CA cert in a local file. Run the following command, swapping the values where necessary:

```bash
# TODO test this with data-integrator output
curl --cacert demo-ca.chain -XGET https://username:password@opensearch_ip:9200/
```

Sending a `GET` request to this `/` endpoint should return some basic information about your opensearch deployment, which should look something like this:

```json
{
  "name" : "opensearch-1",
  "cluster_name" : "opensearch-test-opensearch-provider-tk22",
  "cluster_uuid" : "JH6o9FPSS0OU5jz_xcHmQg",
  "version" : {
    "distribution" : "opensearch",
    "number" : "2.4.1",
    "build_type" : "tar",
    "build_hash" : "f2f809ea280ffba217451da894a5899f1cec02ab",
    "build_date" : "2022-12-12T22:17:42.341124910Z",
    "build_snapshot" : false,
    "lucene_version" : "9.4.2",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
```

If this command fails, ensure the opensearch units are all in an active-idle state you've configured the data-integrator charm to set `extra_user_roles=admin`.

The command we just ran used the `--cacert` flag to pass in the ca chain generated by the TLS operator, ensuring secure transmission between our local machine and the opensearch node. To recap, the CA chain is generated by the TLS operator, and is passed over to the opensearch charm, which provides this cert in its databag to any application that relates to it. using the `opensearch-client` relation interface. When developing charms that relate to the opensearch operator, ensure you use this cert to authenticate communication.

To add some data, run the following command:

```bash
curl --cacert test-ca.chain \
  -XPOST https://username:password@opensearch_ip:9200/albums/_doc/1 \
  -d '{"artist": "Vulfpeck", "genre": ["Funk", "Jazz"], "title": "Thrill of the Arts"}' \
  -H 'Content-Type: application/json'
```

This command uses the same authentication to sent a `POST` request to the same node as before, but it sends a specific JSON payload to a specific document address. The output should look something like this:

```json
{
  "_index":"albums",
  "_id":"1",
  "_version":2,
  "result":"updated",
  "_shards": {
    "total":2,
    "successful":2,
    "failed":0
  },
  "_seq_no":4,
  "_primary_term":1
}
```

Note the `"failed":0` response, under `"_shards"`.

Use the following command to query this document:

```bash
curl --cacert test-ca.chain -XGET https://username:password@opensearch_ip:9200/albums/_doc/1
```

This query should output something like the following:

```json
{
  "_index":"albums",
  "_id":"1",
  "_version":2,
  "_seq_no":4,
  "_primary_term":1,
  "found":true,
  "_source":{
    "artist": "Vulfpeck",
    "genre": ["Funk", "Jazz"],
    "title": "Thrill of the Arts"
  }
}
```

To add data in bulk using the [OpenSearch Bulk API](https://opensearch.org/docs/latest/api-reference/document-apis/bulk/), copy and paste the following data into a file called `bulk-albums.json`, ensuring that you keep the newline at the end of the file:

```json
{ "index" : { "_index": "albums", "_id" : "2" } }
{"artist": "Herbie Hancock", "genre": ["Jazz"],  "title": "Head Hunters"}
{ "index" : { "_index": "albums", "_id" : "3" } }
{"artist": "Lydian Collective", "genre": ["Jazz"],  "title": "Adventure"}
{ "index" : { "_index": "albums", "_id" : "4" } }
{"artist": "Rush", "genre": ["Prog"],  "title": "Moving Pictures"}

```

Then, to send this data to the bulk endpoint, run the following command:

```bash
curl --cacert test-ca.chain -XPOST https://username:password@opensearch_ip:9200/_bulk --data-binary @bulk-albums.json  -H 'Content-Type: application/json'
```

To test this command worked, we can run a search query for Jazz in our albums index, using the following command:

```bash
curl --cacert test-ca.chain -XGET https://username:password@opensearch_ip:9200/albums/_search?q=Jazz
```

This should return a JSON response with all the Jazz albums in the index:

```json
{
  "took": 35,
  "timed_out": false,
  "_shards": {
    "total": 1,
    "successful": 1,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "value": 3,
      "relation": "eq"
    },
    "max_score": 0.4121628,
    "hits": [{
      "_index": "albums",
      "_id": "1",
      "_score": 0.4121628,
      "_source": {
        "artist": "Vulfpeck",
        "genre": ["Funk", "Jazz"],
        "title": "Thrill of the Arts"
      }
    }, {
      "_index": "albums",
      "_id": "2",
      "_score": 0.4121628,
      "_source": {
        "artist": "Herbie Hancock",
        "genre": ["Jazz"],
        "title": "Head Hunters"
      }
    }, {
      "_index": "albums",
      "_id": "3",
      "_score": 0.4121628,
      "_source": {
        "artist": "Lydian Collective",
        "genre": ["Jazz"],
        "title": "Adventure"
      }
    }]
  }
}
```

### Remove the user

To remove the user, remove the relation. Removing the relation automatically removes the user that was created when the relation was created. Enter the following to remove the relation:

```bash
juju remove-relation opensearch data-integrator
```

Now try again to connect in the same way as the previous section

```bash
# TODO test this with data-integrator output
curl --cacert demo-ca.chain -XGET https://username:password@opensearch_ip:9200/
```

This should output something like the following error:

```bash
Unauthorized
```

If you wanted to recreate this user all you would need to do is relate the the two applications and run the same action on data-integrator to get the same credentials:

```bash
juju relate data-integrator opensearch
juju run-action data-integrator/leader get-credentials --wait
```

You can connect to the database with this new username and password:

```bash
curl --cacert test-ca.chain -XGET https://new_username:new_password@opensearch_ip:9200/albums/_search?q=Jazz
```

Note that the data in our index has not changed.

<!-- FIXME this currently fails due to a bug. -->
Also, note that the certificate does not change across relations. To create a new CA cert, remove the relation between opensearch and the tls-certificates operator, wait for opensearch to enter a blocked status, then recreate the relation. Run the get-credentials action on the data-integrator charm again to get the new credentials, and test them again with the above search request.

---

## Scale Charmed OpenSearch

You can add two replicas to your deployed OpenSearch application with:

```bash
juju add-unit opensearch -n 2
```

You can now watch the replica set add these replicas with: `juju status --watch 1s`. It usually takes several minutes for the replicas to be added to the replica set. You’ll know that all three replicas are ready when `juju status --watch 1s` reports:

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

### Remove replicas

Removing a unit from the Juju application scales down your OpenSearch cluster by one node. Before we scale down the nodes we no longer need, list all the units with `juju status`. Here you will see three units: `opensearch/0`, `opensearch/1`, and `opensearch/2`. Each of these units hosts an OpenSearch node. To remove the node hosted on the unit `opensearch/2` enter:

```bash
juju remove-unit opensearch/2
```

You’ll know that the replica was successfully removed when `juju status --watch 1s` reports:

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
tls-certificates-operator/0*  active    idle   1        10.137.5.33

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
3        started  10.23.62.55   juju-d35d30-3  jammy       Running
5        started  10.23.62.216  juju-d35d30-5  jammy       Running
```

---

## Next Steps

In this tutorial we've successfully deployed OpenSearch, added/removed replicas, added/removed users to/from the database, and even enabled and disabled TLS. You may now keep your Charmed OpenSearch deployment running and write to the database or remove it entirely using the steps in [Remove Charmed Opensearch and Juju](#remove-charmed-opensearch-and-juju). If you're looking for what to do next you can:

- Check out other charms on [charmhub.io](https://charmhub.io/)
- Read about [High Availability Best Practices](https://canonical.com/blog/database-high-availability)
- [Report](https://github.com/canonical/opensearch-operator/issues) any problems you encountered.
- [Give us your feedback](https://chat.charmhub.io/charmhub/channels/data-platform).
- [Contribute to the code base](https://github.com/canonical/opensearch-operator)

### Remove Charmed OpenSearch and Juju

*Warning: when you remove Charmed OpenSearch as shown below you will lose all the data in your cluster. Furthermore, when you remove Juju as shown below you will lose access to any other applications you have hosted on Juju.*

To remove Charmed OpenSearch and the model it is hosted on run the command:

```bash
juju destroy-model tutorial --destroy-storage --force
```

Next step is to remove the Juju controller. You can see all of the available controllers by entering `juju controllers`. To remove the controller enter:

```bash
juju destroy-controller opensearch-demo
```

Finally to remove Juju altogether, enter:

```bash
sudo snap remove juju --purge
```

### License

The Charmed OpenSearch Operator is distributed under the Apache Software License, version 2.0. It [installs/operates/depends on] [OpenSearch Community Edition](https://github.com/opensearch-project/OpenSearch/), which is licensed under the Apache Software License, version 2.0.

### Trademark Notice

OpenSearch is a registered trademark of Amazon Web Services. Other trademarks are property of their respective owners.
