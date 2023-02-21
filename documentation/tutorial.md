# Charmed MongoDB tutorial
The Charmed OpenSearch Operator delivers automated operations management from [day 0 to day 2](https://codilime.com/blog/day-0-day-1-day-2-the-software-lifecycle-in-the-cloud-age/) on the [OpenSearch](https://github.com/opensearch-project/OpenSearch/) document database. It is an open source, end-to-end, production-ready data platform [on top of Juju](https://juju.is/). This tutorial will cover the following:
- [Set up your environment using LXD and Juju.](#setting-up-your-environment)
- [Deploy OpenSearch using a single command.](#deploy-charmed-opensearch)
- [Enable secure transactions with TLS.](#transport-layer-security-tls)
- [Access the REST API and query indices.](#connecting-to-opensearch)
- [Replicate your OpenSearch cluster to add High Availability.](#scale-charmed-opensearch)
- [Change the admin password.](#passwords)
- [Integrate other applications with OpenSearch using Juju Relations.](#relations)

This tutorial assumes a basic understanding of the following:
- Basic linux terminal commands.
- OpenSearch concepts such as indices and users.
  - To learn more about these concepts, visit the [OpenSearch Documentation](https://opensearch.org/docs/latest/)

### Minimum requirements
Before we start, make sure your machine meets the following requirements:
- Ubuntu 20.04 (Focal) or later.
- 8GB of RAM.
- 2 CPU cores.
- At least 20GB of available storage.
- Access to the internet for downloading the required snaps and charms.

For a complete list of OpenSearch system requirements, please read the [Opensearch Documentation](https://opensearch.org/docs/2.4/install-and-configure/install-opensearch/index/).

---

## Setting up your environment

### Prepare LXD
The simplest way to get started with Charmed OpenSearch is to set up a local LXD cloud. LXD is a system container and virtual machine manager that comes pre-installed on Ubuntu. Juju interfaces with LXD to control the containers on which Charmed OpenSearch runs. While this tutorial covers some of the basics of using LXD, you can [learn more about LXD here](https://linuxcontainers.org/lxd/getting-started-cli/).

Verify that LXD is installed by entering `which lxd` into the command line. This will output:
```
/snap/bin/lxd
```

Although LXD is already installed, we need to run `lxd init` to perform post-installation tasks. For this tutorial the default parameters are preferred and the network bridge should be set to have no IPv6 addresses, since Juju does not support IPv6 addresses with LXD:
```shell
lxd init --auto
lxc network set lxdbr0 ipv6.address none
```

You can list all LXD containers by entering the command `lxc list` in to the command line. Although at this point in the tutorial none should exist and you'll only see this as output:
```
+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```


### Install and prepare Juju
Juju is an Operator Lifecycle Manager (OLM) for clouds, bare metal, LXD or Kubernetes. We will be using it to deploy and manage Charmed OpenSearch. As with LXD, Juju is installed using a snap package:
```shell
sudo snap install juju --classic
```

Juju already has a built-in knowledge of LXD and how it works, so there is no additional setup or configuration needed. A controller will be used to deploy and control Charmed OpenSearch. Run the following command to bootstrap a Juju controller named ‘opensearch-demo’ on LXD. This bootstrapping processes can take several minutes depending on your system resources:
```shell
juju bootstrap localhost opensearch-demo
```

The Juju controller should exist within an LXD container. You can verify this by entering the command `lxc list`; you should see the following:
```
+---------------+---------+-----------------------+------+-----------+-----------+
|     NAME      |  STATE  |         IPV4          | IPV6 |   TYPE    | SNAPSHOTS |
+---------------+---------+-----------------------+------+-----------+-----------+
| juju-<id>     | RUNNING | 10.105.164.235 (eth0) |      | CONTAINER | 0         |
+---------------+---------+-----------------------+------+-----------+-----------+
```
where `<id>` is a unique combination of numbers and letters such as `9d7e4e-0`

The controller can hold multiple models. In each model, we deploy charmed applications. Set up a specific model for this tutorial, named ‘tutorial’:
```shell
juju add-model tutorial
```

You can now view the model you created above by entering the command `juju status` into the command line. You should see the following:
```
Model    Controller         Cloud/Region         Version  SLA          Timestamp
tutorial opensearch-demo    localhost/localhost  2.9.37   unsupported  23:20:53Z

Model "admin/tutorial" is empty.
```

### Setting Kernel Parameters

Before deploying Charmed OpenSearch, we need to set some [kernel parameters](https://www.kernel.org/doc/Documentation/sysctl/vm.txt). These are necessary requirements for OpenSearch to function correctly, and because we're using LXD containers to deploy our charm, and containers share a kernel with their host, we need to set these kernel parameters on the host machine.

First, we need to get the current parameters of the kernel because we will need to reset them after the tutorial (although rebooting your machine will also do the trick). We're only changing three specific parameters, so we're filtering the output for those three parameters:
```shell
sudo sysctl -a | grep -E 'swappiness|max_map_count|tcp_retries2'
```

This command should return something like the following:

```shell
net.ipv4.tcp_retries2 = 15
vm.max_map_count = 262144
vm.swappiness = 60
```

Note these variables so we can reset them later. Not doing so may cause some system instability. Set the kernel parameters to the new recommended values like so:


```shell
sudo sysctl -w vm.max_map_count=262144 vm.swappiness=0 net.ipv4.tcp_retries2=5
```

Please note that these values reset on system reboot, so if you complete this tutorial in multiple stages, you'll need to set these values each time you restart your computer.

---

## Deploy Charmed OpenSearch

To deploy Charmed OpenSearch, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/opensearch?channel=edge) and deploy it to your model:
```shell
juju deploy opensearch --channel=edge
```

Juju will now fetch Charmed OpenSearch and begin deploying it to the LXD cloud. This process can take several minutes depending on your machine. You can track the progress by running:
```shell
juju status --watch=1s
```

This command is useful for checking the status of your Juju Model, including the applications and machines that it hosts. Some of the helpful information it displays include IP addresses, ports, state, etc. The output of this command updates once per second. When the application is ready, `juju status` will show:
```
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

```shell
vm.swappiness should be 0 - net.ipv4.tcp_retries2 should be 5
```

---

## Transport Layer Security (TLS)
[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) is used to encrypt data exchanged between two applications; it secures data transmitted over the network. Typically, enabling TLS within a highly available database, and between a highly available database and client/server applications, requires domain-specific knowledge and a high level of expertise. Fortunately, the domain-specific knowledge has been encoded into Charmed OpenSearch. This means enabling TLS on Charmed Opensearch is easily available and requires minimal effort on your end.

TLS is enabled via relations, by relating Charmed OpenSearch to the [TLS Certificates Charm](https://charmhub.io/tls-certificates-operator). The TLS Certificates Charm centralises TLS certificate management in a consistent manner and handles providing, requesting, and renewing TLS certificates.


### Configure TLS
Before enabling TLS on Charmed OpenSearch we must first deploy the `TLS-certificates-operator` charm:
```shell
juju deploy tls-certificates-operator --channel=beta
```

Wait until the `tls-certificates-operator` is ready to be configured. When it is ready to be configured `juju status --watch 1s`. Will show:
```
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
```shell
juju config tls-certificates-operator generate-self-signed-certificates="true" ca-common-name="Tutorial CA"
```
*Note: this tutorial uses [self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate); self-signed certificates should not be used in a production cluster. To set the correct certificates, see the [TLS operator documentation](https://github.com/canonical/tls-certificates-operator).*

### Enable TLS
After configuring the certificates `juju status` will show the status of `tls-certificates-operator` as active. To enable TLS on Charmed OpenSearch, relate the two applications:
```shell
juju relate tls-certificates-operator opensearch
```

The output of `juju status` should now resemble the following:

```
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

## Connecting to OpenSearch
> **!** *Disclaimer: this part of the tutorial accesses MongoDB via the `admin` user. **Do not** directly interface with the admin user in a production environment. In a production environment [always create a separate user](https://www.mongodb.com/docs/manual/tutorial/create-users/) and connect to MongoDB with that user instead. Later in the section covering Relations we will cover how to access MongoDB without the admin user.*

The first action most users take after installing MongoDB is accessing MongoDB. The easiest way to do this is via the MongoDB shell, with `mongosh`. You can read more about the MongoDB shell [here](https://www.mongodb.com/docs/mongodb-shell/). For this part of the Tutorial we will access MongoDB via  `mongosh`. Fortunately there is no need to install the Mongo shell, as `mongosh` is already installed on the units hosting the Charmed MongoDB application.

### MongoDB URI
Connecting to the database requires a Uniform Resource Identifier (URI), MongoDB expects a [MongoDB specific URI](https://www.mongodb.com/docs/manual/reference/connection-string/). The URI for MongoDB contains information which is used to authenticate us to the database. We use a URI of the format:
```shell
mongodb://<username>:<password>@<hosts>/<database name>?replicaSet=<replica set name>
```

Connecting via the URI requires that you know the values for `username`, `password`, `hosts`, `database name`, and the `replica set name`. We will show you how to retrieve the necessary fields and set them to environment variables.

**Retrieving the username:** In this case, we are using the `admin` user to connect to MongoDB. Use `admin` as the username:
```shell
export DB_USERNAME="admin"
```

**Retrieving the password:** The password can be retrieved by running the `get-password` action on the Charmed MongoDB application:
```shell
juju run-action mongodb/leader get-password --wait
```
Running the command should output:
```yaml
unit-mongodb-0:
  UnitId: mongodb/0
  id: "2"
  results:
    admin-password: <password>
  status: completed
  timing:
    completed: 2022-12-02 11:30:01 +0000 UTC
    enqueued: 2022-12-02 11:29:57 +0000 UTC
    started: 2022-12-02 11:30:01 +0000 UTC
```
Use the password under the result: `admin-password`:
```shell
export DB_PASSWORD=$(juju run-action mongodb/leader get-password --wait | grep admin-password|  awk '{print $2}')
```

**Retrieving the hosts:** The hosts are the units hosting the MongoDB application. The host’s IP address can be found with `juju status`:
```
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  11:31:16Z

App      Version  Status  Scale  Charm    Channel   Rev  Exposed  Message
mongodb           active      1  mongodb  dpe/edge   96  no       Replica set primary

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        <host IP>    27017/tcp  Replica set primary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running

```
Set the variable `HOST_IP` to the IP address for `mongodb/0`:
```shell
export HOST_IP=$(juju run --unit mongodb/0 -- hostname -I | xargs)
```

**Retrieving the database name:** In this case we are connecting to the `admin` database. Use `admin` as the database name. Once we access the database via the MongoDB URI, we will create a `test-db` database to store data.
```shell
export DB_NAME="admin"
```

**Retrieving the replica set name:** The replica set name is the name of the application on Juju hosting MongoDB. The application name in this tutorial is `mongodb`. Use `mongodb` as the replica set name.
```shell
export REPL_SET_NAME="mongodb"
```

### Generate the MongoDB URI
Now that we have the necessary fields to connect to the URI, we can connect to MongoDB with `mongosh` via the URI. We can create the URI with:
```shell
export URI=mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP/$DB_NAME?replicaSet=$REPL_SET_NAME
```
Now view and save the output of the URI:
```shell
echo $URI
```

### Connect via MongoDB URI
As said earlier, `mongosh` is already installed in Charmed MongoDB. To access the unit hosting Charmed MongoDB, ssh into it:
```shell
juju ssh mongodb/0
```
*Note if at any point you'd like to leave the unit hosting Charmed MongoDB, enter* `exit`.

While `ssh`d into `mongodb/0`, we can access `mongosh`, using the URI that we saved in the step [Generate the MongoDB URI](#generate-the-mongodb-uri).
```shell
mongosh <saved URI>
```

You should now see:
```
Current Mongosh Log ID: 6389e2adec352d5447551ae0
Connecting to:    mongodb://<credentials>@10.23.62.156/admin?replicaSet=mongodb&appName=mongosh+1.6.1
Using MongoDB:    5.0.14
Using Mongosh:    1.6.1

For mongosh info see: https://docs.mongodb.com/mongodb-shell/


To help improve our products, anonymous usage data is collected and sent to MongoDB periodically (https://www.mongodb.com/legal/privacy-policy).
You can opt-out by running the disableTelemetry() command.

------
   The server generated these startup warnings when booting
   2022-12-02T11:24:05.416+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
------

------
   Enable MongoDB's free cloud-based monitoring service, which will then receive and display
   metrics about your deployment (disk utilization, CPU, operation statistics, etc).

   The monitoring data will be available on a MongoDB website with a unique URL accessible to you
   and anyone you share the URL with. MongoDB may use this information to make product
   improvements and to suggest MongoDB products and deployment options to you.

   To enable free monitoring, run the following command: db.enableFreeMonitoring()
   To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
------

mongodb [primary] admin>
```

You can now interact with MongoDB directly using any [MongoDB commands](https://www.mongodb.com/docs/manual/reference/command/). For example entering `show dbs` should output something like:
```
admin   172.00 KiB
config  120.00 KiB
local   404.00 KiB
```
Now that we have access to MongoDB we can create a database named `test-db`. To create this database enter:
```shell
use test-db
```
Now lets create a user called `testUser` with read/write access to the database `test-db` that we just created. Enter:
```shell
db.createUser({
  user: "testUser",
  pwd: "password",
  roles: [
    { role: "readWrite", db: "test-db" }
  ]
})
```
You can verify that you added the user correctly by entering the command `show users` into the mongo shell. This will output:
```json
[
  {
    _id: 'test-db.testUser',
    userId: new UUID("6e841e28-b1bc-4719-bf42-ba4b164fc546"),
    user: 'testUser',
    db: 'test-db',
    roles: [ { role: 'readWrite', db: 'test-db' } ],
    mechanisms: [ 'SCRAM-SHA-1', 'SCRAM-SHA-256' ]
  }
]
```
Feel free to test out any other MongoDB commands. When you’re ready to leave the MongoDB shell you can just type `exit`. Once you've typed `exit` you will be back in the host of Charmed MongoDB (`mongodb/0`). Exit this host by once again typing `exit`. Now you will be in your original shell where you first started the tutorial; here you can interact with Juju and LXD.

*Note: if you accidentally exit one more time you will leave your terminal session and all of the environment variables used in the URI will be removed. If this happens redefine these variables as described in the section that describes how to [create the MongoDB URI](#mongodb-uri).*

---

## Scale Charmed OpenSearch
Replication is a popular feature of MongoDB; replicas copy data making a database highly available. This means the application can provide self-healing capabilities in case one MongoDB replica fails.

> **!** *Disclaimer: this tutorial hosts replicas all on the same machine, this should not be done in a production environment. To enable high availability in a production environment, replicas should be hosted on different servers to [maintain isolation](https://canonical.com/blog/database-high-availability).*


### Add replicas
You can add two replicas to your deployed MongoDB application with:
```shell
juju add-unit mongodb -n 2
```

You can now watch the replica set add these replicas with: `juju status --watch 1s`. It usually takes several minutes for the replicas to be added to the replica set. You’ll know that all three replicas are ready when `juju status --watch 1s` reports:
```
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  14:42:04Z

App      Version  Status  Scale  Charm    Channel   Rev  Exposed  Message
mongodb           active      3  mongodb  dpe/edge   96  no       Replica set primary

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        10.23.62.156    27017/tcp  Replica set primary
mongodb/1   active    idle   1        10.23.62.55     27017/tcp  Replica set secondary
mongodb/2   active    idle   2        10.23.62.243    27017/tcp  Replica set secondary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
1        started  10.23.62.55   juju-d35d30-1  focal       Running
2        started  10.23.62.243  juju-d35d30-2  focal       Running
```

You can trust that Charmed MongoDB added these replicas correctly. But if you wanted to verify the replicas got added correctly you could connect to MongoDB via `mongosh`. Since your replica set has 2 additional hosts you will need to update the hosts in your URI. You can retrieve these host IPs with:
```shell
export HOST_IP_1=$(juju run --unit mongodb/1 -- hostname -I | xargs)
export HOST_IP_2=$(juju run --unit mongodb/2 -- hostname -I | xargs)
```

Then recreate the URI using your new hosts and reuse the `username`, `password`, `database name`, and `replica set name` that you previously used when you *first* connected to MongoDB:
```shell
export URI=mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP,$HOST_IP_1,$HOST_IP_2/$DB_NAME?replicaSet=$REPL_SET_NAME
```

Now view and save the output of the URI:
```shell
echo $URI
```

Like earlier we access `mongosh` by `ssh`ing into one of the Charmed MongoDB hosts:
```shell
juju ssh mongodb/0
```

While `ssh`d into `mongodb/0`, we can access `mongosh`, using our new URI that we saved above.
```shell
mongosh <saved URI>
```

Now type `rs.status()` and you should see your replica set configuration. It should look something like this:
```json
{
  set: 'mongodb',
  date: ISODate("2022-12-02T14:39:52.732Z"),
  myState: 1,
  term: Long("1"),
  syncSourceHost: '',
  syncSourceId: -1,
  heartbeatIntervalMillis: Long("2000"),
  majorityVoteCount: 2,
  writeMajorityCount: 2,
  votingMembersCount: 3,
  writableVotingMembersCount: 3,
  optimes: {
    lastCommittedOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    lastCommittedWallTime: ISODate("2022-12-02T14:39:50.020Z"),
    readConcernMajorityOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    appliedOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    durableOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    lastAppliedWallTime: ISODate("2022-12-02T14:39:50.020Z"),
    lastDurableWallTime: ISODate("2022-12-02T14:39:50.020Z")
  },
  lastStableRecoveryTimestamp: Timestamp({ t: 1669991950, i: 1 }),
  electionCandidateMetrics: {
    lastElectionReason: 'electionTimeout',
    lastElectionDate: ISODate("2022-12-02T11:24:09.587Z"),
    electionTerm: Long("1"),
    lastCommittedOpTimeAtElection: { ts: Timestamp({ t: 1669980249, i: 1 }), t: Long("-1") },
    lastSeenOpTimeAtElection: { ts: Timestamp({ t: 1669980249, i: 1 }), t: Long("-1") },
    numVotesNeeded: 1,
    priorityAtElection: 1,
    electionTimeoutMillis: Long("10000"),
    newTermStartDate: ISODate("2022-12-02T11:24:09.630Z"),
    wMajorityWriteAvailabilityDate: ISODate("2022-12-02T11:24:09.651Z")
  },
  members: [
    {
      _id: 0,
      name: '10.23.62.156:27017',
      health: 1,
      state: 1,
      stateStr: 'PRIMARY',
      uptime: 11747,
      optime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
      optimeDate: ISODate("2022-12-02T14:39:50.000Z"),
      lastAppliedWallTime: ISODate("2022-12-02T14:39:50.020Z"),
      lastDurableWallTime: ISODate("2022-12-02T14:39:50.020Z"),
      syncSourceHost: '',
      syncSourceId: -1,
      infoMessage: '',
      electionTime: Timestamp({ t: 1669980249, i: 2 }),
      electionDate: ISODate("2022-12-02T11:24:09.000Z"),
      configVersion: 5,
      configTerm: 1,
      self: true,
      lastHeartbeatMessage: ''
    },
    {
      _id: 1,
      name: '10.23.62.55:27017',
      health: 1,
      state: 2,
      stateStr: 'SECONDARY',
      uptime: 305,
      optime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
      optimeDurable: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
      optimeDate: ISODate("2022-12-02T14:39:50.000Z"),
      optimeDurableDate: ISODate("2022-12-02T14:39:50.000Z"),
      lastAppliedWallTime: ISODate("2022-12-02T14:39:50.020Z"),
      lastDurableWallTime: ISODate("2022-12-02T14:39:50.020Z"),
      lastHeartbeat: ISODate("2022-12-02T14:39:51.868Z"),
      lastHeartbeatRecv: ISODate("2022-12-02T14:39:51.882Z"),
      pingMs: Long("0"),
      lastHeartbeatMessage: '',
      syncSourceHost: '10.23.62.156:27017',
      syncSourceId: 0,
      infoMessage: '',
      configVersion: 5,
      configTerm: 1
    },
    {
      _id: 2,
      name: '10.23.62.243:27017',
      health: 1,
      state: 2,
      stateStr: 'SECONDARY',
      uptime: 300,
      optime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
      optimeDurable: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
      optimeDate: ISODate("2022-12-02T14:39:50.000Z"),
      optimeDurableDate: ISODate("2022-12-02T14:39:50.000Z"),
      lastAppliedWallTime: ISODate("2022-12-02T14:39:50.020Z"),
      lastDurableWallTime: ISODate("2022-12-02T14:39:50.020Z"),
      lastHeartbeat: ISODate("2022-12-02T14:39:51.861Z"),
      lastHeartbeatRecv: ISODate("2022-12-02T14:39:52.372Z"),
      pingMs: Long("0"),
      lastHeartbeatMessage: '',
      syncSourceHost: '10.23.62.55:27017',
      syncSourceId: 1,
      infoMessage: '',
      configVersion: 5,
      configTerm: 1
    }
  ],
  ok: 1,
  '$clusterTime': {
    clusterTime: Timestamp({ t: 1669991990, i: 1 }),
    signature: {
      hash: Binary(Buffer.from("dbe96e73cf659617bb88b6ad11152551c0dd9c8d", "hex"), 0),
      keyId: Long("7172510554420936709")
    }
  },
  operationTime: Timestamp({ t: 1669991990, i: 1 })
}
```

Now exit the MongoDB shell by typing:
```shell
exit
```
Now you should be back in the host of Charmed MongoDB (`mongodb/0`). To exit this host type:
```shell
exit
```
You should now be shell you started in where you can interact with Juju and LXD.

### Remove replicas
Removing a unit from the application, scales the replicas down. Before we scale down the replicas, list all the units with `juju status`, here you will see three units `mongodb/0`, `mongodb/1`, and `mongodb/2`. Each of these units hosts a MongoDB replica. To remove the replica hosted on the unit `mongodb/2` enter:
```shell
juju remove-unit mongodb/2
```

You’ll know that the replica was successfully removed when `juju status --watch 1s` reports:
```
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  14:44:25Z

App      Version  Status  Scale  Charm    Channel   Rev  Exposed  Message
mongodb           active      2  mongodb  dpe/edge   96  no       Replica set primary

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        10.23.62.156    27017/tcp  Replica set primary
mongodb/1   active    idle   1        10.23.62.55     27017/tcp  Replica set secondary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
1        started  10.23.62.55   juju-d35d30-1  focal       Running

```

As previously mentioned you can trust that Charmed MongoDB removed this replica correctly. This can be checked by verifying that the new URI (where the removed host has been excluded) works properly.

---

## Passwords
When we accessed MongoDB earlier in this tutorial, we needed to include a password in the URI. Passwords help to secure our database and are essential for security. Over time it is a good practice to change the password frequently. Here we will go through setting and changing the password for the admin user.

### Retrieve the admin password
As previously mentioned, the admin password can be retrieved by running the `get-password` action on the Charmed MongoDB application:
```shell
juju run-action mongodb/leader get-password --wait
```
Running the command should output:
```yaml
unit-mongodb-0:
  UnitId: mongodb/0
  id: "2"
  results:
    admin-password: <password>
  status: completed
  timing:
    completed: 2022-12-02 11:30:01 +0000 UTC
    enqueued: 2022-12-02 11:29:57 +0000 UTC
    started: 2022-12-02 11:30:01 +0000 UTC
```
The admin password is under the result: `admin-password`.


### Rotate the admin password
You can change the admin password to a new random password by entering:
```shell
juju run-action mongodb/leader set-password --wait
```
Running the command should output:
```yaml
unit-mongodb-0:
  UnitId: mongodb/0
  id: "4"
  results:
    admin-password: <new password>
  status: completed
  timing:
    completed: 2022-12-02 14:53:30 +0000 UTC
    enqueued: 2022-12-02 14:53:25 +0000 UTC
    started: 2022-12-02 14:53:28 +0000 UTC
```
The admin password is under the result: `admin-password`. It should be different from your previous password.

*Note when you change the admin password you will also need to update the admin password the in MongoDB URI; as the old password will no longer be valid.* Update the DB password used in the URI and update the URI:
```shell
export DB_PASSWORD=$(juju run-action mongodb/leader get-password --wait | grep admin-password|  awk '{print $2}')
export URI=mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP/$DB_NAME?replicaSet=$REPL_SET_NAME
```

### Set the admin password
You can change the admin password to a specific password by entering:
```shell
juju run-action mongodb/leader set-password password=<password> --wait
```
Running the command should output:
```yaml
unit-mongodb-0:
  UnitId: mongodb/0
  id: "4"
  results:
    admin-password: <password>
  status: completed
  timing:
    completed: 2022-12-02 14:53:30 +0000 UTC
    enqueued: 2022-12-02 14:53:25 +0000 UTC
    started: 2022-12-02 14:53:28 +0000 UTC
```
The admin password under the result: `admin-password` should match whatever you passed in when you entered the command.

*Note that when you change the admin password you will also need to update the admin password in the MongoDB URI, as the old password will no longer be valid.* To update the DB password used in the URI:
```shell
export DB_PASSWORD=$(juju run-action mongodb/leader get-password --wait | grep admin-password|  awk '{print $2}')
export URI=mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP/$DB_NAME?replicaSet=$REPL_SET_NAME
```

---

## Relations
<!---Juju 3.0 uses integrations; I haven’t been able to find the docs for 2.9 --->
Relations, or what Juju documentation [describes as Integration](https://juju.is/docs/sdk/integration), are the easiest way to create a user for MongoDB in Charmed MongoDB. Relations automatically create a username, password, and database for the desired user/application. As mentioned earlier in the [Access MongoDB section](#access-mongodb) it is a better practice to connect to MongoDB via a specific user rather than the admin user.

### Data Integrator Charm
Before relating to a charmed application, we must first deploy our charmed application. In this tutorial we will relate to the [Data Integrator Charm](https://charmhub.io/data-integrator). This is a bare-bones charm that allows for central management of database users, providing support for different kinds of data platforms (e.g. MongoDB, MySQL, PostgreSQL, Kafka, etc) with a consistent, opinionated and robust user experience. In order to deploy the Data Integrator Charm we can use the command `juju deploy` we have learned above:

```shell
juju deploy data-integrator --channel edge --config database-name=test-database
```
The expected output:
```
Located charm "data-integrator" in charm-hub...
Deploying "data-integrator" from charm-hub charm "data-integrator"...
```

### Relate to MongoDB
Now that the Database Integrator Charm has been set up, we can relate it to MongoDB. This will automatically create a username, password, and database for the Database Integrator Charm. Relate the two applications with:
```shell
juju relate data-integrator mongodb
```
Wait for `juju status --watch 1s` to show:
```
ubuntu@ip-172-31-11-104:~/data-integrator$ juju status
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  10:32:09Z

App                  Version  Status  Scale  Charm                Channel   Rev  Exposed  Message
data-integrator               active      1  data-integrator      edge       3   no
mongodb                       active      2  mongodb              dpe/edge   96  no

Unit                    Workload  Agent  Machine  Public address  Ports      Message
data-integrator/0*  active    idle   5        10.23.62.216               received mongodb credentials
mongodb/0*              active    idle   0        10.23.62.156    27017/tcp
mongodb/1               active    idle   1        10.23.62.55     27017/tcp  Replica set primary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
1        started  10.23.62.55   juju-d35d30-1  focal       Running
5        started  10.23.62.216  juju-d35d30-5  jammy       Running
```
To retrieve information such as the username, password, and database. Enter:
```shell
juju run-action data-integrator/leader get-credentials --wait
```
This should output something like:
```yaml
​​unit-data-integrator-0:
  UnitId: data-integrator/0
  id: "24"
  results:
    mongodb:
      database: test-database
      endpoints: 10.23.62.55,10.23.62.156
      password: VMnRws6BlojzDi5e1m2GVWOgJaoSs44d
      replset: mongodb
      uris: mongodb://relation-4:VMnRws6BlojzDi5e1m2GVWOgJaoSs44d@10.23.62.55,10.23.62.156/test-database?replicaSet=mongodb&authSource=admin
      username: relation-4
    ok: "True"
  status: completed
  timing:
    completed: 2022-12-06 10:33:24 +0000 UTC
    enqueued: 2022-12-06 10:33:20 +0000 UTC
    started: 2022-12-06 10:33:24 +0000 UTC
```
Save the value listed under `uris:` *(Note: your hostnames, usernames, and passwords will likely be different.)*

### Access the related database
Notice that in the previous step when you typed `juju run-action data-integrator/leader get-credentials --wait` the command not only outputted the username, password, and database, but also outputted the URI. This means you do not have to generate the URI yourself. To connect to this URI first ssh into `mongodb/0`:
```shell
juju ssh mongodb/0
```
Then access `mongosh` with the URI that you copied above:

```shell
mongosh "<uri copied from juju run-action data-integrator/leader get-credentials --wait>"
```
*Note: be sure you wrap the URI in `"` with no trailing whitespace*.

You will now be in the mongo shell as the user created for this relation. When you relate two applications Charmed MongoDB automatically sets up a user and database for you. Enter `db.getName()` into the MongoDB shell, this will output:
```shell
test-database
```
This is the name of the database we specified when we first deployed the `data-integrator` charm. To create a collection in the "test-database" and then show the collection enter:
```shell
db.createCollection("test-collection")
show collections
```
Now insert a document into this database:
```shell
db.test_collection.insertOne(
  {
    First_Name: "Jammy",
    Last_Name: "Jellyfish",
  })
```
You can verify this document was inserted by running:
```shell
db.test_collection.find()
```

Now exit the MongoDB shell by typing:
```shell
exit
```
Now you should be back in the host of Charmed MongoDB (`mongodb/0`). To exit this host type:
```shell
exit
```
You should now be shell you started in where you can interact with Juju and LXD.

### Remove the user
To remove the user, remove the relation. Removing the relation automatically removes the user that was created when the relation was created. Enter the following to remove the relation:
```shell
juju remove-relation mongodb data-integrator
```

Now try again to connect to the same URI you just used in [Access the related database](#access-the-related-database):
```shell
juju ssh mongodb/0
mongosh "<uri copied from juju run-action data-integrator/leader get-credentials --wait>"
```
*Note: be sure you wrap the URI in `"` with no trailing whitespace*.

This will output an error message:
```
Current Mongosh Log ID: 638f5ffbdbd9ec94c2e58456
Connecting to:    mongodb://<credentials>@10.23.62.38,10.23.62.219/mongodb?replicaSet=mongodb&authSource=admin&appName=mongosh+1.6.1
MongoServerError: Authentication failed.
```
As this user no longer exists. This is expected as `juju remove-relation mongodb data-integrator` also removes the user.

Now exit the MongoDB shell by typing:
```shell
exit
```
Now you should be back in the host of Charmed MongoDB (`mongodb/0`). To exit this host type:
```shell
exit
```
You should now be shell you started in where you can interact with Juju and LXD.

If you wanted to recreate this user all you would need to do is relate the the two applications again:
```shell
juju relate data-integrator mongodb
```
Re-relating generates a new password for this user, and therefore a new URI you can see the new URI with:
```shell
juju run-action data-integrator/leader get-credentials --wait
```
Save the result listed with `uris:`.

You can connect to the database with this new URI:
```shell
juju ssh mongodb/0
mongosh "<uri copied from juju run-action data-integrator/leader get-credentials --wait>"
```
*Note: be sure you wrap the URI in `"` with no trailing whitespace*.

From there if you enter `db.test_collection.find()` you will see all of your original documents are still present in the database.

---

## Next Steps
In this tutorial we've successfully deployed MongoDB, added/removed replicas, added/removed users to/from the database, and even enabled and disabled TLS. You may now keep your Charmed MongoDB deployment running and write to the database or remove it entirely using the steps in [Remove Charmed MongoDB and Juju](#remove-charmed-mongodb-and-juju). If you're looking for what to do next you can:
- Run [Charmed MongoDB on Kubernetes](https://github.com/canonical/mongodb-k8s-operator).
- Check out our Charmed offerings of [PostgreSQL](https://charmhub.io/postgresql?channel=edge) and [Kafka](https://charmhub.io/kafka?channel=edge).
- Read about [High Availability Best Practices](https://canonical.com/blog/database-high-availability)
- [Report](https://github.com/canonical/mongodb-operator/issues) any problems you encountered.
- [Give us your feedback](https://chat.charmhub.io/charmhub/channels/data-platform).
- [Contribute to the code base](https://github.com/canonical/mongodb-operator)

### Remove Charmed MongoDB and Juju
If you're done using Charmed MongoDB and Juju and would like to free up resources on your machine, you can remove Charmed MongoDB and Juju. *Warning: when you remove Charmed MongoDB as shown below you will lose all the data in MongoDB. Further, when you remove Juju as shown below you will lose access to any other applications you have hosted on Juju.*

To remove Charmed MongoDB and the model it is hosted on run the command:
```shell
juju destroy-model tutorial --destroy-storage --force
```

Next step is to remove the Juju controller. You can see all of the available controllers by entering `juju controllers`. To remove the controller enter:
```shell
juju destroy-controller opensearch-demo
```

Finally to remove Juju altogether, enter:
```shell
sudo snap remove juju --purge
```

### License:
The Charmed MongoDB Operator is distributed under the Apache Software License, version 2.0. It [installs/operates/depends on] [MongoDB Community Edition](https://github.com/mongodb/mongo), which is licensed under the Server Side Public License (SSPL).

### Trademark Notice
MongoDB' is a trademark or registered trademark of MongoDB Inc. Other trademarks are property of their respective owners.
