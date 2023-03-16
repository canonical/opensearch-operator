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