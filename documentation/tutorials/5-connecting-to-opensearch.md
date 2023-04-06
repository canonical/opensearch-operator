## Relations
<!---Juju 3.0 uses integrations; I haven’t been able to find the docs for 2.9 --->
Relations, or what Juju documentation [describes as Integrations](https://juju.is/docs/sdk/integration), are the easiest way to connect to Charmed OpenSearch. Relations automatically create a username, password, and database for the desired user/application, as well as defining access permissions.

### Data Integrator Charm
The best way to create a user and password for manual use (i.e. connecting to opensearch directly using `curl`, which is what we'll be doing later) is to add a relation between Charmed Opensearch and the [Data Integrator Charm](https://charmhub.io/data-integrator). This is a bare-bones charm that allows for central management of database users, providing support for different kinds of data platform products (e.g. MongoDB, MySQL, PostgreSQL, Kafka, etc) with a consistent, opinionated and robust user experience. In order to deploy the Data Integrator Charm we can use the command `juju deploy` as follows:

```bash
juju deploy data-integrator --channel=edge --config index-name=test-index --config extra-user-roles=admin
```

The expected output:

```bash
Located charm "data-integrator" in charm-hub...
Deploying "data-integrator" from charm-hub charm "data-integrator"...
```

Wait for `watch -c juju status --color` to show:

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:38:21Z

App                        Version  Status   Scale  Charm                      Channel  Rev  Exposed  Message
data-integrator                     blocked      1  data-integrator            edge      11  no       Please relate the data-integrator with the desired product
opensearch                          active       1  opensearch                 edge      22  no
tls-certificates-operator           active       1  tls-certificates-operator  stable    22  no

Unit                          Workload  Agent  Machine  Public address  Ports  Message
data-integrator/0*            blocked   idle   2        10.180.162.96          Please relate the data-integrator with the desired product
opensearch/0*                 active    idle   0        10.180.162.97
tls-certificates-operator/0*  active    idle   1        10.180.162.44

Machine  State    Address        Inst id        Series  AZ  Message
0        started  10.180.162.97  juju-3305a8-0  jammy       Running
1        started  10.180.162.44  juju-3305a8-1  jammy       Running
2        started  10.180.162.96  juju-3305a8-2  jammy       Running

```

### Relate to OpenSearch

Now that the Database Integrator Charm has been set up, we can relate it to Charmed OpenSearch. This will automatically create a username, password, and CA certificate for the Database Integrator Charm. Relate the two applications with:

```bash
juju relate data-integrator opensearch
```

Wait for `watch -c juju status --color` to show:

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:40:22Z

App                        Version  Status  Scale  Charm                      Channel  Rev  Exposed  Message
data-integrator                     active      1  data-integrator            edge      11  no
opensearch                          active      1  opensearch                 edge      22  no
tls-certificates-operator           active      1  tls-certificates-operator  stable    22  no

Unit                          Workload  Agent  Machine  Public address  Ports  Message
data-integrator/0*            active    idle   2        10.180.162.96
opensearch/0*                 active    idle   0        10.180.162.97
tls-certificates-operator/0*  active    idle   1        10.180.162.44

Machine  State    Address        Inst id        Series  AZ  Message
0        started  10.180.162.97  juju-3305a8-0  jammy       Running
1        started  10.180.162.44  juju-3305a8-1  jammy       Running
2        started  10.180.162.96  juju-3305a8-2  jammy       Running

Relation provider                       Requirer                               Interface                 Type     Message
data-integrator:data-integrator-peers   data-integrator:data-integrator-peers  data-integrator-peers     peer
opensearch:opensearch-client            data-integrator:opensearch             opensearch_client         regular
opensearch:opensearch-peers             opensearch:opensearch-peers            opensearch_peers          peer
opensearch:service                      opensearch:service                     rolling_op                peer
tls-certificates-operator:certificates  opensearch:certificates                tls-certificates          regular
tls-certificates-operator:replicas      tls-certificates-operator:replicas     tls-certificates-replica  peer
```

To retrieve information such as the username, password, and database. Enter:

```bash
juju run-action data-integrator/leader get-credentials --wait
```

This should output something like:

```yaml
unit-data-integrator-0:
  UnitId: data-integrator/0
  id: "2"
  results:
    ok: "True"
    opensearch:
      endpoints: 10.180.162.97:9200
      index: test-index
      password: wPe02Gl7OiJPBTKh21DKvC0X9bzb9ZjQ
      tls-ca: |-
        -----BEGIN CERTIFICATE-----
        MIIC6jCCAdKgAwIBAgIULtS8XNzJj5N8...
        -----END CERTIFICATE-----
      username: opensearch-client_5
      version: 2.6.0
  status: completed
  timing:
    completed: 2023-04-05 15:41:11 +0000 UTC
    enqueued: 2023-04-05 15:41:09 +0000 UTC
    started: 2023-04-05 15:41:10 +0000 UTC
```

Save the CA certificate (value of `tls-ca` in the previous response), username, and password, because you'll need them in the next section.

### Create and Access OpenSearch Indices

Before connecting to OpenSearch, it is mandatory that you [enable TLS on this cluster](./4-enable-tls.md), following the previous step in the tutorial.

You can access the opensearch REST API any way you prefer, but in this tutorial we're going to use `curl`. Get the IP of an opensearch node from the output of `juju status` (any of the nodes should work fine), and store the CA certificate in a local file. Run the following command, swapping the values where necessary:

```bash
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/
```

Sending a `GET` request to this `/` endpoint should return some basic information about your opensearch deployment, which should look something like this:

```json
{
  "name" : "opensearch-0",
  "cluster_name" : "opensearch-tutorial",
  "cluster_uuid" : "4Oe44nUzQOavu71_ifHn0w",
  "version" : {
    "distribution" : "opensearch",
    "number" : "2.6.0",
    "build_type" : "tar",
    "build_hash" : "7203a5af21a8a009aece1474446b437a3c674db6",
    "build_date" : "2023-02-24T18:57:04.388618985Z",
    "build_snapshot" : false,
    "lucene_version" : "9.5.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
```

If this command fails, ensure the opensearch units are all in an active-idle state.

The command we just ran used the `--cacert` flag to pass in the CA chain generated by the TLS operator, ensuring secure and encrypted HTTP communications between our local host and the opensearch node.
To recap, the CA chain is generated by the TLS operator, and is passed over to the opensearch charm, which provides this cert in its databag to any application that relates to it using the `opensearch-client` relation interface. When developing charms that relate to the opensearch operator, ensure you use this cert along the user credentials (username/password pair) to authenticate communications.

To index some data, run the following command:

```bash
curl --cacert demo-ca.pem \
  -XPOST https://username:password@opensearch_node_ip:9200/albums/_doc/1?refresh=true \
  -d '{"artist": "Vulfpeck", "genre": ["Funk", "Jazz"], "title": "Thrill of the Arts"}' \
  -H 'Content-Type: application/json' -H 'Accept: application/json'
```

This command uses the same certificate and user credentials to send a `POST` request to the same node as before, but it sends a specific JSON payload to a specific document address. The output should look like the following:

```json
{
  "_index": "albums",
  "_id": "1",
  "_version": 1,
  "result": "created",
  "forced_refresh": true,
  "_shards": {
    "total": 2,
    "successful": 1,
    "failed": 0
  },
  "_seq_no": 0,
  "_primary_term": 1
}
```

Note from the response that our request was successful and the document indexed.

Use the following command to retrieve the previous document:

```bash
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/albums/_doc/1
```

This call should output something like the following:

```json
{
  "_index":"albums",
  "_id":"1",
  "_version":1,
  "_seq_no":0,
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

We should receive a rather long response. What is of interest to us is the portion of this response that indicates whether an error occurred or not, shown below:
```
{
  "took": 16,
  "errors": false,
  "items": [ ... ]
}
```

Then, to send this data to the bulk endpoint, run the following command:

```bash
curl --cacert demo-ca.pem -XPOST https://username:password@opensearch_node_ip:9200/_bulk --data-binary @bulk-albums.json  -H 'Content-Type: application/json'
```

To view the previously indexed documents, we can run a search query for the `Jazz` keyword in our `albums` index, using the following command:

```bash
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/albums/_search?q=Jazz
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

In order to remove the user used in the previous calls, remove the relation. Removing the relation automatically removes the user that was created when the relation was created. Run the following to remove the relation:

```bash
juju remove-relation opensearch data-integrator
```

Now try again to connect in the same way as the previous section

```bash
# TODO test this with data-integrator output
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/
```

This should output something like the following error:

```bash
Unauthorized
```

If you wanted to recreate this user all you would need to do is relate the two applications and run the same action on data-integrator to get the new credentials:

```bash
juju relate data-integrator opensearch
juju run-action data-integrator/leader get-credentials --wait
```

You can now connect to the database with this new username and password:

```bash
curl --cacert demo-ca.pem -XGET https://new_username:new_password@opensearch_node_ip:9200/albums/_search?q=Jazz
```

Note that the data in our index has not changed.

Also, note that the certificate does not change across relations. To create a new certificate, remove the relation between opensearch and the tls-certificates operator, wait for opensearch to enter a blocked status, then recreate the relation. Run the `get-credentials` action on the data-integrator charm again to get the new credentials, and test them again with the above search request.

---

## Next Steps

The next stage in this tutorial is about horizontally scaling the OpenSearch cluster, and can be found [here](./6-horizontal-scaling.md).
