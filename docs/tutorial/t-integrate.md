> [Charmed OpenSearch Tutorial](/t/9722) >  4. Integrate with a client application

# Integrate with a client application

[Integrations](https://juju.is/docs/sdk/integration) (also known as "relations") are the easiest way to connect to Charmed OpenSearch. Integrations automatically create a username, password, and database for the desired user/application, and define access permissions.

## Summary
- [Deploy the Data Integrator charm](#heading--deploy-data-integrator)
- [Integrate with OpenSearch](#heading--integrate-opensearch)
- [Create and access OpenSearch indices](#heading--indices)
---
<a href="#heading--deploy-data-integrator"><h2 id="heading--deploy-data-integrator"> Deploy the Data Integrator charm </h2></a>
The best way to create a user and password for manual use (i.e. connecting to OpenSearch directly using `curl`, which is what we'll be doing later) is to add a relation between Charmed OpenSearch and the [Data Integrator Charm](https://charmhub.io/data-integrator). 

Data Integrator is a bare-bones charm that allows for central management of database users, providing support for different kinds of data platform products (e.g. MongoDB, MySQL, PostgreSQL, Kafka, etc) with a consistent and robust user experience. 

Deploy Data Integrator as follows:

```shell
juju deploy data-integrator --channel=edge --config index-name=test-index --config extra-user-roles=admin
```

The expected output:

```shell
Located charm "data-integrator" in charm-hub...
Deploying "data-integrator" from charm-hub charm "data-integrator"...
```

Wait for `watch -c juju status --color` to show:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.4.4    unsupported  17:06:27+02:00

App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
data-integrator                    blocked      1  data-integrator           latest/edge     36  no       Please relate the data-integrator with the desired product
opensearch                         active       1  opensearch                2/edge         117  no       
self-signed-certificates           active       1  self-signed-certificates  latest/stable  155  no       

Unit                         Workload  Agent  Machine  Public address  Ports     Message
data-integrator/0*           blocked   idle   2        10.121.127.224            Please relate the data-integrator with the desired product
opensearch/0*                active    idle   0        10.121.127.140  9200/tcp  
self-signed-certificates/0*  active    idle   1        10.121.127.164            

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.121.127.140  juju-454312-0  ubuntu@22.04      Running
1        started  10.121.127.164  juju-454312-1  ubuntu@22.04      Running
2        started  10.121.127.224  juju-454312-2  ubuntu@22.04      Running
```
<a href="#heading--integrate-opensearch"><h2 id="heading--integrate-opensearch">  Integrate with OpenSearch </h2></a>
Now that the Database Integrator charm has been set up, we can relate it to Charmed OpenSearch. This will automatically create a username, password, and CA certificate for the Database Integrator charm. 

Integrate the two applications with:

```shell
juju integrate data-integrator opensearch
```

Wait for `watch -c juju status --color --relations` to show:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.4.4    unsupported  17:13:12+02:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
data-integrator                    active      1  data-integrator           latest/edge     36  no       
opensearch                         active      1  opensearch                2/edge         117  no       
self-signed-certificates           active      1  self-signed-certificates  latest/stable  155  no       

Unit                         Workload  Agent  Machine  Public address  Ports     Message
data-integrator/0*           active    idle   2        10.121.127.224            
opensearch/0*                active    idle   0        10.121.127.140  9200/tcp  
self-signed-certificates/0*  active    idle   1        10.121.127.164            

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.121.127.140  juju-454312-0  ubuntu@22.04      Running
1        started  10.121.127.164  juju-454312-1  ubuntu@22.04      Running
2        started  10.121.127.224  juju-454312-2  ubuntu@22.04      Running

Integration provider                   Requirer                               Interface              Type     Message
data-integrator:data-integrator-peers  data-integrator:data-integrator-peers  data-integrator-peers  peer     
opensearch:node-lock-fallback          opensearch:node-lock-fallback          node_lock_fallback     peer     
opensearch:opensearch-client           data-integrator:opensearch             opensearch_client      regular  
opensearch:opensearch-peers            opensearch:opensearch-peers            opensearch_peers       peer     
opensearch:upgrade-version-a           opensearch:upgrade-version-a           upgrade                peer     
self-signed-certificates:certificates  opensearch:certificates                tls-certificates       regular  
```

To retrieve information such as the username, password, and database. Enter:

```shell
juju run data-integrator/leader get-credentials
```

This should output something like:

```yaml
Running operation 5 with 1 task
  - task 6 on unit-data-integrator-1

Waiting for task 6...
ok: "True"
opensearch:
  data: '{"extra-user-roles": "admin", "index": "test-index", "requested-secrets":
    "[\"username\", \"password\", \"tls\", \"tls-ca\", \"uris\"]"}'
  endpoints: 10.121.127.126:9200,10.121.127.140:9200
  index: test-index
  password: IMmfxWbPOQbi792E73b0ihFFDXovCmRy
  tls-ca: |-
    -----BEGIN CERTIFICATE-----
    MIIDPzCCAiegAwIBAgI...
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIIDOzCCAiOgAwIBA...
    -----END CERTIFICATE-----
  username: opensearch-client_7
  version: 2.14.0
```

Save the CA certificate (value of `tls-ca` in the previous response), username, and password, because you'll need them in the next section.

<a href="#heading--indices"><h2 id="heading--indices"> Create and access OpenSearch indices</h2></a>

Before connecting to OpenSearch, it is mandatory that you [enable TLS on this cluster](./4-enable-tls.md), following the previous step in the tutorial.

You can access the opensearch REST API any way you prefer, but in this tutorial we're going to use `curl`. Get the IP of an opensearch node from the output of `juju status` (any of the nodes should work fine), and store the CA certificate in a local file. Run the following command, swapping the values where necessary:

```shell
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

```shell
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

```shell
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

```shell
curl --cacert demo-ca.pem -XPOST https://username:password@opensearch_node_ip:9200/_bulk --data-binary @bulk-albums.json  -H 'Content-Type: application/json'
```

To view the previously indexed documents, we can run a search query for the `Jazz` keyword in our `albums` index, using the following command:

```shell
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

## Remove the user

In order to remove the user used in the previous calls, remove the relation. Removing the relation automatically removes the user that was created when the relation was created. Run the following to remove the relation:

```shell
juju remove-relation opensearch data-integrator
```

Now try again to connect in the same way as the previous section

```shell
curl --cacert demo-ca.pem -XGET https://username:password@opensearch_node_ip:9200/
```

This should output something like the following error:

```shell
Unauthorized
```

If you wanted to recreate this user all you would need to do is relate the two applications and run the same action on data-integrator to get the new credentials:

```shell
juju integrate data-integrator opensearch
juju run-action data-integrator/leader get-credentials --wait
```

You can now connect to the database with this new username and password:

```shell
curl --cacert demo-ca.pem -XGET https://new_username:new_password@opensearch_node_ip:9200/albums/_search?q=Jazz
```

Note that the data in our index has not changed.

Also, note that the certificate does not change across relations. To create a new certificate, remove the relation between opensearch and the tls-certificates operator, wait for opensearch to enter a blocked status, then recreate the relation. Run the `get-credentials` action on the data-integrator charm again to get the new credentials, and test them again with the above search request.


>**Next step**: [5. Manage passwords](/t/9728)