(how-to-guides-enable-jwt-authentication)=
# How to enable JWT Authentication

This document shows how to enable authentication with JSON Web Tokens (JWT) in OpenSearch.

## Prerequisites

* A running deployment of Opensearch on VM with minimum charm revision 275 (22.04) or 276 (24.04)
* A valid JSON Web Token for testing, issued by the JWT provider of your choice
* The signing-key with which the JWT was signed

The generation of JWT's is not part of the scope of this document.

## Deploy and configure JWT integrator

The configuration for JWT authentication is provided to OpenSearch via the JWT integrator charm.

Deploy the charm:

```shell
juju deploy jwt-integrator --channel 1/edge
```

After the deployment has settled,
the charm will be in blocked status because of missing configuration.
You can check this with `juju status`:

```shell
opensearch  dev-controller  localhost/localhost  3.6.8    unsupported  12:02:14Z

App                       Version  Status   Scale  Charm                     Channel   Rev  Exposed  Message
jwt-integrator                     blocked      1  jwt-integrator            1/edge      1  no       Missing 'signing-key' or 'roles-key' con... Run `status-detail`: 0 action required; 1 additional statuses.
opensearch                         active       3  opensearch                2/edge    276  no       
self-signed-certificates           active       1  self-signed-certificates  1/stable  317  no       

Unit                         Workload  Agent  Machine  Public address  Ports     Message
jwt-integrator/0*            blocked   idle   3        10.65.50.163              Missing 'signing-key' or 'roles-key' con... Run `status-detail`: 0 action required; 1 additional statuses.
opensearch/0*                active    idle   0        10.65.50.55     9200/tcp  
opensearch/1                 active    idle   1        10.65.50.63     9200/tcp  
opensearch/2                 active    idle   2        10.65.50.37     9200/tcp  
self-signed-certificates/0*  active    idle   4        10.65.50.79               
```

Now, configure the JWT parameters to JWT integrator.
First, create a secret containing the signing-key:

```shell
juju add-secret jwt-key signing-key="<your-signing-key>"
```

Take a note of the secret URI for later.

Now grant permissions for the secret to JWT integrator:

```shell
juju grant-secret jwt-key jwt-integrator
```

The next step is to provide the secret URI as configuration option:

```shell
juju config jwt-integrator signing-key=<your-secret-URI>
```

Configure all other configuration options, according to your JWT provider:

```shell
juju config jwt-integrator roles-key=role subject-key=user jwt-url-parameter=jwt ...
```

## Enable JWT in OpenSearch

Now it's time to enable JWT authentication in OpenSearch.
This is done by integrating the JWT integrator with OpenSearch:

```shell
juju integrate jwt-integrator opensearch
```

After a few moments, OpenSearch has applied the provided configuration
and updated its security plugin. Now you can query Opensearch with your JWT:

```shell
curl --header "Authorization: Bearer <your-jwt-here>" -XGET "https://<ip-address>:9200/_cat/nodes" -k
```

## Large Deployments

If you have an OpenSearch large deployments cluster, it is required to integrate
the JWT integrator with the main-orchestrator of your large deployment.

Check which of your deployed OpenSearch applications is the main-orchestrator
by checking the `integrations` section of `juju status`:

```shell
Integration provider                           Requirer                                Interface           Type     Message
opensearch-main:peer-cluster-orchestrator      opensearch-data:peer-cluster            peer_cluster        regular  
```

Now integrate the JWT integrator with this application:

```shell
juju integrate jwt-integrator opensearch-main
```

If the wrong application of your large deployments is integrated with the JWT integrator,
you will see a `blocked` status:

```shell
App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
jwt-integrator                     active       1  jwt-integrator            1/edge           1  no       
opensearch-data                    blocked      3  opensearch                                 3  no       JWT relation must be created with Main-cluster-orchestrator
opensearch-failover                active       1  opensearch                                 1  no       
opensearch-main                    active       1  opensearch                                 2  no       
self-signed-certificates           active       1  self-signed-certificates  latest/stable  264  no       
```

## Enabling JWT authentication with OpenSearch Dashboards

To use JWT authentication in the OpenSearch Dashboards UI, all you need to do
is integrate the JWT integrator with Opensearch Dashboards:

```shell
juju integrate jwt-integrator opensearch-dashboards
```

Make sure you have configured the configuration option `jwt-url-parameter` to the JWT integrator:

```shell
juju config jwt-integrator jwt-url-parameter="jwt"
```

After a few moments, you can access it by adding your JWT as a URL parameter in the Browser like this:

```shell
http://<ip-address>:5601?jwt=<your-jwt>
```
