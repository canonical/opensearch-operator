---
myst:
  html_meta:
    description: "Enable JSON Web Token (JWT) authentication in Charmed OpenSearch using the JWT integrator charm for secure token-based access."
---

(how-to-guides-enable-jwt-authentication)=
# How to enable JWT authentication

This guide shows how to enable JSON Web Token (JWT) authentication for Charmed OpenSearch
using the JWT integrator charm.

## Prerequisites

* A running Charmed OpenSearch deployment (revision 275+ on 22.04, or 276+ on 24.04)
* A valid JWT for testing, issued by your JWT provider
* The signing key used to sign the JWT

## Deploy and configure the JWT integrator

Deploy the charm:

```shell
juju deploy jwt-integrator --channel 1/edge
```

The charm will be `blocked` until configured.

Create a Juju secret with your signing key:

```shell
juju add-secret jwt-key signing-key="<signing-key>"
```

Note the secret URI, then grant access and configure:

```shell
juju grant-secret jwt-key jwt-integrator
juju config jwt-integrator signing-key=<secret-uri>
```

The `roles-key` option is **required** — the charm remains `blocked` until it is set.
It specifies the JWT claim key from which OpenSearch extracts the user's roles:

```shell
juju config jwt-integrator roles-key=<roles-key>
```

Configure additional options for your JWT provider:

```shell
juju config jwt-integrator subject-key=<subject-key> jwt-url-parameter=<parameter>
```

## Integrate with OpenSearch

```shell
juju integrate jwt-integrator opensearch
```

After integration, OpenSearch updates its security plugin. Query with your JWT:

```shell
curl -k -H "Authorization: Bearer <jwt>" -XGET "https://<unit-ip>:9200/_cat/nodes"
```

## Large deployments

In large deployments, integrate the JWT integrator with the **main orchestrator** application.

Identify it from `juju status` integrations:

```text
Integration provider                           Requirer                                Interface           Type     Message
opensearch-main:peer-cluster-orchestrator      opensearch-data:peer-cluster            peer_cluster        regular  
```

Integrate:

```shell
juju integrate jwt-integrator opensearch-main
```

If integrated with the wrong application, the charm shows `blocked`.
Remove the invalid relation and integrate with the main orchestrator.

## Use with OpenSearch Dashboards

To enable JWT authentication in OpenSearch Dashboards:

```shell
juju config jwt-integrator jwt-url-parameter=jwt
juju integrate jwt-integrator opensearch-dashboards
```

Access the UI by appending the JWT as a URL parameter:

```text
http://<dashboards-ip>:5601?jwt=<jwt>
```

## Expected result

After integrating the JWT integrator with OpenSearch, `juju status` shows both applications
`active`. Requests to OpenSearch with a valid JWT bearer token return `200 OK`:

```shell
curl -k -H "Authorization: Bearer <jwt>" -XGET "https://<unit-ip>:9200/_cat/nodes"
```

## Next steps

* [Access OpenSearch using OAuth](how-to-access-using-oauth) — an alternative token-based authentication method.
* [Security explanation](explanation-security-index) — background on authentication and TLS.
