---
myst:
  html_meta:
    description: "Secure Charmed OpenSearch with OAuth authentication using Canonical Identity Platform (Hydra) and query with OAuth tokens."
---

(how-to-access-using-oauth)=
# How to access OpenSearch using OAuth

This guide shows how to authenticate OpenSearch requests with OAuth tokens
issued by the Canonical Identity Platform (Hydra).

## Prerequisites

* A working LXD cloud with Juju bootstrapped
* MicroK8s installed locally (for the Identity Platform)
* Network access between the host and LXD containers
* Minimum 4 CPUs, 16 GB RAM

## Deploy OpenSearch on LXD

Deploy OpenSearch and the `data-integrator` charm in a new model:

```shell
juju add-model opensearch-model localhost/localhost
juju deploy opensearch -n 3 --channel 2/edge
juju deploy data-integrator --channel=stable \
  --config index-name=admin-index \
  --config extra-user-roles=admin
```

Wait until all units become active:

```shell
juju status --watch 5s
```

## Deploy the Identity Platform on MicroK8s

The Identity Platform runs on Kubernetes. The steps below use MicroK8s, but any
Juju-supported K8s cluster will work.

### Prepare MicroK8s

Install MicroK8s and enable the required addons:

```shell
sudo snap install microk8s --classic
sudo microk8s enable hostpath-storage dns
sudo microk8s enable metallb:10.0.0.2-10.0.0.5
```

```{note}
The MetalLB address range must provide at least two IP addresses
(one for `traefik-public` and one for `traefik-admin`).
If you are also running COS Lite or other LoadBalancer services on the
same MicroK8s instance, increase the range accordingly.
```

Add MicroK8s to your Juju controller:

```shell
sudo microk8s config > microk8s-cluster.yaml
export KUBECONFIG="$PWD/microk8s-cluster.yaml"
juju add-k8s microk8s-cluster -c <controller-name>
```

### Deploy Identity Platform

Create a model on the MicroK8s cloud and deploy the Identity Platform bundle:

```shell
juju add-model -c <controller-name> oauth microk8s-cluster/localhost
juju deploy identity-platform --channel edge --trust true
```

Wait until all units become active. The `kratos-external-idp-integrator` will remain
`blocked` — this is expected and does not affect OAuth functionality.

## Create cross-model integrations

The Identity Platform and OpenSearch run in separate models (and potentially on
different clouds). Use Juju cross-model offers to connect them.

### Offer certificates and OAuth from the Identity Platform model

Switch to the Identity Platform model and offer the certificates and OAuth endpoints:

```shell
juju switch oauth
juju offer self-signed-certificates:certificates
juju offer hydra:oauth
```

### Consume and integrate in the OpenSearch model

Switch to the OpenSearch model, consume the offers, and integrate them with OpenSearch:

```shell
juju switch opensearch-model
juju consume admin/oauth.self-signed-certificates
juju consume admin/oauth.hydra
juju integrate opensearch admin/oauth.self-signed-certificates
juju integrate opensearch admin/oauth.hydra
```

## Create an OAuth client and obtain a token

With the Identity Platform running, create an OAuth client in Hydra and use it
to request an access token.

### Create a client in Hydra

Create an OAuth client:

```shell
juju switch oauth
juju run hydra/leader create-oauth-client \
  grant-types='["client_credentials"]' \
  audience='["opensearch"]' \
  scope='["openid","profile","email","phone","offline"]'
```

Record the `client-id` and `client-secret` from the output.

### Get the Hydra public URL

Retrieve the proxied endpoints from Traefik:

```shell
juju run traefik-public/0 show-proxied-endpoints
```

Note the `hydra.url` value (e.g. `https://10.0.0.3/oauth-hydra`).

Set environment variables:

```shell
export OAUTH_CLIENT_ID=<client-id>
export OAUTH_CLIENT_SECRET=<client-secret>
export HYDRA_URL=<hydra-url>
```

### Fetch an access token

Request an access token from Hydra using the client credentials:

```shell
curl -k -u "${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}" \
  -X POST "${HYDRA_URL}/oauth2/token" \
  -d "scope=openid" \
  -d "grant_type=client_credentials" \
  -d "audience=opensearch"
```

Export the token from the JSON response:

```shell
export OAUTH_ACCESS_TOKEN=<access-token>
```

### Test the token (before role mapping)

Switch to the OpenSearch model and query the cluster with the token:

```shell
juju switch opensearch-model
export OPENSEARCH_ADDRESS="$(juju status | grep opensearch/0 | awk -F' ' '{print $5}')"

curl -k -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
```

Expect a `403 security_exception` — the client has no mapped roles yet.

### Get a username from the Data Integrator

Retrieve credentials from the `data-integrator` charm:

```shell
juju run data-integrator/0 get-credentials
```

Note the `username` field (e.g. `opensearch-client_4`):

```shell
export DATA_INTEGRATOR_USER=<username>
```

## Configure role mapping

Map the OAuth client ID to the Data Integrator user:

```shell
juju config opensearch roles_mapping="{\"$OAUTH_CLIENT_ID\":\"$DATA_INTEGRATOR_USER\"}"
```

Wait for the charm to apply the change:

```shell
juju status --watch 5s
```

### Verify access

Re-run the same request — it should now succeed:

```shell
curl -k -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
```

You should now receive a `200 OK` response with a list of indices.

## Expected result

After role mapping is configured, requests to OpenSearch with a valid OAuth bearer token
return `200 OK` instead of `403 security_exception`. The `_cat/indices` endpoint returns
the list of indices the mapped user has access to.

## Next steps

* [Enable JWT authentication](how-to-guides-enable-jwt-authentication) — an alternative token-based authentication method.
* [Integrate with an application](how-to-integrate-with-an-application) — connect client applications using the `data-integrator` charm.
