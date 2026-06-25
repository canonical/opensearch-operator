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

### Prepare MicroK8s

```shell
sudo snap install microk8s --classic
sudo microk8s enable hostpath-storage dns
sudo microk8s enable metallb:10.0.0.2-10.0.0.3
```

Add MicroK8s to your Juju controller:

```shell
sudo microk8s config > microk8s-cluster.yaml
export KUBECONFIG="$PWD/microk8s-cluster.yaml"
juju add-k8s microk8s-cluster -c <controller-name>
```

### Deploy Identity Platform

```shell
juju add-model -c <controller-name> oauth microk8s-cluster/localhost
juju deploy identity-platform --channel edge --trust true
```

Wait until all units become active. The `kratos-external-idp-integrator` will remain
`blocked` — this is expected and does not affect OAuth functionality.

## Create cross-model integrations

### Offer certificates and OAuth from the Identity Platform model

```shell
juju switch oauth
juju offer self-signed-certificates:certificates
juju offer hydra:oauth
```

### Consume and integrate in the OpenSearch model

```shell
juju switch opensearch-model
juju consume admin/oauth.self-signed-certificates
juju consume admin/oauth.hydra
juju integrate opensearch admin/oauth.self-signed-certificates
juju integrate opensearch admin/oauth.hydra
```

## Create an OAuth client and obtain a token

### Create a client in Hydra

```shell
juju switch oauth
juju run hydra/leader create-oauth-client \
  grant-types='["client_credentials"]' \
  audience='["opensearch"]' \
  scope='["openid","profile","email","phone","offline"]'
```

Record the `client-id` and `client-secret` from the output.

### Get the Hydra public URL

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

```shell
juju switch opensearch-model
export OPENSEARCH_ADDRESS="$(juju status | grep opensearch/0 | awk -F' ' '{print $5}')"

curl -k -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
```

Expect a `403 security_exception` — the client has no mapped roles yet.

### Get a username from the Data Integrator

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

```shell
curl -k -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
```

You should now receive a `200 OK` response with a list of indices.
