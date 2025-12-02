(how-to-access-using-oauth)=
# How to access OpenSearch using OAuth

This guide shows how to secure an OpenSearch deployment with OAuth tokens issued by
Canonical’s Identity Platform (Hydra) and then query OpenSearch using generated tokens.

## Prerequisites

* A working LXD cloud on your machine.
* Juju installed and logged in.
* MicroK8s installed locally (used to run the Identity Platform bundle).
* Network access between your host and the LXD containers.
* Minimum 4 cpus, 16 GB RAM is needed.

## Deploy OpenSearch on LXD

Add an LXD model and deploy the OpenSearch and Data Integrator charms:

```shell
juju add-model opensearch-model localhost/localhost
juju deploy opensearch -n 3 --channel 2/edge
juju deploy data-integrator --channel=stable \
  --config index-name=admin-index \
  --config extra-user-roles=admin
```

```{note}
Opensearch is deployed with 3 units to support high availability as a production recommendation.
```

Wait until all the units become active:

```shell
juju status --watch 5s
```

## Deploy the Identity Platform on MicroK8s

### Prepare MicroK8s and add it to the existing controller

Install MicroK8s and enable hostpath-storage, dns and metallb plugins:

```shell
sudo snap install microk8s --classic
sudo microk8s enable hostpath-storage dns
sudo microk8s enable metallb:10.0.0.2-10.0.0.3
```

Add MicroK8s cloud to your existing Juju Controller using kubeconfig file:

```shell
sudo microk8s config > microk8s-cluster.yaml
export KUBECONFIG="$PWD/microk8s-cluster.yaml"
juju controllers    # note your controller name
juju add-k8s microk8s-cluster -c <controller-name>
```

Confirm clouds:

```text
$ juju clouds
Clouds available on the controller:
Cloud             Regions  Default    Type
localhost         1        localhost  lxd  
microk8s-cluster  1        localhost  k8s  

Clouds available on the client:
Cloud      Regions  Default    Type  Credentials  Source    Description
localhost  1        localhost  lxd   1            built-in  LXD Container Hypervisor
microk8s   0                   k8s   0            built-in  A local Kubernetes context
```

### Deploy Identity Platform

Create a dedicated model on the MicroK8s cloud and deploy the bundle (trusted).

```shell
juju add-model -c <controller-name> oauth microk8s-cluster/localhost
juju deploy identity-platform --channel edge --trust true
```

Wait until all the units become active except kratos-external-idp-integrator. It will be in blocked status as below:

```text
$ juju status --watch 10s
Model  Controller  Cloud/Region                Version  SLA          Timestamp
oauth  demo        microk8s-cluster/localhost  3.5.7    unsupported  23:37:14+03:00

App                                  Version  Status   Scale  Charm                                Channel        Rev  Address         Exposed  Message
hydra                                v2.3.0   active       1  hydra                                latest/edge    339  10.152.183.135  no       
identity-platform-login-ui-operator  0.21.2   active       1  identity-platform-login-ui-operator  latest/edge    146  10.152.183.232  no       
kratos                               v1.3.1   active       1  kratos                               latest/edge    500  10.152.183.35   no       
kratos-external-idp-integrator                blocked      1  kratos-external-idp-integrator       latest/edge    245  10.152.183.100  no       Invalid configuration: Missing required configuration 'issuer_url' for provider 'generic'
postgresql-k8s                       14.15    active       1  postgresql-k8s                       14/stable      495  10.152.183.250  no       
self-signed-certificates                      active       1  self-signed-certificates             latest/stable  155  10.152.183.229  no       
traefik-admin                        v2.11.0  active       1  traefik-k8s                          latest/stable  176  10.0.0.2        no       
traefik-public                       v2.11.0  active       1  traefik-k8s                          latest/stable  176  10.0.0.3        no       

Unit                                    Workload  Agent  Address      Ports  Message
hydra/0*                                active    idle   10.1.65.134         
identity-platform-login-ui-operator/0*  active    idle   10.1.65.135         
kratos-external-idp-integrator/0*       blocked   idle   10.1.65.137         Invalid configuration: Missing required configuration 'issuer_url' for provider 'generic'
kratos/0*                               active    idle   10.1.65.145         
postgresql-k8s/0*                       active    idle   10.1.65.139         Primary
self-signed-certificates/0*             active    idle   10.1.65.140         
traefik-admin/0*                        active    idle   10.1.65.143         
traefik-public/0*                       active    idle   10.1.65.144         

Offer                     Application               Charm                     Rev  Connected  Endpoint      Interface         Role
hydra                     hydra                     hydra                     339  1/1        oauth         oauth             provider
self-signed-certificates  self-signed-certificates  self-signed-certificates  155  1/1        certificates  tls-certificates  provider
```

## Offer/consume relations for certificates and OAuth

### Integrate self-signed-certificates with OpenSearch

Offer the certificates interface from the oauth model and relate it to OpenSearch.

Switch to the oauth model and create an offer for certificates:

```shell
juju switch oauth
juju offer self-signed-certificates:certificates
```

Switch back to the opensearch model and consume the created offer in the previous step:

```shell
juju switch opensearch-model
juju consume admin/oauth.self-signed-certificates
juju integrate opensearch admin/oauth.self-signed-certificates
```

### Integrate OAuth (Hydra) with OpenSearch

Create an offer for Hydra’s oauth endpoint:

```shell
juju switch oauth
juju offer hydra:oauth
```

Switch to opensearch model and consume the offer from Hydra:

```shell
juju switch opensearch-model
juju consume admin/oauth.hydra
juju integrate opensearch admin/oauth.hydra
```

## Access Opensearch Using OAuth Client

### Create an OAuth client in Hydra

To allow OpenSearch to authenticate requests with OAuth2, you must create a new client in Hydra. The client will use the client_credentials grant type and request the Opensearch audience. Run the following action on the Hydra leader unit:

```shell
juju switch oauth
juju run hydra/leader create-oauth-client \
  grant-types='["client_credentials"]' \
  audience='["opensearch"]' \
  scope='["openid","profile","email","phone","offline"]'
```

Record the client-id and client-secret from the output.

The output will be similar to the following output:

```text
juju run hydra/leader create-oauth-client \
  grant-types='["client_credentials"]' \
  audience='["opensearch"]', \
  scope='["openid", "profile", "email", "phone", "offline"]' 
demo:admin/oauth (no change)
Running operation 1 with 1 task
  - task 2 on unit-hydra-0

Waiting for task 2...
audience: '[''opensearch'']'
client-id: e9c3b483-90be-4843-b821-1152e40aaa0a
client-secret: 8kskC~j~avq-fv_218ky8ApJf-
grant-types: '[''client_credentials'']'
redirect-uris: '[]'
response-types: '[''code'']'
scope: '[''openid'', ''profile'', ''email'', ''phone'', ''offline'']'
token-endpoint-auth-method: client_secret_basic
```

### Get the Hydra public URL

Hydra is fronted by Traefik. Ask Traefik for proxied endpoints:

```shell
juju run traefik-public/0 show-proxied-endpoints
```

Copy the `hydra.url` value, for example, `https://10.0.0.3/oauth-hydra`.

Export convenient variables:

```shell
export OAUTH_CLIENT_ID="<client-id>"
export OAUTH_CLIENT_SECRET="<client-secret>"
export HYDRA_URL="https://10.0.0.3/oauth-hydra"
```

### Fetch an access token from Hydra

```shell
curl -k -u "${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}" \
  -X POST "${HYDRA_URL}/oauth2/token" \
  -d "scope=openid" \
  -d "grant_type=client_credentials" \
  -d "audience=opensearch"
```

Save access_token from the JSON output:

```shell
export OAUTH_ACCESS_TOKEN="<access_token>"
```

### Call OpenSearch with the token (expect 403 before mapping)

Get the OpenSearch leader’s address:

```shell
juju switch opensearch-model
export OPENSEARCH_ADDRESS="$(juju status | grep opensearch/0 | awk -F' ' '{print $5}')"

curl -k -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
```

Test the API:

```shell
curl -k -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
```

Expected 403 security_exception as the client has no mapped roles yet as below:

```text
  {"error":{"root_cause":[{"type":"security_exception","reason":"no permissions for [indices:monitor/settings/get] and User [name=e9c3b483-90be-4843-b821-1152e40aaa0a, backend_roles=[], requestedTenant=null]"}],"type":"security_exception","reason":"no permissions for [indices:monitor/settings/get] and User [name=e9c3b483-90be-4843-b821-1152e40aaa0a, backend_roles=[], requestedTenant=null]"},"status":403}
```

### Retrieve a user from the Data Integrator

The Data Integrator provides a username you can map the OAuth client to:

```shell
juju run data-integrator/0 get-credentials
```

Expect an output in the following format:

```shell
$ juju run data-integrator/0 get-credentials
Running operation 1 with 1 task
  - task 2 on unit-data-integrator-0

Waiting for task 2...
ok: "True"
opensearch:
  data: '{"extra-user-roles": "admin", "index": "admin-index", "provided-secrets":
    "[\"mtls-cert\"]", "requested-secrets": "[\"username\", \"password\", \"tls\",
    \"tls-ca\", \"uris\", \"read-only-uris\"]"}'
  endpoints: 10.75.243.59:9200
  index: admin-index
  password: pbe9c5UP3BnJQOsLHq61Hg8qc5GgdJkP
  tls-ca: |-
    -----BEGIN CERTIFICATE-----
   ...
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE----
   ...
    -----END CERTIFICATE-----
  username: opensearch-client_4
  version: 2.19.2
```

Copy the username (e.g. `opensearch-client_4`) and export it:

```shell
export DATA_INTEGRATOR_USER="opensearch-client_4"
```

## Configure OpenSearch roles mapping

Set the charm’s roles_mapping with your OAuth client ID -> user mapping.

Juju config values are strings hence pass JSON as a quoted string.

```shell
juju config opensearch roles_mapping="{\"$OAUTH_CLIENT_ID\":\"$DATA_INTEGRATOR_USER\"}"
```

Wait for the charm to apply the change:

```shell
juju status --watch 5s
```

### Retrigger the API (should work)

```shell
curl -k -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
```

Expected a list of indices (green/yellow),  200 OK as following:

```text
curl -k \
  -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN}" \
  "https://${OPENSEARCH_ADDRESS}:9200/_cat/indices"
green  open .plugins-ml-config           QnsDThyaTAKw8cASRYeQMw 1 0  1 0   4kb   4kb
green  open .opensearch-observability    coXcpdLWSOqbSQ136tbADg 1 0  0 0  208b  208b
green  open top_queries-2025.08.29-70656 GDHtcml_R6Okh2siIKgmPw 1 0 40 6 108kb 108kb
green  open .opendistro_security         RPVY1SdfT_KzAPAX-aUCuw 1 0 10 1  71kb  71kb
yellow open admin-index                  1BQKqmjTQVa6_CeBTi53Gw 1 1  0 0  208b  208b
green  open .charm_node_lock             8KbPHHy3QneIW8uWbTuBhQ 1 0  1 0 4.1kb 4.1kb
```
