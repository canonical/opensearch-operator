---
myst:
  html_meta:
    description: Enable LDAP authentication in Charmed OpenSearch on machines or Kubernetes.
---

(how-to-enable-ldap-authentication)=

# How to enable LDAP authentication

LDAP (Lightweight Directory Access Protocol) enables centralized authentication for OpenSearch clusters, reducing the
overhead of managing local credentials and access policies.

This guide shows how to integrate LDAP as an authentication method with Charmed OpenSearch.

## Prerequisites

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

You'll need:

- Charmed OpenSearch
- A Kubernetes cloud registered with your Juju controller
````

````{tab-item} K8s
:sync: k8s

You'll need:

- Charmed OpenSearch K8s
````
`````

## Deploy an LDAP server on Kubernetes

Charmed OpenSearch works with any provider of the `ldap` interface. This guide covers the two Canonical-maintained
ones: the [Authentik LDAP outpost](https://charmhub.io/authentik-ldap-outpost), which exposes an Authentik directory
over LDAP, and [GLAuth](https://charmhub.io/glauth-k8s), a lightweight LDAP server. Both are Kubernetes charms.

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

For machine deployments, create a Kubernetes model for the LDAP provider and its supporting applications. We'll then
create a cross-model relation to the OpenSearch VM model.

```shell
juju add-model <k8s_model> <k8s_cloud>
```
````
````{tab-item} K8s
:sync: k8s

For Kubernetes deployments, you can simply deploy the LDAP provider and its supporting applications alongside
OpenSearch without a separate Juju model.

````

`````

OpenSearch only connects to LDAP over LDAPS. This example uses `self-signed-certificates` as the certificate provider.
If it is already deployed in the model containing the LDAP provider, reuse it instead of deploying it again.

```{note}
This guide uses `self-signed-certificates` for demonstration. For production deployments,
use your organisation's preferred certificate authority.
```

`````{tab-set}
---
sync-group: ldap-provider
---
````{tab-item} Authentik
:sync: authentik

Deploy the Authentik server, its worker, the LDAP outpost, and the supporting database, ingress, and certificate
charms:

```shell
juju deploy postgresql-k8s --channel 14/stable --trust
juju deploy authentik-server --channel latest/stable --trust
juju deploy authentik-worker --channel latest/stable --trust
juju deploy authentik-ldap-outpost --channel latest/stable --trust
juju deploy traefik-k8s --trust
juju deploy self-signed-certificates --channel 1/stable
```

Integrate them:

```shell
juju integrate authentik-server:pg-database postgresql-k8s:database
juju integrate authentik-server:authentik-cluster authentik-worker
juju integrate authentik-server:authentik-server-info authentik-ldap-outpost
juju integrate authentik-server:traefik-route traefik-k8s
juju integrate authentik-ldap-outpost:traefik-route traefik-k8s
```

Traefik is required: the outpost does not provision a certificate of its own, so Traefik terminates LDAPS for it on
port 636. Wait until `traefik-k8s` is `active`, then provide it with a certificate:

```shell
juju integrate traefik-k8s:certificates self-signed-certificates
```

```{note}
Traefik requests its certificate for its load balancer address. If the integration is added before that address is
assigned, Traefik keeps serving its default certificate, which OpenSearch does not trust.
```

The outpost serves the directory under the base DN `dc=ldap,dc=goauthentik,dc=io`. To use a different one, set the
`base_dn` config option of `authentik-ldap-outpost`.

Users and groups are managed in Authentik itself. To reach its web interface, generate a recovery link for the
bootstrap administrator:

```shell
juju run authentik-server/leader create-recovery-link
```

```{note}
The outpost defaults to `search_mode=cached` and `bind_mode=cached`, which serve a periodically refreshed snapshot of
the directory. Directory changes -- new users, changed group membership, changed passwords -- can take until the next
synchronisation to reach OpenSearch. Set both to `direct` if every request must reflect the live Authentik state.
```
````

````{tab-item} GLAuth
:sync: glauth

Deploy `glauth-k8s`, `self-signed-certificates`, and `postgresql-k8s`:

```shell
juju deploy glauth-k8s --channel latest/stable --trust --config ldaps_enabled=true
juju deploy self-signed-certificates --channel 1/stable
juju deploy postgresql-k8s --channel 14/stable --trust
```

`ldaps_enabled=true` is **required**: GLAuth starts with LDAPS disabled.

Integrate `glauth-k8s` with `self-signed-certificates` and `postgresql-k8s`:

```shell
juju integrate glauth-k8s self-signed-certificates
juju integrate glauth-k8s:pg-database postgresql-k8s:database
```

Deploy the [Traefik charm](https://charmhub.io/traefik-k8s) to expose the LDAPS endpoint of GLAuth, and integrate the
two applications:

```shell
juju deploy traefik-k8s --trust
juju integrate traefik-k8s glauth-k8s:ldaps-ingress
```

Deploy the [`glauth-utils` charm](https://charmhub.io/glauth-utils) to manage LDAP users, and integrate it with the
GLAuth application:

```shell
juju deploy glauth-utils --channel latest/stable --trust
juju integrate glauth-k8s glauth-utils
```

Users and groups can now be created using `glauth-utils`.
````

`````

## Create a cross-model relation (VM only)

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

### Expose cross-model relations

Offer the `ldap` endpoint of the provider you deployed -- `authentik-ldap-outpost` or `glauth-k8s` -- together with
the CA certificate that signed its LDAPS certificate:

```shell
juju offer <ldap_provider>:ldap ldap
juju offer self-signed-certificates:send-ca-cert ldap-cert
```

### Consume offers

Switch to the OpenSearch model:

```shell
juju switch <opensearch_model>
```

Consume the LDAP offers:

```shell
juju consume admin/<k8s_model>.ldap
juju consume admin/<k8s_model>.ldap-cert
```

The OpenSearch machines must be able to reach the address that Traefik exposes. To see it, run `juju run traefik-k8s/0 show-proxied-endpoints` in the Kubernetes model.
````

````{tab-item} K8s
:sync: k8s

This procedure applies to machine deployments. On Kubernetes, proceed to the next section: [Configure roles](ldap-configure-roles).
````
`````

(ldap-configure-roles)=

## Configure roles

Permissions are granted to an LDAP group through the [`data-integrator` charm](https://charmhub.io/data-integrator).

The LDAP group name **must be identical** to the key of the Juju secret created below. Juju secret keys must:

- start with a lowercase letter
- be at least three characters long
- contain only lowercase letters, digits and single hyphens

### Grant permissions to a group

Make sure the model containing OpenSearch is selected:

```shell
juju switch <opensearch_model>
```

Deploy one `data-integrator` for each LDAP group you want to grant permissions to:

```shell
juju deploy data-integrator search-admin-di --channel latest/edge
```

Create a Juju secret whose key is the LDAP group name, and grant it to the integrator:

```shell
juju add-secret search-admin-secret search-admin=password
juju grant-secret search-admin-secret search-admin-di
```

Configure the `data-integrator`:

```shell
juju config search-admin-di \
  index-name=search-index \
  entity-type=GROUP \
  entity-permissions='[{"resource_name":"search-index","resource_type":"index_permissions","privileges":["read","search","get","write"]}]' \
  requested-entities-secret=<secret-uri>
```

- `entity-type`: must be `GROUP` to grant permissions to an LDAP group.
- `entity-permissions`: a list with one entry containing:
  - `resource_name`: the index or index pattern the group may access.
  - `resource_type`: must be `index_permissions`
  - `privileges`: the OpenSearch action groups to allow.
- `requested-entities-secret`: the URI of the secret whose key is the group name.

Integrate it with OpenSearch:

```shell
juju integrate search-admin-di opensearch
```

### Create the group and its users in LDAP

Make sure the LDAP group exists and contains its users. Its name must be identical to the key of the Juju secret above.

`````{tab-set}
---
sync-group: ldap-provider
---
````{tab-item} Authentik
:sync: authentik

Create the group and its users in the Authentik web interface, and add the users to the group.
````

````{tab-item} GLAuth
:sync: glauth

Create the group and its users with `glauth-utils`.
````
`````

### Configure the directory layout

OpenSearch uses four config options to search the directory:

- `ldap_user_base`: The base DN in the directory tree from which user searches are performed. Default
  `ou=users,dc=glauth,dc=com`
- `ldap_user_search`: The search filter used to locate a user entry, where `{0}` is replaced with the login username.
  Default `(cn={0})`
- `ldap_user_rolename`: The attribute on a user entry that specifies which groups the user belongs to. Default
  `memberOf`
- `ldap_role_name_attr`: The attribute on a group entry that OpenSearch will read as the group name. Default `ou`

`````{tab-set}
---
sync-group: ldap-provider
---
````{tab-item} Authentik
:sync: authentik

Authentik stores users under `ou=users` of its base DN and names groups with a `cn` RDN. Point OpenSearch at them,
substituting the base DN if you changed it:

```shell
juju config opensearch \
  ldap_user_base="ou=users,dc=ldap,dc=goauthentik,dc=io" \
  ldap_role_name_attr=cn
```
````

````{tab-item} GLAuth
:sync: glauth

The defaults match the layout of GLAuth. If your directory uses a different schema, adjust the options above.
````
`````

## Enable LDAP

To enable LDAP authentication, integrate the OpenSearch charm with the LDAP provider and with the CA certificate of its
LDAPS endpoint:

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

```shell
juju integrate opensearch:ldap ldap
juju integrate opensearch:ldap-certificate-transfer ldap-cert
```
````

````{tab-item} K8s
:sync: k8s

Substitute `<ldap_provider>` with `authentik-ldap-outpost` or `glauth-k8s`:

```shell
juju integrate opensearch:ldap <ldap_provider>:ldap
juju integrate opensearch:ldap-certificate-transfer self-signed-certificates:send-ca-cert
```
````
`````

Check the status of the OpenSearch model:

```shell
juju status -m <opensearch_model>
```

Wait until all applications report `active` and all unit agents report `idle`. When everything has stabilised, LDAP
users can log in with their directory credentials and inherit the permissions granted by the roles corresponding to
their LDAP groups.

## Disable LDAP

You can disable LDAP by removing the relations with the LDAP provider:

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

```shell
juju remove-relation opensearch:ldap-certificate-transfer ldap-cert
juju remove-relation opensearch:ldap ldap
```
````

````{tab-item} K8s
:sync: k8s

```shell
juju remove-relation opensearch:ldap-certificate-transfer self-signed-certificates:send-ca-cert
juju remove-relation opensearch:ldap <ldap_provider>:ldap
```
````
`````
