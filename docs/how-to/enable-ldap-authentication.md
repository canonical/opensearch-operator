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

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

For machine deployments, create a Kubernetes model for the [`glauth-k8s` charm](https://charmhub.io/glauth-k8s) and its supporting applications. We'll then create a cross-model relation to the OpenSearch VM model.

```shell
juju add-model <k8s_model> <k8s_cloud>
```
````
````{tab-item} K8s
:sync: k8s

For Kubernetes deployments, you can simply deploy the [`glauth-k8s` charm](https://charmhub.io/glauth-k8s) and its supporting applications alongside OpenSearch without a separate Juju model.

````

`````

Deploy `glauth-k8s` and `postgresql-k8s`:

```shell
juju deploy glauth-k8s --channel latest/stable --trust --config ldaps_enabled=true
juju deploy postgresql-k8s --channel 14/stable --trust
```

`ldaps_enabled=true` is **required**: OpenSearch only connects to LDAP over LDAPS.

This example uses `self-signed-certificates` as the certificate provider. If it is already deployed in the model
containing GLAuth, reuse it. Otherwise, deploy it:

```shell
juju deploy self-signed-certificates --channel 1/stable
```

```{note}
This guide uses `self-signed-certificates` for demonstration. For production deployments,
use your organisation's preferred certificate authority.
```

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

## Create a cross-model relation (VM only)

`````{tab-set}
````{tab-item} VM
:sync: vm

### Expose cross-model relations

To offer the LDAP interface of GLAuth and the CA certificate that signed its LDAPS certificate, run:

```shell
juju offer glauth-k8s:ldap ldap
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

### Adjust the directory layout (optional)

If your directory uses a different schema, you can fine tune how OpenSearch searches the directory using four config
options:

- `ldap_user_base`: The base DN in the directory tree from which user searches are performed. Default
  `ou=users,dc=glauth,dc=com`
- `ldap_user_search`: The search filter used to locate a user entry, where `{0}` is replaced with the login username.
  Default `(cn={0})`
- `ldap_user_rolename`: The attribute on a user entry that specifies which groups the user belongs to. Default
  `memberOf`
- `ldap_role_name_attr`: The attribute on a group entry that OpenSearch will read as the group name. Default `ou`

## Enable LDAP

To enable LDAP authentication, integrate the OpenSearch charm with GLAuth and with the CA certificate of its LDAPS
endpoint:

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

```shell
juju integrate opensearch:ldap glauth-k8s:ldap
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

You can disable LDAP by removing the relations with GLAuth:

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
juju remove-relation opensearch:ldap glauth-k8s:ldap
```
````
`````
