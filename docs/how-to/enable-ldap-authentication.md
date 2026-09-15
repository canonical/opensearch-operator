---
myst:
  html_meta:
    description: "Enable LDAP authentication in Charmed OpenSearch on machines or Kubernetes."
---

(how-to-enable-ldap-authentication)=
# How to enable LDAP authentication

LDAP (Lightweight Directory Access Protocol) enables centralized authentication for OpenSearch clusters, 
reducing the overhead of managing local credentials and access policies.

This guide shows how to integrate LDAP as an authentication method with Charmed OpenSearch.

## Prerequisites

* A running Charmed OpenSearch deployment (revision #todo add revision)
* A Kubernetes cloud registered with your Juju controller

## Deploy an LDAP server on Kubernetes

`````{tab-set}
:sync-group: substrate

````{tab-item} VM
:sync: vm

For machine deployments, you'll need a separate Juju controller with a Kubernetes model in order to deploy the [`glauth-k8s` charm](https://charmhub.io/glauth-k8s). We'll then create a cross-controller relation to the OpenSearch VM model.

```shell
juju switch <k8s_controller>
juju add-model <k8s_model>
```
````
````{tab-item} K8s
:sync: k8s

For Kubernetes deployments, you can simply deploy GLAuth and its supporting applications alongside OpenSearch without a separate Juju model.

````

`````

Deploy `glauth-k8s`, `self-signed-certificates`, and `postgresql-k8s`:
```shell
juju deploy glauth-k8s --channel latest/edge --trust --config ldaps_enabled=true
juju deploy self-signed-certificates --trust
juju deploy postgresql-k8s --channel 14/stable --trust
```

`ldaps_enabled=true` is **required**.

Integrate `glauth-k8s` with `self-signed-certificates` and `postgresql-k8s`:

```shell
juju integrate glauth-k8s self-signed-certificates
juju integrate glauth-k8s:pg-database postgresql-k8s:database
```
Deploy the [`glauth-utils` charm](https://charmhub.io/glauth-utils) to manage LDAP users, and integrate it with the GLAuth application:

```shell
juju deploy glauth-utils --channel edge --trust
juju integrate glauth-k8s glauth-utils
```

Users and groups can now be created using `glauth-utils`.

## Create a cross-model relation (VM only)

`````{tab-set}
````{tab-item} VM
:sync: vm

## Expose cross-controller URLs

Deploy the [Traefik charm](https://charmhub.io/traefik-k8s) in order to expose endpoints from the K8s cluster:

```shell
juju deploy traefik-k8s --trust
```

Integrate the two applications:

```shell
juju integrate traefik-k8s glauth-k8s:ldaps-ingress
```

## Expose cross-model relations

To offer the GLAuth interfaces, run:

```shell
juju offer glauth-k8s:ldap ldap
juju offer glauth-k8s:send-ca-cert send-ca-cert
```

## Consume offers

Switch to the VM controller:

```shell
juju switch <lxd_controller>:<my-model>
```

Consume the LDAP offers:

```shell
juju consume <k8s_controller>:admin/<k8s_model>.ldap
juju consume <k8s_controller>:admin/<k8s_model>.send-ca-cert
```
````

````{tab-item} K8s
:sync: k8s

This procedure applies to machine deployments. On Kubernetes, proceed to the next section: [Configure roles](ldap-configure-roles).
````
`````

(ldap-configure-roles)=
## Configure roles

Permissions are granted to an LDAP group through the [`data-integrator` charm](https://charmhub.io/data-integrator). The LDAP group name
**must be identical** to the key of the Juju secret created below. Supported group names may contain only lowercase letters, digits and hyphens.

### Grant permissions to a group

Deploy one `data-integrator` for each LDAP group you want to grant permissions to:

```shell
juju deploy data-integrator search-admin-di --channel latest/edge
```

Create a Juju secret whose key is the LDAP group name, and grant it to the integrator:

```shell
juju add-secret search-admin-secret search-admin=password
juju grant-secret search-admin-secret search-admin-di
```

Configure the data-integrator:

```shell
juju config search-admin-di \
  index-name=search-index \
  entity-type=GROUP \
  entity-permissions='[{"resource_name":"search-index","resource_type":"index_permissions","privileges":["read","search","get","write"]}]' \
  requested-entities-secret=<secret-uri>
```

* `entity-type`: must be `GROUP` to grant permissions to an LDAP group.
* `entity-permissions`: a list with one entry containing:
    * `resource_name`: the index or index pattern the group may access.
    * `resource_type`: must be `index_permissions`
    * `privileges`: the OpenSearch action groups to allow.
* `requested-entities-secret`: the URI of the secret whose key is the group name.

Integrate it with OpenSearch:

```shell
juju integrate search-admin-di opensearch
```

### Create the group and its users in LDAP

Create an LDIF file defining your LDAP data:

```text
dn: ou=search-admin,ou=opensearch,ou=users,dc=glauth,dc=com
objectClass: posixGroup
ou: search-admin
gidNumber: 5503

dn: cn=alice,ou=search-admin,ou=opensearch,ou=users,dc=glauth,dc=com
changetype: add
objectClass: posixAccount
uidNumber: 5004
gidNumber: 5503
cn: alice
sn: alice
uid: alice
userPassword: {SHA256}<sha256-hash-of-password>
```

Copy the file to the `glauth-utils` unit and run the `apply-ldif` action:

```shell
juju scp <file.ldif> glauth-utils/leader:/var/tmp/<file.ldif>
juju run glauth-utils/leader apply-ldif path=/var/tmp/<file.ldif>
```

### Adjust the directory layout (optional)

If your directory uses a different schema, you can fine tune how OpenSearch searches the directory using four config options:

* `ldap_user_base`: The base DN in the directory tree from which user searches are performed. Default `ou=users,dc=glauth,dc=com`
* `ldap_user_search`: The search filter used to locate a user entry, where `{0}` is replaced with the login username. Default `(cn={0})`
* `ldap_user_rolename`: The attribute on a user entry that specifies which groups the user belongs to. Default `memberOf`
* `ldap_role_name_attr`: The attribute on a group entry that OpenSearch will read as the group name. Default `ou`

## Enable LDAP

To enable LDAP authentication, integrate the OpenSearch charm with the Glauth charm:

```shell
juju integrate opensearch:ldap ldap
juju integrate opensearch:ldap-certificate-transfer send-ca-cert
```

When everything has stabilised, LDAP users can log in with their directory credentials and inherit the permissions granted by the roles corresponding to their LDAP groups.

## Disable LDAP

You can disable LDAP by removing the relations with GLAuth:

```shell
juju remove-relation opensearch:ldap-certificate-transfer send-ca-cert
juju remove-relation opensearch:ldap ldap
```
