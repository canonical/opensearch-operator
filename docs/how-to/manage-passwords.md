---
myst:
  html_meta:
    description: "Retrieve and rotate the admin password in Charmed OpenSearch, and rotate the credentials issued to integrated client applications."
---

(how-to-manage-passwords)=
# How to manage passwords

This guide shows how to retrieve and rotate the admin password and how to rotate the
credentials Charmed OpenSearch issues to integrated client applications.

## Manage the admin password

The `admin` user is an internal charm user. Use its credentials for cluster administration
only — client applications must obtain their own credentials through an integration.

```{note}
The `get-password` and `set-password` actions take an optional `username` parameter
that defaults to `admin`. `set-password` must be run on the leader unit.
```

### Retrieve the admin password

To get admin password:

```shell
juju run opensearch/leader get-password
```

The action returns the `admin` password and the CA certificate chain used to generate the
admin client certificate.

### Rotate the admin password

To generate a random password:

```shell
juju run opensearch/leader set-password
```

To set a specific password:

```shell
juju run opensearch/leader set-password password=<new-password>
```

Both commands return the new password as `admin-password`.
The previous password stops working immediately.

## Manage client credentials

Charmed OpenSearch generates a dedicated user and password for each client integration.
These credentials are passed to the client application over the relation, so you do not
retrieve or set them directly.

### Rotate client credentials

Remove and re-add the integration to generate a new user with a new password:

```shell
juju remove-relation opensearch <application>
juju integrate opensearch <application>
```

The client application receives the new credentials over the relation.

## Next steps

* [Manage TLS encryption](how-to-enable-tls-encryption) to rotate certificates and private keys.
* [Integrate with an application](how-to-integrate-with-an-application) to connect a client.
