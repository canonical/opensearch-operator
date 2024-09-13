# How to enable TLS encryption

This guide will show how to enable TLS using the [`self-signed-certificates` operator](https://github.com/canonical/self-signed-certificates-operator) as an example.

[note type="caution"]
**[Self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate) are not recommended for a production environment.**

Check [this guide](https://discourse.charmhub.io/t/11664) for an overview of the signed and self-signed certificate charms available.
[/note]

## Summary

* [Enable TLS](#enable-tls)
* [Disable TLS](#disable-tls)
* [Manage certificates](#manage-certificates)
  * [Check certificates in use](#check-certificates-in-use)
  * [Update keys](#update-keys)

---

## Enable TLS

First, deploy the TLS charm and configure the name of the Certificate Authority:
```shell
juju deploy self-signed-certificates --config ca-common-name="My CA"
```

To enable TLS on Charmed OpenSearch, integrate the two applications:
```shell
juju integrate self-signed-certificates opensearch
```
After the deployment has settled, you can see the relation by running `juju status --relations` .

## Disable TLS

TLS is a requirement for Charmed OpenSearch, therefore TLS should not be disabled.

## Manage certificates

### Check certificates in use

To check the certificates in use by OpenSearch, you can run:

```shell
openssl s_client -showcerts -connect `leader_unit_IP:port` < /dev/null | grep issuer
```

### Update keys

Updates to private keys for certificate signing requests (CSR) can be made via the `set-tls-private-key` action. Charmed OpenSearch uses three types of certificates:

* `app-admin`: used for administrative actions on opensearch
* `unit-transport`: used for internal communication between opensearch nodes
* `unit-http`: used for external communication between opensearch and clients (users or applications)

The private key for `app-admin` can only be applied on the leader-unit.

Updates to each of these can be done with auto-generated keys:

```shell
juju run opensearch/leader set-tls-private-key category=app-admin
juju run opensearch/leader set-tls-private-key category=unit-transport
juju run opensearch/leader set-tls-private-key category=unit-http
```

It is also possible to use self-generated keys:
```shell
openssl genrsa -out unit-http.pem 3072
openssl genrsa -out unit-transport.pem 3072
openssl genrsa -out app-admin.pem 3072
```

Apply the private key for `app-admin` to the juju leader:
```shell
juju run opensearch/leader set-tls-private-key category=app-admin key="$(base64 -w0 app-admin.pem)"
```

Apply the private keys for `unit-transport` and `unit-http` to all units (including the leader):
```shell
juju run opensearch/leader set-tls-private-key category=unit-http key="$(base64 -w0 unit-http.pem)"
juju run opensearch/leader set-tls-private-key category=unit-transport key="$(base64 -w0 unit-transport.pem)"
```