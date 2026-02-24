---
myst:
  html_meta:
    description: "Secure your Charmed OpenSearch deployment with TLS encryption, including enabling encryption, managing certificate
s, and rotating TLS/CA certificates."
---

(how-to-guides-tls-encryption-index)=
# How to manage TLS encryption

This guide shows how to enable TLS encryption for a Charmed OpenSearch deployment and manage its
certificates, including updating private keys and rotating TLS and CA certificates.

For a step-by-step introduction to enabling TLS encryption, see the [Tutorial](tutorial-3-enable-encryption).

(how-to-enable-tls-encryption)=
## Enable TLS encryption

This guide will show how to enable TLS using the
[`self-signed-certificates` operator](https://github.com/canonical/self-signed-certificates-operator)
as an example.

```{caution}
**[Self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate)
are not recommended for a production environment.**

Check the [X.509 certificates topic](https://charmhub.io/topics/security-with-x-509-certificates)
for an overview of the signed and self-signed certificate charms available.
```

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

(how-to-check-tls-keys)=
### Check certificates in use

To check the certificates in use by OpenSearch, you can run:

```shell
openssl s_client -showcerts -connect leader_unit_IP:port < /dev/null | grep issuer
```

(how-to-update-tls-keys)=
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

(how-to-rotate-tls-ca-certificates)=
## Rotate TLS certificates

Charmed OpenSearch uses three types of TLS certificates:

1. `app-admin`: used for the administration of the OpenSearch cluster.
2. `unit-transport`: used for the communication between the OpenSearch nodes.
3. `unit-http`: used for the communication between OpenSearch and clients.

Two scenarios trigger the rotation of TLS certificates:

1. The certificate has expired/is about to expire: In this case, the Charmed OpenSearch will automatically request a new certificate.
2. You want to rotate the certificate: In this case, you can manually request a new certificate.

(manual-rotate-tls-cert)=
### Manually rotate the TLS certificates

You can manually start a rotation of the TLS certificates by changing the TLS private key for the type of certificate you want to rotate.

```bash
juju run opensearch/leader set-tls-private-key category=<category>
```

Where `<category>` is one of `app-admin`, `unit-transport`, or `unit-http`.

This will automatically generate a new private key and regenerate the certificate signing request
(CSR) for the specified category.
The new CSR will be sent to the operator you are using to provide the certificates for signing.
Once the new certificate is signed, it will be automatically applied to the OpenSearch cluster.

For more information on the different approaches to update the key please refer to the
[Update keys](how-to-update-tls-keys) section above.

## Rotate CA certificates

The CA certificate is used to sign the TLS certificates.
The CA certificate is provided to the OpenSearch cluster by the operator you are using
to provide the certificates. In this section, we will describe the process of rotating
the CA certificate using the [`self-signed-certificates` operator](https://charmhub.io/self-signed-certificates)
and the [`manual-tls` operator](https://charmhub.io/manual-tls-certificates).

### Using the `self-signed-certificates operator`

Currently, the `self-signed-certificates operator` does not support the rotation of the CA certificate.
If you need to rotate the CA certificate, you will need to start the rotation process manually.

You can manually start the rotation of the common name (CN) of the CA certificate
by changing the `ca-common-name` configuration option of the `self-signed-certificates operator`.

```bash
juju config self-signed-certificates ca-common-name=<new-ca-common-name>
```

The `self-signed-certificates operator` will automatically generate a new CA certificate
with the new common name, revoke all TLS certificates that were issued with the previous
CA certificate and send their invalidation to the OpenSearch cluster.

Upon receiving the information about the revoked TLS certificates, the OpenSearch cluster
will automatically request new TLS certificates from the `self-signed-certificates operator`.
After generating these certificates, they will be provided to OpenSearch.
Charmed OpenSearch checks each available TLS certificate for a new CA thereby triggering
a rolling restart of the cluster to apply the new CA certificate.

Until the rolling restart is complete, the OpenSearch cluster will ignore the new TLS certificates
and not apply them to the nodes. This will only be done once all nodes in the cluster have updated
the new CA and can communicate using the newly issued TLS certificates.

As indicated in the [Check certificates in use](how-to-check-tls-keys) section above,
you can check the certificates in use by running the following command:

```bash
openssl s_client -showcerts -connect leader_unit_IP:port < /dev/null | grep issuer
```

Where `leader_unit_IP` is the IP address of the leader unit and `port` is the port number of the OpenSearch service.
This command will show the issuer of the certificate in use which should include the new CA certificate common name.

### Using the `manual-tls operator`

The `manual-tls operator` is used to manually provide the TLS certificates to the OpenSearch cluster.
To rotate the CA certificate using the `manual-tls operator`,
you will need to manually start the TLS certificate rotation process and sign them using the new CA certificate.

If you still have the old CSR files, you can use them to start the rotation process.
If you do not have the old CSR files, you can generate new CSRs by [manually rotating the TLS certificates](manual-rotate-tls-cert).

To start the rotation process, sign the (old, or newly generated) CSRs using the new CA certificate
and then proceed to provide the new certificates to the OpenSearch cluster using the `manual-tls operator`:

```bash
juju run manual-tls-certificates/leader provide-certificate \
  relation-id=<id> \
  certificate="$(base64 -w0 certificate.pem)" \
  ca-chain="$(base64 -w0 ca_chain.pem)" \
  ca-certificate="$(base64 -w0 ca_certificate.pem)" \
  certificate-signing-request="$(base64 -w0 csr.pem)" \
  unit-name="<unit-name>"
```

Once the new certificate is provided to the OpenSearch cluster, the OpenSearch cluster will
automatically detect the new CA certificate and trigger a CA rotation on the node which results
in new CSRs being generated. You can then sign the new CSRs using the new CA certificate
and provide the new certificates to the OpenSearch node using the `manual-tls operator`.

```{caution}
The distribution of certificates must follow a specific order.
The leader unit is first followed by the remaining nodes.
```

This process needs to be repeated for each unit in the OpenSearch cluster.
Once all the units have the new CA certificate, the OpenSearch cluster will update
the TLS certificates on the nodes, either by reloading them via API or by triggering
a rolling restart of the OpenSearch cluster. Restarting to apply the new TLS certificates
is only required if the issuer, the subject or the subject alternative names (sans) of
the new certificate are different than before. If they stay the same, the new TLS certificates
can be reloaded on the fly.

As indicated in the [Check certificates in use](how-to-check-tls-keys) section above,
you can check the certificates in use by running the following command:

```bash
openssl s_client -showcerts -connect leader_unit_IP:port < /dev/null | grep issuer
```

Where `leader_unit_IP` is the IP address of the leader unit and `port` is the port number
of the OpenSearch service. This command will show the issuer of the certificate in use which
should include the new CA certificate common name.
