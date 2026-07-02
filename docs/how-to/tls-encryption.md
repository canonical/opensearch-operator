---
myst:
  html_meta:
    description: "Manage TLS encryption for Charmed OpenSearch, including enabling TLS, updating private keys, and rotating TLS and CA certificates."
---

(how-to-guides-tls-encryption-index)=
# How to manage TLS encryption

(how-to-enable-tls-encryption)=

This guide shows how to enable TLS encryption, update private keys, and rotate TLS/CA certificates
for a Charmed OpenSearch deployment.

For a step-by-step introduction, see the [Tutorial](tutorial-3-enable-encryption).

```{note}
TLS is mandatory for Charmed OpenSearch and cannot be disabled.
```

## Enable TLS encryption

The example below uses the
[`self-signed-certificates` operator](https://github.com/canonical/self-signed-certificates-operator).

```{caution}
**[Self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate)
are not recommended for production.**

See the [X.509 certificates topic](https://charmhub.io/topics/security-with-x-509-certificates)
for an overview of available certificate charms.
```

Deploy the TLS charm:

```shell
juju deploy self-signed-certificates --config ca-common-name="My CA"
```

Integrate it with OpenSearch:

```shell
juju integrate self-signed-certificates opensearch
```

Verify the relation with `juju status --relations`.

(how-to-check-tls-keys)=
## Check certificates in use

To inspect the issuer of the certificate currently served by OpenSearch:

```shell
openssl s_client -showcerts -connect <unit-ip>:<port> < /dev/null | grep issuer
```

(how-to-update-tls-keys)=
## Update private keys

Private keys can be updated via the `set-tls-private-key` action.
Charmed OpenSearch uses three certificate categories:

* `app-admin` — administrative actions (leader unit only)
* `unit-transport` — internal node-to-node communication
* `unit-http` — external client-to-node communication

### Auto-generate new keys

```shell
juju run opensearch/leader set-tls-private-key category=app-admin
juju run opensearch/leader set-tls-private-key category=unit-transport
juju run opensearch/leader set-tls-private-key category=unit-http
```

### Use custom keys

Generate keys with OpenSSL:

```shell
openssl genrsa -out unit-http.pem 3072
openssl genrsa -out unit-transport.pem 3072
openssl genrsa -out app-admin.pem 3072
```

Apply them:

```shell
juju run opensearch/leader set-tls-private-key category=app-admin key="$(base64 -w0 app-admin.pem)"
juju run opensearch/leader set-tls-private-key category=unit-http key="$(base64 -w0 unit-http.pem)"
juju run opensearch/leader set-tls-private-key category=unit-transport key="$(base64 -w0 unit-transport.pem)"
```

(how-to-rotate-tls-ca-certificates)=
## Rotate TLS certificates

Certificate rotation is triggered automatically when a certificate expires.
To rotate manually, regenerate the private key for the desired category:

(manual-rotate-tls-cert)=

```shell
juju run opensearch/leader set-tls-private-key category=<category>
```

Where `<category>` is `app-admin`, `unit-transport`, or `unit-http`.

This generates a new private key and CSR, which is sent to the certificate provider for signing.
Once signed, the new certificate is automatically applied to the cluster.

## Rotate CA certificates

The CA certificate is provided by the TLS operator you are using.
The rotation process differs depending on the operator.

### With `self-signed-certificates`

Trigger CA rotation by changing the common name:

```shell
juju config self-signed-certificates ca-common-name=<new-ca-common-name>
```

This will:

1. Generate a new CA certificate with the new common name.
2. Revoke all previously issued TLS certificates.
3. Cause OpenSearch to automatically request new certificates.
4. Trigger a rolling restart to apply the new CA across all nodes.

Until the rolling restart completes, nodes continue using the old certificates.

Verify the new CA is in use:

```shell
openssl s_client -showcerts -connect <unit-ip>:<port> < /dev/null | grep issuer
```

### With `manual-tls-certificates`

To rotate the CA with the `manual-tls` operator, sign CSRs with the new CA certificate
and provide them to the cluster. If you no longer have the original CSR files,
[regenerate them](#manual-rotate-tls-cert) first.

Provide the new certificate to each unit, **starting with the leader**:

```shell
juju run manual-tls-certificates/leader provide-certificate \
  relation-id=<relation-id> \
  certificate="$(base64 -w0 certificate.pem)" \
  ca-chain="$(base64 -w0 ca_chain.pem)" \
  ca-certificate="$(base64 -w0 ca_certificate.pem)" \
  certificate-signing-request="$(base64 -w0 csr.pem)" \
  unit-name="<unit-name>"
```

```{caution}
Always distribute certificates to the leader unit first, then to the remaining nodes.
```

After receiving the new CA, each node generates new CSRs that must be signed with the new CA
and provided back. Repeat for every unit in the cluster.

Once all units have the new CA, OpenSearch reloads certificates (or triggers a rolling restart
if the issuer, subject, or SANs have changed).

Verify the rotation:

```shell
openssl s_client -showcerts -connect <unit-ip>:<port> < /dev/null | grep issuer
```

## Expected result

After enabling TLS, `juju status` shows the OpenSearch application `active` (no longer
`blocked` with a "Missing TLS relation" message). After key updates or certificate/CA rotation,
`openssl s_client ... | grep issuer` shows the new issuer.

## Next steps

* [Enable monitoring (COS)](how-to-monitoring) — observe the cluster with TLS in place.
* [Security explanation](explanation-security-index) — background on TLS and authentication.
