---
myst:
  html_meta:
    description: "Understand TLS certificate categories, rotation mechanics, and CA rotation in Charmed OpenSearch."
---

(explanation-tls-certificates)=
# TLS certificates

TLS encryption is mandatory in Charmed OpenSearch — the charm does not function without it.
This page explains the three categories of TLS certificates the charm manages, how certificate
rotation works, and how CA rotation triggers rolling restarts.

For details on the cryptographic implementation (checksums, source verification, keystore
and truststore management), see [Cryptography](explanation-security-cryptography).

## Certificate categories

Charmed OpenSearch uses three categories of TLS certificates, each serving a different
communication channel:

| Category | Used for | Can be set on |
| :--- | :--- | :--- |
| `app-admin` | Administrative actions on the OpenSearch cluster (e.g. cluster management API calls) | Leader unit only |
| `unit-transport` | Internal communication between OpenSearch nodes (internode traffic) | All units (including leader) |
| `unit-http` | External communication between OpenSearch and clients (users or applications) | All units (including leader) |

Separating certificates by channel allows independent rotation of each category without
affecting the others. For example, you can rotate the `unit-http` certificate (used by
external clients) without disrupting internode communication.

## Certificate lifecycle

Certificates are managed through the TLS certificate provider charm (e.g.
`self-signed-certificates` or `manual-tls-certificates`). The charm generates a
Certificate Signing Request (CSR) for each unit and category, sends it to the provider
for signing, and stores the returned certificate in a password-protected keystore.

### Automatic rotation on expiry

When a certificate expires or is about to expire, the charm automatically requests a new
certificate from the provider. No manual intervention is required.

### Manual rotation

You can manually trigger certificate rotation by regenerating the private key for the
desired category. This generates a new CSR, which is sent to the provider for signing.
Once signed, the new certificate is automatically applied to the cluster.

```shell
juju run opensearch/leader set-tls-private-key category=<category>
```

Where `<category>` is `app-admin`, `unit-transport`, or `unit-http`.

## CA certificate rotation

The CA certificate is provided by the TLS operator and is used to sign all TLS certificates.
Rotating the CA certificate is a more involved process because all nodes must trust the
new CA before they can communicate.

### With `self-signed-certificates`

Trigger CA rotation by changing the common name:

```shell
juju config self-signed-certificates ca-common-name=<new-ca-common-name>
```

This causes the following sequence:

1. A new CA certificate is generated with the new common name.
2. All previously issued TLS certificates are revoked.
3. OpenSearch detects the revoked certificates and automatically requests new ones.
4. Once new certificates are issued, a **rolling restart** is triggered to apply the
   new CA across all nodes.

During the transition, nodes trust both the old and the new CA: the old CA is kept
until the new one is applied to all nodes. This keeps the cluster operational throughout
the rolling restart.

### With `manual-tls-certificates`

CA rotation with the `manual-tls` operator requires manual signing of CSRs with the new
CA certificate. The process is:

1. Sign the existing (or newly generated) CSRs with the new CA certificate.
2. Provide the new certificates to each unit, **starting with the leader**.
3. After receiving the new CA, each node generates new CSRs that must be signed with
   the new CA and provided back.
4. Repeat for every unit in the cluster.

```{caution}
Always distribute certificates to the leader unit first, then to the remaining nodes.
Distributing out of order can cause cluster communication failures.
```

Once all units have the new CA, OpenSearch reloads certificates. A rolling restart is
only required if the issuer, subject, or subject alternative names (SANs) of the new
certificate differ from the previous one. If they are the same, certificates can be
reloaded on the fly without a restart.

## See also

* [How to manage TLS encryption](how-to-enable-tls-encryption) — step-by-step guide for enabling TLS, updating keys, and rotating certificates.
* [Cryptography](explanation-security-cryptography) — details on encryption, keystore, truststore, and authentication.
* [Security hardening guide](explanation-security-index) — overall security guidance.
