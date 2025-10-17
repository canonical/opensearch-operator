(explanation-security-cryptography)=
# Cryptography

This document describes the cryptography used by Charmed OpenSearch.

## Resource checksums

Charmed OpenSearch and Charmed OpenSearch Dashboards operators use pinned revisions
of their respective snaps to provide reproducible and secure environments.

The [Charmed OpenSearch snap](https://snapstore.io/opensearch) and
[Charmed OpenSearch Dashboards snap](https://snapstore.io/opensearch-dashboards)
package the OpenSearch and OpenSearch Dashboards workloads, respectively,
along with the necessary dependencies and utilities for operator lifecycle management.
For details on the contents of these snaps, refer to the `snapcraft.yaml` file in the source code:
[Charmed OpenSearch snap contents](https://github.com/canonical/opensearch-snap/blob/2/edge/snap/snapcraft.yaml)
and
[Charmed OpenSearch Dashboards snap contents](https://github.com/canonical/opensearch-dashboards-snap/blob/2/edge/snap/snapcraft.yaml).

Every artifact included in the snaps is verified against its SHA-256 or SHA-512 checksum after download.

## Sources verification

Charmed OpenSearch sources are stored in:

* GitHub repositories for snaps, rocks and charms
* LaunchPad repositories for the OpenSearch and OpenSearch Dashboards upstream fork used for building their respective distributions

### LaunchPad

Distributions are built using private repositories only, hosted as part of the
[SOSS namespace](https://launchpad.net/soss) to eventually integrate with Canonical’s
standard process for fixing CVEs.
Branches associated with releases are mirrored to a public repository, hosted in the
[Data Platform namespace](https://launchpad.net/~data-platform) to also provide the community
with the patched source code.

### GitHub

All OpenSearch artifacts built by Canonical are published and released programmatically
using release pipelines implemented via GitHub Actions.
Distributions are published as both GitHub and LaunchPad releases via the
[central-uploader repository](https://github.com/canonical/central-uploader),
while charms, snaps and rocks are published using the workflows of their respective repositories.

All repositories in GitHub are set up with branch protection rules, requiring:

* new commits to be merged to main branches via pull request with at least 2 approvals from repository maintainers
* new commits to be signed (e.g. using GPG keys)
* developers to sign the [Canonical Contributor License Agreement (CLA)](https://ubuntu.com/legal/contributors)

## Encryption

Charmed OpenSearch can be used to deploy a secure OpenSearch cluster that provides
encryption-in-transit capabilities out of the box for:

* Internode communications
* OpenSearch Dashboard connection
* External client connection

To set up a secure connection Charmed OpenSearch and Charmed OpenSearch Dashboards
applications need to be integrated with TLS Certificate Provider charms,
e.g. self-signed-certificates operator. Certificate Signing Requests (CSRs) are generated
for every unit using the tls_certificates_interface library that uses
the cryptography Python library to create X.509 compatible certificates.
The CSR is signed by the TLS Certificate Provider, returned to the units, and stored
in a password-protected Keystore file. The password of the Keystore is stored in Juju secrets.
The relation also provides the CA certificate, which is loaded into a password-protected
Truststore file.

When encryption is enabled, hostname verification is turned on for client connections,
including inter-node communication. The cipher suite can be customized by specifying
a list of allowed cipher suites for external clients and OpenSearch Dashboards connections.

Encryption at rest is currently not supported, although it can be provided by the substrate
(cloud or on-premises).

## Authentication

In Charmed OpenSearch, authentication layers can be enabled for:

1. OpenSearch Dashboards connections
2. OpenSearch inter-node communication
3. OpenSearch clients

### OpenSearch authentication to OpenSearch Dashboards

Authentication to OpenSearch Dashboards is based on HTTP basic authentication
with username and password and implemented both for client-server (with OpenSearch)
and server-server communication. Username and passwords are exchanged using peer relations
among OpenSearch units and using normal relations between OpenSearch and Opensearch Dashboards.

The file needs to be readable and writable by root (as it is created by the charm)
and readable by the snap_daemon user running the OpenSearch server snap commands.

### OpenSearch inter-node authentication

Authentication among nodes is based on the HTTP basic authentication with username and password.
Usernames and passwords are exchanged via peer relations.

The OpenSearch username and password, used by nodes to authenticate one another,
are stored in an OpenSearch configuration file in plain text format.

The file needs to be readable and writable by root (as it is created by the charm)
and readable by the snap_daemon user running the OpenSearch server snap commands.

### Client authentication to OpenSearch

Authentication among nodes is based on the HTTP basic authentication with username and password.
Usernames and passwords are exchanged via peer relations.

Usernames and passwords are stored in OpenSearch to be used by the OpenSearch processes
and their filesystem structure, in peer-relation data to be used by the OpenSearch charm
and in external relation to be shared with client applications.
