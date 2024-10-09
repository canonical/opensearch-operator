# Revision 168 release notes
<sub>24 September 2024</sub>

Charmed OpenSearch Revision 168 has been deployed to the [`2/stable` channel](https://charmhub.io/opensearch?channel=2/stable) on Charmhub.

To upgrade from a previous revision of the OpenSearch charm, see [how to perform a minor upgrade](https://charmhub.io/opensearch/docs/h-minor-upgrade).

## Summary
* [Highlights and features](#highlights)
* [Requirements and compatibility](#requirements-and-compatibility)
* [Integrations](#integrations)
* [Software contents](#software-contents)
* [Known issues and limitations](#known-issues-and-limitations)
* [Join the community](#join-the-community)

---

## Highlights
This section goes over the features included in this release, starting with a description of major highlights, and finishing with a comprehensive list of [all other features](#other-features).

### Large scale deployments

Deploy a single OpenSearch cluster composed of multiple Juju applications. Each application executes any of the available roles in OpenSearch. Large deployments support a diverse range of deployment constraints, roles, and regions.
* [How to set up a large deployment](/t/15573)

### Security automations

Manage TLS certificates and passwords in single point with Juju integrations and rotate your TLS certificates without any downtime.

* [How to enable TLS encryption](/t/14783)
* [How to rotate TLS/CA certificates](/t/15422)

### Monitoring

Integrate with the Canonical Observability Stack (COS) and the OpenSearch Dashboards charm to monitor operational performance and visualize stored data across all clusters.

* [How to enable monitoring](/t/14560)
* [OpenSearch Dashboards: How to connect to OpenSearch](/t/https://charmhub.io/opensearch-dashboards/docs/h-db-connect)

### Backups

Backup and restore with an Amazon S3-compatible storage backend.

* [How to configure S3 storage](/t/14097)
* [How to create a backup](/t/14098)

### Other features
* **Automated rolling restart**
* **Automated minor upgrade** of OpenSearch version
* **Automated deployment** for single and multiple clusters
* **Backup and restore** for single and multiple clusters
* **User management** and automated user and index setup with the [Data Integrator charm](https://charmhub.io/data-integrator)
* **TLS encryption** (HTTP and transport layers) and certificate rotation
* **Observability** of OpenSearch clusters and operational tooling via COS and the 
 [OpenSearch Dashboards charm](https://charmhub.io/opensearch-dashboards)
* **Plugin management**: Index State Management, KNN and MLCommons
* **OpenSearch security patching** and bug-fixing mechanisms

For a detailed list of commits throughout all revisions, check our [GitHub Releases](https://github.com/canonical/opensearch-operator/releases).

## Requirements and compatibility
* Juju `v3.5.3+`
  * Older minor versions of Juju 3 may be compatible, but are not officially supported.
* LXD `v6.1`
  * Older LXD versions may be compatible, but are not officially supported.
* Integration with a TLS charm
  * [`self-signed-certificates`](https://charmhub.io/self-signed-certificates) revision 155+ or [`manual-tls-certificates`](https://charmhub.io/manual-tls-certificates) revision 108+

See the [system requirements page](/t/14565) for more information about software and hardware prerequisites.

## Integrations

Like all Juju charms, OpenSearch can easily integrate with other charms by implementing common interfaces/endpoints.

OpenSearch can be seamlessly integrated out of the box with:

* [TLS certificates charms](https://charmhub.io/topics/security-with-x-509-certificates#heading--understanding-your-x-509-certificates-requirements)
  * **Note**: Charmed OpenSearch supports integration with [tls-certificates library](https://charmhub.io/tls-certificates-interface/libraries/tls_certificates) `v2` or higher.
* [COS Lite](https://charmhub.io/cos-lite)
* [OpenSearch Dashboards](https://charmhub.io/opensearch-dashboards)
* [Data Integrator](https://charmhub.io/data-integrator)
* [S3 Integrator](https://charmhub.io/s3-integrator)

See the [Integrations page](https://charmhub.io/opensearch/integrations) for a list of all interfaces and compatible charms.

## Software contents

This charm is based on the Canonical [opensearch-snap](https://github.com/canonical/opensearch-snap). It packages:
* OpenSearch v2.17.0
* OpenJDK `v21`

## Known issues and limitations

The following issues are known and scheduled to be fixed in the next maintenance release.

* We currently do not support node role repurposing from cluster manager to a non cluster manager
* Storage re-attachment from previous clusters is not currently automated. For manual instructions, see the how-to guide [How to recover from attached storage](/t/15616).

## Join the community

Charmed OpenSearch is an official distribution of OpenSearch . It’s an open-source project that welcomes community contributions, suggestions, fixes and constructive feedback.

* Raise an issue or feature request in the [GitHub repository](https://github.com/canonical/opensearch-operator/issues).
* Meet the community and chat with us in our [Matrix channel](https://matrix.to/#/#charmhub-data-platform:ubuntu.com) or [leave a comment](https://discourse.charmhub.io/t/charmed-opensearch-documentation/9729).
* See the Charmed OpenSearch [contribution guidelines](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) on GitHub and read the Ubuntu Community's [Code of Conduct](https://ubuntu.com/community/code-of-conduct).