---
relatedlinks: "[GitHub](https://github.com/canonical/opensearch-operator), [Charmhub](https://charmhub.io/opensearch), [Charmhub&#32;(K8s)](https://charmhub.io/opensearch-k8s)"
myst:
  html_meta:
    description: "Deploy and manage OpenSearch clusters with automated operations, TLS encryption, backups, and horizontal scaling on any cloud using Juju."
---

(index)=
# Charmed OpenSearch documentation

Charmed OpenSearch is an open-source operator, packaged as a
[Juju charm](https://documentation.ubuntu.com/juju/3.6/reference/charm/),
that simplifies the deployment, scaling, and management of
[OpenSearch](http://opensearch.org/) clusters on physical hardware, VMs,
and cloud environments including AWS, Azure, OpenStack, and VMware.

The charm automates OpenSearch operations from
[Day 0 to Day 2](https://codilime.com/blog/day-0-day-1-day-2-the-software-lifecycle-in-the-cloud-age/)
with capabilities such as TLS encryption, user management, horizontal scaling,
replication, password rotation, monitoring, and application integration.

## In this documentation

Charmed OpenSearch documentation has the following topics.

### Get started

| | |
|---|---|
| **Getting started** | [Requirements](reference-system-requirements) • [Tutorial: Introduction](tutorial-index) • [Step 1: Environment setup](tutorial-1-set-up-the-environment) |
| **Deployment** | [Standard deployment](how-to-deploy-standard) • [Large deployment](how-to-deploy-large) |
| **Cluster management** | [Horizontal scaling](how-to-scale-horizontally) • [Applications integration](how-to-integrate-with-an-application) • [Version upgrades](how-to-minor-upgrade) • [Version rollback](how-to-minor-rollback) |
| **Monitoring & performance** | [Monitoring](how-to-monitoring) • [SMTP notifications](how-to-guides-add-smtp-credentials) • [Performance optimization](how-to-optimize-cluster-performance) • [Load testing](how-to-perform-load-testing) • [OpenSearch Dashboards](dashboard-index) |
| **Backups** | [Create a backup](how-to-create-a-backup) • [Azure configuration](how-to-back-up-configure-azure-storage) • [S3 configuration](how-to-back-up-configure-s3) • [Restore from a local backup](how-to-restore-a-local-backup) • [Migrate a cluster](how-to-migrate-a-cluster) • [Recover from attached storage](how-to-persistent-storage) |
| **Security** | [Overview](explanation-security-index) • [Enable encryption](how-to-enable-tls-encryption) • [Rotate certificates](how-to-rotate-tls-ca-certificates) • [Manage passwords](how-to-manage-passwords) • [OAuth](how-to-access-using-oauth) • [JWT Auth](how-to-guides-enable-jwt-authentication) • [Cryptography](explanation-security-cryptography) |
| **Internals** | [Node roles](explanation-node-roles) • [Cluster health](explanation-cluster-health) • [Performance profiles](explanation-performance-profiles) • [Persistent storage](explanation-persistent-storage) • [TLS certificates](explanation-tls-certificates) • [Alert rules](ref-alert-rules) • [Monitoring overview](explanation-monitoring) • [Software testing](explanation-software-testing) • [Release notes](reference-release-notes-index) |
| **Contributing** | [Contribute](contributing-guide) |

## How the documentation is organized

This documentation uses the [Diátaxis documentation structure](https://diataxis.fr/):

- The [Tutorial](tutorial-index) walks you through deploying your first Charmed OpenSearch cluster from scratch, step by step.
- [How-to guides](how-to-index) help you solve specific operational tasks such as enabling TLS, scaling, or integrating with other applications.
- [Reference](reference-index) lets you look up system requirements, release notes, and configuration options.
- [Explanation](explanation-index) helps you understand the design decisions behind security, monitoring, and software testing.

## Project & community

Charmed OpenSearch is an official distribution of OpenSearch.
It’s an open-source project that welcomes community contributions, suggestions,
fixes and constructive feedback.

### Get involved

- [Join the Discourse forum](https://discourse.charmhub.io/tag/opensearch)
- [Chat with us on Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
- [Report an issue](https://github.com/canonical/opensearch-operator/issues/new)
- [Contribute](contributing-guide) to the code and documentation
- Explore [Canonical's open-source data platform](https://canonical.com/data)

### Governance and policies

- [Read our Code of Conduct](https://ubuntu.com/community/code-of-conduct)
- [Report a security issue](https://wiki.ubuntu.com/DebuggingSecurity#How_to_File) — please do not use GitHub issues for security topics
- [Canonical Contributor Agreement](https://ubuntu.com/legal/contributors)

## License & trademark

The Charmed OpenSearch ROCK, Charmed OpenSearch snap,
and Charmed OpenSearch Operator are free software, distributed under the
[Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/2-24.04/edge/licenses/LICENSE-rock).
They install and operate OpenSearch, which is also licensed under the
[Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/2-24.04/edge/licenses/LICENSE-opensearch).

OpenSearch is a registered trademark of Amazon Web Services.
Other trademarks are property of their respective owners. Charmed OpenSearch is not sponsored,
endorsed, or affiliated with Amazon Web Services.

```{toctree}
:titlesonly:
:hidden:

Home <self>
tutorial/index
how-to/index
reference/index
explanation/index
Contributor's guide<contributing>
```

```{toctree}
:caption: OpenSearch Dashboards
:titlesonly:
:hidden:

Dashboards documentation <dashboards/docs/index>
```
