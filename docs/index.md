---
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

### Get started

Set up your environment, understand the requirements, and deploy your first Charmed OpenSearch cluster.

| | |
|---|---|
| **Getting started** | [Requirements](reference-system-requirements) • [Tutorial: Introduction](tutorial-index) • [Step 1: Environment setup](tutorial-1-set-up-the-environment)   |
| **Deployment** | [Deploy with LXD](how-to-deploy-lxd) • [Large deployment](how-to-deploy-large) |

### Operate and maintain

Manage day-to-day cluster operations, keep it up to date, and ensure resilience through scaling, backups, and upgrades.

| | |
|---|---|
| **Cluster management** | [Horizontal scaling](how-to-scale-horizontally) • [Applications integration](how-to-integrate-with-an-application) • [Version upgrades](how-to-minor-upgrade) • [Version rollback](how-to-minor-rollback) |
| **Monitoring & performance** | [Monitoring](how-to-monitoring) • [SMTP notifications](how-to-guides-add-smtp-credentials) • [Performance optimization](how-to-optimize-cluster-performance) • [Load testing](how-to-perform-load-testing) • [OpenSearch Dashboards](dashboard-index) |
| **Backups** | [Create a backup](how-to-create-a-backup) • [Azure configuration](how-to-back-up-configure-azure-storage) • [S3 configuration](how-to-back-up-configure-s3) • [Restore from a local backup](how-to-restore-a-local-backup) • [Migrate a cluster](how-to-migrate-a-cluster) • [Recover from attached storage](how-to-persistent-storage) |

### Secure and extend

Protect your cluster with encryption and authentication, and integrate additional tools.

| | |
|---|---|
| **Security** | [Overview](explanation-security-index) • [Enable encryption](how-to-enable-tls-encryption) • [Rotate certificates](how-to-rotate-tls-ca-certificates) • [OAuth](how-to-access-using-oauth) • [JWT Auth](how-to-guides-enable-jwt-authentication) • [Cryptography](explanation-security-cryptography) |
| **Internals** | [Alert rules](alert-rules) • [Monitoring overview](explanation-monitoring) • [Software testing](explanation-software-testing) • [Release notes](reference-release-notes-index) |

## How the documentation is organized

This documentation uses the [Diátaxis documentation structure](https://diataxis.fr/):

- The [Tutorial](tutorial-index) walks you through deploying your first Charmed OpenSearch cluster from scratch, step by step.
- [How-to guides](how-to-index) help you solve specific operational tasks such as enabling TLS, scaling, or integrating with other applications.
- [Reference](reference-index) lets you look up system requirements, release notes, and configuration options.
- [Explanation](explanation-index) helps you understand the design decisions behind security, monitoring, and software testing.

## Project & community

Charmed OpenSearch is an official distribution of OpenSearch.
It’s an open-source project that welcomes community contributions, suggestions,
fixes and constructive feedback:

- Raise an issue or feature request in the [GitHub repository](https://github.com/canonical/opensearch-operator/issues).
- Meet the community and chat with us in our [Matrix channel](https://matrix.to/#/#charmhub-data-platform:ubuntu.com) or [leave a comment](https://discourse.charmhub.io/t/charmed-opensearch-documentation/9729).
- See the Charmed OpenSearch [contribution guidelines](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) on GitHub and read the Ubuntu Community's [Code of Conduct](https://ubuntu.com/community/code-of-conduct).
- Explore [Canonical's open-source data platform](https://canonical.com/data).

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
```

```{toctree}
:caption: OpenSearch Dashboards
:titlesonly:
:hidden:

Dashboards documentation <dashboards/docs/index>
```
