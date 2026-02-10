---
myst:
  html_meta:
    description: "Deploy and manage OpenSearch clusters with automated operations, TLS encryption, backups, and horizontal scaling on any cloud using Juju."
---

(index)=
# Charmed OpenSearch Documentation

Charmed OpenSearch is an open-source software operator that packages the
[OpenSearch](http://opensearch.org/) search and data analytics suite with simplified deployment,
operation, and management via the Juju CLI. It can be deployed on physical and virtual machines,
as well as other cloud and cloud-like environments, including AWS, Azure, OpenStack and VMWare.

Charmed OpenSearch  has multiple operator features such as automated deployment, TLS encryption,
user management, horizontal scaling, replication, password rotation, and easy integration
with other applications.

This charm is for anyone looking for a complete data analytics suite.
You could be a team of system administrators maintaining large data infrastructures,
a software developer who wants to connect their application with a powerful search engine,
or even someone curious to learn more about Charmed OpenSearch through our guided tutorial.

To see the Charmed OpenSearch features and releases, visit our
[GitHub Releases page](https://github.com/canonical/opensearch-operator/releases).

<!--
The Charmed OpenSearch (VM Operator) release aligns with the [OpenSearch upstream major version naming](https://opensearch.org/docs/latest/version-history/). OpenSearch releases major versions such as 1.0, 2.0, and so on.

A charm version combines both the application major version and / (slash) the channel, e.g. `2/stable`, `2/candidate`, `2/edge`. 
The channels are ordered from the most stable to the least stable, candidate, and edge. More risky channels like edge are always implicitly available. 
So, if the candidate is listed, you can pull the candidate and edge. When stable is listed, all three are available.

The upper portion of this page describes the Operating System (OS) where the charm can run, e.g. 2/stable is compatible and should run on a machine with Ubuntu 22.04 OS.
-->

## In this documentation

| | |
|--|--|
| **Tutorial** | [Introduction](tutorial-index) • [Step 1: Environment setup](tutorial-1-set-up-the-environment) |
| **Deployment** | [Deploy with LXD](how-to-deploy-lxd) • [Large deployment](how-to-deploy-large) • [Requirements](reference-system-requirements) |
| **Operations** | [Horizontal scaling](how-to-scale-horizontally) • [Performance optimization](how-to-optimize-cluster-performance) • [Applications integration](how-to-integrate-with-an-application) • [Version upgrades](how-to-minor-upgrade) • [Version rollback](how-to-minor-rollback) • [Monitoring](how-to-monitoring) • [Load testing](how-to-perform-load-testing) • [Software testing](explanation-software-testing) |
| **Backups** | [Create a backup](how-to-create-a-backup) • [Azure configuration](how-to-back-up-configure-azure-storage) • [S3 configuration](how-to-back-up-configure-s3) • [Restore from a local backup](how-to-restore-a-local-backup) • [Migrate a cluster](how-to-migrate-a-cluster) • [Recover from attached storage](how-to-persistent-storage) |
| **Security** | [Overview](explanation-security-index) • [Enable encryption](how-to-enable-tls-encryption) • [Rotate certificates](how-to-rotate-tls-ca-certificates) • [OAuth](how-to-access-using-oauth) • [JWT Auth](how-to-guides-enable-jwt-authentication) • [Cryptography](explanation-security-cryptography) |

## How the documentation is organised

[Tutorial](tutorial-index): For new users needing to learn how to use Charmed OpenSearch <br>
[How-to guides](how-to-index): For users needing step-by-step instructions to achieve a practical goal <br>
[Reference](reference-index): For precise, theoretical, factual information to be used while working with the charm <br>
[Explanation](explanation-index): For deeper understanding of key Charmed OpenSearch concepts <br>

## Project & community

Charmed OpenSearch is an official distribution of OpenSearch.
It’s an open-source project that welcomes community contributions, suggestions,
fixes and constructive feedback:

- Raise an issue or feature request in the [Github repository](https://github.com/canonical/opensearch-operator/issues).
- Meet the community and chat with us in our [Matrix channel](https://matrix.to/#/#charmhub-data-platform:ubuntu.com) or [leave a comment](https://discourse.charmhub.io/t/charmed-opensearch-documentation/9729).
- See the Charmed OpenSearch [contribution guidelines](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) on GitHub and read the Ubuntu Community's [Code of Conduct](https://ubuntu.com/community/code-of-conduct).

## License & trademark

The Charmed OpenSearch ROCK, Charmed OpenSearch snap,
and Charmed OpenSearch Operator are free software, distributed under the
[Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/2-24.04/edge/licenses/LICENSE-rock).
They install and operate OpenSearch, which is also licensed under the
[Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/2-24.04/edge/licenses/LICENSE-opensearch).

OpenSearch is a registered trademark of Amazon Web Services.
Other trademarks are property of their respective owners. Charmed OpenSearch is not sponsored,
endorsed, or affiliated with Amazon Web Services.

This documentation follows the
[Diataxis framework](https://canonical.com/blog/diataxis-a-new-foundation-for-canonical-documentation).

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
