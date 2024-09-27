# Charmed OpenSearch Documentation
Charmed OpenSearch is an open-source software operator that packages the [OpenSearch](http://opensearch.org/) search and data analytics suite with simplified deployment, operation, and management via the Juju CLI. It can be deployed on physical and virtual machines, as well as other cloud and cloud-like environments, including AWS, Azure, OpenStack and VMWare. 

Charmed OpenSearch  has multiple operator features such as automated deployment, TLS encryption, user management, horizontal scaling, replication, password rotation, and easy integration with other applications. 

This charm is for anyone looking for a complete data analytics suite. You could be a team of system administrators maintaining large data infrastructures, a software developer who wants to connect their application with a powerful search engine, or even someone curious to learn more about Charmed OpenSearch through our guided tutorial.

To see the Charmed OpenSearch features and releases, visit our [GitHub Releases page](https://github.com/canonical/opensearch-operator/releases).
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
|  [**Tutorials**](/t/9722)</br>  [Get started](/t/9722) - a hands-on introduction to using the Charmed OpenSearch operator for new users </br> |  [**How-to guides**](/t/10994) </br> Step-by-step guides covering key operations such as [scaling](/t/10994), [TLS encryption](/t/14783), or [monitoring](/t/14560) |
| [**Reference**](/t/14109) </br> Technical information such as [system requirements](/t/14565) | <!--[Explanation]() </br> Concepts - discussion and clarification of key topics-->  |

## Project & community
Charmed OpenSearch is an official distribution of OpenSearch . It’s an open-source project that welcomes community contributions, suggestions, fixes and constructive feedback.
- Raise an issue or feature request in the [Github repository](https://github.com/canonical/opensearch-operator/issues).
- Meet the community and chat with us in our [Matrix channel](https://matrix.to/#/#charmhub-data-platform:ubuntu.com) or [leave a comment](https://discourse.charmhub.io/t/charmed-opensearch-documentation/9729).
- See the Charmed OpenSearch [contribution guidelines](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) on GitHub and read the Ubuntu Community's [Code of Conduct](https://ubuntu.com/community/code-of-conduct).

## License & trademark
The Charmed OpenSearch ROCK, Charmed OpenSearch Snap, and Charmed OpenSearch Operator are free software, distributed under the 
[Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/main/licenses/LICENSE-rock). They install and operate OpenSearch, 
which is also licensed under the [Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/main/licenses/LICENSE-opensearch).

OpenSearch is a registered trademark of Amazon Web Services. Other trademarks are property of their respective owners. Charmed OpenSearch is not sponsored, 
endorsed, or affiliated with Amazon Web Services.

This documentation follows the [Diataxis Framework](https://canonical.com/blog/diataxis-a-new-foundation-for-canonical-documentation).

## Navigation

[details=Navigation]

| Level | Path                       | Navlink                                      |
|----------|-------------------------|----------------------------------------------|
| 1 | tutorial | [Tutorial]()                                 |
| 2 | t-overview | [Overview](/t/9722) |
| 2 | t-set-up | [1. Set up the environment](/t/9724) |
| 2 | t-deploy-opensearch | [2. Deploy OpenSearch](/t/9716) |
| 2 | t-enable-tls | [3. Enable encryption](/t/9718) |
| 2 | t-integrate | [4. Integrate with a client application](/t/9714) |
| 2 | t-passwords | [5. Manage passwords](/t/9728) |
| 2 | t-horizontal-scaling | [6. Scale horizontally](/t/9720)  |
| 2 | t-clean-up | [7. Clean up the environment](/t/9726) |
| 1 | how-to | [How To]() |
| 2 | h-deploy-lxd | [Deploy on LXD](/t/14575) |
| 2 | h-large-deployment | [Launch a large deployment](/t/15573) |
| 2 | h-horizontal-scaling  | [Scale horizontally](/t/10994) |
| 2 | h-integrate | [Integrate with your charm](/t/15333) |
| 2 | h-enable-tls | [Enable TLS encryption](/t/14783) |
| 2 | h-rotate-tls-ca-certificates   | [Rotate TLS/CA certificates](/t/15422) |
| 2 | h-enable-monitoring | [Enable monitoring](/t/14560) |
| 2 | h-load-testing | [Perform load testing](/t/13987) |
| 2 | h-attached-storage| [Recover from attached storage](/t/15616) |
| 2 | h-backups | [Back up and restore]() |
| 3 | h-configure-s3 | [Configure S3](/t/14097) |
| 3 | h-create-backup | [Create a backup](/t/14098) |
| 3 | h-restore-backup | [Restore a local backup](/t/14099) |
| 3 | h-migrate-cluster | [Migrate a cluster](/t/14100) |
| 2 | h-upgrade | [Upgrade]() |
| 3 | h-minor-upgrade | [Perform a minor upgrade](/t/14141) |
| 3 | h-minor-rollback | [Perform a minor rollback](/t/14142) |
| 1 | reference | [Reference]() |
| 2 | release-notes| [Release notes]() |
| 3 | revision-168| [Revision 168](/t/14050) |
| 2 | r-system-requirements | [System requirements](/t/14565) |
| 2 | r-software-testing | [Charm testing](/t/14109) |

[/details]