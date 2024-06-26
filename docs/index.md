# Charmed OpenSearch Documentation
[OpenSearch](http://opensearch.org/) is an open-source search and analytics suite. Developers build solutions for search, data observability, 
data ingestion and more using OpenSearch. OpenSearch is offered under the Apache Software Licence, version 2.0, which means the community 
maintains it as free, open-source software. OpenSearch and Dashboards were derived initially from Elasticsearch 7.10.2 and Kibana 7.10.2.

Applications like OpenSearch must be managed and operated in production environments. This means that OpenSearch application administrators and analysts who run workloads in various infrastructures should be able to automate tasks for repeatable operational work. Technologies such 
as software operators encapsulate the knowledge, wisdom and expertise of a real-world operations team and codify it into a computer program that helps to operate complex server applications like OpenSearch and other data applications.

Canonical has developed an open-source operator called [Charmed OpenSearch (VM operator)](https://charmhub.io/opensearch), making it easier to operate OpenSearch. This operator delivers automated operations management from day 0 to day 2 on the [OpenSearch Community Edition](https://github.com/opensearch-project/OpenSearch/).

The Charmed OpenSearch Virtual Machine (VM) operator deploys and operates OpenSearch on physical, Virtual Machines (VM) and other cloud and cloud-like environments, including AWS, Azure, OpenStack and VMWare. In addition, the Charmed OpenSearch (VM operator) uses [Charmed OpenSearch (Snap Package)](https://snapcraft.io/opensearch) as the software package used to build the operator.

Charmed OpenSearch (VM Operator) has multiple operator features such as automated deployment, Transport Layer Security (TLS) implementation, user management and horizontal scaling, replication, password rotation, and easy to use integration with other applications.


## Release and versions

To see the Charmed OpenSearch features and releases, visit our [GitHub Releases page](https://github.com/canonical/opensearch-operator/releases).

The Charmed OpenSearch (VM Operator) release aligns with the [OpenSearch upstream major version naming](https://opensearch.org/docs/latest/version-history/). OpenSearch releases major versions such as 1.0, 2.0, and so on.


A charm version combines both the application major version and / (slash) the channel, e.g. `2/stable`, `2/candidate`, `2/edge`. 
The channels are ordered from the most stable to the least stable, candidate, and edge. More risky channels like edge are always implicitly available. 
So, if the candidate is listed, you can pull the candidate and edge. When stable is listed, all three are available.

The upper portion of this page describes the Operating System (OS) where the charm can run, e.g. 2/stable is compatible and should run on a machine with Ubuntu 22.04 OS.


## Security, Bugs and feature request
If you find a bug in this operator or want to request a specific feature, here are the useful links:
- Raise the issue or feature request in the [Canonical Github repository](https://github.com/canonical/opensearch-operator/issues).
- Meet the community and chat with us if there are issues and feature requests in our [Mattermost Channel](https://chat.charmhub.io/charmhub/channels/data-platform)
and join the [Discourse Forum](https://discourse.charmhub.io/tag/opensearch).


## Contributing
Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, 
and [CONTRIBUTING.md](https://github.com/canonical/mongodb-operator/blob/main/CONTRIBUTING.md) for developer guidance.

[Read our Code of Conduct](https://ubuntu.com/community/code-of-conduct).


## Trademark notice
OpenSearch is a registered trademark of Amazon Web Services. Other trademarks are property of their respective owners. Charmed OpenSearch is not sponsored, 
endorsed, or affiliated with Amazon Web Services.


## License
The Charmed OpenSearch ROCK, Charmed OpenSearch Snap, and Charmed OpenSearch Operator are free software, distributed under the 
[Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/main/licenses/LICENSE-rock). They install and operate OpenSearch, 
which is also licensed under the [Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/main/licenses/LICENSE-opensearch).

This documentation follows the [Diataxis Framework](https://canonical.com/blog/diataxis-a-new-foundation-for-canonical-documentation)

## Navigation


| Level | Path                       | Navlink                                      |
|----------|-------------------------|----------------------------------------------|
| 1     | tutorial                   | [Tutorial]()                                 |
| 2     | t-overview                 | [1. Introduction](/t/9722)                   |
| 2     | t-setup-environment        | [2. Set up the environment](/t/9724)         |
| 2     | t-deploy-opensearch        | [3. Deploy OpenSearch](/t/9716)              |
| 2     | t-enable-tls               | [4. Enable encryption](/t/9718)              |
| 2     | t-connecting-to-opensearch | [5. Connect to OpenSearch](/t/9714)          |
| 2     | t-user-management          | [6. Manage user](/t/9728)                    |
| 2     | t-horizontal-scaling       | [7. Scale deployment horizontally](/t/9720)  |
| 2     | t-teardown                 | [8. Cleanup your environment](/t/9726)       |
| 1     | how-to                     | [How To]()                                   |
| 2     | h-safe-horizontal-scaling  | [Safe horizontal scaling](/t/10994)          |
| 2     | h-backup                   | [Manage backups]()                           |
| 3     | h-configure-s3             | [Configure S3](/t/14097)                     |
| 3     | h-create-backup            | [Create a backup](/t/14098)                  |
| 3     | h-restore-local-backup     | [Restore a local backup](/t/14099)           |
| 3     | h-migrate-cluster          | [Migrate a cluster](/t/14100)                |
| 1     | reference                  | [Reference]()                                |
| 2     | r-testing                  | [Charm Testing reference](/t/14109)                                |

# Contents

1. [Tutorial](tutorial)
  1. [1. Introduction](tutorial/t-overview.md)
  1. [2. Set up the environment](tutorial/t-setup-environment.md)
  1. [3. Deploy OpenSearch](tutorial/t-deploy-opensearch.md)
  1. [4. Enable encryption](tutorial/t-enable-tls.md)
  1. [5. Connect to OpenSearch](tutorial/t-connecting-to-opensearch.md)
  1. [6. Manage user](tutorial/t-user-management.md)
  1. [7. Scale deployment horizontally](tutorial/t-horizontal-scaling.md)
  1. [8. Cleanup your environment](tutorial/t-teardown.md)
1. [How To](how-to)
  1. [Safe horizontal scaling](how-to/h-safe-horizontal-scaling.md)
  1. [Manage backups](how-to/h-backup)
    1. [Configure S3](how-to/h-backup/h-configure-s3.md)
    1. [Create a backup](how-to/h-backup/h-create-backup.md)
    1. [Restore a local backup](how-to/h-backup/h-restore-local-backup.md)
    1. [Migrate a cluster](how-to/h-backup/h-migrate-cluster.md)
1. [Reference](reference)
  1. [Charm Testing reference](reference/r-testing.md)