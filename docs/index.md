# Charmed OpenSearch Documentation
Charmed OpenSearch is a software operator that packages the open-source [OpenSearch](http://opensearch.org/) search and data analytics suite with a system for simplified deployment, operation, and management. 

Applications like OpenSearch must be managed and operated in production environments. This means that administrators and analysts who run workloads in various infrastructures should be able to automate tasks for repeatable operational work. Charmed software operators encapsulate the expertise of a real-world operations team into a set of tools that helps to operate complex server applications like OpenSearch and other data applications.

The Charmed OpenSearch Virtual Machine (VM) operator deploys and operates OpenSearch on physical and virtual machines, as well as other cloud and cloud-like environments, including AWS, Azure, OpenStack and VMWare. It uses the [Charmed OpenSearch Snap](https://snapcraft.io/opensearch) to build the operator.

Charmed OpenSearch  has multiple operator features such as automated deployment, TLS encryption, user management, horizontal scaling, replication, password rotation, and easy to use integration with other applications.

## In this documentation
| | |
|--|--|
|  [Tutorials](/t/9722)</br>  Get started - a hands-on introduction to using the Charmed OpenSearch operator for new users </br> |  [How-to guides](/t/10994) </br> Step-by-step guides covering key operations and common tasks |
| [Reference](/t/14109) </br> Technical information - specifications, APIs, architecture | [Explanation]() </br> Concepts - discussion and clarification of key topics  |


## Release and versions

To see the Charmed OpenSearch features and releases, visit our [GitHub Releases page](https://github.com/canonical/opensearch-operator/releases).
<!--
The Charmed OpenSearch (VM Operator) release aligns with the [OpenSearch upstream major version naming](https://opensearch.org/docs/latest/version-history/). OpenSearch releases major versions such as 1.0, 2.0, and so on.

A charm version combines both the application major version and / (slash) the channel, e.g. `2/stable`, `2/candidate`, `2/edge`. 
The channels are ordered from the most stable to the least stable, candidate, and edge. More risky channels like edge are always implicitly available. 
So, if the candidate is listed, you can pull the candidate and edge. When stable is listed, all three are available.

The upper portion of this page describes the Operating System (OS) where the charm can run, e.g. 2/stable is compatible and should run on a machine with Ubuntu 22.04 OS.
-->

## Project & community
If you find a bug in this operator or want to request a specific feature, here are the useful links:
- Raise the issue or feature request in the [Canonical Github repository](https://github.com/canonical/opensearch-operator/issues).
- Meet the community and chat with us if there are issues and feature requests in our [Mattermost Channel](https://chat.charmhub.io/charmhub/channels/data-platform)
and join the [Discourse Forum](https://discourse.charmhub.io/tag/opensearch).

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, 
and [CONTRIBUTING.md](https://github.com/canonical/mongodb-operator/blob/main/CONTRIBUTING.md) for developer guidance.

[Read our Code of Conduct](https://ubuntu.com/community/code-of-conduct).

## License & trademark
The Charmed OpenSearch ROCK, Charmed OpenSearch Snap, and Charmed OpenSearch Operator are free software, distributed under the 
[Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/main/licenses/LICENSE-rock). They install and operate OpenSearch, 
which is also licensed under the [Apache Software License, version 2.0](https://github.com/canonical/charmed-opensearch-rock/blob/main/licenses/LICENSE-opensearch).

OpenSearch is a registered trademark of Amazon Web Services. Other trademarks are property of their respective owners. Charmed OpenSearch is not sponsored, 
endorsed, or affiliated with Amazon Web Services.

This documentation follows the [Diataxis Framework](https://canonical.com/blog/diataxis-a-new-foundation-for-canonical-documentation).

## Navigation


| Level | Path                       | Navlink                                      |
|----------|-------------------------|----------------------------------------------|
| 1     | tutorial                   | [Tutorial]()                                 |
| 2     | t-overview                 | [Overview](/t/9722)                   |
| 2     | t-set-up        | [1. Set up the environment](/t/9724)         |
| 2     | t-deploy-opensearch        | [2. Deploy OpenSearch](/t/9716)              |
| 2     | t-enable-tls               | [3. Enable encryption](/t/9718)              |
| 2     | t-integrate | [4. Integrate with a client application](/t/9714)          |
| 2     | t-passwords          | [5. Manage passwords](/t/9728)                    |
| 2     | t-horizontal-scaling       | [6. Scale horizontally](/t/9720)  |
| 2     | t-clean-up                 | [7. Clean up the environment](/t/9726)       |
| 1     | how-to                     | [How To]()                                   |
| 2     | h-horizontal-scaling  | [Scale horizontally](/t/10994)          |
| 2     | h-enable-tls   | [Enable TLS encryption](/t/14783)          |
| 2     | h-enable-monitoring | [Enable monitoring](/t/14560) |
| 2     | h-backups                   | [Back up and restore]()                           |
| 3     | h-configure-s3             | [Configure S3](/t/14097)                     |
| 3     | h-create-backup            | [Create a backup](/t/14098)                  |
| 3     | h-restore-backup     | [Restore a local backup](/t/14099)           |
| 3     | h-migrate-cluster          | [Migrate a cluster](/t/14100)                |
| 2     | h-contribute | [Contribute](/t/14557) |
| 1     | reference                  | [Reference]()                                |
| 2     | r-system-requirements | [System requirements](/t/14565) |
| 2     | r-software-testing                  | [Charm testing](/t/14109)                                |

# Contents

1. [Tutorial](tutorial)
  1. [Overview](tutorial/t-overview.md)
  1. [1. Set up the environment](tutorial/t-set-up.md)
  1. [2. Deploy OpenSearch](tutorial/t-deploy-opensearch.md)
  1. [3. Enable encryption](tutorial/t-enable-tls.md)
  1. [4. Integrate with a client application](tutorial/t-integrate.md)
  1. [5. Manage passwords](tutorial/t-passwords.md)
  1. [6. Scale horizontally](tutorial/t-horizontal-scaling.md)
  1. [7. Clean up the environment](tutorial/t-clean-up.md)
1. [How To](how-to)
  1. [Scale horizontally](how-to/h-horizontal-scaling.md)
  1. [Enable TLS encryption](how-to/h-enable-tls.md)
  1. [Enable monitoring](how-to/h-enable-monitoring.md)
  1. [Back up and restore](how-to/h-backups)
    1. [Configure S3](how-to/h-backups/h-configure-s3.md)
    1. [Create a backup](how-to/h-backups/h-create-backup.md)
    1. [Restore a local backup](how-to/h-backups/h-restore-backup.md)
    1. [Migrate a cluster](how-to/h-backups/h-migrate-cluster.md)
  1. [Contribute](how-to/h-contribute.md)
1. [Reference](reference)
  1. [System requirements](reference/r-system-requirements.md)
  1. [Charm testing](reference/r-software-testing.md)