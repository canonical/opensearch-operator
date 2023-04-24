# Charmed OpenSearch Documentation
[OpenSearch](http://opensearch.org/) is an open-source search and analytics suite. Developers build solutions for search, data observability, 
data ingestion and more using OpenSearch. OpenSearch is offered under the Apache Software Licence, version 2.0, which means the community 
maintains it as free, open-source software. OpenSearch and Dashboards were derived initially from Elasticsearch 7.10.2 and Kibana 7.10.2.

Applications like OpenSearch must be managed and operated in production environments. This means that OpenSearch application administrators 
and analysts who run workloads in various infrastructures should be able to automate tasks for repeatable operational work. Technologies such 
as software operators encapsulate the knowledge, wisdom and expertise of a real-world operations team and codify it into a computer program 
that helps to operate complex server applications like OpenSearch and other data applications.

Canonical has developed an open-source operator called [Charmed OpenSearch (VM operator)](https://charmhub.io/opensearch), making it easier 
to operate OpenSearch. This operator delivers automated operations management from day 0 to day 2 on the [OpenSearch Community Edition](https://github.com/opensearch-project/OpenSearch/).

The Charmed OpenSearch Virtual Machine (VM) operator deploys and operates OpenSearch on physical, Virtual Machines (VM) and other cloud 
and cloud-like environments, including AWS, Azure, OpenStack and VMWare. In addition, the Charmed OpenSearch (VM operator) uses 
[Charmed OpenSearch (Snap Package)](https://snapcraft.io/opensearch) as the software package used to build the operator.

Charmed OpenSearch (VM Operator) has multiple operator features such as automated deployment, Transport Layer Security (TLS) implementation, 
user management and horizontal scaling, replication, password rotation, and easy to use integration with other applications.


## Release and versions

To see the Charmed OpenSearch features and releases, visit our [Github Releases page](https://github.com/canonical/opensearch-operator/releases).

The Charmed OpenSearch (VM Operator) release aligns with the [OpenSearch upstream major version naming](https://opensearch.org/docs/latest/version-history/). 
OpenSearch releases major versions such as 1.0, 2.0, and so on.


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


| Level | Path                       | Navlink                                                                                    |
|-------|----------------------------|--------------------------------------------------------------------------------------------|
| 1     | tutorial                   | [Tutorial]()                                                                               |
| 2     | t-overview                 | [1. Introduction](/t/charmed-opensearch-tutorial-overview/9722)                            |
| 2     | t-setup-environment        | [2. Set up the environment](/t/charmed-opensearch-tutorial-setup-environment/9724)         |
| 2     | t-deploy-opensearch        | [3. Deploy OpenSearch](/t/charmed-opensearch-tutorial-deploy-opensearch/9716)              |
| 2     | t-enable-tls               | [4. Enable encryption](/t/charmed-opensearch-tutorial-enable-tls/9718)                     |
| 2     | t-connecting-to-opensearch | [5. Connect to OpenSearch](/t/charmed-opensearch-tutorial-connecting-to-opensearch/9714)   |
| 2     | t-user-management          | [6. Manage user](/t/charmed-opensearch-tutorial-user-management/9728)                      |
| 2     | t-horizontal-scaling       | [7. Scale deployment horizontally](/t/charmed-opensearch-tutorial-horizontal-scaling/9720) |
| 2     | t-teardown                 | [8. Cleanup your environment](/t/charmed-opensearch-tutorial-teardown/9726)                |
| 1     | reference                  | [Reference]()                                                                              |
| 2     | r-actions                  | [Actions](https://charmhub.io/opensearch/actions)                                          |
| 2     | r-configurations           | [Configurations](https://charmhub.io/opensearch/configure)                                 |
| 2     | r-libraries                | [Libraries](https://charmhub.io/opensearch/libraries/helpers)                              |