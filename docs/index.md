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
|  [**Tutorials**](tutorial-index)</br>  [Get started](tutorial-index) - a hands-on introduction to using the Charmed OpenSearch operator for new users </br> |  [**How-to guides**](how-to-guides-index) </br> Step-by-step guides covering key operations such as [scaling](how-to-scale-horizontally), [TLS encryption](how-to-enable-tls-encryption), or [monitoring](how-to-monitoring-enable-cos) |
| [**Reference**](reference-index) </br> Technical information such as [system requirements](reference-system-requirements) | [Explanation](explanation-index) </br> Concepts - discussion and clarification of key topics  |

## Project & community

Charmed OpenSearch is an official distribution of OpenSearch .
It’s an open-source project that welcomes community contributions, suggestions,
fixes and constructive feedback:

- Raise an issue or feature request in the [Github repository](https://github.com/canonical/opensearch-operator/issues).
- Meet the community and chat with us in our [Matrix channel](https://matrix.to/#/#charmhub-data-platform:ubuntu.com) or [leave a comment](https://discourse.charmhub.io/t/charmed-opensearch-documentation/9729).
- See the Charmed OpenSearch [contribution guidelines](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) on GitHub and read the Ubuntu Community's [Code of Conduct](https://ubuntu.com/community/code-of-conduct).

## License & trademark

The Charmed OpenSearch ROCK, Charmed OpenSearch Snap,
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
