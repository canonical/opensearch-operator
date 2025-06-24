# Security hardening guide

This document provides an overview of security features and guidance for hardening the security of [Charmed OpenSearch](https://charmhub.io/opensearch) deployments, including setting up and managing a secure environment.

## Environment

The environment where Charmed OpenSearch operates can be divided into two components:

1. Cloud
2. Juju

### Cloud

Charmed OpenSearch can be deployed on top of several clouds and virtualization layers:

|Cloud|Security guides|
| --- | --- |
|OpenStack|[OpenStack Security Guide](https://docs.openstack.org/security-guide/)|
|AWS|[Best Practices for Security, Identity and Compliance](https://aws.amazon.com/architecture/security-identity-compliance), [AWS security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html#access-keys-and-secret-access-keys)|
|Azure|[Azure security best practices and patterns](https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns), [Managed identities for Azure resource](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/)|

### Juju

Juju is the component responsible for orchestrating the entire lifecycle, from deployment to Day 2 operations. For more information on Juju security hardening, see the [Juju security](https://discourse.charmhub.io/t/juju-security/15684) page and the [How to harden your deployment](https://juju.is/docs/juju/harden-your-deployment) guide.

#### Cloud credentials

When configuring cloud credentials to be used with Juju, ensure that users have correct permissions to operate at the required level. Juju superusers responsible for bootstrapping and managing controllers require elevated permissions to manage several kinds of resources, such as virtual machines, networks, storages, etc. Please refer to the links below for more information on the policies required to be used depending on the cloud.

|Cloud|Cloud user policies|
| --- | --- |
|OpenStack|N/A|
|AWS|[Juju AWS Permission](https://discourse.charmhub.io/t/juju-aws-permissions/5307), [AWS Instance Profiles](https://discourse.charmhub.io/t/using-aws-instance-profiles-with-juju-2-9/5185), [Juju on AWS](https://juju.is/docs/juju/amazon-ec2)|
|Azure|[Juju Azure Permission](https://juju.is/docs/juju/microsoft-azure), [How to use Juju with Microsoft Azure](https://discourse.charmhub.io/t/how-to-use-juju-with-microsoft-azure/15219)|

#### Juju users

It is very important that Juju users are set up with minimal permissions depending on the scope of their operations. Please refer to the [User access levels](https://juju.is/docs/juju/user-permissions) documentation for more information on the access levels and corresponding abilities.

Juju user credentials must be stored securely and rotated regularly to limit the chances of unauthorized access due to credentials leakage.

## Applications

In the following, we provide guidance on how to harden your deployment using:

1. Operating system
2. Security upgrades
3. Encryption
4. Authentication
5. Monitoring

### Operating system

Charmed OpenSearch and Charmed OpenSearch Dashboards currently run on top of Ubuntu 22.04. Deploy a [Landscape Client Charm](https://charmhub.io/landscape-client?) to connect the underlying VM to a Landscape User Account to manage security upgrades and integrate [Ubuntu Pro](https://ubuntu.com/pro) subscriptions.

### Security upgrades

Charmed OpenSearch and Charmed OpenSearch Dashboards operators install a pinned revision of the [Charmed OpenSearch snap](https://snapcraft.io/opensearch) and [Charmed OpenSearch Dashboards snap](https://snapcraft.io/opensearch-dashboards), respectively, to provide reproducible and secure environments.

New versions of Charmed OpenSearch and Charmed OpenSearch Dashboards may be released to provide patching of vulnerabilities (CVEs). It is important to refresh the charm regularly to make sure the workload is as secure as possible. For more information on how to refresh the charm, see the [how-to upgrade](https://charmhub.io/opensearch/docs/h-minor-upgrade) guide.

### Encryption

Charmed OpenSearch is deployed with encryption enabled. To do that, you need to relate Charmed OpenSearch and Charmed OpenSearch Dashboards to one of the TLS certificate operator charms. Please refer to the [Charming Security page](https://charmhub.io/topics/security-with-x-509-certificates) for more information on how to select the right certificate provider for your use case.

For more information on encryption, see the [Cryptography](https://discourse.charmhub.io/t/charmed-opensearch-explanation-cryptography/17243) explanation page and the [How to enable encryption](https://charmhub.io/opensearch/docs/h-enable-tls) guide.

### Authentication

Charmed OpenSearch supports the password [authentication](https://charmhub.io/opensearch/docs/t-passwords)

### Monitoring

Charmed OpenSearch provides native integration with the [Canonical Observability Stack (COS)](https://charmhub.io/topics/canonical-observability-stack). To reduce the blast radius of infrastructure disruptions, the general recommendation is to deploy COS and the observed application into separate environments, isolated from one another. Refer to the [COS production deployments best practices](https://charmhub.io/topics/canonical-observability-stack/reference/best-practices) for more information.

For instructions, see the [How to integrate the Charmed OpenSearch deployment with COS](https://charmhub.io/opensearch/docs/h-monitoring) guide.

## Additional Resources

For details on the cryptography used by Charmed OpenSearch, see the [Cryptography](https://discourse.charmhub.io/t/charmed-opensearch-explanation-cryptography/17243) explanation page.