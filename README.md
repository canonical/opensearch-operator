# OpenSearch Operator

## Description

The Charmed OpenSearch Operator deploys and operates the [OpenSearch](https://opensearch.org/) software on VMs and machine clusters.

This operator provides an OpenSearch cluster, with:
- TLS (for the HTTP and Transport layers)
- Automated node discovery

The Operator in this repository is a Python script which wraps OpenSearch installed by the OpenSearch Snap, providing lifecycle management and handling events (install, start, etc).

## Usage

Bootstrap a [lxd controller](https://juju.is/docs/olm/lxd#heading--create-a-controller) to juju and create a model:

```shell
juju add-model opensearch
```

Configure the system settings required by [OpenSearch](https://opensearch.org/docs/2.3/opensearch/install/important-settings/), 
we'll do that by creating and setting a [`cloudinit-userdata.yaml` file](https://juju.is/docs/olm/juju-model-config) on the model.
```
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
    - [ 'sysctl', '-w', 'vm.swappiness=0' ]
    - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
EOF

juju model-config ./cloudinit-userdata.yaml
```

### Basic Usage
To deploy a single unit of OpenSearch using its default configuration.

```shell
juju deploy opensearch --channel edge
```

## Relations

Supported [relations](https://juju.is/docs/olm/relations):

#### `tls-certificates` interface:

The Charmed OpenSearch Operator also supports TLS encryption on the HTTP and Transport layers. TLS is enabled by default:

```shell
# Deploy the TLS Certificates Operator. 
juju deploy tls-certificates-operator --channel=edge
# Add the necessary configurations for TLS.
juju config tls-certificates-operator generate-self-signed-certificates="true" ca-common-name="Test CA" 
# Enable TLS via relation.
juju relate opensearch tls-certificates-operator
# Disable TLS by removing relation.
juju remove-relation opensearch tls-certificates-operator
```

**Note:** The TLS settings shown here are for self-signed-certificates, which are not recommended for production clusters. The TLS Certificates Operator offers a variety of configurations. Read more on the TLS Certificates Operator [here](https://charmhub.io/tls-certificates-operator).

## Security
Security issues in the Charmed OpenSearch Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) for developer guidance.

## License
The Charmed OpenSearch Operator is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](https://github.com/canonical/opensearch-operator/blob/main/LICENSE) for more information.
