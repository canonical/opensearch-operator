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

Configure the system settings required by [OpenSearch](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/),
we'll do that by creating and setting a [`cloudinit-userdata.yaml` file](https://juju.is/docs/olm/juju-model-config) on the model. 
As well as setting some kernel settings on the host machine.
```
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'echo', 'vm.max_map_count=262144', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'vm.swappiness=0', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'net.ipv4.tcp_retries2=5', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'fs.file-max=1048576', '>>', '/etc/sysctl.conf' ]
    - [ 'sysctl', '-p' ]
EOF

echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
echo "vm.swappiness=0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

juju model-config --file=./cloudinit-userdata.yaml
```

### Basic Usage
To deploy a single unit of OpenSearch using its default configuration.

```shell
juju deploy opensearch --channel=2/edge
```

## Relations

Supported [relations](https://juju.is/docs/olm/relations):

#### `opensearch-client` interface:

To connect to the Charmed OpenSearch Operator and exchange data, relate to the `opensearch-client` endpoint:

```shell
juju deploy data-integrator --channel=2/edge
juju relate opensearch data-integrator
```

### TLS:

The Charmed OpenSearch Operator also supports TLS encryption on the HTTP and Transport layers. TLS is enabled by default.

The charm relies on the `tls-certificates` interface.

#### 1. Self-signed certificates:

```shell
# Deploy the self-signed TLS Certificates Operator.
juju deploy self-signed-certificates --channel=latest/stable

# Add the necessary configurations for TLS.
juju config \
    self-signed-certificates \
    ca-common-name="Test CA" \
    certificate-validity=365 \
    root-ca-validity=365
    
# Enable TLS via relation.
juju integrate self-signed-certificates opensearch

# Disable TLS by removing relation.
juju remove-relation opensearch self-signed-certificates
```

**Note:** The TLS settings shown here are for self-signed-certificates, which are not recommended for production clusters. The Self Signed Certificates Operator offers a variety of configuration options. Read more on the TLS Certificates Operator [here](https://charmhub.io/self-signed-certificates).

## Security
Security issues in the Charmed OpenSearch Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) for developer guidance.

## License
The Charmed OpenSearch Operator is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](https://github.com/canonical/opensearch-operator/blob/main/LICENSE) for more information.
