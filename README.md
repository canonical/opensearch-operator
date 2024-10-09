# Wazuh Indexer Operator
[![Charmhub](https://charmhub.io/wazuh-indexer/badge.svg)](https://charmhub.io/wazuh-indexer)
[![Release](https://github.com/canonical/wazuh-indexer-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/wazuh-indexer-operator/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/wazuh-indexer-operator/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/canonical/wazuh-indexer-operator/actions/workflows/ci.yaml)
[![Docs](https://github.com/canonical/wazuh-indexer-operator/actions/workflows/sync_docs.yaml/badge.svg)](https://github.com/canonical/wazuh-indexer-operator/actions/workflows/sync_docs.yaml)

## Description

The Charmed Wazuh Indexer Operator deploys and operates the [Wazuh](https://wazuh.com/) software on VMs and machine clusters.

This operator provides an Wazuh Indexer cluster, with:
- TLS (for the HTTP and Transport layers)
- Automated node discovery
- Observability
- Backup / Restore
- Safe horizontal scale-down/up
- Large deployments

The Operator in this repository is a Python project installing and managing Wazuh Indexer installed from the [Wazuh Indexer Snap](https://snapcraft.io/wazuh-indexer), providing lifecycle management and handling events (install, start, etc).

## Usage

Bootstrap a [lxd controller](https://juju.is/docs/olm/lxd#heading--create-a-controller) to juju and create a model:

```shell
juju add-model wazuh-indexer
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

sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT

sudo sysctl -p

juju model-config --file=./cloudinit-userdata.yaml
```

### Basic Usage
To deploy a single unit of Wazuh Indexer using its default configuration.

```shell
juju deploy wazuh-indexer --channel=4/edge
```

## Relations / Integrations

The relevant provided [relations](https://juju.is/docs/olm/relations) of Charmed Wazuh Indexer are:

### Client interface:

To connect to the Charmed Wazuh Indexer Operator and exchange data, relate to the `opensearch-client` endpoint:

```shell
juju deploy data-integrator --channel=2/edge
juju integrate wazuh-indexer data-integrator
```

### Large deployments:
Charmed Wazuh Indexer also allows to form large clusters or join an existing deployment, through the relations:
- `peer-cluster`
- `peer-cluster-orchestrator`
```
juju integrate main:peer-cluster-orchestrator data-hot:peer-cluster
```

## TLS:

The Charmed Wazuh Indexer Operator also supports TLS encryption as a first class citizen, on both the HTTP and Transport layers. 
TLS is enabled by default and is a requirement for the charm to start.

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
juju integrate self-signed-certificates wazuh-indexer

# Disable TLS by removing relation.
juju remove-relation wazuh-indexer self-signed-certificates
```

**Note:** The TLS settings shown here are for self-signed-certificates, which are not recommended for production clusters. The Self Signed Certificates Operator offers a variety of configuration options. Read more on the TLS Certificates Operator [here](https://charmhub.io/self-signed-certificates).

## Security
Security issues in the Charmed Wazuh Indexer Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/wazuh-indexer-operator/blob/main/CONTRIBUTING.md) for developer guidance.

## License
The Charmed Wazuh Indexer Operator is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](https://github.com/canonical/wazuh-indexer-operator/blob/main/LICENSE) for more information.
