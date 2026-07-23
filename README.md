# OpenSearch Operator
[![Charmhub](https://charmhub.io/opensearch/badge.svg)](https://charmhub.io/opensearch)
[![Release](https://github.com/canonical/opensearch-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/opensearch-operator/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/opensearch-operator/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/canonical/opensearch-operator/actions/workflows/ci.yaml)
[![Docs](https://github.com/canonical/opensearch-operator/actions/workflows/sync_docs.yaml/badge.svg)](https://github.com/canonical/opensearch-operator/actions/workflows/sync_docs.yaml)

## Description

The Charmed OpenSearch Operator deploys and operates the [OpenSearch](https://opensearch.org/) software on both machine (VMs/LXD) and Kubernetes clusters.

This operator provides an OpenSearch cluster, with:
- TLS (for the HTTP and Transport layers)
- Automated node discovery
- Observability
- Backup / Restore
- Safe horizontal scale-down/up
- Large deployments

This repository contains two charms, each in its own folder:

- [`machine/`](machine) — the **machine charm** (`opensearch`), which installs and manages OpenSearch from the [OpenSearch Snap](https://snapcraft.io/opensearch) on VMs and machine clusters.
- [`kubernetes/`](kubernetes) — the **Kubernetes charm** (`opensearch-k8s`), which deploys and manages OpenSearch as a container workload on Kubernetes.

Both charms are Python projects that provide lifecycle management and handle events (install, start, etc).

## Usage

### Machine charm (`opensearch`)

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

sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT

sudo sysctl -p

juju model-config --file=./cloudinit-userdata.yaml
```

To deploy a single unit of OpenSearch using its default configuration:

```shell
juju deploy opensearch --channel=2/edge
```

### Kubernetes charm (`opensearch-k8s`)

Bootstrap a Kubernetes controller to juju and create a model:

```shell
juju add-model opensearch
```

OpenSearch benefits from certain kernel settings being applied on the underlying
Kubernetes hosts (the nodes where the workload pods are scheduled). These are not
required, but are recommended for production setups. Apply the following on each
node:

```
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
fs.file-max=1048576
EOT

sudo sysctl -p
```

Note that `net.ipv4.tcp_retries2` is scoped to the pod's network namespace
rather than the host, so it cannot be set on the node. To configure it, deploy
the [data-platform-k8s-mutator](https://github.com/canonical/data-platform-k8s-mutator)
charm alongside OpenSearch on the Kubernetes cluster, which sets this sysctl
value on the workload pods. This is likewise not required, but recommended for
production setups.

To deploy a single unit of OpenSearch using its default configuration:

```shell
juju deploy opensearch-k8s --channel=2/edge
```

## Relations / Integrations

The relevant provided [relations](https://juju.is/docs/olm/relations) of Charmed OpenSearch are shown below. The examples use the machine charm's application name (`opensearch`); substitute `opensearch-k8s` when using the Kubernetes charm.

### Client interface

To connect to the Charmed OpenSearch Operator and exchange data, relate to the `opensearch-client` endpoint:

```shell
juju deploy data-integrator --channel=latest/stable
juju integrate opensearch data-integrator
```

### Large deployments
Charmed OpenSearch also allows to form large clusters or join an existing deployment, through the relations:
- `peer-cluster`
- `peer-cluster-orchestrator`
```
juju integrate main:peer-cluster-orchestrator data-hot:peer-cluster
```

## TLS

The Charmed OpenSearch Operator also supports TLS encryption as a first class citizen, on both the HTTP and Transport layers. 
TLS is enabled by default and is a requirement for the charm to start.

The charm relies on the `tls-certificates` interface.

#### Example with Self-signed certificates
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
