# Contributing

## Overview

This document explains the processes and practices recommended for contributing enhancements to
this operator.

<!-- TEMPLATE-TODO: Update the URL for issue creation -->

- Generally, before developing enhancements to this charm, you should consider [opening an issue
  ](https://github.com/canonical/operator-opensearch/issues) explaining your use case.
- If you would like to chat with us about your use-cases or proposed implementation, you can reach
  us at [Canonical Mattermost public channel](https://chat.charmhub.io/charmhub/channels/charm-dev)
  or [Discourse](https://discourse.charmhub.io/).
- Familiarising yourself with the [Charmed Operator Framework](https://juju.is/docs/sdk) library
  will help you a lot when working on new features or bug fixes.
- All enhancements require review before being merged. Code review typically examines
  - code quality
  - test coverage
  - user experience for Juju administrators of this charm.
- Please help us out in ensuring easy to review branches by rebasing your pull request branch onto
  the `main` branch. This also avoids merge commits and creates a linear Git commit history.

## Developing

You can create an environment for development with `tox`:

```shell
tox devenv -e integration
source venv/bin/activate
```

### Testing

To run tests, run the following

```shell
tox -e format       # update your code according to linting rules
tox -e lint         # code style
tox -e unit         # unit tests
tox -m integration  # integration tests, running on juju 2.
tox                 # runs 'format', 'lint', and 'unit' environments
```

Integration tests can be run for separate areas of functionality:

```shell
tox -e j2-charm-integration      # basic charm integration tests
tox -e j2-tls-integration        # TLS-specific integration tests
tox -e j2-client-integration     # Validates the `opensearch-client` integration
tox -e j2-ha-integration         # HA tests
tox -e j2-h-scaling-integration  # HA tests specific to horizontal scaling
```

If you're running tests on juju 3, replace the `j2` prefix with `j3`

## Build charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Deploy

OpenSearch has a set of system requirements to correctly function, you can find the list [here](https://opensearch.org/docs/2.6/opensearch/install/important-settings/).
To set those settings using cloudinit-userdata:
```bash
# Create a cloudinit-userdata file, to set the required system settings of opensearch.
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
    - [ 'sysctl', '-w', 'vm.swappiness=0' ]
    - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
EOF
```

or in a single machine:
```bash
sudo sysctl -w vm.max_map_count=262144 vm.swappiness=0 net.ipv4.tcp_retries2=5
```

Then create a new model and set the previously generated file in it.
```bash
# Create a model
juju add-model dev

# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"

# Add cloudinit-userdata
juju model-config ./cloudinit-userdata.yaml

# Increase the frequency of the update-status event
juju model-config update-status-hook-interval=1m
```

You can then deploy the charm with a TLS relation.
```bash
# Deploy the TLS-certificates operator
juju deploy tls-certificates-operator --channel edge --show-log --verbose

# generate a CA certificate
juju config tls-certificates-operator generate-self-signed-certificates=true ca-common-name="CN_CA"

# Deploy the opensearch charm
juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --series jammy --show-log --verbose

# Relate the opensearch charm with the TLS operator
juju relate tls-certificates-operator opensearch
```

**Note:** The TLS settings shown here are for self-signed-certificates, which are not recommended for production clusters. The TLS Certificates Operator offers a variety of configurations. Read more on the TLS Certificates Operator [here](https://charmhub.io/tls-certificates-operator).


## Canonical Contributor Agreement
Canonical welcomes contributions to the Charmed Template Operator. Please check out our [contributor agreement](https://ubuntu.com/legal/contributors) if you're interested in contributing to the solution.
