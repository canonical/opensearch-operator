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


## Build charm

Build the charm in this git repository using tox.

There are two alternatives to build the charm: using the charm cache or not.
Cache will speed the build by downloading all dependencies from charmcraftcache-hub.

### Build Without Cache

To run the traditional build only using `charmcraft`, run the following command:

```shell
tox -e build-production
```

### Build With Cache

First, ensure you have the right dependencies:
* charmcraft v2.5.4+
* charmcraftcache

By running the following commands:

```shell
pip install charmcraftcache
sudo snap refresh charmcraft --channel=latest/beta
```

Then, start the build:

```shell
tox -e build-dev
```

## Developing

You can create an environment for development with `tox`:

```shell
tox devenv -e integration
source venv/bin/activate
```

### Testing

To run tests, first build the charm as described above, then run the following

```shell
tox -e format       # update your code according to linting rules
tox -e lint         # code style
tox -e unit         # unit tests
tox -m integration  # integration tests, running on juju 3.
tox                 # runs 'format', 'lint', and 'unit' environments
```

Integration tests can be run for separate files:

```shell
tox -e integration -- tests/integration/ha/test_storage.py
```

#### Running different versions of libjuju

To try different versions of libjuju, run:

```shell
poetry add --lock --group integration,unit juju@<YOUR CHOSEN VERSION>
```

#### Testing Backups

Backup testing installs microceph and, optionally, can run on AWS and GCP object stores.
For that, pass the access / secret / service account information as env. variables.

To run the test only against microceph:

```shell
tox -e integration -- tests/integration/ha/test_backups.py --group='microceph' # test backup service
```

And against public clouds + microceph:

```shell
SECRETS_FROM_GITHUB=$(cat <path-to>/credentials.json) tox -e integration -- tests/integration/ha/test_backups.py
```

Where, for AWS only, `credentials.json` should look like (the `IGNORE` is necessary to remove GCP):
```json
{ "AWS_ACCESS_KEY": ..., "AWS_SECRET_KEY": ..., "GCP_SECRET_KEY": "IGNORE" }
```

For GCP only, some additional information is needed. The pytest script runs with `boto3` and needs `GCP_{ACCESS,SECRET}_KEY` to clean up the object store; whereas OpenSearch uses the `service account` json file.

```json
{ "AWS_SECRET_KEY": "IGNORE", "GCP_ACCESS_KEY": ..., "GCP_SECRET_KEY": ..., "GCP_SERVICE_ACCOUNT": ... }
```

Combine both if AWS and GCP are to be used.


#### Cleaning Test Environment

Remove the following files / folders: `poetry.lock`, `.tox`, `requirements*`.


## Deploy

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
