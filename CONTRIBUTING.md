# Contributing

## Overview

This document explains the processes and practices recommended for contributing enhancements to
this operator.

<!-- TEMPLATE-TODO: Update the URL for issue creation -->

- Generally, before developing enhancements to this charm, you should consider [opening an issue
  ](https://github.com/canonical/operator-template/issues) explaining your use case.
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

You can use the environments created by `tox` for development:

```shell
tox --notest -e unit
source .tox/unit/bin/activate
```

### Testing

```shell
tox -e fmt           # update your code according to linting rules
tox -e lint          # code style
tox -e unit          # unit tests
tox -e integration   # integration tests
tox                  # runs 'lint' and 'unit' environments
```

## Build charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Deploy

<!-- TEMPLATE-TODO: Update the deploy command for name of charm-->

```bash
# Create a cloudinit-userdata file
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'ulimit', '-n', '65536' ]
    - [ 'echo', 'ulimit -n 65536', '>>', '/etc/profile.d/limits.sh' ]
    - [ 'sed', '-i', '/^# End of file.*/i \root soft nofile 65536\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', '/^# End of file.*/i \root soft nofile 1048576\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', '/^# End of file.*/i \* soft nofile 65536\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', '/^# End of file.*/i \* soft nofile 1048576\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', 's@.*DefaultLimitNOFILE.*@DefaultLimitNOFILE=65536:1048576@', '/etc/systemd/system.conf' ]
    - [ 'sed', '-i', 's@.*DefaultLimitNOFILE.*@DefaultLimitNOFILE=65536:1048576@', '/etc/systemd/user.conf' ]
    - [ 'sed', '-i', '/^# end of pam.*/i \session    required   pam_limits.so\n', '/etc/pam.d/common-session' ]
    - [ 'sed', '-i', '/^# end of pam.*/i \session    required   pam_limits.so\n', '/etc/pam.d/common-session-noninteractive' ]
    - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
    - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
EOF

# Create a model
juju add-model dev

# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"

# Add cloudinit-userdata
juju model-config ./cloudinit-userdata.yaml

# Increase the frequency of the update-status event
juju model-config update-status-hook-interval=1m

# Deploy the TLS-certificates operator
juju deploy tls-certificates-operator --channel edge --show-log --verbose

# generate a CA certificate
juju config tls-certificates-operator generate-self-signed-certificates=true ca-common-name="CN_CA"

# Deploy the opensearch charm
juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --show-log --verbose

# Relate the opensearch charm with the TLS operator
juju relate tls-certificates-operator opensearch
```

## Canonical Contributor Agreement

<!-- TEMPLATE-TODO: Update the description with the name of charm-->

Canonical welcomes contributions to the Charmed Template Operator. Please check out our [contributor agreement](https://ubuntu.com/legal/contributors) if you're interested in contributing to the solution.
