# operator-template

## Description
OpenSearch Machine Charm

## Usage

```
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'ulimit', '-n', '65536' ]
    - [ 'echo', 'ulimit -n 65536', '>>', '/etc/profile.d/limits.sh' ]
    - [ 'sed', '-i', '/^# End of file.*/i \root soft nofile 65536\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', '/^# End of file.*/i \root hard nofile 1048576\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', '/^# End of file.*/i \* soft nofile 65536\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', '/^# End of file.*/i \* hard nofile 1048576\n', '/etc/security/limits.conf' ]
    - [ 'sed', '-i', 's@.*DefaultLimitNOFILE.*@DefaultLimitNOFILE=65536:1048576@', '/etc/systemd/system.conf' ]
    - [ 'sed', '-i', 's@.*DefaultLimitNOFILE.*@DefaultLimitNOFILE=65536:1048576@', '/etc/systemd/user.conf' ]
    - [ 'sed', '-i', '/^# end of pam.*/i \session    required   pam_limits.so\n', '/etc/pam.d/common-session' ]
    - [ 'sed', '-i', '/^# end of pam.*/i \session    required   pam_limits.so\n', '/etc/pam.d/common-session-noninteractive' ]
    - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
    - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
EOF

juju model-config ./cloudinit-userdata.yaml

juju add-model dev
juju model-config logging-config="<root>=INFO;unit=DEBUG"
juju model-config update-status-hook-interval=1m
juju model-config ./cloudinit-userdata.yaml

juju switch :dev

juju deploy tls-certificates-operator --channel edge --show-log --verbose
juju config tls-certificates-operator generate-self-signed-certificates=true ca-common-name="CN_CA"

juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --show-log --verbose
juju relate tls-certificates-operator opensearch
```

## Relations

TODO: Provide any relations which are provided or required by your charm

## OCI Images

TODO: Include a link to the default image your charm uses

## Contributing

<!-- TEMPLATE-TODO: Change this URL to be the full Github path to CONTRIBUTING.md-->

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this
charm following best practice guidelines, and
[CONTRIBUTING.md](https://github.com/<name>/<operator>/blob/main/CONTRIBUTING.md) for developer
guidance.
