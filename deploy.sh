#!/usr/bin/env bash

destroy=${1:-"false"}

#cat <<EOF > cloudinit-userdata.yaml
#cloudinit-userdata: |
#  postruncmd:
#    - [ 'echo', 'ulimit -n 65536', '>>', '/etc/profile.d/limits.sh' ]
#    - [ 'sed', '-i', '/^# End of file.*/i \* soft nofile 65536\n', '/etc/security/limits.conf' ]
#    - [ 'sed', '-i', '/^# End of file.*/i \* soft nofile 1048576\n', '/etc/security/limits.conf' ]
#    - [ 'sed', '-i', 's@.*DefaultLimitNOFILE.*@DefaultLimitNOFILE=65536:1048576@', '/etc/systemd/system.conf' ]
#    - [ 'sed', '-i', 's@.*DefaultLimitNOFILE.*@DefaultLimitNOFILE=65536:1048576@', '/etc/systemd/user.conf' ]
#EOF

if [ "${destroy}" == "true" ]; then
    juju destroy-model -y dev --no-wait --force --destroy-storage

    juju add-model dev
    juju model-config logging-config="<root>=INFO;unit=DEBUG"
    juju model-config update-status-hook-interval=1m
    # juju model-config ./cloudinit-userdata.yaml

    juju switch :dev

    juju deploy tls-certificates-operator --channel edge --show-log --verbose
    juju config tls-certificates-operator generate-self-signed-certificates=true ca-common-name="CN_CA"
else
    juju switch :dev
    juju remove-application opensearch --force
fi

charmcraft pack

juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --show-log --verbose

juju relate tls-certificates-operator opensearch
