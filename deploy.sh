#!/usr/bin/env bash

destroy=${1:-"false"}
serverstack=${2:-"false"}

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
    - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
EOF

if [ "${destroy}" == "true" ]; then
    juju destroy-model -y dev --no-wait --force --destroy-storage

    juju add-model dev
    juju model-config logging-config="<root>=INFO;unit=DEBUG"
    juju model-config update-status-hook-interval=1m
    juju model-config ./cloudinit-userdata.yaml

    juju switch :dev

    juju deploy tls-certificates-operator --channel edge --show-log --verbose
    juju config tls-certificates-operator generate-self-signed-certificates=true ca-common-name="CN_CA"
else
    juju switch :dev
    juju remove-application opensearch --force
fi

if [ "${serverstack}" == "true" ]; then
    ssh -i ~/.ssh/admin.key ubuntu@juju cd ~/opensearch-operator && git fetch && git checkout init-charm && git pull && charmcraft pack
    scp -i ~/.ssh/admin.key ubuntu@juju:~/opensearch-operator/opensearch_ubuntu-22.04-amd64.charm .
else
    charmcraft pack
fi

juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --show-log --verbose
juju relate tls-certificates-operator opensearch
