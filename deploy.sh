#!/usr/bin/env bash

destroy=${1:-"false"}

cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ "sysctl", "-w", "vm.swappiness=0" ]
    - [ "sysctl", "-w", "vm.max_map_count=262144" ]
    - [ "sysctl", "-w", "net.ipv4.tcp_retries2=5" ]
EOF

if [ "${destroy}" == "true" ]; then
    juju destroy-model -y dev --no-wait --force --destroy-storage

    juju add-model dev
    juju switch :dev

    juju deploy tls-certificates-operator --channel edge --show-log --verbose
    juju config tls-certificates-operator generate-self-signed-certificates=true ca-common-name="CN_CA"
else
    juju switch :dev
    juju remove-application opensearch --force
fi

juju model-config logging-config="<root>=INFO;unit=DEBUG"
juju model-config ./cloudinit-userdata.yaml

charmcraft pack

juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --show-log --verbose

juju relate tls-certificates-operator opensearch
