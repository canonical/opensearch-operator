#!/usr/bin/env bash

juju destroy-model -y opensearch --no-wait --force --destroy-storage

juju add-model opensearch
juju switch :opensearch
juju model-config logging-config="<root>=INFO;unit=DEBUG"

charmcraft pack

juju deploy tls-certificates-operator --channel edge --show-log --verbose

juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --show-log --verbose

juju relate tls-certificates-operator opensearch
