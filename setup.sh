#/usr/bin/bash

echo "running setup.sh"

sudo sysctl -w vm.max_map_count=262144 vm.swappiness=0 net.ipv4.tcp_retries2=5
export JUJU_VERSION=$(juju version | cut -c1-1)
echo "juju major version is $JUJU_VERSION"

echo "setup.sh completed"
