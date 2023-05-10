#/usr/bin/bash

echo "running setup.sh"

sudo sysctl -w vm.max_map_count=262144 vm.swappiness=0 net.ipv4.tcp_retries2=5
export JUJU_VER=$(juju version | cut -c1-1)

echo "setup.sh completed"