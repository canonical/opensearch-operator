#!/bin/bash
# Upgrade guide bootstrap: set up the environment and deploy the baseline
# cluster that the guide tasks (extracted from docs/how-to/upgrade.md)
# operate on. This script is hand-written, not generated.

set -euo pipefail

. "${SPREAD_PATH:-$(cd "$(dirname "$0")/../.." && pwd)}/helpers.sh"

# ---------------------------------------------------------------------------
# LXD + Juju
# ---------------------------------------------------------------------------
if ! command -v lxd &>/dev/null; then
  snap install lxd
fi
lxd init --auto || true
lxc network set lxdbr0 ipv6.address none || true

snap install juju --channel 3/stable
mkdir -p /root/.local/share

# Kernel parameters required by OpenSearch (shared with the LXD host kernel).
sysctl -w vm.max_map_count=262144
sysctl -w vm.swappiness=0
sysctl -w net.ipv4.tcp_retries2=5

juju bootstrap localhost opensearch-upgrade || true
juju add-model upgrade

# ---------------------------------------------------------------------------
# Resolve charm revisions for the upgrade scenarios
# ---------------------------------------------------------------------------
python3 "$SPREAD_PATH/resolve_revisions.py" -o /root/revisions.env
. /root/revisions.env
echo "Revisions: REV_TO=$REV_TO REV_BASELINE=$REV_BASELINE REV_FROM_SAME=$REV_FROM_SAME REV_FROM_DIFF=$REV_FROM_DIFF"

# ---------------------------------------------------------------------------
# Baseline deployment: opensearch at REV_BASELINE + TLS
# (DEPLOY_BASE comes from resolve_revisions.py and matches the charm revisions)
# ---------------------------------------------------------------------------
juju deploy self-signed-certificates --channel latest/stable
juju deploy opensearch --channel 2/stable --revision="$REV_BASELINE" \
  --base "$DEPLOY_BASE" -n 3
juju integrate self-signed-certificates opensearch

wait_idle --timeout 3600

# ---------------------------------------------------------------------------
# Seed a test index so shard/health assertions are meaningful
# ---------------------------------------------------------------------------
save_ca_and_password

curl -sS --cacert cert.pem -X PUT \
  "https://${OS_UNIT_IP}:9200/upgrade-test-index" \
  -u "admin:${OS_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -d '{"settings": {"number_of_shards": 1, "number_of_replicas": 1}}'

curl -sS --cacert cert.pem -X POST \
  "https://${OS_UNIT_IP}:9200/upgrade-test-index/_doc?refresh=true" \
  -u "admin:${OS_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -d '{"message": "baseline document"}'

cluster_health green

echo "Bootstrap complete: baseline cluster ready at revision $REV_BASELINE."
