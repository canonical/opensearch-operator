#!/bin/bash
# Extracted from : docs/how-to/upgrade.md
# Regenerate with: python3 extract_guide_tasks.py docs/how-to/upgrade.md <output.sh>
#
# Only ```shell fences are extracted; use any other tag to naturally exclude a block.

set -euo pipefail

# Load shared helpers (wait_idle, retry_until_success, etc.).
HELPERS="${SPREAD_PATH:-$(cd "$(dirname "$0")" && pwd)}/helpers.sh"
. "$HELPERS"



# --- Task setup (hidden) ---
. /root/revisions.env
save_ca_and_password

juju status

# --- Test assertion ---
# Identify the stuck unit (waiting/executing with the start message).
STUCK_UNIT=$(juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
units = data['applications']['opensearch']['units']
for name, unit in units.items():
    msg = unit['workload-status'].get('message', '')
    if 'Waiting for OpenSearch to start' in msg:
        print(name)
        break
")
echo "Stuck unit: ${STUCK_UNIT:-<none>}"

_TEST_VAR_0="${OS_UNIT_IP}"
_TEST_VAR_1="${OS_PASSWORD}"

curl --cacert cert.pem -X GET "https://${_TEST_VAR_0}:9200/_cluster/health?pretty" -u admin:${_TEST_VAR_1}

# --- Test assertion ---
cluster_health

curl --cacert cert.pem -X GET "https://${_TEST_VAR_0}:9200/_cluster/allocation/explain?pretty" -u admin:${_TEST_VAR_1}

# --- Test assertion ---
# Capture any orphaned index names for the delete step.
ORPHANED_INDICES=$(curl -sS --cacert cert.pem \
  "https://${OS_UNIT_IP}:9200/_cluster/allocation/explain?pretty" \
  -u "admin:${OS_PASSWORD}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    index = data.get('index')
    if index and data.get('current_state') == 'unassigned':
        print(index)
except Exception:
    pass
")
echo "Orphaned indices: ${ORPHANED_INDICES:-<none>}"

curl --cacert cert.pem -X DELETE "https://${_TEST_VAR_0}:9200/index1" -u admin:${_TEST_VAR_1}

for index in ${ORPHANED_INDICES}; do
  curl -sS --cacert cert.pem -X DELETE "https://${OS_UNIT_IP}:9200/${index}" \
    -u "admin:${OS_PASSWORD}"
done

curl --cacert cert.pem -X GET "https://${_TEST_VAR_0}:9200/_cluster/health?pretty" -u admin:${_TEST_VAR_1}

# --- Test assertion ---
cluster_health

curl --cacert cert.pem -X PUT "https://${_TEST_VAR_0}:9200/_cluster/settings" -H 'Content-Type: application/json' -u admin:${_TEST_VAR_1} -d'
{
  "persistent": {
    "cluster.routing.allocation.enable": "all"
  }
}
'

juju add-unit opensearch -n 1

wait_idle --timeout 1800

juju remove-unit opensearch/2

_TEST_VAR_0="${STUCK_UNIT}"

if [[ -n "${STUCK_UNIT:-}" ]]; then
  juju remove-unit "$STUCK_UNIT"
fi

wait_idle --timeout 1800

curl --cacert cert.pem -X DELETE "https://${_TEST_VAR_0}:9200/.charm_node_lock/_doc/0?refresh=true" -u admin:${_TEST_VAR_1}

# Check whether the departed unit still holds the node lock; delete if so.
LOCK_HOLDER=$(curl -sS --cacert cert.pem \
  "https://${OS_UNIT_IP}:9200/.charm_node_lock/_doc/0" \
  -u "admin:${OS_PASSWORD}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if data.get('found'):
        print(data['_source'].get('unit-name', ''))
except Exception:
    pass
" || true)
if [[ -n "${LOCK_HOLDER:-}" ]]; then
  echo "Lock held by ${LOCK_HOLDER} — deleting"
  curl -sS --cacert cert.pem \
    -X DELETE "https://${OS_UNIT_IP}:9200/.charm_node_lock/_doc/0?refresh=true" \
    -u "admin:${OS_PASSWORD}"
else
  echo "No stale lock found"
fi

curl --cacert cert.pem -X GET "https://${_TEST_VAR_0}:9200/_cat/nodes" -u admin:${_TEST_VAR_1}

# --- Test assertion ---
nodes=$(curl -sS --cacert cert.pem "https://${OS_UNIT_IP}:9200/_cat/nodes" \
  -u "admin:${OS_PASSWORD}" | wc -l)
expected=$(juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(len(data['applications']['opensearch']['units']))
")
[[ "$nodes" -eq "$expected" ]] || { echo "Expected ${expected} nodes in cluster, got ${nodes}"; exit 1; }

curl --cacert cert.pem -XGET "https://${_TEST_VAR_0}:9200/_cluster/health?pretty" -u admin:${_TEST_VAR_1}

# --- Test assertion ---
cluster_health green
