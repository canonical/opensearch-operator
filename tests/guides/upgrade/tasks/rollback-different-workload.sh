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
# Reset to the upgraded baseline before testing the different-workload rollback.
. /root/revisions.env
juju refresh opensearch --revision="$REV_TO"
wait_idle --timeout 3600
save_ca_and_password

# Roll back to a revision with a different workload version.
juju refresh opensearch --revision="$REV_FROM_DIFF"

# --- Test assertion ---
# Wait for the blocked unit and capture its id.
BLOCKED_UNIT=$(juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
units = data['applications']['opensearch']['units']
for name, unit in units.items():
    msg = unit['workload-status'].get('message', '')
    if 'Rollback incompatible' in msg or 'Rollback unsupported' in msg:
        print(name)
        break
")
if [[ -z "$BLOCKED_UNIT" ]]; then
  echo "ERROR: no blocked unit found after different-workload rollback"
  juju status
  exit 1
fi
echo "Blocked unit: $BLOCKED_UNIT"
juju run "$BLOCKED_UNIT" force-refresh-start check-compatibility=false

_TEST_VAR_0="${OS_UNIT_IP}"
_TEST_VAR_1="${OS_PASSWORD}"

curl --cacert cert.pem -XGET "https://${_TEST_VAR_0}:9200/_cluster/health?pretty" -u admin:${_TEST_VAR_1}

# --- Test assertion ---
# After the forced rollback the cluster may be degraded; recovery is the
# next task. Here we only assert the endpoint responds.
cluster_health
