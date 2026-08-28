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

_TEST_VAR_0="${REV_TO}"
_TEST_VAR_1="${OS_UNIT_IP}"
_TEST_VAR_2="${OS_PASSWORD}"

juju status

# --- Test assertion ---
juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
rev = data['applications']['opensearch']['charm-rev']
assert str(rev) == '$REV_FROM_SAME', f'Expected revision $REV_FROM_SAME, got {rev}'
"

juju add-unit opensearch

wait_idle --timeout 1800

# --- Test assertion ---
juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
units = data['applications']['opensearch']['units']
assert len(units) == 4, f'Expected 4 units after scale-up, got {len(units)}'
"

juju run opensearch/leader pre-upgrade-check

# --- Test assertion ---
output=$(juju run opensearch/leader pre-upgrade-check 2>&1)
echo "$output"
echo "$output" | grep -q 'Charm is ready for upgrade'

# --- Test assertion ---
wait_app_status opensearch blocked --timeout 1800
juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
units = data['applications']['opensearch']['units']
highest = max(int(name.split('/')[1]) for name in units)
message = units[f'opensearch/{highest}']['workload-status']['message']
assert 'outdated' not in message, f'Highest unit not upgraded yet: {message}'
"

juju run opensearch/leader resume-upgrade

wait_idle --timeout 3600

# --- Test assertion ---
rev=$(current_revision opensearch)
[[ "$rev" == "$REV_TO" ]] || { echo "Expected revision $REV_TO after upgrade, got $rev"; exit 1; }

_TEST_VAR_0="$(juju status --format=json | python3 -c "import json,sys; units=json.load(sys.stdin)['applications']['opensearch']['units']; print(max(int(n.split('/')[1]) for n in units))")"

juju remove-unit opensearch/${_TEST_VAR_0}

wait_idle --timeout 1800

# --- Test assertion ---
juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
units = data['applications']['opensearch']['units']
assert len(units) == 3, f'Expected 3 units after scale-back, got {len(units)}'
"

juju run opensearch/leader get-password

save_ca_and_password

curl --cacert cert.pem -XGET "https://${_TEST_VAR_1}:9200/_cluster/health?pretty" -u admin:${_TEST_VAR_2}

# --- Test assertion ---
cluster_health green
