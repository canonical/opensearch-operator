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
# Reset to the pre-upgrade baseline: refresh back to REV_FROM_SAME and settle.
. /root/revisions.env
juju refresh opensearch --revision="$REV_FROM_SAME"
wait_idle --timeout 3600
save_ca_and_password

_TEST_VAR_0="${REV_FROM_SAME}"

juju refresh opensearch --revision=${_TEST_VAR_0}

# Start a fresh upgrade so we can roll it back mid-flight.
juju refresh opensearch --revision="$REV_TO"
wait_app_status opensearch blocked --timeout 1800

# --- Test assertion ---
# pre-upgrade-check must refuse to run mid-upgrade.
output=$(juju run opensearch/leader pre-upgrade-check 2>&1) && rc=0 || rc=$?
if [[ "$rc" -eq 0 ]]; then
  echo "ERROR: pre-upgrade-check unexpectedly succeeded mid-upgrade"
  exit 1
fi
echo "$output" | grep -q 'Upgrade already in progress'

wait_idle --timeout 3600

# --- Test assertion ---
rev=$(current_revision opensearch)
[[ "$rev" == "$REV_FROM_SAME" ]] || { echo "Expected revision $REV_FROM_SAME after rollback, got $rev"; exit 1; }
cluster_health green
