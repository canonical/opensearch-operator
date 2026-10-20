#!/usr/bin/env bash
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

set -euo pipefail
shopt -s inherit_errexit

get_unit() {
  local app=$1
  juju status -m "$MAIN_MODEL" "$app" --format=json |
    jq -r --arg app "$app" '.applications[$app].units // {} | keys | .[0] // empty'
}

get_orchestrators() {
  local unit=$1
  juju show-unit -m "$MAIN_MODEL" "$unit" --endpoint opensearch-peers --app --format=json |
    jq -r --arg unit "$unit" '.[$unit]."relation-info"[0]."application-data".orchestrators // "{}"'
}

get_elected_failover() {
  local unit
  unit=$(get_unit "$MAIN_APP")
  if [ -z "$unit" ]; then
    return 0
  fi
  get_orchestrators "$unit" | jq -r '.failover_app.name // empty'
}

echo "Waiting for failover election..."
deadline=$((SECONDS + TIMEOUT))
while true; do
  failover=$(get_elected_failover)
  if [ "$failover" = "$FAILOVER_APP" ]; then
    exit 0
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "\`$MAIN_APP\` failed to elect \`$FAILOVER_APP\` after $TIMEOUT seconds." >&2
    exit 1
  fi
  sleep 10
done
