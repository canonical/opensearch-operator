#!/bin/bash
# Shared helpers for the upgrade-guide spread tests.
#
# Source this file at the top of every generated script (done automatically
# by extract_guide_tasks.py):
#   . "$SPREAD_PATH/helpers.sh"
#
# Derived from tests/tutorial/helpers.sh, extended with upgrade-specific
# helpers (revision tracking, app/unit status waiting, cluster health).

# Spread SSHs in as root but does not always set HOME=/root, which causes the
# Juju client to fail looking up its config in $HOME/.local/share/juju.
export HOME=/root

# ---------------------------------------------------------------------------
# wait_idle – poll until every Juju unit in the model is active/idle.
#
# Usage:
#   wait_idle [--timeout SECONDS] [--interval SECONDS]
#             [--allow-blocked APP1,APP2,...]
#
# Defaults:
#   --timeout  600   (10 minutes)
#   --interval  30   (check every 30 seconds)
#
# --allow-blocked accepts a comma-separated list of application names that
# are expected to be in blocked/idle state.  Units belonging to those apps
# are treated as settled when they are blocked/idle.  All other units must
# still be active/idle.
#
# Returns 0 when all units are active/idle, 1 on timeout.
# ---------------------------------------------------------------------------
wait_idle() {
    local timeout=600
    local interval=30
    local allow_blocked=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)       timeout="$2";       shift 2 ;;
            --interval)      interval="$2";      shift 2 ;;
            --allow-blocked) allow_blocked="$2"; shift 2 ;;
            *) echo "wait_idle: unknown option: $1" >&2; return 1 ;;
        esac
    done

    local elapsed=0
    echo "Waiting for all Juju units to be active/idle (timeout=${timeout}s, poll=${interval}s)…"

    while [[ "$elapsed" -lt "$timeout" ]]; do
        local not_ready
        # Run the poll pipeline with pipefail disabled so a non-zero exit from
        # "juju status" (common while machines are still provisioning) does not
        # abort a calling script that has  set -euo pipefail  active.
        not_ready=$(
            set +o pipefail
            export ALLOW_BLOCKED="$allow_blocked"
            juju status --format=json 2>/dev/null | python3 -c '
import json, sys, os
try:
    data = json.load(sys.stdin)
    allowed = set(os.environ.get("ALLOW_BLOCKED", "").split(",")) - {""}
    not_ready = 0
    total_units = 0
    for app_name, app in data.get("applications", {}).items():
        for unit in app.get("units", {}).values():
            total_units += 1
            ws = unit.get("workload-status", {}).get("current", "")
            js = unit.get("juju-status",    {}).get("current", "")
            if ws == "active" and js == "idle":
                continue
            if ws == "blocked" and js == "idle" and app_name in allowed:
                continue
            not_ready += 1
    if total_units == 0:
        print("provisioning")
    else:
        print(not_ready)
except Exception:
    print("provisioning")
'
        ) || not_ready="provisioning"

        if [[ "$not_ready" == "0" ]]; then
            echo "All units active/idle after ${elapsed}s."
            juju status
            return 0
        elif [[ "$not_ready" == "provisioning" ]]; then
            echo "[${elapsed}s elapsed] still provisioning – rechecking in ${interval}s…"
        else
            echo "[${elapsed}s elapsed] ${not_ready} unit(s) not yet active/idle – rechecking in ${interval}s…"
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "Timed out after ${timeout}s. Final status:"
    juju status
    return 1
}

# ---------------------------------------------------------------------------
# retry_until_success – retry a command with a fixed interval until it
# succeeds or the timeout is reached.
#
# Usage:
#   retry_until_success [--timeout SECONDS] [--interval SECONDS]
#                       [--description TEXT] -- COMMAND [ARGS...]
#
# Defaults:
#   --timeout   1200  (20 minutes)
#   --interval   120  (retry every 2 minutes)
#
# Returns 0 on success, 1 when all attempts are exhausted.
# ---------------------------------------------------------------------------
retry_until_success() {
    local timeout=1200
    local interval=120
    local description="command"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)     timeout="$2";     shift 2 ;;
            --interval)    interval="$2";    shift 2 ;;
            --description) description="$2"; shift 2 ;;
            --)            shift; break ;;
            *) echo "retry_until_success: unknown option: $1" >&2; return 1 ;;
        esac
    done

    if [[ $# -eq 0 ]]; then
        echo "retry_until_success: no command specified after --" >&2
        return 1
    fi

    local elapsed=0
    echo "Retrying ${description} (timeout=${timeout}s, interval=${interval}s)…"

    while [[ "$elapsed" -lt "$timeout" ]]; do
        if "$@" 2>&1; then
            echo "${description} succeeded after ${elapsed}s."
            return 0
        fi
        echo "[${elapsed}s elapsed] ${description} failed – retrying in ${interval}s…"
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "ERROR: ${description} did not succeed within ${timeout}s"
    return 1
}

# ---------------------------------------------------------------------------
# current_revision APP – print the charm revision of APP from juju status.
# ---------------------------------------------------------------------------
current_revision() {
    local app="$1"
    juju status --format=json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
app = data['applications']['${app}']
print(app.get('charm-rev', app.get('revision', '')))
"
}

# ---------------------------------------------------------------------------
# wait_app_status APP STATUS [--timeout SECONDS] [--interval SECONDS]
#
# Poll until the *application* workload status equals STATUS
# (e.g. blocked, maintenance, active).
# ---------------------------------------------------------------------------
wait_app_status() {
    local app="$1"; shift
    local want_status="$1"; shift
    local timeout=1200
    local interval=30

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)  timeout="$2";  shift 2 ;;
            --interval) interval="$2"; shift 2 ;;
            *) echo "wait_app_status: unknown option: $1" >&2; return 1 ;;
        esac
    done

    local elapsed=0
    echo "Waiting for app '${app}' to reach status '${want_status}' (timeout=${timeout}s)…"

    while [[ "$elapsed" -lt "$timeout" ]]; do
        local status
        status=$(juju status --format=json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data['applications']['${app}']['application-status']['current'])
except Exception:
    print('')
" ) || status=""
        if [[ "$status" == "$want_status" ]]; then
            echo "App '${app}' is '${want_status}' after ${elapsed}s."
            return 0
        fi
        echo "[${elapsed}s elapsed] app '${app}' status: '${status:-unknown}' – rechecking in ${interval}s…"
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "Timed out waiting for app '${app}' to reach '${want_status}'. Final status:"
    juju status
    return 1
}

# ---------------------------------------------------------------------------
# wait_unit_message UNIT REGEX [--timeout SECONDS] [--interval SECONDS]
#
# Poll until the workload-status message of UNIT matches REGEX.
# UNIT is a juju unit name such as 'opensearch/2' or 'opensearch/leader'.
# ---------------------------------------------------------------------------
wait_unit_message() {
    local unit="$1"; shift
    local regex="$1"; shift
    local timeout=1200
    local interval=30

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)  timeout="$2";  shift 2 ;;
            --interval) interval="$2"; shift 2 ;;
            *) echo "wait_unit_message: unknown option: $1" >&2; return 1 ;;
        esac
    done

    local elapsed=0
    echo "Waiting for unit '${unit}' message to match '${regex}' (timeout=${timeout}s)…"

    while [[ "$elapsed" -lt "$timeout" ]]; do
        local message
        message=$(juju show-unit "$unit" --format=json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    unit = list(data.values())[0]
    print(unit['workload-status'].get('message', ''))
except Exception:
    print('')
" ) || message=""
        if [[ -n "$message" && "$message" =~ $regex ]]; then
            echo "Unit '${unit}' message matches after ${elapsed}s: ${message}"
            return 0
        fi
        echo "[${elapsed}s elapsed] unit '${unit}' message: '${message:-<none>}' – rechecking in ${interval}s…"
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "Timed out waiting for unit '${unit}' message to match '${regex}'. Final status:"
    juju status
    return 1
}

# ---------------------------------------------------------------------------
# save_ca_and_password – fetch admin credentials and CA chain via the
# get-password action and store them for curl.
#
# Writes ./cert.pem, exports OS_PASSWORD and OS_UNIT_IP (public address of
# the leader unit). Must be called from a script (not a subshell) for the
# exports to persist.
# ---------------------------------------------------------------------------
save_ca_and_password() {
    local output
    output=$(juju run opensearch/leader get-password --format=json)
    OS_PASSWORD=$(echo "$output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
result = list(data.values())[0]['results'][0]['result']
print(result['password'])
")
    local ca_chain
    ca_chain=$(echo "$output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
result = list(data.values())[0]['results'][0]['result']
chain = result.get('ca-chain', result.get('ca_chain', ''))
print(chain)
")
    printf '%s\n' "$ca_chain" > cert.pem
    OS_UNIT_IP=$(juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
units = data['applications']['opensearch']['units']
for name, unit in units.items():
    if unit.get('leader', False):
        print(unit['public-address'])
        break
")
    export OS_PASSWORD OS_UNIT_IP
    echo "Saved credentials (unit IP: ${OS_UNIT_IP})."
}

# ---------------------------------------------------------------------------
# reset_baseline – destroy the model and redeploy the baseline cluster.
#
# Used by task setups: scenarios must start from a clean baseline because
# workload downgrades are impossible (OpenSearch cannot downgrade), so a
# `juju refresh` back to the baseline revision after an upgrade leaves a
# poisoned state. Redeploying is the only reliable reset.
#
# Requires /root/revisions.env (REV_BASELINE, DEPLOY_BASE) — sourced here.
# ---------------------------------------------------------------------------
reset_baseline() {
    . /root/revisions.env
    juju destroy-model upgrade --force --no-wait --destroy-storage --no-prompt || true
    juju add-model upgrade

    juju deploy self-signed-certificates --channel latest/stable
    juju deploy opensearch --channel 2/stable --revision="$REV_BASELINE" \
        --base "$DEPLOY_BASE" -n 3
    juju integrate self-signed-certificates opensearch

    wait_idle --timeout 3600
    save_ca_and_password

    # Seed a test index so shard/health assertions are meaningful.
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
    echo "Baseline reset complete: rev $REV_BASELINE on $DEPLOY_BASE."
}

# ---------------------------------------------------------------------------
# cluster_health [EXPECTED_STATUS] – query the cluster health endpoint.
#
# Prints the JSON response. When EXPECTED_STATUS is given (green, yellow…),
# retries until the cluster reports that status and fails on timeout.
# Requires save_ca_and_password to have been called first.
# ---------------------------------------------------------------------------
cluster_health() {
    local expected="${1:-}"
    local timeout=1200
    local interval=30
    local elapsed=0

    local cmd=(
        curl -sS --cacert cert.pem
        "https://${OS_UNIT_IP}:9200/_cluster/health?pretty"
        -u "admin:${OS_PASSWORD}"
    )

    if [[ -z "$expected" ]]; then
        "${cmd[@]}"
        return
    fi

    echo "Waiting for cluster health '${expected}' (timeout=${timeout}s)…"
    while [[ "$elapsed" -lt "$timeout" ]]; do
        local response status
        response=$("${cmd[@]}") || response=""
        status=$(echo "$response" | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin)['status'])
except Exception:
    print('')
" ) || status=""
        if [[ "$status" == "$expected" ]]; then
            echo "Cluster health is '${expected}' after ${elapsed}s."
            echo "$response"
            return 0
        fi
        echo "[${elapsed}s elapsed] cluster health: '${status:-unknown}' – rechecking in ${interval}s…"
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "Timed out waiting for cluster health '${expected}'. Last response:"
    "${cmd[@]}" || true
    return 1
}
