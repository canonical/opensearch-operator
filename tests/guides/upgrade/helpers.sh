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
    # The JSON shape of "juju run <action> --format=json" differs across juju
    # versions (results may be a dict or a list, with or without a nested
    # "result" key), so search for the keys anywhere in the document.
    OS_PASSWORD=$(echo "$output" | python3 -c "
import json, sys

def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = find_key(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_key(item, key)
            if found is not None:
                return found
    return None

data = json.load(sys.stdin)
password = find_key(data, 'password')
print(password if password is not None else '')
")
    local ca_chain
    ca_chain=$(echo "$output" | python3 -c "
import json, sys

def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = find_key(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_key(item, key)
            if found is not None:
                return found
    return None

data = json.load(sys.stdin)
chain = find_key(data, 'ca-chain')
if chain is None:
    chain = find_key(data, 'ca_chain')
print(chain if chain is not None else '')
")
    if [[ -z "$OS_PASSWORD" || -z "$ca_chain" ]]; then
        echo "ERROR: could not extract password/CA chain from get-password output:" >&2
        echo "$output" >&2
        return 1
    fi
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
# juju_refresh APP REVISION [EXTRA_ARGS...] – refresh APP to REVISION with
# retry.
#
# `juju refresh` intermittently fails right after a model churn with
#   ERROR "app" deploy incomplete, please try refresh again in a little bit.
# which Juju itself says is transient. Wrap the refresh in a retry loop so
# the tasks don't die on this race.
#
# Returns 0 when the refresh was accepted, 1 when retries are exhausted.
# ---------------------------------------------------------------------------
juju_refresh() {
    local app="$1"; shift
    local revision="$1"; shift

    retry_until_success \
        --timeout 600 \
        --interval 30 \
        --description "juju refresh ${app} to revision ${revision}" \
        -- juju refresh "$app" --revision="$revision" "$@"
}

# ---------------------------------------------------------------------------
# wait_highest_unit_upgraded [EXPECTED_VERSION] – poll until the highest
# ordinal unit of the opensearch app has actually finished its workload
# upgrade.
#
# The app turns `blocked` as soon as the upgrade *starts*, long before the
# highest unit's workload is actually replaced. This gate waits until the
# highest unit is active/idle AND its status message reports a running
# OpenSearch version that is not marked "(outdated)".
#
# When EXPECTED_VERSION is given (e.g. "2.19.4"), the message must report
# exactly that version. Without it, any non-outdated running version is
# accepted (used for rollbacks, where the target version is the old one).
#
# Returns 0 when the unit is upgraded, 1 on timeout.
# ---------------------------------------------------------------------------
wait_highest_unit_upgraded() {
    local expected_version="${1:-}"
    local timeout=1800
    local interval=30
    local elapsed=0

    echo "Waiting for highest opensearch unit to finish its workload upgrade (timeout=${timeout}s)…"

    while [[ "$elapsed" -lt "$timeout" ]]; do
        local payload
        payload=$(juju status --format=json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    units = data['applications']['opensearch']['units']
    highest = max(int(name.split('/')[1]) for name in units)
    unit = units[f'opensearch/{highest}']
    print(unit.get('workload-status', {}).get('current', ''))
    print(unit.get('workload-status', {}).get('message', ''))
    print(unit.get('juju-status', {}).get('current', ''))
except Exception:
    print('error')
    print('')
    print('')
" ) || payload="error
"

        local workload_status message agent_status
        workload_status=$(echo "$payload" | sed -n 1p)
        message=$(echo "$payload" | sed -n 2p)
        agent_status=$(echo "$payload" | sed -n 3p)

        if [[ "$workload_status" == "active" && "$agent_status" == "idle" \
              && "$message" != *"(outdated)"* && "$message" == *"running"* ]]; then
            if [[ -z "$expected_version" || "$message" == *"OpenSearch ${expected_version} running"* ]]; then
                echo "Highest unit upgraded after ${elapsed}s: ${message}"
                return 0
            fi
        fi
        echo "[${elapsed}s elapsed] highest unit: '${workload_status}/${agent_status}: ${message}' – rechecking in ${interval}s…"
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "ERROR: highest opensearch unit did not finish upgrading within ${timeout}s. Final status:"
    juju status
    return 1
}

# ---------------------------------------------------------------------------
# juju_run_action UNIT ACTION [PARAMS...] – run a Juju action and fail the
# task when the action itself fails.
#
# `juju run` returns non-zero when the action fails, but under `set -e` a
# failing action inside a pipeline or subshell can be silently swallowed.
# This wrapper always propagates the failure with a clear message.
# ---------------------------------------------------------------------------
juju_run_action() {
    local unit="$1"; shift
    local action="$1"; shift

    echo "Running action ${action} on ${unit}…"
    if ! juju run "$unit" "$action" "$@"; then
        echo "ERROR: action ${action} on ${unit} failed" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# clear_node_lock – delete the charm node-lock document if it exists.
#
# Requires save_ca_and_password to have been called first. Tolerates a 404
# (lock already gone).
# ---------------------------------------------------------------------------
clear_node_lock() {
    local lock_holder
    lock_holder=$(curl -sS --cacert cert.pem \
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
    if [[ -n "${lock_holder:-}" ]]; then
        echo "Node lock held by ${lock_holder} — deleting"
        curl -sS --cacert cert.pem \
            -X DELETE "https://${OS_UNIT_IP}:9200/.charm_node_lock/_doc/0?refresh=true" \
            -u "admin:${OS_PASSWORD}"
    else
        echo "No stale node lock found"
    fi
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
    juju destroy-model upgrade --force --no-wait --destroy-storage --no-prompt \
        || { echo "ERROR: failed to destroy model 'upgrade'"; return 1; }
    # Wait until the model is really gone; add-model races with teardown.
    local elapsed=0
    while juju models --format=json 2>/dev/null | python3 -c "
import json, sys
sys.exit(0 if 'upgrade' in [m['name'] for m in json.load(sys.stdin).get('models', [])] else 1)
" 2>/dev/null; do
        [[ "$elapsed" -ge 300 ]] && { echo "ERROR: model 'upgrade' still present after 300s"; return 1; }
        sleep 10
        elapsed=$(( elapsed + 10 ))
    done
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
