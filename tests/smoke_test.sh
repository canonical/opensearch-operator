#!/usr/bin/env bash

set -eux


### CONSTANT VALUES
DEFAULT_NODE_COUNT=3
TEST_IDX="test"
# Default APP name:
APP="opensearch"
OSD="opensearch-dashboard"
MODEL=

# Error codes
ERROR_OPTION=1
ERROR_BASIC_HTTP=2
ERROR_CLUSTER_NOT_GREEN=3
ERROR_CLUSTER_COUNT_WRONG=4
ERROR_CREATE_INDEX_FAILED=5
ERROR_SHARDS_NOT_STARTED=6
ERROR_DELETING_IDX_FAILED=7
################################################


function usage() {
cat << EOF
usage: smoke_test.sh [OPTIONS]
To be ran / setup once per cluster.
--model            (Required)  Model name for the deployment
--opensearch       (Optional)  Name of the opensearch app to be targeted for these tests
--model            (Optional)  Name of the opensearch-dashboard app to be targeted for these tests
--help                         Shows help menu
EOF

exit $ERROR_OPTION
}


function set_arguments() {

    echo $@
    exit 0

    while [ $# -gt 0 ]; do
        case $1 in
            --model) shift
                MODEL=$1
                ;;
            --opensearch) shift
                APP=$1
                ;;
            --dashboard) shift
                OSD=$1
                ;;
            *)
                usage
                ;;
        esac
        shift
    done
    shift $((OPTIND-1))
}


function run_prechecks() {
    if ! jq --help > /dev/null 2>&1; then
        echo "Missing jq command, consider installing it with 'sudo snap install jq --classic'"
        exit 1
    fi
    if ! curl --help > /dev/null 2>&1; then
        echo "Missing curl command, consider installing it with 'sudo apt install curl'"
        exit 1
    fi
    if ! juju --help > /dev/null 2>&1; then
        echo "Missing juju command"
        exit 1
    fi
    if ! juju models | grep $MODEL > /dev/null 2>&1; then
        echo "Model ${MODEL} not found in Juju"
        exit 1
    fi
}


# Doing the first checks before moving on
set_arguments
run_prechecks

# Now, we wait for all apps to be active / idle
for app in $(juju status -m test --format json | jq -r '.applications | keys[]'); do 
    juju wait-for application $app \
        --query='name=="$app" && (status=="active" || status=="idle")'
done

OPENSEARCH_IP=$(juju exec --unit "${APP}"/leader -m "${MODEL}" -- unit-get public-address)
OPENSEARCH_USERNAME=$(juju run "$APP"/leader get-password --format=json 2>/dev/null | jq -r '. | values[].results.username')
OPENSEARCH_PASSWORD=$(juju run "$APP"/leader get-password --format=json 2>/dev/null | jq -r '. | values[].results.password')


# Now, the basic is all set, we move on to the actual tests
function check_cluster_status() {
    status=$(curl -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/_cluster/health" | jq -r .status)
    echo "Cluster status is $status"

    if [ "$status" != "green" ]; then
        echo "Cluster status is not green"
        exit $ERROR_CLUSTER_NOT_GREEN
    fi
}

function check_cluster_node_count() {
    count=$(curl -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/_nodes" | jq -r '.nodes | keys[]' | wc -l)
    echo "Cluster node count is $count"

    if [ $count -ne DEFAULT_NODE_COUNT ]; then
        echo "Cluster node count is different than three"
        exit $ERROR_CLUSTER_COUNT_WRONG
    fi
}

function check_create_idx_and_validate_shards() {
    ack=$(curl -XPUT -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/${TEST_IDX}" -H 'Content-Type: application/json' -d'
    {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 2
        }
    }')
    echo "Index creation ack: $ack"

    if [ "$(echo "$ack" | jq -r .acknowledged)" != "true" ]; then
        echo "Index creation failed"
        exit $ERROR_CREATE_INDEX_FAILED
    fi

    # Now we check the shards
    sleep 30
    shards="$(curl -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/_cat/shards/${TEST_IDX]?format=json" | jq -c '.[] | select(.state | contains("STARTED"))' | wc -l)"
    echo "Shards started: $shards"
    if [ $shards -ne 3 ]; then
        echo "Shards are not as expected"
        exit $ERROR_SHARDS_NOT_STARTED
    fi
}

function check_delete_idx() {
    ack=$(curl -XDELETE -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/${TEST_IDX}")
    echo "Index deletion ack: $ack"
    if [ "$(echo "$ack" | jq -r .acknowledged)" != "true" ]; then
        echo "Index creation failed"
        exit $ERROR_DELETING_IDX_FAILED
    fi
}

check_cluster_status
check_cluster_node_count