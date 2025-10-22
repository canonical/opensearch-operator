#!/usr/bin/env bash

set -eu


### CONSTANT VALUES
DEFAULT_NODE_COUNT=3
TEST_IDX="test"
# Default APP name:
APP="opensearch"
OSD="opensearch-dashboard"
URL=
OSD_PORT=5601
INTEGRATOR="data-integrator"
MODEL=

# Error codes
ERROR_OPTION=1
#ERROR_BASIC_HTTP=2
ERROR_CLUSTER_NOT_GREEN=3
ERROR_CLUSTER_COUNT_WRONG=4
ERROR_CREATE_INDEX_FAILED=5
#ERROR_SHARDS_NOT_STARTED=6
ERROR_DELETING_IDX_FAILED=7
ERROR_INDEXING_DOC_FAILED=8
ERROR_COUNT_INDEX_DOC_FAILED=9
ERROR_DASHBOARDS_NOT_ACCESSIBLE=10
################################################


function usage() {
cat << EOF
usage: smoke_test.sh [OPTIONS]
To be ran / setup once per cluster.
-m            (Required)  Model name for the deployment
-o            (Optional)  Name of the opensearch app to be targeted for these tests. Defaults to "opensearch"
-u            (Optional)  OpenSearch dashboards URL. Defaults to empty value.
-d            (Optional)  Name of the opensearch-dashboard app to be targeted for these tests if the URL is not set. Defaults to "opensearch-dashboard"
-i            (Optional)  Name of the data-integrator app to be targeted for these tests. Defaults to "data-integrator"
--help                    Shows help menu
EOF

exit $ERROR_OPTION
}

while [ $# -gt 0 ]; do
    case $1 in
        -m) shift
            MODEL=$1
            ;;
        -o) shift
            APP=$1
            ;;
        -d) shift
            OSD=$1
            ;;
        -u) shift
            URL=$1
            ;;
        -i) shift
            INTEGRATOR=$1
            ;;
        *)
            usage
            ;;
    esac
    shift
done
shift $((OPTIND-1))


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
    if ! juju models | grep "$MODEL" > /dev/null 2>&1; then
        echo "Model ${MODEL} not found in Juju"
        exit 1
    fi
}


# Doing the first checks before moving on
run_prechecks

# Now, we wait for all apps to be active
for app in $(juju status -m "${MODEL}" --format json | jq -r '.applications | keys[]'); do 
    juju wait-for application "$app"
done

OPENSEARCH_IP=$(juju exec --unit "${APP}"/leader -m "${MODEL}" -- unit-get public-address)
if [ -z "$URL" ]; then
    URL=$(juju exec --unit "${OSD}"/leader -m "${MODEL}" -- unit-get public-address)
else
    OSD_PORT=443
fi

OPENSEARCH_CREDENTIALS=$(juju run "${APP}"/leader get-password --format=json 2>/dev/null)
OPENSEARCH_USERNAME=$(echo "${OPENSEARCH_CREDENTIALS}" | jq -r '. | values[].results.username')
OPENSEARCH_PASSWORD=$(echo "${OPENSEARCH_CREDENTIALS}" | jq -r '. | values[].results.password')

INTEGRATOR_CREDENTIALS=$(juju run "$INTEGRATOR"/leader get-credentials --format=json 2>/dev/null)
INTEGRATOR_USERNAME=$(echo "${INTEGRATOR_CREDENTIALS}" | jq -r '. | values[].results' | jq --arg app "$APP" -r '.[$app].username')
INTEGRATOR_PASSWORD=$(echo "${INTEGRATOR_CREDENTIALS}" | jq -r '. | values[].results' | jq --arg app "$APP" -r '.[$app].password')

############################################################
#                                                          #
#                                                          #
#               OPENSEARCH  DASHBOARDS                     #
#                                                          #
#                                                          #
############################################################

function check_dashboards_accessible() {
    val=$(curl -XPOST -sk -H "Content-Type: application/json" -H "osd-xsrf: true" -d "{\"username\": \"${OPENSEARCH_USERNAME}\", \"password\": \"${OPENSEARCH_PASSWORD}\"}" "https://${URL}:${OSD_PORT}/auth/login" | jq -r .username)
    if [ "$val" == "null" ] || [ "$val" != "${OPENSEARCH_USERNAME}" ]; then
        echo "Dashboards is not accessible"
        exit $ERROR_DASHBOARDS_NOT_ACCESSIBLE
    fi
}

function check_integrator_dashboards_accessible() {
    val=$(curl -XPOST -sk -H "Content-Type: application/json" -H "osd-xsrf: true" -d "{\"username\": \"${INTEGRATOR_USERNAME}\", \"password\": \"${INTEGRATOR_PASSWORD}\"}" "https://${URL}:${OSD_PORT}/auth/login" | jq -r .username)
    if [ "$val" == "null" ] || [ "$val" != "${INTEGRATOR_USERNAME}" ]; then
        echo "Dashboards is not accessible"
        exit $ERROR_DASHBOARDS_NOT_ACCESSIBLE
    fi
}

check_dashboards_accessible
check_integrator_dashboards_accessible

############################################################
#                                                          #
#                                                          #
#               OPENSEARCH                                 #
#                                                          #
#                                                          #
############################################################



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

    if [ "$count" -ne $DEFAULT_NODE_COUNT ]; then
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
    sleep 10
    shards=$(curl -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/_cat/shards/${TEST_IDX}?format=json" | jq -c '.[] | select(.state | contains("STARTED"))' | wc -l)
    echo "Shards started: $shards"
    if [ "$(echo "$ack" | jq -r .acknowledged)" != "true" ]; then
        echo "Indexing document failed"
        exit $ERROR_INDEXING_DOC_FAILED
    fi
}

function check_index_data() {

    for id in {1..100}; do
        ack=$(curl -XPUT -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/${TEST_IDX}/_doc/${id}" -H 'Content-Type: application/json' -d"{\"test\": \"${id}\"}")
        if [ "$(echo "$ack" | jq -r ._shards.total)" -ne $DEFAULT_NODE_COUNT ]; then
            echo "Data in index is not as expected"
            exit "$ERROR_DATA_NOT_FOUND"
        fi
    done

    sleep 15s

    ack=$(curl -sk -u "${OPENSEARCH_USERNAME}":"${OPENSEARCH_PASSWORD}" "https://${OPENSEARCH_IP}:9200/${TEST_IDX}/_count")
    echo "Indexing document count ack: $ack"
    if [ "$(echo "$ack" | jq -r .count)" -ne 100 ]; then
        echo "Indexing count document failed"
        exit $ERROR_COUNT_INDEX_DOC_FAILED
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
check_create_idx_and_validate_shards
check_index_data
check_delete_idx
