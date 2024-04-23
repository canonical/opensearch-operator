#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the OpenSearch charm with backups and restores.

This test suite will test backup and restore functionality of the OpenSearch charm
against every cloud provider currently supported. Tests are separated into groups
that falls in 2x categories:
* Per cloud provider tests: backup, restore, remove-readd relation and disaster recovery
* All cloud providers tests: build, deploy, test expected API errors and switch configs
                             between the clouds to ensure config changes are working as expected

The latter test group is called "all". The former is a set of groups, each corresponding to a
different cloud.
"""

import asyncio
import logging
import subprocess
import time
import uuid
from typing import Dict

import boto3
import pytest
from charms.opensearch.v0.opensearch_backups import S3_REPOSITORY
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.test_horizontal_scaling import IDLE_PERIOD
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_leader_unit_id,
    get_leader_unit_ip,
    http_request,
    run_action,
)
from ..helpers_deployments import get_application_units, wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .helpers import (
    app_name,
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
    assert_restore_indices_and_compare_consistency,
    create_backup,
    list_backups,
    restore,
    start_and_check_continuous_writes,
)
from .helpers_data import index_docs_count

logger = logging.getLogger(__name__)

S3_INTEGRATOR = "s3-integrator"
S3_INTEGRATOR_CHANNEL = "latest/edge"
TIMEOUT = 10 * 60
BackupsPath = f"opensearch/{uuid.uuid4()}"


# We use this global variable to track the current relation of:
#    backup-id <-> continuous-writes index document count
# We use this global variable then to restore each backup on full DR scenario.
cwrites_backup_doc_count = {}


# Keeps track of the current continuous_writes object that we are using.
# This is relevant for the case where we have a test failure and we need to clean
# the cluster
global_cwrites = None


@pytest.fixture(scope="function")
async def force_clear_cwrites_index():
    """Force clear the global cwrites_backup_doc_count."""
    global global_cwrites
    try:
        if global_cwrites:
            await global_cwrites.clear()
    except Exception:
        pass


@pytest.fixture(scope="session")
def cloud_configs(
    github_secrets: Dict[str, str], microceph: Dict[str, str]
) -> Dict[str, Dict[str, str]]:
    # Figure out the address of the LXD host itself, where tests are executed
    # this is where microceph will be installed.
    ip = subprocess.check_output(["hostname", "-I"]).decode().split()[0]
    results = {
        "microceph": {
            "endpoint": f"http://{ip}",
            "bucket": microceph.bucket,
            "path": BackupsPath,
            "region": "default",
        },
    }
    if "AWS_ACCESS_KEY" in github_secrets:
        results["aws"] = {
            "endpoint": "https://s3.amazonaws.com",
            "bucket": "data-charms-testing",
            "path": BackupsPath,
            "region": "us-east-1",
        }
    return results


@pytest.fixture(scope="session")
def cloud_credentials(
    github_secrets: Dict[str, str], microceph: Dict[str, str]
) -> Dict[str, Dict[str, str]]:
    """Read cloud credentials."""
    results = {
        "microceph": {
            "access-key": microceph.access_key_id,
            "secret-key": microceph.secret_access_key,
        },
    }
    if "AWS_ACCESS_KEY" in github_secrets:
        results["aws"] = {
            "access-key": github_secrets["AWS_ACCESS_KEY"],
            "secret-key": github_secrets["AWS_SECRET_KEY"],
        }
    return results


@pytest.fixture(scope="session", autouse=True)
def remove_backups(
    # ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
):
    """Remove previously created backups from the cloud-corresponding bucket."""
    yield

    logger.info("Cleaning backups from cloud buckets")
    for cloud_name, config in cloud_configs.items():
        if (
            cloud_name not in cloud_credentials
            or "access-key" not in cloud_credentials[cloud_name]
            or "secret-key" not in cloud_credentials[cloud_name]
        ):
            # This cloud has not been used in this test run
            continue

        session = boto3.session.Session(
            aws_access_key_id=cloud_credentials[cloud_name]["access-key"],
            aws_secret_access_key=cloud_credentials[cloud_name]["secret-key"],
            region_name=config["region"],
        )
        s3 = session.resource("s3", endpoint_url=config["endpoint"])
        bucket = s3.Bucket(config["bucket"])

        # Some of our runs target only a single cloud, therefore, they will
        # raise errors on the other cloud's bucket. We catch and log them.
        try:
            bucket.objects.filter(Prefix=f"{BackupsPath}/").delete()
        except Exception as e:
            logger.warning(f"Failed to clean up backups: {e}")


async def _configure_s3(
    ops_test: OpsTest, config: Dict[str, str], credentials: Dict[str, str], app_name: str
) -> None:
    await ops_test.model.applications[S3_INTEGRATOR].set_config(config)
    s3_integrator_id = (await get_application_units(ops_test, S3_INTEGRATOR))[
        0
    ].id  # We redeploy s3-integrator once, so we may have anything >=0 as id
    await run_action(
        ops_test,
        s3_integrator_id,
        "sync-s3-credentials",
        params=credentials,
        app=S3_INTEGRATOR,
    )
    await ops_test.model.wait_for_idle(
        apps=[app_name, S3_INTEGRATOR],
        status="active",
        timeout=TIMEOUT,
    )


S3_INTEGRATOR = "s3-integrator"
S3_INTEGRATOR_CHANNEL = "latest/edge"
TIMEOUT = 10 * 60


DEPLOY_CLOUD_GROUP_MARKS = [
    (
        pytest.param(
            cloud_name,
            deploy_type,
            id=f"{cloud_name}-{deploy_type}",
            marks=pytest.mark.group(f"{cloud_name}-{deploy_type}"),
        )
    )
    for cloud_name in ["microceph", "aws"]
    for deploy_type in ["large", "small"]
]


DEPLOY_SMALL_ONLY_CLOUD_GROUP_MARKS = [
    (
        pytest.param(
            cloud_name,
            deploy_type,
            id=f"{cloud_name}-{deploy_type}",
            marks=pytest.mark.group(f"{cloud_name}-{deploy_type}"),
        )
    )
    for cloud_name in ["microceph", "aws"]
    for deploy_type in ["small"]
]


DEPLOY_LARGE_ONLY_CLOUD_GROUP_MARKS = [
    (
        pytest.param(
            cloud_name,
            deploy_type,
            id=f"{cloud_name}-{deploy_type}",
            marks=pytest.mark.group(f"{cloud_name}-{deploy_type}"),
        )
    )
    for cloud_name in ["microceph", "aws"]
    for deploy_type in ["large"]
]


@pytest.mark.parametrize("cloud_name,deploy_type", DEPLOY_SMALL_ONLY_CLOUD_GROUP_MARKS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_small_deployment_build_and_deploy(
    ops_test: OpsTest, cloud_name: Dict[str, Dict[str, str]]
) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3 integration."""
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    # Credentials not set yet, this will move the opensearch to blocked state
    # Credentials are set per test scenario
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)


@pytest.mark.parametrize("cloud_name,deploy_type", DEPLOY_LARGE_ONLY_CLOUD_GROUP_MARKS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_large_deployment_build_and_deploy(
    ops_test: OpsTest, cloud_name: Dict[str, Dict[str, str]]
) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    tls_config = {"ca-common-name": "CN_CA"}

    my_charm = await ops_test.build_charm(".")

    main_orchestrator_conf = {
        "cluster_name": "backup-test",
        "init_hold": False,
        "roles": "cluster_manager",
    }
    failover_orchestrator_conf = {
        "cluster_name": "backup-test",
        "init_hold": True,
        "roles": "cluster_manager",
    }
    data_hot_conf = {"cluster_name": "backup-test", "init_hold": True, "roles": "data.hot"}

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=tls_config),
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(
            my_charm,
            application_name="main",
            num_units=1,
            series=SERIES,
            config=main_orchestrator_conf,
        ),
        ops_test.model.deploy(
            my_charm,
            application_name="failover",
            num_units=1,
            series=SERIES,
            config=failover_orchestrator_conf,
        ),
        ops_test.model.deploy(
            my_charm, application_name="data-hot", num_units=3, series=SERIES, config=data_hot_conf
        ),
    )

    # Large deployment setup
    await ops_test.model.integrate("main:peer-cluster-orchestrator", "failover:peer-cluster")
    await ops_test.model.integrate("main:peer-cluster-orchestrator", "data-hot:peer-cluster")
    await ops_test.model.integrate("failover:peer-cluster-orchestrator", "data-hot:peer-cluster")

    # TLS setup
    await ops_test.model.integrate("main", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate("failover", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate("data-hot", TLS_CERTIFICATES_APP_NAME)

    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, "main", "failover", "data-hot"],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            "main": 1,
            "failover": 1,
            "data-hot": 3,
        },
        idle_period=IDLE_PERIOD,
    )

    # Credentials not set yet, this will move the opensearch to blocked state
    # Credentials are set per test scenario
    await ops_test.model.integrate("main", S3_INTEGRATOR)


@pytest.mark.parametrize("cloud_name,deploy_type", DEPLOY_CLOUD_GROUP_MARKS)
@pytest.mark.abort_on_fail
async def test_create_backup_and_restore(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
    deploy_type: str,
) -> None:
    """Runs the backup process whilst writing to the cluster into 'noisy-index'."""
    app = (await app_name(ops_test)) or (APP_NAME if deploy_type == "small" else "main")
    leader_id = await get_leader_unit_id(ops_test)
    unit_ip = await get_leader_unit_ip(ops_test)
    config = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    assert (
        backup_id := await create_backup(
            ops_test,
            leader_id,
            unit_ip=unit_ip,
        )
    ) > 0
    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )
    global cwrites_backup_doc_count
    cwrites_backup_doc_count[backup_id] = await index_docs_count(
        ops_test,
        app,
        unit_ip,
        ContinuousWrites.INDEX_NAME,
    )


@pytest.mark.parametrize("cloud_name,deploy_type", DEPLOY_CLOUD_GROUP_MARKS)
@pytest.mark.abort_on_fail
async def test_remove_and_readd_s3_relation(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
    deploy_type: str,
) -> None:
    """Removes and re-adds the s3-credentials relation to test backup and restore."""
    app = (await app_name(ops_test)) or (APP_NAME if deploy_type == "small" else "main")
    leader_id: str = await get_leader_unit_id(ops_test)
    unit_ip: str = await get_leader_unit_ip(ops_test)
    config: Dict[str, str] = cloud_configs[cloud_name]

    logger.info("Remove s3-credentials relation")
    # Remove relation
    await ops_test.model.applications[app].destroy_relation(
        "s3-credentials", f"{S3_INTEGRATOR}:s3-credentials"
    )
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    logger.info("Re-add s3-credentials relation")
    await ops_test.model.integrate(app, S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    assert (
        backup_id := await create_backup(
            ops_test,
            leader_id,
            unit_ip=unit_ip,
        )
    ) > 0
    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )
    global cwrites_backup_doc_count
    cwrites_backup_doc_count[backup_id] = await index_docs_count(
        ops_test,
        app,
        unit_ip,
        ContinuousWrites.INDEX_NAME,
    )


@pytest.mark.parametrize("cloud_name,deploy_type", DEPLOY_SMALL_ONLY_CLOUD_GROUP_MARKS)
@pytest.mark.abort_on_fail
async def test_restore_to_new_cluster(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
    deploy_type: str,
    force_clear_cwrites_index,
) -> None:
    """Deletes the entire OpenSearch cluster and redeploys from scratch.

    Restores each of the previous backups we created and compare with their doc count.
    The cluster is considered healthy if:
    1) At each backup restored, check our track of doc count vs. current index count
    2) Try to write to that new index.
    """
    app = (await app_name(ops_test)) or (APP_NAME if deploy_type == "small" else "main")
    logging.info("Destroying the application")
    await asyncio.gather(
        ops_test.model.remove_application(S3_INTEGRATOR, block_until_done=True),
        ops_test.model.remove_application(app, block_until_done=True),
        ops_test.model.remove_application(TLS_CERTIFICATES_APP_NAME, block_until_done=True),
    )

    logging.info("Deploying a new cluster")
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, app],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    # Credentials not set yet, this will move the opensearch to blocked state
    # Credentials are set per test scenario
    await ops_test.model.integrate(app, S3_INTEGRATOR)

    leader_id = await get_leader_unit_id(ops_test)
    unit_ip = await get_leader_unit_ip(ops_test)
    config: Dict[str, str] = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)
    backups = await list_backups(ops_test, leader_id)

    global cwrites_backup_doc_count
    # We are expecting 2x backups available
    assert len(backups) == 2
    assert len(cwrites_backup_doc_count) == 2
    count = 0
    for backup_id in backups.keys():
        assert await restore(ops_test, backup_id, unit_ip, leader_id)
        count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)

        # Ensure we have the same doc count as we had on the original cluster
        assert count == cwrites_backup_doc_count[backup_id]

        # restart the continuous writes and check the cluster is still accessible post restore
        assert await start_and_check_continuous_writes(ops_test, unit_ip, app)

    # Now, try a backup & restore with continuous writes
    logger.info("Final stage of DR test: try a backup & restore with continuous writes")
    writer: ContinuousWrites = ContinuousWrites(ops_test, app)

    # store the global cwrites object
    global global_cwrites
    global_cwrites = writer

    await writer.start()
    time.sleep(10)
    assert (
        backup_id := await create_backup(
            ops_test,
            leader_id,
            unit_ip=unit_ip,
        )
    ) > 0
    # continuous writes checks
    await assert_continuous_writes_increasing(writer)
    await assert_continuous_writes_consistency(ops_test, writer, app)
    # This assert assures we have taken a new backup, after the last restore from the original
    # cluster. That means the index is writable.
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )
    # Clear the writer manually, as we are not using the conftest c_writes_runner to do so
    await writer.clear()


# -------------------------------------------------------------------------------------------
# Tests for the "all" group
#
# This group will iterate over each cloud, update its credentials via config and rerun
# the backup and restore tests.
# -------------------------------------------------------------------------------------------


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_deploy_and_test_status(ops_test: OpsTest) -> None:
    """Build, deploy and test status of an HA cluster of OpenSearch and corresponding backups.

    This test group will iterate over each cloud, update its credentials via config and rerun
    the backup and restore tests.
    """
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    # Credentials not set yet, this will move the opensearch to blocked state
    # Credentials are set per test scenario
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
async def test_repo_missing_message(ops_test: OpsTest) -> None:
    """Check the repo is missing error returned by OpenSearch.

    We use the message format to monitor the cluster status. We need to know if this
    message pattern changed between releases of OpenSearch.
    """
    unit_ip = await get_leader_unit_ip(ops_test)
    resp = await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}", json_resp=True
    )
    logger.debug(f"Response: {resp}")
    assert resp["status"] == 404
    assert "repository_missing_exception" in resp["error"]["type"]


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
async def test_wrong_s3_credentials(ops_test: OpsTest) -> None:
    """Check the repo is misconfigured."""
    unit_ip = await get_leader_unit_ip(ops_test)
    app = (await app_name(ops_test)) or APP_NAME

    config = {
        "endpoint": "http://localhost",
        "bucket": "error",
        "path": "/",
        "region": "default",
    }
    credentials = {
        "access-key": "error",
        "secret-key": "error",
    }

    # Not using _configure_s3 as this method will cause opensearch to block
    await ops_test.model.applications[S3_INTEGRATOR].set_config(config)
    await run_action(
        ops_test,
        0,
        "sync-s3-credentials",
        params=credentials,
        app=S3_INTEGRATOR,
    )
    await ops_test.model.wait_for_idle(
        apps=[S3_INTEGRATOR],
        status="active",
        timeout=TIMEOUT,
    )
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["blocked"],
        units_statuses=["active"],
        wait_for_exact_units=3,
        idle_period=30,
    )

    resp = await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}/_all", json_resp=True
    )
    logger.debug(f"Response: {resp}")
    assert resp["status"] == 500
    assert "repository_exception" in resp["error"]["type"]
    assert "Could not determine repository generation from root blobs" in resp["error"]["reason"]


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
async def test_change_config_and_backup_restore(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    force_clear_cwrites_index,
) -> None:
    """Run for each cloud and update the cluster config."""
    unit_ip: str = await get_leader_unit_ip(ops_test)
    app: str = (await app_name(ops_test)) or APP_NAME
    leader_id: str = await get_leader_unit_id(ops_test)

    initial_count: int = 0
    for cloud_name in cloud_configs.keys():
        logger.debug(
            f"Index {ContinuousWrites.INDEX_NAME} has {initial_count} documents, starting there"
        )
        # Start the ContinuousWrites here instead of bringing as a fixture because we want to do
        # it for every cloud config we have and we have to stop it before restore, right down.
        writer: ContinuousWrites = ContinuousWrites(ops_test, app, initial_count=initial_count)

        # store the global cwrites object
        global global_cwrites
        global_cwrites = writer

        await writer.start()
        time.sleep(10)

        logger.info(f"Syncing credentials for {cloud_name}")
        config: Dict[str, str] = cloud_configs[cloud_name]
        await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

        assert (
            backup_id := await create_backup(
                ops_test,
                leader_id,
                unit_ip=unit_ip,
            )
        ) != ""
        # continuous writes checks
        await assert_continuous_writes_increasing(writer)
        await assert_continuous_writes_consistency(ops_test, writer, app)
        await assert_restore_indices_and_compare_consistency(
            ops_test, app, leader_id, unit_ip, backup_id
        )
        # Clear the writer manually, as we are not using the conftest c_writes_runner to do so
        await writer.clear()
