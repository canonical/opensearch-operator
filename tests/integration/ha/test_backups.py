#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
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
import os
import random
import string
import time
import uuid
from datetime import datetime
from typing import Dict

import boto3
import botocore
import pytest
from azure.storage.blob import BlobServiceClient
from charms.opensearch.v0.constants_charm import (
    OPENSEARCH_BACKUP_ID_FORMAT,
    BackupRelShouldNotExist,
    BackupSetupFailed,
)
from charms.opensearch.v0.opensearch_snapshots import S3_REPOSITORY
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.test_horizontal_scaling import IDLE_PERIOD
from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    get_leader_unit_id,
    get_leader_unit_ip,
    http_request,
    run_action,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers import (
    add_juju_secret,
    app_name,
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
    assert_restore_indices_and_compare_consistency,
    assert_start_and_check_continuous_writes,
    create_backup,
    list_backups,
    restore,
)
from .helpers_data import index_docs_count

logger = logging.getLogger(__name__)

ALL_GROUPS = {
    (cloud_name, deploy_type): pytest.param(
        cloud_name,
        deploy_type,
        id=f"{cloud_name}-{deploy_type}",
        marks=[pytest.mark.group(id=f"{cloud_name}-{deploy_type}")],
    )
    for cloud_name in ["microceph", "aws", "azure"]
    for deploy_type in ["large", "small"]
}

ALL_DEPLOYMENTS_ALL_CLOUDS = list(ALL_GROUPS.values())
SMALL_DEPLOYMENTS_ALL_CLOUDS = [
    ALL_GROUPS[(cloud, "small")] for cloud in ["aws", "microceph", "azure"]
]
LARGE_DEPLOYMENTS_ALL_CLOUDS = [
    ALL_GROUPS[(cloud, "large")] for cloud in ["aws", "microceph", "azure"]
]

S3_INTEGRATOR = "s3-integrator"
S3_INTEGRATOR_CHANNEL = "1/stable"
S3_RELATION = "s3-credentials"
AZURE_INTEGRATOR = "azure-storage-integrator"
AZURE_INTEGRATOR_CHANNEL = "latest/edge"
AZURE_RELATION = "azure-credentials"

TIMEOUT = 20 * 60
BackupsPath = f"opensearch/{uuid.uuid4()}"


# We use this global variable to track the current relation of:
#    backup-id <-> continuous-writes index document count
# We use this global variable then to restore each backup on full DR scenario.
cwrites_backup_doc_count: Dict[str, int] = {}

# Keeps track of the current continuous_writes object that we are using.
# This is relevant for the case where we have a test failure and we need to clean
# the cluster
global_cwrites = None


@pytest.fixture(scope="function")
async def force_clear_cwrites_index():
    """Force clear the global cwrites index if a previous writer is still around."""
    global global_cwrites
    try:
        if global_cwrites:
            await global_cwrites.clear()
    except Exception:
        pass


#  MicroCeph (RADOS GW) integration
# We rely on the preparation fixtures provided in the same test tree (conftest.py):
# - storage_config(): {endpoint, bucket, path, region, tls-ca-chain (base64 PEM)}
# - storage_credentials(): {access-key, secret-key}
# These are produced by a setup that bootstraps microceph,
# enables RGW on 445 with a self-signed cert,
# and writes cert.pem to the working directory.


@pytest.fixture(scope="session")
def cloud_configs(microceph: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Return cloud configs, including MicroCeph with HTTPS and tls-ca-chain."""
    results = {
        "microceph": {
            "endpoint": microceph["endpoint"],
            "bucket": microceph["bucket"],
            "path": BackupsPath,
            "region": microceph.get("region", "") or "test",
            "tls-ca-chain": microceph["tls-ca-chain"],
        },
    }
    if os.environ.get("AWS_ACCESS_KEY"):
        results["aws"] = {
            "endpoint": "https://s3.amazonaws.com",
            "bucket": "data-charms-testing",
            "path": BackupsPath,
            "region": "us-east-1",
        }
    if os.environ.get("AZURE_SECRET_KEY"):
        results["azure"] = {
            "connection-protocol": "abfss",
            "container": "data-charms-testing",
            "path": BackupsPath,
        }
    return results


@pytest.fixture(scope="session")
def cloud_credentials(microceph: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Return credentials for each cloud."""
    results = {
        "microceph": {
            "access-key": microceph["access-key"],
            "secret-key": microceph["secret-key"],
        },
    }
    if os.environ.get("AWS_ACCESS_KEY"):
        results["aws"] = {
            "access-key": os.environ["AWS_ACCESS_KEY"],
            "secret-key": os.environ["AWS_SECRET_KEY"],
        }
    if os.environ.get("AZURE_SECRET_KEY"):
        results["azure"] = {
            "secret-key": os.environ["AZURE_SECRET_KEY"],
            "storage-account": os.environ["AZURE_STORAGE_ACCOUNT"],
        }
    return results


@pytest.fixture(scope="session", autouse=True)
def remove_backups(  # noqa C901
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
):
    """Remove previously created backups from cloud buckets/containers."""
    yield

    logger.info("Cleaning backups from cloud buckets")
    for cloud_name, config in cloud_configs.items():
        if cloud_name not in cloud_credentials:
            continue

        if cloud_name in ("aws", "microceph"):
            if not all(k in cloud_credentials[cloud_name] for k in ("access-key", "secret-key")):
                continue

            # For MicroCeph we must verify with the local self-signed cert.
            # cert.pem is created by the microceph preparation fixture.
            verify_arg = "cert.pem" if cloud_name == "microceph" else True
            session = boto3.session.Session(
                aws_access_key_id=cloud_credentials[cloud_name]["access-key"],
                aws_secret_access_key=cloud_credentials[cloud_name]["secret-key"],
                region_name=config.get("region") or None,
            )
            s3 = session.client("s3", endpoint_url=config["endpoint"], verify=verify_arg)

            try:
                # list and delete objects with BackupsPath prefix
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=config["bucket"], Prefix=f"{BackupsPath}/"):
                    for obj in page.get("Contents", []):
                        s3.delete_object(Bucket=config["bucket"], Key=obj["Key"])
            except botocore.exceptions.BotoCoreError as e:
                logger.warning(f"Failed to clean up backups on {cloud_name}: {e}")

        if cloud_name == "azure":
            if not all(
                k in cloud_credentials[cloud_name] for k in ("secret-key", "storage-account")
            ):
                continue

            storage_account = cloud_credentials[cloud_name]["storage-account"]
            secret_key = cloud_credentials[cloud_name]["secret-key"]
            connection_string = (
                f"DefaultEndpointsProtocol=https;AccountName={storage_account};"
                f"AccountKey={secret_key};EndpointSuffix=core.windows.net"
            )
            blob_service_client = BlobServiceClient.from_connection_string(connection_string)
            container_client = blob_service_client.get_container_client(config["container"])

            try:
                for blob in container_client.list_blobs(name_starts_with=BackupsPath):
                    container_client.delete_blob(blob.name)
            except Exception as e:
                logger.warning(f"Failed to clean up backups on azure: {e}")


async def _configure_s3(
    ops_test: OpsTest,
    config: Dict[str, str],
    credentials: Dict[str, str],
    app_name: str | None = None,
) -> None:
    """Configure s3-integrator with endpoint/bucket/path/region and optional tls-ca-chain."""
    base_cfg = {
        "endpoint": config["endpoint"],
        "bucket": config["bucket"],
        "path": config["path"],
        "region": config.get("region", "") or "",
    }
    if "tls-ca-chain" in config:
        base_cfg["tls-ca-chain"] = config["tls-ca-chain"]  # base64 PEM

    await ops_test.model.applications[S3_INTEGRATOR].set_config(base_cfg)

    # credentials via juju secret
    local_label = "".join(random.choice(string.ascii_letters) for _ in range(10))
    credentials_secret_uri = await add_juju_secret(
        ops_test,
        S3_INTEGRATOR,
        local_label,
        {"secret-key": credentials["secret-key"], "access-key": credentials["access-key"]},
    )
    await ops_test.model.applications[S3_INTEGRATOR].set_config(
        {"credentials": credentials_secret_uri}
    )

    apps = [S3_INTEGRATOR] if app_name is None else [S3_INTEGRATOR, app_name]
    await ops_test.model.wait_for_idle(apps=apps, status="active", timeout=TIMEOUT)


async def _configure_azure(
    ops_test: OpsTest,
    config: Dict[str, str],
    credentials: Dict[str, str],
    app_name: str | None = None,
) -> None:
    await ops_test.model.applications[AZURE_INTEGRATOR].set_config(config)

    local_label = "".join(random.choice(string.ascii_letters) for _ in range(10))
    credentials_secret_uri = await add_juju_secret(
        ops_test,
        AZURE_INTEGRATOR,
        local_label,
        {"secret-key": credentials["secret-key"]},
    )
    await ops_test.model.applications[AZURE_INTEGRATOR].set_config(
        {"storage-account": credentials["storage-account"], "credentials": credentials_secret_uri}
    )

    apps = [AZURE_INTEGRATOR] if app_name is None else [AZURE_INTEGRATOR, app_name]
    await ops_test.model.wait_for_idle(apps=apps, status="active", timeout=TIMEOUT)


@pytest.mark.parametrize("cloud_name,deploy_type", SMALL_DEPLOYMENTS_ALL_CLOUDS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_small_deployment_build_and_deploy(
    ops_test: OpsTest, charm, series, cloud_name: str, deploy_type: str
) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3/Azure integration."""
    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    config = {"ca-common-name": "CN_CA"}

    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_integrator_channel = (
        AZURE_INTEGRATOR_CHANNEL if cloud_name == "azure" else S3_INTEGRATOR_CHANNEL
    )

    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(backup_integrator, channel=backup_integrator_channel),
        ops_test.model.deploy(charm, num_units=3, series=series, config=CONFIG_OPTS),
    )

    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    await ops_test.model.integrate(APP_NAME, backup_integrator)


@pytest.mark.parametrize("cloud_name,deploy_type", LARGE_DEPLOYMENTS_ALL_CLOUDS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_large_deployment_build_and_deploy(
    ops_test: OpsTest, charm, series, cloud_name: str, deploy_type: str
) -> None:
    """Build and deploy a large cluster (main/failover orchestrators + data.hot node)."""
    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    tls_config = {"ca-common-name": "CN_CA"}

    main_orchestrator_conf = {
        "cluster_name": "backup-test",
        "init_hold": False,
        "roles": "cluster_manager,data",
    }
    failover_orchestrator_conf = {
        "cluster_name": "backup-test",
        "init_hold": True,
        "roles": "cluster_manager",
    }
    data_hot_conf = {"cluster_name": "backup-test", "init_hold": True, "roles": "data.hot"}

    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_integrator_channel = (
        AZURE_INTEGRATOR_CHANNEL if cloud_name == "azure" else S3_INTEGRATOR_CHANNEL
    )

    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=tls_config
        ),
        ops_test.model.deploy(backup_integrator, channel=backup_integrator_channel),
        ops_test.model.deploy(
            charm,
            application_name="main",
            num_units=1,
            series=series,
            config=main_orchestrator_conf | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name="failover",
            num_units=2,
            series=series,
            config=failover_orchestrator_conf | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=APP_NAME,
            num_units=1,
            series=series,
            config=data_hot_conf | CONFIG_OPTS,
        ),
    )

    await ops_test.model.integrate("main:peer-cluster-orchestrator", "failover:peer-cluster")
    await ops_test.model.integrate("main:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster")
    await ops_test.model.integrate(
        "failover:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster"
    )

    await ops_test.model.integrate("main", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate("failover", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)

    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, "main", "failover", APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1, "main": 1, "failover": 2, APP_NAME: 1},
        idle_period=IDLE_PERIOD,
        timeout=3600,
    )

    await ops_test.model.integrate("main", backup_integrator)


@pytest.mark.parametrize("cloud_name,deploy_type", LARGE_DEPLOYMENTS_ALL_CLOUDS)
@pytest.mark.abort_on_fail
async def test_large_setups_relations_with_misconfiguration(
    ops_test: OpsTest, cloud_name: str, deploy_type: str
) -> None:
    """Confirm expected blocked messages under misconfiguration."""
    if cloud_name == "azure":
        config = {"connection-protocol": "abfss", "container": "error", "path": "/"}
        credentials = {"storage-account": "error", "secret-key": "error"}
        await _configure_azure(ops_test=ops_test, config=config, credentials=credentials)
    else:
        config = {
            "endpoint": "http://localhost",
            "bucket": "error",
            "path": "/",
            "region": "default",
        }
        credentials = {"access-key": "error", "secret-key": "error"}
        await _configure_s3(ops_test=ops_test, config=config, credentials=credentials)

    await wait_until(
        ops_test,
        apps=["main"],
        apps_statuses=["blocked"],
        apps_full_statuses={"main": {"blocked": [BackupSetupFailed]}},
        idle_period=IDLE_PERIOD,
    )

    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_relation = AZURE_RELATION if cloud_name == "azure" else S3_RELATION

    await ops_test.model.integrate(f"failover:{backup_relation}", backup_integrator)
    await ops_test.model.integrate(f"{APP_NAME}:{backup_relation}", backup_integrator)
    await wait_until(
        ops_test,
        apps=["failover", APP_NAME],
        apps_statuses=["blocked"],
        apps_full_statuses={
            "failover": {"blocked": [BackupRelShouldNotExist]},
            APP_NAME: {"blocked": [BackupRelShouldNotExist]},
        },
        idle_period=IDLE_PERIOD,
    )

    await ops_test.model.applications[APP_NAME].destroy_relation(
        f"{APP_NAME}:{backup_relation}", backup_integrator
    )
    await ops_test.model.applications["failover"].destroy_relation(
        f"failover:{backup_relation}", backup_integrator
    )

    await wait_until(
        ops_test,
        apps=["main"],
        apps_statuses=["blocked"],
        apps_full_statuses={"main": {"blocked": [BackupSetupFailed]}},
        idle_period=IDLE_PERIOD,
    )
    await wait_until(
        ops_test, apps=["failover", APP_NAME], apps_statuses=["active"], idle_period=IDLE_PERIOD
    )


@pytest.mark.parametrize("cloud_name,deploy_type", ALL_DEPLOYMENTS_ALL_CLOUDS)
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
    """Create a backup while writes are ongoing, then verify restore."""
    app = (await app_name(ops_test) or APP_NAME) if deploy_type == "small" else "main"
    apps = [app] if deploy_type == "small" else [app, APP_NAME]
    leader_id = await get_leader_unit_id(ops_test, app=app)
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    config = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    if cloud_name == "azure":
        await _configure_azure(ops_test, config, cloud_credentials[cloud_name], app)
    else:
        await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    date_before_backup = datetime.utcnow()
    await asyncio.sleep(5)

    assert (
        datetime.strptime(
            backup_id := await create_backup(ops_test, leader_id, unit_ip=unit_ip, app=app),
            OPENSEARCH_BACKUP_ID_FORMAT,
        )
        > date_before_backup
    )

    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, apps)
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )

    global cwrites_backup_doc_count
    cwrites_backup_doc_count[backup_id] = await index_docs_count(
        ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME
    )


@pytest.mark.parametrize("cloud_name,deploy_type", ALL_DEPLOYMENTS_ALL_CLOUDS)
@pytest.mark.abort_on_fail
async def test_remove_and_readd_backup_relation(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
    deploy_type: str,
) -> None:
    """Remove and re-add the backup relation, then ensure backup/restore still works."""
    app = (await app_name(ops_test) or APP_NAME) if deploy_type == "small" else "main"
    apps = [app] if deploy_type == "small" else [app, APP_NAME]

    leader_id = await get_leader_unit_id(ops_test, app=app)
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    config = cloud_configs[cloud_name]

    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_relation = AZURE_RELATION if cloud_name == "azure" else S3_RELATION

    logger.info("Remove backup relation")
    await ops_test.model.applications[app].destroy_relation(
        backup_relation, f"{backup_integrator}:{backup_relation}"
    )
    await ops_test.model.wait_for_idle(
        apps=[app], status="active", timeout=1400, idle_period=IDLE_PERIOD
    )

    logger.info("Re-add backup credentials relation")
    await ops_test.model.integrate(app, backup_integrator)
    await ops_test.model.wait_for_idle(
        apps=[app], status="active", timeout=1400, idle_period=IDLE_PERIOD
    )

    logger.info(f"Syncing credentials for {cloud_name}")
    if cloud_name == "azure":
        await _configure_azure(ops_test, config, cloud_credentials[cloud_name], app)
    else:
        await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    date_before_backup = datetime.utcnow()
    await asyncio.sleep(5)

    assert (
        datetime.strptime(
            backup_id := await create_backup(ops_test, leader_id, unit_ip=unit_ip, app=app),
            OPENSEARCH_BACKUP_ID_FORMAT,
        )
        > date_before_backup
    )

    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, apps)
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )

    global cwrites_backup_doc_count
    cwrites_backup_doc_count[backup_id] = await index_docs_count(
        ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME
    )


@pytest.mark.parametrize("cloud_name,deploy_type", SMALL_DEPLOYMENTS_ALL_CLOUDS)
@pytest.mark.abort_on_fail
async def test_restore_to_new_cluster(
    ops_test: OpsTest,
    charm,
    series,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
    deploy_type: str,
    force_clear_cwrites_index,
) -> None:
    """Tear down cluster, redeploy clean, then restore prior backups and validate."""
    app = (await app_name(ops_test) or APP_NAME) if deploy_type == "small" else "main"
    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_integrator_channel = (
        AZURE_INTEGRATOR_CHANNEL if cloud_name == "azure" else S3_INTEGRATOR_CHANNEL
    )

    logging.info("Destroying the application")
    await asyncio.gather(
        ops_test.model.remove_application(backup_integrator, block_until_done=True),
        ops_test.model.remove_application(app, block_until_done=True),
        ops_test.model.remove_application(TLS_CERTIFICATES_APP_NAME, block_until_done=True),
    )

    logging.info("Deploying a new cluster")
    await ops_test.model.set_config(MODEL_CONFIG)
    config = {"ca-common-name": "CN_CA"}

    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(backup_integrator, channel=backup_integrator_channel),
        ops_test.model.deploy(charm, num_units=3, series=series, config=CONFIG_OPTS),
    )

    await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, app],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    await ops_test.model.integrate(app, backup_integrator)

    leader_id = await get_leader_unit_id(ops_test, app=app)
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    config_cloud = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    if cloud_name == "azure":
        await _configure_azure(ops_test, config_cloud, cloud_credentials[cloud_name], app)
    else:
        await _configure_s3(ops_test, config_cloud, cloud_credentials[cloud_name], app)

    backups = await list_backups(ops_test, leader_id, app=app)

    global cwrites_backup_doc_count
    assert len(backups) == 2
    assert len(cwrites_backup_doc_count) == 2

    for backup_id in backups.keys():
        assert await restore(ops_test, backup_id, unit_ip, leader_id, app=app)
        count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)
        assert count == cwrites_backup_doc_count[backup_id]
        await assert_start_and_check_continuous_writes(ops_test, unit_ip, app)

    # Final DR: take a fresh backup while writing on the new cluster
    logger.info("Final DR stage: backup+restore with active writes")
    writer: ContinuousWrites = ContinuousWrites(ops_test, app)

    global global_cwrites
    global_cwrites = writer

    await writer.start()
    time.sleep(10)
    date_before_backup = datetime.utcnow()
    await asyncio.sleep(5)

    assert (
        datetime.strptime(
            backup_id := await create_backup(ops_test, leader_id, unit_ip=unit_ip, app=app),
            OPENSEARCH_BACKUP_ID_FORMAT,
        )
        > date_before_backup
    )

    await assert_continuous_writes_increasing(writer)
    await assert_continuous_writes_consistency(ops_test, writer, [app])
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )
    await writer.clear()


@pytest.mark.group(id="all")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_deploy_and_test_status(ops_test: OpsTest, charm, series) -> None:
    """Deploy HA cluster + s3-integrator (credentials set per scenario later)."""
    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(charm, num_units=3, series=series, config=CONFIG_OPTS),
    )

    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)


@pytest.mark.group(id="all")
@pytest.mark.abort_on_fail
async def test_repo_missing_message(ops_test: OpsTest) -> None:
    """Validate the repository missing message format from OpenSearch."""
    app: str = (await app_name(ops_test)) or APP_NAME
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    resp = await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}", json_resp=True
    )
    logger.debug(f"Response: {resp}")
    assert resp["status"] == 404
    assert "repository_missing_exception" in resp["error"]["type"]


@pytest.mark.group(id="all")
@pytest.mark.abort_on_fail
async def test_wrong_s3_credentials(ops_test: OpsTest) -> None:
    """Verify blocked status and error from OpenSearch when S3 creds are wrong."""
    app = (await app_name(ops_test)) or APP_NAME
    unit_ip = await get_leader_unit_ip(ops_test, app=app)

    config = {"endpoint": "http://localhost", "bucket": "error", "path": "/", "region": "default"}
    credentials = {"access-key": "error", "secret-key": "error"}

    await ops_test.model.applications[S3_INTEGRATOR].set_config(config)
    await run_action(ops_test, 0, "sync-s3-credentials", params=credentials, app=S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(apps=[S3_INTEGRATOR], status="active", timeout=TIMEOUT)
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["blocked"],
        units_statuses=["active", "blocked"],
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


@pytest.mark.group(id="all")
@pytest.mark.abort_on_fail
async def test_change_config_and_backup_restore(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    force_clear_cwrites_index,
) -> None:
    """Cycle through each S3-like cloud config and perform backup and restore."""
    app: str = (await app_name(ops_test)) or APP_NAME
    unit_ip: str = await get_leader_unit_ip(ops_test, app=app)
    leader_id: int = await get_leader_unit_id(ops_test, app=app)

    initial_count: int = 0
    for cloud_name in cloud_configs.keys():
        if cloud_name == "azure":
            continue

        logger.debug(
            f"Index {ContinuousWrites.INDEX_NAME} has {initial_count} documents, starting there"
        )
        writer: ContinuousWrites = ContinuousWrites(ops_test, app, initial_count=initial_count)

        global global_cwrites
        global_cwrites = writer

        await writer.start()
        time.sleep(10)

        logger.info(f"Syncing credentials for {cloud_name}")
        config = cloud_configs[cloud_name]
        await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

        date_before_backup = datetime.utcnow()
        await asyncio.sleep(5)

        assert (
            datetime.strptime(
                backup_id := await create_backup(ops_test, leader_id, unit_ip=unit_ip),
                OPENSEARCH_BACKUP_ID_FORMAT,
            )
            > date_before_backup
        )

        await assert_continuous_writes_increasing(writer)
        await assert_continuous_writes_consistency(ops_test, writer, [app])
        await assert_restore_indices_and_compare_consistency(
            ops_test, app, leader_id, unit_ip, backup_id
        )
        await writer.clear()
