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
from copy import deepcopy
from datetime import datetime
from typing import Dict

import boto3
import pytest
from azure.storage.blob import BlobServiceClient
from charms.opensearch.v0.constants_charm import (
    OPENSEARCH_BACKUP_ID_FORMAT,
    BackupCredentialIncorrect,
    BackupRelShouldNotExist,
)
from charms.opensearch.v0.opensearch_snapshots import AZURE_REPOSITORY, S3_REPOSITORY
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
from ..helpers_deployments import get_application_units, wait_until
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
ALL_AWS_GROUP = "all-aws"
ALL_MICROCEPH_GROUP = "all-microceph"
ALL_AZURE_GROUP = "all-azure"

S3_INTEGRATOR = "s3-integrator"
S3_INTEGRATOR_CHANNEL = "1/stable"
S3_RELATION = "s3-credentials"
AZURE_INTEGRATOR = "azure-storage-integrator"
AZURE_INTEGRATOR_CHANNEL = "latest/edge"
AZURE_RELATION = "azure-credentials"

TIMEOUT = 30 * 60
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


@pytest.fixture(scope="session")
def cloud_configs(microceph_config: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    # Figure out the address of the LXD host itself, where tests are executed
    # this is where microceph will be installed.
    results: Dict[str, Dict[str, str]] = {"microceph": microceph_config}
    if os.environ.get("AWS_ACCESS_KEY"):
        results["aws"] = {
            "endpoint": "https://s3.amazonaws.com",
            "bucket": "data-charms-testing",
            "path": BackupsPath,
            "region": "us-east-1",
        }
    if os.environ.get("AZURE_SECRET_KEY"):
        results["azure"] = {
            "connection-protocol": "https",
            "container": "data-charms-testing",
            "path": BackupsPath,
        }
    return results


@pytest.fixture(scope="session")
def cloud_credentials(
    microceph_credentials: Dict[str, str],
) -> Dict[str, Dict[str, str]]:
    """Read cloud credentials."""
    results: Dict[str, Dict[str, str]] = {"microceph": microceph_credentials}
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

        if cloud_name == "aws" or cloud_name == "microceph":
            if (
                "access-key" not in cloud_credentials[cloud_name]
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

        if cloud_name == "azure":
            if (
                "secret-key" not in cloud_credentials[cloud_name]
                or "storage-account" not in cloud_credentials[cloud_name]
            ):
                # This cloud has not been used in this test run
                continue

            storage_account = cloud_credentials[cloud_name]["storage-account"]
            secret_key = cloud_credentials[cloud_name]["secret-key"]
            connection_string = f"DefaultEndpointsProtocol=https;AccountName={storage_account};AccountKey={secret_key};EndpointSuffix=core.windows.net"
            blob_service_client = BlobServiceClient.from_connection_string(connection_string)
            container_client = blob_service_client.get_container_client(config["container"])

            # List and delete blobs with the specified prefix
            blobs_to_delete = container_client.list_blobs(name_starts_with=BackupsPath)

            try:
                for blob in blobs_to_delete:
                    container_client.delete_blob(blob.name)
            except Exception as e:
                logger.warning(f"Failed to clean up backups: {e}")


async def _configure_s3_for_aws(
    ops_test: OpsTest,
    config: Dict[str, str],
    credentials: Dict[str, str],
) -> None:
    """Configure s3-integrator with endpoint/bucket/path/region."""
    base_cfg = {
        "endpoint": config["endpoint"],
        "bucket": config["bucket"],
        "path": config["path"],
        "region": config.get("region", "") or "",
    }
    await ops_test.model.applications[S3_INTEGRATOR].set_config(base_cfg)
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
    await ops_test.model.wait_for_idle(apps=[S3_INTEGRATOR], timeout=TIMEOUT)


async def _configure_s3_for_microceph(
    ops_test: OpsTest,
    config: Dict[str, str],
    credentials: Dict[str, str],
) -> None:
    """Configure s3-integrator with endpoint/bucket/path/region and tls-ca-chain."""
    base_cfg = {
        "endpoint": config["endpoint"],
        "bucket": config["bucket"],
        "path": config["path"],
        "region": config.get("region", "") or "",
        "tls-ca-chain": config.get("tls-ca-chain"),
    }
    await ops_test.model.applications[S3_INTEGRATOR].set_config(base_cfg)
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
    await ops_test.model.wait_for_idle(apps=[S3_INTEGRATOR], timeout=TIMEOUT)


async def _configure_azure(
    ops_test: OpsTest,
    config: Dict[str, str],
    credentials: Dict[str, str],
) -> None:
    logger.info("Adding Juju secret for secret-key config option for azure-storage-integrator")

    # Creates a new secret for each test
    local_label = "".join(random.choice(string.ascii_letters) for _ in range(10))
    credentials_secret_uri = await add_juju_secret(
        ops_test,
        AZURE_INTEGRATOR,
        local_label,
        {"secret-key": credentials["secret-key"]},
    )
    logger.info(
        f"Juju secret for secret-key config option for azure-storage-integrator added. Secret URI: {credentials_secret_uri}"
    )

    full_cfg = deepcopy(config)
    full_cfg.update(
        {
            "storage-account": credentials["storage-account"],
            "credentials": credentials_secret_uri,
        }
    )
    # apply new configuration options
    logger.info("Setting up configuration for azure-storage-integrator charm...")
    await ops_test.model.applications[AZURE_INTEGRATOR].set_config(full_cfg)

    await ops_test.model.wait_for_idle(apps=[AZURE_INTEGRATOR], timeout=TIMEOUT)


def _is_related_with(ops_test: OpsTest, app_name: str, target_app_name: str) -> bool:
    """Check if app_name has a relation with target_app_name."""
    app = ops_test.model.applications.get(app_name)
    for relation in app.relations:
        for endpoint in relation.endpoints:
            if endpoint.application_name == target_app_name:
                logger.info("%s and %s already integrated", app_name, target_app_name)
                return True
    logger.info("%s and %s are not integrated yet", app_name, target_app_name)
    return False


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
    # Deploy TLS Certificates operator.
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
    await ops_test.model.integrate(APP_NAME, backup_integrator)


@pytest.mark.parametrize("cloud_name,deploy_type", LARGE_DEPLOYMENTS_ALL_CLOUDS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_large_deployment_build_and_deploy(
    ops_test: OpsTest, charm, series, cloud_name: str, deploy_type: str
) -> None:
    """Build and deploy a large cluster (main/failover orchestrators + data.hot node).

    The following apps will be deployed:
    * main: the main orchestrator
    * failover: the failover orchestrator
    * opensearch (or APP_NAME): the data.hot node

    The data node is selected to adopt the "APP_NAME" value because it is the node which
    ContinuousWrites will later target its writes to.
    """
    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
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
    data_hot_conf = {
        "cluster_name": "backup-test",
        "init_hold": True,
        "roles": "data.hot",
    }

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

    # Large deployment setup
    await ops_test.model.integrate("main:peer-cluster-orchestrator", "failover:peer-cluster")
    await ops_test.model.integrate("main:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster")
    await ops_test.model.integrate(
        "failover:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster"
    )

    # TLS setup
    await ops_test.model.integrate("main", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate("failover", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)

    # Charms except s3-integrator should be active
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, "main", "failover", APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            "main": 1,
            "failover": 2,
            APP_NAME: 1,
        },
        idle_period=IDLE_PERIOD,
        timeout=3600,
    )

    # Credentials not set yet, this will move the opensearch to blocked state
    # Credentials are set per test scenario
    await ops_test.model.integrate("main", backup_integrator)


@pytest.mark.parametrize("cloud_name,deploy_type", LARGE_DEPLOYMENTS_ALL_CLOUDS)
@pytest.mark.abort_on_fail
async def test_large_setups_relations_with_misconfiguration(
    ops_test: OpsTest,
    cloud_name: str,
    deploy_type: str,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
) -> None:
    """Confirm expected blocked messages under misconfiguration."""
    if cloud_name == "azure":
        bad_config = {"connection-protocol": "abfss", "container": "error", "path": "/"}
        bad_credentials = {"storage-account": "error", "secret-key": "error"}
        await _configure_azure(
            ops_test=ops_test,
            config=bad_config,
            credentials=bad_credentials,
        )
        logger.info("Azure cloud is selected.")
    elif cloud_name == "aws":
        bad_config = {
            "endpoint": "http://localhost",
            "bucket": "error",
            "path": "/",
            "region": "default",
        }
        bad_credentials = {"access-key": "error", "secret-key": "error"}
        await _configure_s3_for_aws(
            ops_test=ops_test,
            config=bad_config,
            credentials=bad_credentials,
        )
        logger.info("AWS cloud is selected.")
    else:
        cfg = cloud_configs["microceph"]
        bad_config = {
            "endpoint": "https://localhost:445",
            "bucket": "error",
            "path": "etcd",
            "region": "default",
            "tls-ca-chain": cfg.get("tls-ca-chain"),
        }
        bad_credentials = {"access-key": "error", "secret-key": "error"}

        await _configure_s3_for_microceph(
            ops_test=ops_test,
            config=bad_config,
            credentials=bad_credentials,
        )
    await wait_until(
        ops_test,
        apps=["main"],
        apps_full_statuses={"main": {"blocked": [BackupCredentialIncorrect]}},
        idle_period=IDLE_PERIOD,
    )
    logger.info("Opensearch is blocked by invalid config/credentials.")

    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_relation = AZURE_RELATION if cloud_name == "azure" else S3_RELATION

    # Now, relate failover cluster to backup-integrator and review the status
    await ops_test.model.integrate(f"failover:{backup_relation}", backup_integrator)
    await ops_test.model.integrate(f"{APP_NAME}:{backup_relation}", backup_integrator)
    await wait_until(
        ops_test,
        apps=["failover", APP_NAME],
        apps_full_statuses={
            "failover": {"blocked": [BackupRelShouldNotExist]},
            APP_NAME: {"blocked": [BackupRelShouldNotExist]},
        },
        idle_period=IDLE_PERIOD,
    )

    # Reverting should return it to normal
    await ops_test.model.applications[APP_NAME].destroy_relation(
        f"{APP_NAME}:{backup_relation}", backup_integrator, block_until_done=True
    )
    await ops_test.model.applications["failover"].destroy_relation(
        f"failover:{backup_relation}", backup_integrator, block_until_done=True
    )

    await wait_until(
        ops_test,
        apps=["main"],
        apps_full_statuses={"main": {"blocked": [BackupCredentialIncorrect]}},
        idle_period=IDLE_PERIOD,
    )

    # Clean up for subsequent tests: drop backup-integrator relation
    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_relation = AZURE_RELATION if cloud_name == "azure" else S3_RELATION

    try:
        await ops_test.model.applications["main"].destroy_relation(
            f"main:{backup_relation}", backup_integrator, block_until_done=True
        )
        await wait_until(
            ops_test,
            apps=["main"],
            units_statuses=["active"],
            apps_statuses=["active"],
            wait_for_exact_units=1,
            idle_period=IDLE_PERIOD,
        )
        logger.info("Cleaned up misconfigured backup relation from main; main is active again.")
    except Exception:
        logger.info("No backup-integrator relation to clean up after misconfiguration test.")


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

    logger.info(f"Ensuring only correct backup integrator is related for {cloud_name}")
    if cloud_name == "azure":
        await _ensure_only_azure_integrator_related(ops_test, app)
    else:
        await _ensure_only_s3_integrator_related(ops_test, app)

    leader_id = await get_leader_unit_id(ops_test, app=app)
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    config = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    if cloud_name == "azure":
        await _configure_azure(ops_test, config, cloud_credentials[cloud_name])
    elif cloud_name == "aws":
        await _configure_s3_for_aws(ops_test, config, cloud_credentials[cloud_name])
    else:
        await _configure_s3_for_microceph(ops_test, config, cloud_credentials[cloud_name])

    await wait_until(
        ops_test,
        apps=apps,
        apps_statuses=["active"],
        units_statuses=["active"],
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={ap: len(ops_test.model.applications[ap].units) for ap in apps},
    )

    date_before_backup = datetime.utcnow()

    # Wait, we want to make sure the timestamps are different
    await asyncio.sleep(5)

    assert (
        datetime.strptime(
            backup_id := await create_backup(ops_test, leader_id, unit_ip=unit_ip, app=app),
            OPENSEARCH_BACKUP_ID_FORMAT,
        )
        > date_before_backup
    )
    # continuous writes checks
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

    leader_id: int = await get_leader_unit_id(ops_test, app=app)
    unit_ip: str = await get_leader_unit_ip(ops_test, app=app)

    backup_integrator = AZURE_INTEGRATOR if cloud_name == "azure" else S3_INTEGRATOR
    backup_relation = AZURE_RELATION if cloud_name == "azure" else S3_RELATION

    logger.info("Remove backup relation")
    # Remove relation
    await ops_test.model.applications[app].destroy_relation(
        f"{app}:{backup_relation}", backup_integrator, block_until_done=True
    )

    await wait_until(
        ops_test,
        apps=apps,
        units_statuses=["active"],
        apps_statuses=["active"],
        wait_for_exact_units={ap: len(ops_test.model.applications[ap].units) for ap in apps},
        idle_period=IDLE_PERIOD,
        timeout=1400,
    )
    logger.info("Re-add backup credentials relation")
    await ops_test.model.integrate(app, backup_integrator)
    logger.info("Waiting for app status to be active.")
    await wait_until(
        ops_test,
        apps=apps,
        units_statuses=["active"],
        apps_statuses=["active"],
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={ap: len(ops_test.model.applications[ap].units) for ap in apps},
        timeout=1400,
    )

    logger.info(f"Syncing credentials for {cloud_name}")
    if cloud_name == "azure":
        await _configure_azure(ops_test, cloud_configs[cloud_name], cloud_credentials[cloud_name])
    elif cloud_name == "aws":
        await _configure_s3_for_aws(
            ops_test, cloud_configs[cloud_name], cloud_credentials[cloud_name]
        )
    else:
        await _configure_s3_for_microceph(
            ops_test, cloud_configs[cloud_name], cloud_credentials[cloud_name]
        )

    date_before_backup = datetime.utcnow()

    # Wait, we want to make sure the timestamps are different
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
    """Tear down cluster, redeploy clean, then restore prior backups and validate.

    Restores each of the previous backups we created and compare with their doc count.
    The cluster is considered healthy if:
    1) At each backup restored, check our track of doc count vs. current index count
    2) Try to write to that new index.
    """
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
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}

    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(backup_integrator, channel=backup_integrator_channel),
        ops_test.model.deploy(charm, num_units=3, series=series, config=CONFIG_OPTS),
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
    await ops_test.model.integrate(app, backup_integrator)

    leader_id = await get_leader_unit_id(ops_test, app=app)
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    config_cloud = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    if cloud_name == "azure":
        await _configure_azure(ops_test, config_cloud, cloud_credentials[cloud_name])
    elif cloud_name == "aws":
        await _configure_s3_for_aws(ops_test, config_cloud, cloud_credentials[cloud_name])
    else:
        await _configure_s3_for_microceph(ops_test, config_cloud, cloud_credentials[cloud_name])

    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(ops_test.model.applications[app].units),
        idle_period=IDLE_PERIOD,
    )
    backups = await list_backups(ops_test, leader_id, app=app)

    global cwrites_backup_doc_count
    # We are expecting 2x backups available
    assert len(backups) == 2
    assert len(cwrites_backup_doc_count) == 2
    count = 0
    for backup_id in backups.keys():
        assert await restore(ops_test, backup_id, unit_ip, leader_id, app=app)
        count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)

        # Ensure we have the same doc count as we had on the original cluster
        assert count == cwrites_backup_doc_count[backup_id]

        # restart the continuous writes and check the cluster is still accessible post restore
        await assert_start_and_check_continuous_writes(ops_test, unit_ip, app)

    # take a fresh backup while writing on the new cluster
    logger.info("Final stage: backup+restore with active writes")
    writer: ContinuousWrites = ContinuousWrites(ops_test, app)

    # store the global cwrites object
    global global_cwrites
    global_cwrites = writer

    await writer.start()
    time.sleep(10)
    date_before_backup = datetime.utcnow()

    # Wait, we want to make sure the timestamps are different
    await asyncio.sleep(5)

    assert (
        datetime.strptime(
            backup_id := await create_backup(ops_test, leader_id, unit_ip=unit_ip, app=app),
            OPENSEARCH_BACKUP_ID_FORMAT,
        )
        > date_before_backup
    )

    # continuous writes checks
    await assert_continuous_writes_increasing(writer)
    await assert_continuous_writes_consistency(ops_test, writer, [app])
    # This assert assures we have taken a new backup, after the last restore from the original
    # cluster. That means the index is writable.
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )
    # Clear the writer manually, as we are not using the conftest c_writes_runner to do so
    await writer.clear()


# -------------------------------------------------------------------------------------------
# Tests for the "all-s3 and all-azure" groups
#
# This are grouped tests for each each cloud, deploys necessary storage integrator,
# set its credentials via config and rerun the backup and restore tests.
# -------------------------------------------------------------------------------------------


async def _drop_s3_relation_if_any(ops_test: OpsTest, app: str) -> None:
    """If app is related to S3_INTEGRATOR via S3_RELATION, drop that relation."""
    if S3_INTEGRATOR not in ops_test.model.applications:
        return
    if not _is_related_with(ops_test, app, S3_INTEGRATOR):
        return

    app_endpoint = f"{app}:{S3_RELATION}"
    s3_endpoint = f"{S3_INTEGRATOR}:{S3_RELATION}"

    await ops_test.model.applications[app].destroy_relation(
        f"{app}:{S3_RELATION}", S3_INTEGRATOR, block_until_done=True
    )

    await wait_until(
        ops_test,
        apps=[app],
        units_statuses=["active"],
        apps_statuses=["active"],
        wait_for_exact_units=len(ops_test.model.applications[app].units),
        idle_period=IDLE_PERIOD,
        timeout=TIMEOUT,
    )
    logger.info("Dropped S3 relation %s -> %s.", app_endpoint, s3_endpoint)


async def _drop_azure_relation_if_any(ops_test: OpsTest, app: str) -> None:
    """If app is related to AZURE_INTEGRATOR via AZURE_RELATION, drop that relation."""
    if AZURE_INTEGRATOR not in ops_test.model.applications:
        return

    if not _is_related_with(ops_test, app, AZURE_INTEGRATOR):
        return

    app_endpoint = f"{app}:{AZURE_RELATION}"
    azure_endpoint = f"{AZURE_INTEGRATOR}:{AZURE_RELATION}"
    await ops_test.model.applications[app].destroy_relation(
        f"{app}:{AZURE_RELATION}", AZURE_INTEGRATOR, block_until_done=True
    )
    await wait_until(
        ops_test,
        apps=[app],
        units_statuses=["active"],
        apps_statuses=["active"],
        wait_for_exact_units=len(ops_test.model.applications[app].units),
        idle_period=IDLE_PERIOD,
        timeout=TIMEOUT,
    )
    logger.info("Dropped Azure relation %s -> %s.", app_endpoint, azure_endpoint)


async def _ensure_only_s3_integrator_related(
    ops_test: OpsTest,
    app: str,
) -> None:
    """Ensure S3 integrator is deployed and related to app (Azure relation removed)."""
    await _drop_azure_relation_if_any(ops_test, app)

    if S3_INTEGRATOR not in ops_test.model.applications:
        await ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL)
        await wait_until(
            ops_test,
            apps=[S3_INTEGRATOR],
            units_statuses=["blocked"],
            wait_for_exact_units=1,
            idle_period=10,
            timeout=1400,
        )

    # check if relation exists already
    if _is_related_with(ops_test, app, S3_INTEGRATOR):
        return

    app_endpoint = f"{app}:{S3_RELATION}"
    s3_endpoint = f"{S3_INTEGRATOR}:{S3_RELATION}"
    await ops_test.model.integrate(app, S3_INTEGRATOR)
    logger.info("Integrated %s <-> %s.", app_endpoint, s3_endpoint)


async def _ensure_only_azure_integrator_related(ops_test: OpsTest, app: str) -> None:
    """Ensure Azure integrator is deployed and related to app (S3 relation removed)."""
    await _drop_s3_relation_if_any(ops_test, app)

    if AZURE_INTEGRATOR not in ops_test.model.applications:
        await ops_test.model.deploy(AZURE_INTEGRATOR, channel=AZURE_INTEGRATOR_CHANNEL)
        await wait_until(
            ops_test,
            apps=[AZURE_INTEGRATOR],
            units_statuses=["blocked"],
            wait_for_exact_units=1,
            idle_period=10,
            timeout=1400,
        )

    if _is_related_with(ops_test, app, AZURE_INTEGRATOR):
        return

    app_endpoint = f"{app}:{AZURE_RELATION}"
    azure_endpoint = f"{AZURE_INTEGRATOR}:{AZURE_RELATION}"
    await ops_test.model.integrate(app, AZURE_INTEGRATOR)
    logger.info("Integrated %s <-> %s.", app_endpoint, azure_endpoint)


@pytest.mark.group(id=ALL_AWS_GROUP)
@pytest.mark.group(id=ALL_MICROCEPH_GROUP)
@pytest.mark.group(id=ALL_AZURE_GROUP)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_deploy_and_test_status(ops_test: OpsTest, charm, series) -> None:
    """Deploy HA cluster + s3-integrator (credentials set per scenario later)."""
    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(charm, num_units=3, series=series, config=CONFIG_OPTS),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        units_statuses=["active"],
        apps_statuses=["active"],
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            APP_NAME: 3,
        },
        timeout=1400,
    )


@pytest.mark.group(id=ALL_MICROCEPH_GROUP)
@pytest.mark.group(id=ALL_AWS_GROUP)
@pytest.mark.abort_on_fail
async def test_repo_missing_message(ops_test: OpsTest) -> None:
    """Validate the repository missing message format from OpenSearch.

    We use the message format to monitor the cluster status. We need to know if this
    message pattern changed between releases of OpenSearch.
    """
    app: str = (await app_name(ops_test)) or APP_NAME
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    resp = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}",
        json_resp=True,
    )
    logger.debug(f"Response: {resp}")
    assert resp["status"] == 404
    assert "repository_missing_exception" in resp["error"]["type"]


@pytest.mark.group(id=ALL_AWS_GROUP)
@pytest.mark.abort_on_fail
async def test_wrong_aws_credentials(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
) -> None:
    """Verify blocked status and error from OpenSearch when S3 creds are wrong."""
    # Choose provider: prefer aws if present, otherwise microceph
    if "aws" in cloud_configs and "aws" in cloud_credentials:
        provider = "aws"
    else:
        pytest.skip("AWS config/credentials not available for S3 integrator tests.")

    app = (await app_name(ops_test)) or APP_NAME
    await _ensure_only_s3_integrator_related(ops_test, app)

    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    good_config = cloud_configs[provider]
    bad_credentials = {"access-key": "error", "secret-key": "error"}

    await _configure_s3_for_aws(ops_test, good_config, bad_credentials)

    await wait_until(
        ops_test,
        apps=[app],
        apps_full_statuses={app: {"blocked": [BackupCredentialIncorrect]}},
    )
    logger.info("Opensearch 1 app is blocked because of S3 bad credentials.")

    resp = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}/_all",
        json_resp=True,
    )
    logger.debug(f"Response: {resp}")
    status = resp.get("status")
    assert status == 404, f"Unexpected status: {status}, resp={resp}"
    error = resp.get("error")
    assert error is not None, f"No error field in response: {resp}"
    err_type = error.get("type")
    err_reason = error.get("reason", "")
    assert (
        "repository_missing_exception" in err_type
    ), f"Unexpected error type: {err_type}, resp={resp}"
    assert (
        "[s3-repository] missing" in err_reason
    ), f"Unexpected error reason: {err_reason}, resp={resp}"

    # revert back to normal state
    good_credentials = cloud_credentials[provider]
    await _configure_s3_for_aws(ops_test, good_config, good_credentials)
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=3,
        idle_period=IDLE_PERIOD,
    )
    logger.info(
        "Opensearch all apps and units become active after providing valid S3 credentials."
    )
    resp_ok = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}",
        json_resp=True,
    )
    logger.debug(f"Repo response after fixing S3 creds: {resp_ok}")

    assert isinstance(resp_ok, dict)
    assert S3_REPOSITORY in resp_ok


@pytest.mark.group(id=ALL_MICROCEPH_GROUP)
@pytest.mark.abort_on_fail
async def test_wrong_microceph_credentials(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
) -> None:
    """Verify blocked status and error from OpenSearch when S3 creds are wrong."""
    # Choose provider: prefer aws if present, otherwise microceph
    if "microceph" in cloud_configs and "microceph" in cloud_credentials:
        provider = "microceph"
    else:
        pytest.skip("Microceph config/credentials not available for S3 integrator tests.")

    app = (await app_name(ops_test)) or APP_NAME
    await _ensure_only_s3_integrator_related(ops_test, app)

    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    good_config = cloud_configs[provider]
    bad_credentials = {"access-key": "error", "secret-key": "error"}

    await _configure_s3_for_microceph(ops_test, good_config, bad_credentials)

    await wait_until(
        ops_test,
        apps=[app],
        apps_full_statuses={app: {"blocked": [BackupCredentialIncorrect]}},
    )
    logger.info("Opensearch 1 app is blocked because of S3 bad credentials.")

    resp = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}/_all",
        json_resp=True,
    )
    logger.debug(f"Response: {resp}")
    status = resp.get("status")
    assert status == 404, f"Unexpected status: {status}, resp={resp}"
    error = resp.get("error")
    assert error is not None, f"No error field in response: {resp}"
    err_type = error.get("type")
    err_reason = error.get("reason", "")
    assert (
        "repository_missing_exception" in err_type
    ), f"Unexpected error type: {err_type}, resp={resp}"
    assert (
        "[s3-repository] missing" in err_reason
    ), f"Unexpected error reason: {err_reason}, resp={resp}"

    # revert back to normal state
    good_credentials = cloud_credentials[provider]
    await _configure_s3_for_microceph(ops_test, good_config, good_credentials)
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=3,
        idle_period=IDLE_PERIOD,
    )
    logger.info(
        "Opensearch all apps and units become active after providing valid S3 credentials."
    )
    resp_ok = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}",
        json_resp=True,
    )
    logger.debug(f"Repo response after fixing S3 creds: {resp_ok}")

    assert isinstance(resp_ok, dict)
    assert S3_REPOSITORY in resp_ok


@pytest.mark.group(id=ALL_MICROCEPH_GROUP)
@pytest.mark.abort_on_fail
async def test_wrong_microceph_ca_blocked(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
) -> None:
    """Verify the charm reports a blocked status when tls-ca-chain is invalid, then recovers."""
    if "microceph" not in cloud_configs or "microceph" not in cloud_credentials:
        pytest.skip("No microceph config/credentials available in test config.")
    if "tls-ca-chain" not in cloud_configs["microceph"]:
        pytest.skip("No custom CA chain available in test config (microceph not set up).")

    app = (await app_name(ops_test)) or APP_NAME
    await _ensure_only_s3_integrator_related(ops_test, app)
    good_cfg = cloud_configs["microceph"]
    good_creds = cloud_credentials["microceph"]

    await _configure_s3_for_microceph(
        ops_test,
        good_cfg,
        good_creds,
    )
    logger.info("Configured S3 with correct credentials and config.")
    await wait_until(
        ops_test,
        apps=[app],
        units_statuses=["active"],
        apps_statuses=["active"],
        wait_for_exact_units=3,
        idle_period=IDLE_PERIOD,
    )
    # Wrong CA chain
    bad_cfg = deepcopy(good_cfg)
    bad_cfg["tls-ca-chain"] = (
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZJakNDQXdxZ0F3SUJBZ0lVRGVIRm9EbVlYTW5iRVdFd0VMN3lrL1dDbGVvd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0dERVdNQlFHQTFVRUF3d05NVEF1TWpVMUxqY3lMakkwTlRBZUZ3MHlOVEV4TVRNd09ESTJNVE5hRncweQpOakV4TVRNd09ESTJNVE5hTUJneEZqQVVCZ05WQkFNTURURXdMakkxTlM0M01pNHlORFV3Z2dJaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUUNTTDcyMGZxNHhydGR2UHJVK3lUbzlMakF2Y0NPem5yWWQKaUMzK2ZHaFQzYmkwZCtKSitKWm5IZTR6SUM4Ti9qa3RNUjhVdk8ya2V3SnRCZ1FxbmZuZEd5cjlTd0c3OU1VaQp2WnZySHlibS9oNXd6RGo1bWxmdGpaZDRTSnNWdXJNdjlHd3VQUEg5blhQTjVjRk0rQytnVThTczdwb21XUFNIClRVL2dKQkxoNHlidVBtQW9zeVNpTnVEa29QbkJtaUtuMEQyaDViTGp5WGhSL296Yy9xdklVZ3J1a09rSTgxcGIKTmNQbzdwbHZwT25GeURydFBiMEpGak1yWWJZWmhhMk9YL3JwV0hJUWt6NjUrK3RESk5uT2JaeVAvb3NhWjR0bgpTa1pVM2U2MTNzeWFiTjdvRHp1QWxjRGVGS2N5NkRiQXp5ZGJKREdDN2xlRFQrK0JHMGNsUlFveGowUFVEck41Clg3RHVud0Z0czN0TG8vZHJIdXYvaEpZWWxucjQzU0ZEcjBybnhQK2YwZWp4SUFaR2hjYXpKalFKcHVaYlhYSjEKUVQzdEJiREM1RjM1MHZLWnJpME94UnVITTQ3bEMva3krbHpNUjlOSWxEVmVIVTM5Q3ZTUExuOU9mN3JJZFBCOQpaUzhKcTh0RlNjTWZwVzhUdmZpTktEV0RCbndEUVVYQ0d6Nk9rWkpta0g3UVdvRHJSK24rajRPcjdzQ2g1L2ljCld3TENvbjgvU3l4SVNScEJpZDN5QkVNR29NZHZrWlVXY1hheDRzN2FUMkh1cHRwT2JHa0Q2Vno4Y2tJc0ZUV3oKYThZdHNOdXRWbGZpUmgrZ0Jjc3EwRjdEWVJCK2MrdElVRzBkcHlXb2owdmp5cTAxcmlIVDFaMmhjSVFDU29QTwpza01LTXl4ck93SURBUUFCbzJRd1lqQWRCZ05WSFE0RUZnUVVCempKbm54Sy83MDYyUitkOUZ5QTlNT0ZZL2t3Ckh3WURWUjBqQkJnd0ZvQVVCempKbm54Sy83MDYyUitkOUZ5QTlNT0ZZL2t3RHdZRFZSMFRBUUgvQkFVd0F3RUIKL3pBUEJnTlZIUkVFQ0RBR2h3UUsvMGoxTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFCZUZoUHRxMnRCTUdKSgp4alhRalR1eEl1UVE3NXBmK2FxQkRvaHY0MnUwcVNCTkUyYnBVaFN5RUpIckFXNFplQVpFeVN1NlhEd1NYbnVhCnVzNWhOdklhcXhEUlV4ZXhQekE0RUR3emRCcHhpNDN4YzJObHFWaEtBQ3l6NlphSXBoN2R6VTdtUXJYZzNKbWIKVlEweGloNzkvaXFNdnNpejlKdG9ObXFpejdJdGxWeUhCVzF5T3hUdDUxNzNudFZBSzY0RnN2M0NXYWFwaFA3awpidHZDaFVnaDRHaEx5LzdScUJoZnhrb21CekZyRy82VnZKMDM1cnZzT1VHU2hSVUh2VXF5U3lhemRmejdDaUUzCnFCVVYzaUFyMkNBY3lCakQ3Mkx2UjJxd1JrZUpLN3QrdWZtc2M5bDBWNDgzVXdCbC9IWHRXZDljcm8vczExS3cKaS9CWHdsMWFsaStmYURNUkFucG56WUI3blJHUnVmZFNQUUp3anpNdGNERW84Y29ybHd0M2pPRExKK1RybjhGNQpjVDlldWM0Y2dBWXIrL2U4VXo1Mkd0V2VlOXZzZ3dlZVJkZy8rNTVhQ2VFd21oN3g5a0lmR3VicVRkT0dGa0dTCjlFdDN4Mi9YdnNlbnNwbnpDNTQ5ZmVubG1hcHRuelRpMHhkZk03bnNnQTJFQ2NQcUNwakVWZm52ZFZaa0ZnS1cKVzhlaGFQZ1ZmQnNLUDRDcmNXVnFxYXU2ZWFaU0FEOTYvYk4vZDJ5M3hyM1lIcWtBQktmYjBESE1hU2pzRkZFWQprR21TQ0FLaEtzNTBKd2dVYWsvdGxjcFBlUGp0N3JwMjYweTh5VFQ0VEZnOEVrQStpRGFOMUovZGdaL1VqVlFxCi9EeVUyN2Rrb0J5T0dQQTdNWE10cnpaQTI1MFo1QT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
    )

    await _configure_s3_for_microceph(
        ops_test,
        bad_cfg,
        good_creds,
    )
    logger.info("Configured S3 with wrong CA")

    await wait_until(
        ops_test,
        apps=[app],
        apps_full_statuses={app: {"blocked": [BackupCredentialIncorrect]}},
    )
    logger.info("Opensearch 1 app is blocked because of S3 bad CA.")
    # With bad CA, repository verification usually fails.
    # it can be 500 (repo check error) or 404 (repo never created yet).
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    # restore the correct CA and ensure we recover to active.
    await _configure_s3_for_microceph(ops_test, good_cfg, good_creds)
    logger.info("Configured S3 with valid CA.")
    await wait_until(
        ops_test,
        apps=[app],
        units_statuses=["active"],
        apps_statuses=["active"],
        wait_for_exact_units=3,
        idle_period=IDLE_PERIOD,
    )
    logger.info("Opensearch all apps and units become active after providing valid S3 CA.")
    # check if repo endpoint is reachable now (200 if created, 404 if not yet).
    resp_ok = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}",
        json_resp=True,
    )
    logger.debug(f"Repo response after fixing S3 CA: {resp_ok}")

    if "status" in resp_ok:
        assert resp_ok["status"] == 404
    else:
        assert isinstance(resp_ok, dict)
        assert S3_REPOSITORY in resp_ok


@pytest.mark.group(id=ALL_AZURE_GROUP)
@pytest.mark.abort_on_fail
async def test_wrong_azure_credentials(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
) -> None:
    """Verify blocked status and recovery when Azure credentials are wrong."""
    if "azure" not in cloud_configs or "azure" not in cloud_credentials:
        pytest.skip("Azure config/credentials not available for Azure integrator tests.")

    app = (await app_name(ops_test)) or APP_NAME

    await _ensure_only_azure_integrator_related(ops_test, app)

    unit_ip = await get_leader_unit_ip(ops_test, app=app)

    good_cfg = cloud_configs["azure"]
    good_creds = cloud_credentials["azure"]

    # keep storage-account but corrupt secret-key
    bad_creds = deepcopy(good_creds)
    bad_creds["secret-key"] = "invalid-secret-key"

    # Apply bad credentials
    await _configure_azure(ops_test, good_cfg, bad_creds)

    # Charm should eventually report blocked
    await wait_until(
        ops_test,
        apps=[app],
        units_statuses=["active"],
        apps_statuses=["blocked"],
        apps_full_statuses={app: {"blocked": [BackupCredentialIncorrect]}},
        idle_period=IDLE_PERIOD,
    )
    logger.info("Opensearch 1 app is blocked because of Azure bad credentials.")
    # Depending on timing, repo may be missing or failing verification.
    try:
        resp = await http_request(
            ops_test,
            "GET",
            f"https://{unit_ip}:9200/_snapshot/{AZURE_REPOSITORY}/_all",
            json_resp=True,
        )
        logger.debug(f"Azure bad credentials snapshot response: {resp}")
        assert resp["status"] in (404, 500)
    except Exception:
        logger.info("Snapshot request failed with bad Azure credentials (expected).")

    # Restore correct credentials
    await _configure_azure(ops_test, good_cfg, good_creds)
    await wait_until(
        ops_test,
        apps=[app],
        units_statuses=["active"],
        apps_statuses=["active"],
        wait_for_exact_units=3,
        idle_period=IDLE_PERIOD,
    )
    logger.info(
        "Opensearch all apps and units become active after providing valid Azure credentials."
    )
    # Check that the repository endpoint is reachable
    resp_ok = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{AZURE_REPOSITORY}",
        json_resp=True,
    )
    logger.debug(f"Repo response after fixing Azure credentials: {resp_ok}")

    if "status" in resp_ok:
        assert resp_ok["status"] == 404
    else:
        assert isinstance(resp_ok, dict)
        assert AZURE_REPOSITORY in resp_ok


@pytest.mark.parametrize(
    "cloud_name",
    [
        pytest.param(cloud, id=f"all-{cloud}", marks=pytest.mark.group(id=f"all-{cloud}"))
        for cloud in ("aws", "microceph")
    ],
)
@pytest.mark.abort_on_fail
async def test_change_config_and_backup_restore(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    force_clear_cwrites_index,
    cloud_name: str,
) -> None:
    """Cycle through each S3-like cloud config and perform backup and restore."""
    app: str = (await app_name(ops_test)) or APP_NAME
    await _ensure_only_s3_integrator_related(ops_test, app)

    unit_ip: str = await get_leader_unit_ip(ops_test, app=app)
    leader_id: int = await get_leader_unit_id(ops_test, app=app)

    initial_count: int = 0
    logger.info(f"Starting test for cloud: {cloud_name}")
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
    if cloud_name == "aws":
        await _configure_s3_for_aws(ops_test, config, cloud_credentials[cloud_name])
    else:
        await _configure_s3_for_microceph(ops_test, config, cloud_credentials[cloud_name])
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(ops_test.model.applications[app].units),
        idle_period=IDLE_PERIOD,
    )

    date_before_backup = datetime.utcnow()

    # Wait, we want to make sure the timestamps are different
    await asyncio.sleep(5)

    assert (
        datetime.strptime(
            backup_id := await create_backup(
                ops_test,
                leader_id,
                unit_ip=unit_ip,
            ),
            OPENSEARCH_BACKUP_ID_FORMAT,
        )
        > date_before_backup
    )

    # continuous writes checks
    await assert_continuous_writes_increasing(writer)
    await assert_continuous_writes_consistency(ops_test, writer, [app])
    await assert_restore_indices_and_compare_consistency(
        ops_test, app, leader_id, unit_ip, backup_id
    )
    # Clear the writer manually, as we are not using the conftest c_writes_runner to do so
    await writer.clear()
