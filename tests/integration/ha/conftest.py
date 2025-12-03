#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import dataclasses
import json
import logging
import subprocess
import time

import boto3
import botocore.exceptions
import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import APP_NAME, get_application_unit_ids
from .continuous_writes import ContinuousWrites, ReplicationMode
from .helpers import ORIGINAL_RESTART_DELAY, app_name, update_restart_delay


@dataclasses.dataclass(frozen=True)
class ConnectionInformation:
    access_key_id: str
    secret_access_key: str
    bucket: str


logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
async def reset_restart_delay(ops_test: OpsTest):
    """Resets service file delay on all units."""
    yield
    app = (await app_name(ops_test)) or APP_NAME
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)


@pytest.fixture(scope="function")
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    logger.debug(f"Creating ContinuousWrites instance for app with name {app}")
    return ContinuousWrites(ops_test, app)


@pytest.fixture(scope="function")
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
async def c_0_repl_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start(repl_mode=ReplicationMode.WITH_AT_LEAST_0_REPL)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_mode=ReplicationMode.WITH_AT_LEAST_1_REPL)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="session")
def microceph() -> ConnectionInformation:
    """Deploy microceph with rados-gateway and provide the credentials to access it."""
    logger.info("Setting up microceph")

    # we check if microceph is already installed by checking if the credentials file exists
    try:
        with open("microceph_credentials.txt", "r") as cred_file:
            creds = cred_file.readlines()
            access_key_id = creds[0].strip().split("=")[1]
            secret_access_key = creds[1].strip().split("=")[1]
        logger.info("microceph is already installed")
        return ConnectionInformation(access_key_id, secret_access_key, _BUCKET)
    except FileNotFoundError:
        pass

    # socket.gethostbyname() might return `127.0.0.1`,
    # which does not work from inside lxd container
    host_ip = (
        subprocess.run(["hostname", "-I"], capture_output=True, check=True, encoding="utf-8")
        .stdout.strip()
        .split()[0]
    )

    subprocess.run(["sudo", "snap", "install", "microceph"], check=True)
    subprocess.run(["sudo", "microceph", "cluster", "bootstrap"], check=True)
    subprocess.run(["sudo", "microceph", "disk", "add", "loop,4G,3"], check=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            "key.pem",
            "-out",
            "microceph_cert.pem",
            "-sha256",
            "-days",
            "365",
            "-nodes",
            "-subj",
            f"/CN={host_ip}",
            "-addext",
            f"subjectAltName=IP:{host_ip}",
        ],
        check=True,
    )

    with open("microceph_cert.pem", "rb") as cert_file:
        cert = cert_file.read()
        cert_encoded = base64.b64encode(cert)

    with open("key.pem", "rb") as key_file:
        key = key_file.read()
        key_encoded = base64.b64encode(key)

    subprocess.run(
        [
            "sudo",
            "microceph",
            "enable",
            "rgw",
            "--ssl-port",
            "445",
            "--ssl-certificate",
            cert_encoded,
            "--ssl-private-key",
            key_encoded,
        ],
        check=True,
    )
    output = subprocess.run(
        [
            "sudo",
            "microceph.radosgw-admin",
            "user",
            "create",
            "--uid",
            "test",
            "--display-name",
            "test",
        ],
        capture_output=True,
        check=True,
        encoding="utf-8",
    ).stdout
    key = json.loads(output)["keys"][0]
    key_id = key["access_key"]
    secret_key = key["secret_key"]
    # write secret key and access key to file
    with open("microceph_credentials.txt", "w") as cred_file:
        cred_file.write(f"access_key={key_id}\nsecret_key={secret_key}\n")
    logger.info("Creating microceph bucket")
    for attempt in range(3):
        try:
            boto3.client(
                "s3",
                endpoint_url=f"https://{host_ip}:445",
                aws_access_key_id=key_id,
                aws_secret_access_key=secret_key,
                verify="microceph_cert.pem",
            ).create_bucket(Bucket=_BUCKET)
        except botocore.exceptions.EndpointConnectionError:
            if attempt == 2:
                raise
            # microceph is not ready yet
            logger.info("Unable to connect to microceph via S3. Retrying")
            time.sleep(1)
        else:
            break
    logger.info("Set up microceph")
    return ConnectionInformation(key_id, secret_key, _BUCKET)


_BUCKET = "testbucket"
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def microceph_config(microceph: ConnectionInformation) -> dict[str, str]:
    """Provide the configuration required by s3-integrator."""
    # socket.gethostbyname() might return `127.0.0.1`,
    # which does not work from inside lxd container
    host_ip = (
        subprocess.run(["hostname", "-I"], capture_output=True, check=True, encoding="utf-8")
        .stdout.strip()
        .split()[0]
    )

    with open("microceph_cert.pem", "rb") as cert_file:
        cert = cert_file.read()
        cert_encoded = base64.b64encode(cert).decode("utf-8")

    return {
        "endpoint": f"https://{host_ip}:445",
        "bucket": microceph.bucket,
        "path": "etcd",
        "region": "default",
        "tls-ca-chain": cert_encoded,
    }


@pytest.fixture(scope="session")
def microceph_credentials(microceph: ConnectionInformation) -> dict[str, str]:
    """Provide the access-credentials required by s3-integrator."""
    return {
        "access-key": microceph.access_key_id,
        "secret-key": microceph.secret_access_key,
    }


@pytest.fixture(scope="function")
def s3_bucket(microceph_credentials, microceph_config) -> None:
    """Provide a storage bucket on the deployed microceph instance."""
    session = boto3.Session(
        aws_access_key_id=microceph_credentials["access-key"],
        aws_secret_access_key=microceph_credentials["secret-key"],
        region_name=microceph_config["region"] if microceph_config["region"] else None,
    )
    s3 = session.resource(
        "s3", endpoint_url=microceph_config["endpoint"], verify="microceph_cert.pem"
    )
    bucket = s3.Bucket(microceph_config["bucket"])
    return bucket
