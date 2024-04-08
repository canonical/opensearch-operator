#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implementation of WorkloadBase for running on VMs."""
import logging
import os
import secrets
import shutil
import string
import subprocess

from charms.operator_libs_linux.v2 import snap
from core.workload import WorkloadBase
from literals import OPENSEARCH_DASHBOARDS_SNAP_REVISION
from tenacity import retry
from tenacity.retry import retry_if_not_result
from tenacity.stop import stop_after_attempt
from tenacity.wait import wait_fixed
from typing_extensions import override

logger = logging.getLogger(__name__)


class ODWorkload(WorkloadBase):
    """Implementation of WorkloadBase for running on VMs."""

    # SNAP_NAME = "opensearch-dashboards"
    SNAP_NAME = "opensearch-dashboards"
    SNAP_SERVICE = "daemon"

    def __init__(self):
        self.dasbhoards = snap.SnapCache()[self.SNAP_NAME]

    @override
    def start(self) -> None:
        try:
            self.dasbhoards.start(services=[self.SNAP_SERVICE])
        except snap.SnapError as e:
            logger.exception(str(e))

    @override
    def stop(self) -> None:
        try:
            self.dasbhoards.stop(services=[self.SNAP_SERVICE])
        except snap.SnapError as e:
            logger.exception(str(e))

    @override
    def restart(self) -> None:
        try:
            self.dasbhoards.restart(services=[self.SNAP_SERVICE])
        except snap.SnapError as e:
            logger.exception(str(e))

    @override
    def read(self, path: str) -> list[str]:
        if not os.path.exists(path):
            return []
        else:
            with open(path) as f:
                content = f.read().split("\n")

        return content

    @override
    def write(self, content: str, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.chown(os.path.dirname(path), user="snap_daemon", group="root")

        with open(path, "w") as f:
            f.write(content)

        shutil.chown(path, user="snap_daemon", group="root")

    @override
    def exec(self, command: list[str], working_dir: str | None = None) -> str:
        return subprocess.check_output(
            command,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=working_dir,
        )

    @override
    @retry(
        wait=wait_fixed(1),
        stop=stop_after_attempt(5),
        retry_error_callback=lambda state: state.outcome.result(),  # type: ignore
        retry=retry_if_not_result(lambda result: True if result else False),
    )
    def alive(self) -> bool:
        try:
            return bool(self.dasbhoards.services[self.SNAP_SERVICE]["active"])
        except KeyError:
            return False

    @override
    def healthy(self) -> bool:
        return self.alive()

    # --- Charm Specific ---

    def install(self) -> bool:
        """Loads the snap from LP, returning a StatusBase for the Charm to set.

        Returns:
            True if successfully installed. False otherwise.
        """
        try:
            cache = snap.SnapCache()
            dashboards = cache[self.SNAP_NAME]

            dashboards.ensure(
                snap.SnapState.Present,
                revision=OPENSEARCH_DASHBOARDS_SNAP_REVISION,
                channel="edge",
            )

            self.dashboards = dashboards
            self.dashboards.hold()

            return True
        except snap.SnapError as e:
            logger.error(str(e))
            return False

    def generate_password(self) -> str:
        """Creates randomized string for use as app passwords.

        Returns:
            String of 32 randomized letter+digit characters
        """
        return "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(32)])
