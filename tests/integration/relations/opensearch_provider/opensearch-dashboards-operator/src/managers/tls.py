#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for building necessary files for Java TLS auth."""
import logging
import subprocess

import ops.pebble
from core.cluster import SUBSTRATES, ClusterState
from core.workload import WorkloadBase

logger = logging.getLogger(__name__)


class TLSManager:
    """Manager for building necessary files for Java TLS auth."""

    def __init__(self, state: ClusterState, workload: WorkloadBase, substrate: SUBSTRATES):
        self.state = state
        self.workload = workload
        self.substrate = substrate

    def set_private_key(self) -> None:
        """Sets the unit private-key."""
        if not self.state.unit_server.private_key:
            logger.error("Can't set private-key to unit, missing private-key in relation data")
            return

        self.workload.write(
            content=self.state.unit_server.private_key, path=self.workload.paths.server_key
        )

    def set_ca(self) -> None:
        """Sets the unit CA."""
        if not self.state.unit_server.ca:
            logger.error("Can't set CA to unit, missing CA in relation data")
            return

        self.workload.write(content=self.state.unit_server.ca, path=self.workload.paths.ca)

    def set_certificate(self) -> None:
        """Sets the unit certificate."""
        if not self.state.unit_server.certificate:
            logger.error("Can't set certificate to unit, missing certificate in relation data")
            return

        self.workload.write(
            content=self.state.unit_server.certificate, path=self.workload.paths.certificate
        )

    # def set_truststore(self) -> None:
    #     """Creates the unit Java Truststore and adds the unit CA."""
    #     keytool_cmd = "charmed-zookeeper.keytool" if self.substrate == "vm" else "keytool"
    #
    #     try:
    #         self.workload.exec(
    #             command=[
    #                 keytool_cmd,
    #                 "-import",
    #                 "-v",
    #                 "-alias",
    #                 "ca",
    #                 "-file",
    #                 self.workload.paths.ca,
    #                 "-keystore",
    #                 self.workload.paths.truststore,
    #                 "-storepass",
    #                 self.state.unit_server.truststore_password,
    #                 "-noprompt",
    #             ],
    #         )
    #         if self.substrate == "vm":
    #             self.workload.exec(
    #                 command=["chown", "snap_daemon:root", self.workload.paths.truststore],
    #             )
    #
    #     except (subprocess.CalledProcessError, ops.pebble.ExecError) as e:
    #         if "already exists" in str(e.stdout):
    #             return
    #
    #         logger.error(str(e.stdout))
    #         raise e
    #
    # def set_p12_keystore(self) -> None:
    #     """Creates the unit Java Keystore and adds unit certificate + private-key."""
    #     try:
    #         self.workload.exec(
    #             command=[
    #                 "openssl",
    #                 "pkcs12",
    #                 "-export",
    #                 "-in",
    #                 self.workload.paths.certificate,
    #                 "-inkey",
    #                 self.workload.paths.server_key,
    #                 "-passin",
    #                 f"pass:{self.state.unit_server.keystore_password}",
    #                 "-certfile",
    #                 self.workload.paths.certificate,
    #                 "-out",
    #                 self.workload.paths.keystore,
    #                 "-password",
    #                 f"pass:{self.state.unit_server.keystore_password}",
    #             ],
    #         )
    #         if self.substrate == "vm":
    #             self.workload.exec(
    #                 command=["chown", "snap_daemon:root", self.workload.paths.keystore],
    #             )
    #
    #     except (subprocess.CalledProcessError, ops.pebble.ExecError) as e:
    #         logger.error(str(e.stdout))
    #         raise e

    def remove_cert_files(self) -> None:
        """Removes all certs, keys, stores from the unit."""
        try:
            self.workload.exec(
                command=[
                    "rm",
                    "-rf",
                    f"{self.workload.paths.conf_path}/*.pem",
                    f"*{self.workload.paths.conf_path}/*.key",
                    f"*{self.workload.paths.conf_path}/*.p12",
                    f"*{self.workload.paths.conf_path}/*.jks",
                ],
                working_dir=self.workload.paths.conf_path,
            )
        except (subprocess.CalledProcessError, ops.pebble.ExecError) as e:
            logger.error(str(e.stdout))
            raise e
