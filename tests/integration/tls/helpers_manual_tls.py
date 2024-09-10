#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import TYPE_CHECKING, NamedTuple

from charms.tls_certificates_interface.v3.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from juju.model import Model
from juju.unit import Unit
from tenacity import retry, stop_after_attempt, wait_exponential

if TYPE_CHECKING:
    from juju.action import Action

logger = logging.getLogger(__name__)

MANUAL_TLS_CERTIFICATES_APP_NAME = "manual-tls-certificates"


class GetOutstandingCertificateRequestsError(Exception):
    """Exception raised when getting outstanding certificate requests fails."""


class CSRsMissingError(Exception):
    """Exception raised when the number of CSRs in the queue is less than the expected number."""


class ProvidingCertificateFailedError(Exception):
    """Exception raised when providing a certificate fails."""


class CSR(NamedTuple):
    """CSR represents the information about a certificate signing request."""

    relation_id: str
    application_name: str
    unit_name: str
    csr: bytes
    is_ca: bool

    @classmethod
    def from_dict(cls, csr: dict[str, str]) -> CSR:
        """Create a CSR object from a dictionary.

        Arguments:
        ---------
            csr : dict
                The dictionary containing the information about
                the certificate signing request gotten from the charm.

        Returns:
        -------
            CSR: The CSR object.

        """
        return cls(
            relation_id=csr["relation_id"],
            application_name=csr["application_name"],
            unit_name=csr["unit_name"],
            csr=csr["csr"].encode(),
            is_ca=csr["is_ca"],
        )


class ManualTLSAgent:
    """An agent that processes certificate signing requests from the TLS operator."""

    def __init__(self, tls_unit: Unit) -> None:
        """Initialise the agent."""
        self.tls_unit = tls_unit
        self.ca_key = generate_private_key()
        self.ca = generate_ca(self.ca_key, "CN_CA")
        self.csr_queue: list[CSR] = []

    async def get_outstanding_certificate_requests(self) -> None:
        """Get the outstanding certificate requests from the TLS operator.

        Raises
        ------
            GetOutstandingCertificateRequestsError:
                If getting the outstanding certificate requests fails.

        """
        logging.info("Getting outstanding certificate requests")
        action = await self.tls_unit.run_action("get-outstanding-certificate-requests")
        action: Action = await action.wait()
        if action.status != "completed":
            message = action.safe_data.get(
                "message",
                "Failed to get outstanding certificate requests",
            )
            raise GetOutstandingCertificateRequestsError(message)
        csrs = json.loads(action.results["result"])
        self.csr_queue = [CSR.from_dict(csr) for csr in csrs]

    @retry(
        wait=wait_exponential(multiplier=1, min=5, max=20),
        stop=stop_after_attempt(100),
    )
    async def wait_for_csrs_in_queue(self, csrs_count: int = 1) -> None:
        """Wait for the number of csrs in the queue to be equal to the number of csrs specified.

        Arguments:
        ---------
            csrs_count : int
                The number of csrs to wait for in the queue.

        Raises:
        ------
            CSRsMissingError: If the number of csrs in the queue is less than the expected number.

        """
        await self.get_outstanding_certificate_requests()
        if len(self.csr_queue) < csrs_count:
            message = f"{csrs_count - len(self.csr_queue)} CSRs missing in queue"
            raise CSRsMissingError(message)

    async def process_csr(self, csr: CSR) -> None:
        """Process the certificate signing request.

        Arguments:
        ---------
            csr : CSR
                The certificate signing request to process.

        Raises:
        ------
            ProvidingCertificateFailedError: If providing the certificate fails.

        """
        # Generate a certificate
        certificate = generate_certificate(
            csr=csr.csr,
            ca=self.ca,
            ca_key=self.ca_key,
            is_ca=csr.is_ca,
        )
        logger.info("Generated certificate for %s", csr.unit_name)
        # Send the certificate back to the charm
        action = await self.tls_unit.run_action(
            "provide-certificate",
            relation_id=csr.relation_id,
            **{
                "certificate": base64.b64encode(certificate).decode(),
                "ca-certificate": base64.b64encode(self.ca).decode(),
                "certificate-signing-request": base64.b64encode(
                    csr.csr,
                ).decode(),
            },
        )
        action = await action.wait()
        if action.status != "completed":
            message = f"Failed to provide certificate for {csr.unit_name}"
            logging.error(message)
            raise ProvidingCertificateFailedError(message)
        logger.info("Provided certificate to %s", csr.unit_name)

    async def process_queue(self) -> None:
        """Process the certificate signing requests in the queue."""
        while self.csr_queue:
            csr = self.csr_queue.pop()
            await self.process_csr(csr)


async def main() -> None:
    """Run the ManualTLSAgent."""
    logging.info("Starting ManualTLSAgent")
    model = Model()
    await model.connect()

    tls_unit = model.applications[MANUAL_TLS_CERTIFICATES_APP_NAME].units[0]

    agent = ManualTLSAgent(tls_unit)

    while True:
        await agent.wait_for_csrs_in_queue()
        await agent.process_queue()
        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
