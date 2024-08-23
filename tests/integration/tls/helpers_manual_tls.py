# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import json
import logging
from collections import deque
from typing import TYPE_CHECKING, NamedTuple

from charms.tls_certificates_interface.v3.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from juju.unit import Unit
from tenacity import retry, stop_after_attempt, wait_exponential

if TYPE_CHECKING:
    from juju.action import Action

logger = logging.getLogger(__name__)

MANUAL_TLS_CERTIFICATES_APP_NAME = "manual-tls-certificates"


class GettingOutstandingCertificateRequestsFailedError(Exception):
    """Exception raised when getting outstanding certificate requests fails."""

    def __init__(self, message: str) -> None:
        """Initialise the exception."""
        super().__init__(message)


class CSRsMissingError(Exception):
    """Exception raised when the number of CSRs in the queue is less than the expected number."""

    def __init__(self, message: str) -> None:
        """Initialise the exception."""
        super().__init__(message)


class ProvidingCertificateFailedError(Exception):
    """Exception raised when providing a certificate fails."""

    def __init__(self, message: str) -> None:
        """Initialise the exception."""
        super().__init__(message)


class CSR(NamedTuple):
    """CSR represents the information about a certificate signing request."""

    relation_id: str
    application_name: str
    unit_name: str
    csr: bytes
    is_ca: bool

    @classmethod
    def from_charm_csr(cls, charm_csr: dict) -> "CSR":
        """Create a CSR object from a dictionary.

        Arguments:
        ---------
            charm_csr : dict
                The dictionary containing the information about
                the certificate signing request gotten from the charm.

        Returns:
        -------
            CSR: The CSR object.

        """
        return cls(
            relation_id=charm_csr["relation_id"],
            application_name=charm_csr["application_name"],
            unit_name=charm_csr["unit_name"],
            csr=charm_csr["csr"].encode(),
            is_ca=charm_csr["is_ca"],
        )


class ManualTLSAgent:
    """An agent that processes certificate signing requests from the TLS operator."""

    def __init__(self, tls_unit: Unit) -> None:
        """Initialise the agent."""
        self.tls_unit = tls_unit
        self.ca_key = generate_private_key()
        self.ca = generate_ca(self.ca_key, "CN_CA")
        self.csr_queue = deque()

    async def get_outstanding_certificate_requests(self) -> None:
        """Get the outstanding certificate requests from the TLS operator.

        Raises
        ------
            GettingOutstandingCertificateRequestsFailedError:
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
            if "No outstanding certificate requests" in message:
                logging.info(message)
            if "No certificates relation has been created yet" in message:
                logging.info(message)
            logging.error(message)
            raise GettingOutstandingCertificateRequestsFailedError(message)
        csrs = json.loads(action.results["result"])
        self.csr_queue = deque([CSR.from_charm_csr(csr) for csr in csrs])

    @retry(
        wait=wait_exponential(multiplier=1, min=5, max=20),
        stop=stop_after_attempt(100),
    )
    async def wait_for_csrs_in_queue(self, nbr_csrs: int = 1) -> None:
        """Wait for the number of csrs in the queue to be equal to the number of csrs specified.

        Arguments:
        ---------
            nbr_csrs : int
                The number of csrs to wait for in the queue.

        Raises:
        ------
            CSRsMissingError: If the number of csrs in the queue is less than the expected number.

        """
        await self.get_outstanding_certificate_requests()
        if len(self.csr_queue) < nbr_csrs:
            message = f"{nbr_csrs - len(self.csr_queue)} CSRs missing in queue"
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
            message = "Failed to provide certificate for %s", csr.unit_name
            logging.error(message)
            raise ProvidingCertificateFailedError(message)
        logger.info("Provided certificate to %s", csr.unit_name)

    async def process_queue(self) -> None:
        """Process the certificate signing requests in the queue."""
        while self.csr_queue:
            csr = self.csr_queue.popleft()
            await self.process_csr(csr)
