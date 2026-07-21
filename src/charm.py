#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""

import logging
import os

from opensearch_single_kernel.charms.k8s import OpenSearchK8sCharm
from opensearch_single_kernel.charms.vm import OpenSearchVMCharm
from ops.main import main

logger = logging.getLogger(__name__)


def is_k8s():
    """Check if the charm is running in a Kubernetes environment."""
    return "KUBERNETES_SERVICE_HOST" in os.environ


if __name__ == "__main__":
    if is_k8s():
        main(OpenSearchK8sCharm)
    else:
        main(OpenSearchVMCharm)
