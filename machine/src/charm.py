#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""

import logging

from opensearch_single_kernel.charms.vm import OpenSearchVMCharm
from ops.main import main

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    main(OpenSearchVMCharm)
