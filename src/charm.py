#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""

from ops.main import main

from opensearch_single_kernel.charms.vm import OpenSearchVMCharm

if __name__ == "__main__":
    main(OpenSearchVMCharm)