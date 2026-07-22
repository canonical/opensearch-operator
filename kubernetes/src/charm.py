#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Kubernetes Operator for OpenSearch."""

from opensearch_single_kernel.charms.k8s import OpenSearchK8sCharm
from ops.main import main

if __name__ == "__main__":
    main(OpenSearchK8sCharm)
