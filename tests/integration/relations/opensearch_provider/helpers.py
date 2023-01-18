#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from pytest_operator.plugin import OpsTest


async def check_new_relation(ops_test: OpsTest):
    """Smoke test to check relation is online."""
    raise NotImplementedError
