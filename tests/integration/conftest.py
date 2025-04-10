#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import os

import pytest


@pytest.fixture
def ubuntu_base():
    return os.environ["CHARM_UBUNTU_BASE"]


@pytest.fixture
def charm(ubuntu_base):
    # TODO: use instead of ops_test.build_charm
    # Return str instead of pathlib.Path since python-libjuju's model.deploy(), juju deploy, and
    # juju bundle files expect local charms to begin with `./` or `/` to distinguish them from
    # Charmhub charms.
    return f"./opensearch_ubuntu@{ubuntu_base}-amd64.charm"
