#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions for writing tests."""

from typing import Callable
from unittest.mock import patch


def patch_network_get(private_address="10.6.215.1") -> Callable:
    def network_get(*args, **kwargs) -> dict:
        """Patch for the not-yet-implemented testing backend needed for `bind_address`.

        This patch decorator can be used for cases such as:
        self.model.get_binding(event.relation).network.bind_address
        """
        return {
            "bind-addresses": [
                {
                    "mac-address": "00:16:3e:15:a6:9e",
                    "interface-name": "eth0",
                    "addresses": [
                        {"hostname": "", "value": private_address, "cidr": "10.6.215.0/24"}
                    ],
                }
            ],
            "egress-subnets": [f"{private_address}/32"],
            "ingress-addresses": [private_address],
        }

    return patch("ops.testing._TestingModelBackend.network_get", network_get)
