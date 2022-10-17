# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
import shutil
from pathlib import Path
from typing import Callable
from unittest.mock import patch


def patch_network_get(private_address: str = "1.1.1.1") -> Callable:
    def network_get(*args, **kwargs) -> dict:
        """Patch for the not-yet-implemented testing backend needed for `bind_address`.

        This patch decorator can be used for cases such as:
        self.model.get_binding(event.relation).network.bind_address
        """
        return {
            "bind-addresses": [
                {
                    "addresses": [{"value": private_address}],
                }
            ]
        }

    return patch("ops.testing._TestingModelBackend.network_get", network_get)


def copy_file_content_to_tmp(config_dir_path: str, source_path: str) -> str:
    """Copy the content of a file into a temporary file and return it."""
    relative_dir = ""
    if "/" in source_path:
        relative_dir = "/".join(source_path.split("/")[:-1])

    target_dir = f"{config_dir_path}/tmp/{relative_dir}"
    Path(target_dir).mkdir(parents=True, exist_ok=True)

    dest_path = f"{target_dir}/{source_path.split('/')[-1]}"
    shutil.copyfile(f"{config_dir_path}/{source_path}", dest_path)

    return dest_path
