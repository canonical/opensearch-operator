# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for running commands."""

import logging
import os
import subprocess
from types import SimpleNamespace

from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError

# The unique Charmhub library identifier, never change it
LIBID = "f7199a359074406db94294bef78e3f2a"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


def run_cmd(command: str, args: str = None) -> SimpleNamespace:
    """Run command.

    Arg:
        command: can contain arguments
        args: command line arguments
    """
    if args is not None:
        command = f"{command} {args}"

    logger.debug(f"Executing command: {command}")

    try:
        output = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            encoding="utf-8",
            timeout=25,
            env=os.environ,
        )

        logger.debug(f"{command}:\n{output.stdout}")

        if output.returncode != 0:
            logger.error(f"{command}:\n Stderr: {output.stderr}\n Stdout: {output.stdout}")
            raise OpenSearchCmdError(cmd=command, out=output.stdout, err=output.stderr)

        return SimpleNamespace(cmd=command, out=output.stdout, err=output.stderr)
    except (TimeoutError, subprocess.TimeoutExpired):
        raise OpenSearchCmdError(cmd=command)
