# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exception with ops status"""

import ops


class StatusException(Exception):
    """Exception with ops status"""

    def __init__(self, status: ops.StatusBase) -> None:
        super().__init__(status.message)
        self.status = status
