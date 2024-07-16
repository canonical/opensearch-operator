# Copyright 2023 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Handler for the sysctl config.

This library allows your charm to create and configure sysctl options to the machine.

Validation and merge capabilities are added, for situations where more than one application
are setting values. The following files can be created:

- /etc/sysctl.d/90-juju-<app-name>
    Requirements from one application requesting to configure the values.

- /etc/sysctl.d/95-juju-sysctl.conf
    Merged file resulting from all other `90-juju-*` application files.


A charm using the sysctl lib will need a data structure like the following:
```
{
"vm.swappiness": "1",
"vm.max_map_count": "262144",
"vm.dirty_ratio": "80",
"vm.dirty_background_ratio": "5",
"net.ipv4.tcp_max_syn_backlog": "4096",
}
```

Now, it can use that template within the charm, or just declare the values directly:

```python
from charms.operator_libs_linux.v0 import sysctl

class MyCharm(CharmBase):

    def __init__(self, *args):
        ...
        self.sysctl = sysctl.Config(self.meta.name)

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.remove, self._on_remove)

    def _on_install(self, _):
        # Altenatively, read the values from a template
        sysctl_data = {"net.ipv4.tcp_max_syn_backlog": "4096"}}

        try:
            self.sysctl.configure(config=sysctl_data)
        except (sysctl.ApplyError, sysctl.ValidationError) as e:
            logger.error(f"Error setting values on sysctl: {e.message}")
            self.unit.status = BlockedStatus("Sysctl config not possible")
        except sysctl.CommandError:
            logger.error("Error on sysctl")

    def _on_remove(self, _):
        self.sysctl.remove()
```
"""

import logging
import re
from pathlib import Path
from subprocess import STDOUT, CalledProcessError, check_output
from typing import Dict, List

logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "17a6cd4d80104d15b10f9c2420ab3266"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 4

CHARM_FILENAME_PREFIX = "90-juju-"
SYSCTL_DIRECTORY = Path("/etc/sysctl.d")
SYSCTL_FILENAME = SYSCTL_DIRECTORY / "95-juju-sysctl.conf"
SYSCTL_HEADER = f"""# This config file was produced by sysctl lib v{LIBAPI}.{LIBPATCH}
#
# This file represents the output of the sysctl lib, which can combine multiple
# configurations into a single file like.
"""


class Error(Exception):
    """Base class of most errors raised by this library."""

    @property
    def message(self):
        """Return the message passed as an argument."""
        return self.args[0]


class CommandError(Error):
    """Raised when there's an error running sysctl command."""


class ApplyError(Error):
    """Raised when there's an error applying values in sysctl."""


class ValidationError(Error):
    """Exception representing value validation error."""


class Config(Dict):
    """Represents the state of the config that a charm wants to enforce."""

    _apply_re = re.compile(r"sysctl: permission denied on key \"([a-z_\.]+)\", ignoring$")

    def __init__(self, name: str) -> None:
        self.name = name
        self._data = self._load_data()

    def __contains__(self, key: str) -> bool:
        """Check if key is in config."""
        return key in self._data

    def __len__(self):
        """Get size of config."""
        return len(self._data)

    def __iter__(self):
        """Iterate over config."""
        return iter(self._data)

    def __getitem__(self, key: str) -> str:
        """Get value for key form config."""
        return self._data[key]

    @property
    def charm_filepath(self) -> Path:
        """Name for resulting charm config file."""
        return SYSCTL_DIRECTORY / f"{CHARM_FILENAME_PREFIX}{self.name}"

    def configure(self, config: Dict[str, str]) -> None:
        """Configure sysctl options with a desired set of params.

        Args:
            config: dictionary with keys to configure:
        ```
        {"vm.swappiness": "10", ...}
        ```
        """
        self._parse_config(config)

        # NOTE: case where own charm calls configure() more than once.
        if self.charm_filepath.exists():
            self._merge(add_own_charm=False)

        conflict = self._validate()
        if conflict:
            raise ValidationError(f"Validation error for keys: {conflict}")

        snapshot = self._create_snapshot()
        logger.debug("Created snapshot for keys: %s", snapshot)
        try:
            self._apply()
        except ApplyError:
            self._restore_snapshot(snapshot)
            raise

        self._create_charm_file()
        self._merge()

    def remove(self) -> None:
        """Remove config for charm.

        The removal process won't apply any sysctl configuration. It will only merge files from
        remaining charms.
        """
        self.charm_filepath.unlink(missing_ok=True)
        logger.info("Charm config file %s was removed", self.charm_filepath)
        self._merge()

    def _validate(self) -> List[str]:
        """Validate the desired config params against merged ones."""
        common_keys = set(self._data.keys()) & set(self._desired_config.keys())
        conflict_keys = []
        for key in common_keys:
            if self._data[key] != self._desired_config[key]:
                logger.warning(
                    "Values for key '%s' are different: %s != %s",
                    key,
                    self._data[key],
                    self._desired_config[key],
                )
                conflict_keys.append(key)

        return conflict_keys

    def _create_charm_file(self) -> None:
        """Write the charm file."""
        with open(self.charm_filepath, "w") as f:
            f.write(f"# {self.name}\n")
            for key, value in self._desired_config.items():
                f.write(f"{key}={value}\n")

    def _merge(self, add_own_charm=True) -> None:
        """Create the merged sysctl file.

        Args:
            add_own_charm : bool, if false it will skip the charm file from the merge.
        """
        # get all files that start by 90-juju-
        data = [SYSCTL_HEADER]
        paths = set(SYSCTL_DIRECTORY.glob(f"{CHARM_FILENAME_PREFIX}*"))
        if not add_own_charm:
            paths.discard(self.charm_filepath)

        for path in paths:
            with open(path, "r") as f:
                data += f.readlines()
        with open(SYSCTL_FILENAME, "w") as f:
            f.writelines(data)

        # Reload data with newly created file.
        self._data = self._load_data()

    def _apply(self) -> None:
        """Apply values to machine."""
        cmd = [f"{key}={value}" for key, value in self._desired_config.items()]
        result = self._sysctl(cmd)
        failed_values = [
            self._apply_re.match(line) for line in result if self._apply_re.match(line)
        ]
        logger.debug("Failed values: %s", failed_values)

        if failed_values:
            msg = f"Unable to set params: {[f.group(1) for f in failed_values]}"
            logger.error(msg)
            raise ApplyError(msg)

    def _create_snapshot(self) -> Dict[str, str]:
        """Create a snapshot of config options that are going to be set."""
        cmd = ["-n"] + list(self._desired_config.keys())
        values = self._sysctl(cmd)
        return dict(zip(list(self._desired_config.keys()), values))

    def _restore_snapshot(self, snapshot: Dict[str, str]) -> None:
        """Restore a snapshot to the machine."""
        values = [f"{key}={value}" for key, value in snapshot.items()]
        self._sysctl(values)

    def _sysctl(self, cmd: List[str]) -> List[str]:
        """Execute a sysctl command."""
        cmd = ["sysctl"] + cmd
        logger.debug("Executing sysctl command: %s", cmd)
        try:
            return check_output(cmd, stderr=STDOUT, universal_newlines=True).splitlines()
        except CalledProcessError as e:
            msg = f"Error executing '{cmd}': {e.stdout}"
            logger.error(msg)
            raise CommandError(msg)

    def _parse_config(self, config: Dict[str, str]) -> None:
        """Parse a config passed to the lib."""
        self._desired_config = {k: str(v) for k, v in config.items()}

    def _load_data(self) -> Dict[str, str]:
        """Get merged config."""
        config = {}
        if not SYSCTL_FILENAME.exists():
            return config

        with open(SYSCTL_FILENAME, "r") as f:
            for line in f:
                if line.startswith(("#", ";")) or not line.strip() or "=" not in line:
                    continue

                key, _, value = line.partition("=")
                config[key.strip()] = value.strip()

        return config
