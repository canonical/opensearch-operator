# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for editing yaml config files at any depth level and maintaining comments."""
import logging
import re
import sys
import uuid
from collections.abc import Mapping
from enum import Enum
from io import StringIO
from os.path import exists
from typing import Dict, List

from ruamel.yaml import YAML, CommentedSeq
from ruamel.yaml.comments import CommentedSet

# The unique Charmhub library identifier, never change it
LIBID = "69a1559c3e4c40cebd8ff0b255cf13db"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class OutputType(Enum):
    """Enum representing the output type of a write operation."""

    file = "file"
    obj = "obj"
    console = "console"
    all = "all"

    def __str__(self):
        """String representation of enum value."""
        return self.value


class YamlConfigSetter:
    """Utility class for updating YAML config, supporting diverse object types and nestedness.

    conf_setter = YamlConfigSetter()
    put("file.yml", "a.b", "new_name")
    put("file.yml", "a.b/c.obj/key3/key1.a/obj", {"a": "new_name_1", "b": ["hello", "world"]})
    put("file.yml", "a.b/c.arr.simple/[0]", "hello")
    put("file.yml", "a.b/c.arr.complex/[name:name1]", {"a": "new_name_1", "b": ["hello", "world"]})
    put("file.yml", "a.b/c.arr.complex/[name:name5]/val/key", "new_val25")
    put("file.yml", "a.b/c.arr.complex/[0]/val", "complex2_updated")
    put("file.yml", "a.b/c.arr.complex/[0]/new_val/new_sub_key", "updated")
    """

    def __init__(self, base_path: str = None):
        """base_path: if set, where to look for files relatively on "load/put/delete" methods."""
        self.yaml = YAML()
        self.base_path = self.__clean_base_path(base_path)

    def load(self, config_file: str) -> Dict[str, any]:
        """Load the content of a YAML file."""
        path = f"{self.base_path}{config_file}"

        if not exists(path):
            raise FileNotFoundError(f"{path} not found.")

        with open(path, "r") as f:
            lines = f.read().splitlines()

            random_id = uuid.uuid4().hex
            lines.append(f"{random_id}: {random_id}")

            data = self.yaml.load(StringIO("\n".join(lines)))
            del data[random_id]

            return data

    def put(
        self,
        config_file: str,
        key_path: str,
        val: any,
        sep="/",
        output_type: OutputType = OutputType.file,
        inline_array: bool = False,
        output_file: str = None,
    ) -> Dict[str, any]:
        """Add or update the value of a key (or content of array at index / key) if it exists."""
        data = self.load(config_file)

        self.__deep_update(data, key_path.split(sep), val)

        if inline_array:
            data = self.__inline_array_format(data, key_path.split(sep), val)

        self.__dump(
            data,
            output_type,
            f"{self.base_path}{config_file}" if output_file is None else output_file,
        )

        return data

    def delete(
        self,
        config_file: str,
        key_path: str,
        sep="/",
        output_type: OutputType = OutputType.file,
        output_file: str = None,
    ) -> Dict[str, any]:
        """Delete the value of a key (or content of array at index / key) if it exists."""
        data = self.load(config_file)

        self.__deep_delete(data, key_path.split(sep))

        self.__dump(
            data,
            output_type,
            f"{self.base_path}{config_file}" if output_file is None else output_file,
        )

        return data

    def replace(
        self,
        config_file: str,
        old_val: str,
        new_val: any,
        regex: bool = False,
        output_type: OutputType = OutputType.file,
        output_file: str = None,
    ) -> None:
        """Replace any substring in a text file."""
        path = f"{self.base_path}{config_file}"

        if not exists(path):
            raise FileNotFoundError(f"{path} not found.")

        with open(path, "r+") as f:
            data = f.read()

            if regex:
                data = re.sub(r"{}".format(old_val), f"{new_val}", data)
            else:
                data = data.replace(old_val, new_val)

            if output_type in [OutputType.console, OutputType.all]:
                logger.info(data)

            if output_type in [OutputType.file, OutputType.all]:
                if output_file is None or output_file == config_file:
                    f.write(data)
                else:
                    with open(output_file, "w") as g:
                        g.write(data)

    def __dump(self, data: Dict[str, any], output_type: OutputType, target_file: str):
        """Write the YAML data on the corresponding "output_type" stream."""
        if not data:
            return

        if output_type in [OutputType.console, OutputType.all]:
            self.yaml.dump(data, sys.stdout)

        if output_type in [OutputType.file, OutputType.all]:
            with open(target_file, mode="w") as f:
                self.yaml.dump(data, f)

    def __deep_update(self, source, node_keys: List[str], val: any):
        """Recursively traverses the tree of nodes, and writes the value accordingly.

        Arg:
            source: the data object on which the traversal happens, initially the whole document,
                    then as the traversal progresses this is substituted by the remaining part
                    of the tree
            node_keys: the remaining node keys to land on the target node,
                       initially the path provided by the user
            val: the value to be set once the traversal is done and node is found.
        """
        if not node_keys:
            if isinstance(val, set):
                return list(val)

            return val

        if source is None:
            if node_keys[0].startswith("["):
                source = []
            elif node_keys[0].startswith("{"):
                source = set()
            else:
                source = dict()

        current_key: str = node_keys.pop(0)

        # handling the insert / update of simple types on sets
        if current_key.startswith("{"):
            return self.__get_source_for_set(source, val)

        # handling the insert / update on key/val objects
        if isinstance(source, Mapping):
            return self.__get_source_for_object(source, node_keys, val, current_key)

        # handling the insert / update on arrays
        if isinstance(source, list):
            return self.__get_source_for_list(source, node_keys, val, current_key)

        return source

    def __get_source_for_set(self, source, val):
        source = CommentedSet(source)
        if isinstance(val, set) or isinstance(val, list):
            source = val
        else:
            source.add(val)
        return list(source)

    def __get_source_for_object(self, source, node_keys, val, current_key):
        current_val = source.get(current_key, None)
        source[current_key] = self.__deep_update(current_val, node_keys, val)
        return source

    def __get_source_for_list(self, source, node_keys, val, current_key):
        target_index = self.__target_array_index(source, current_key)
        if target_index == -1:
            source.append(self.__deep_update(None, node_keys, val))
        else:
            source[target_index] = self.__deep_update(source[target_index], node_keys, val)

        return source

    def __deep_delete(self, source, node_keys: List[str]):
        if not node_keys:
            return

        if source is None:
            return

        try:
            leaf_level = self.__leaf_level(source, node_keys)
            leaf_key = node_keys.pop(0)

            if leaf_key in leaf_level and (
                isinstance(leaf_level[leaf_key], Mapping) or not leaf_key.startswith("[")
            ):
                del leaf_level[leaf_key]
                return

            if leaf_key.startswith("{"):
                leaf_level.remove(leaf_key[1:-1])
                return

            # list
            target_index = self.__target_array_index(leaf_level, leaf_key)
            del leaf_level[target_index]
        except AttributeError:
            # element not found
            pass

    def __leaf_level(self, current, node_names: List[str]):
        if len(node_names) == 1:
            return current

        current_key = node_names.pop(0)
        if current_key.startswith("[") and current_key.endswith("]"):
            target_index = self.__target_array_index(current, current_key)
            return self.__leaf_level(current[target_index], node_names)

        return self.__leaf_level(current[current_key], node_names)

    @staticmethod
    def __target_array_index(source: list, node_key: str) -> int:
        str_index = node_key[1:-1].strip()

        index = None

        # where user provides a key [key:val] or [key]
        if str_index and not str_index.isnumeric():
            key = str_index.split(":")
            if len(key) == 1:
                index = source.index(str_index)
            else:
                index = -1
                for elt, i in zip(source, range(len(source))):
                    if elt.get(key[0], None) == key[1]:
                        index = i
                        break

                if index == -1:
                    raise ValueError(f"{str_index} not found in the object.")

        exists = index is not None or (str_index and (int(str_index) < len(source)))
        if not exists:
            return -1

        return int(str_index) if index is None else index

    def __inline_array_format(self, data, node_keys: List[str], val: List[any]) -> Dict[str, any]:
        """Reformat a multiline YAML array into one with square braces."""
        leaf_k = node_keys[-1]

        leaf_l = self.__leaf_level(data, node_keys)
        leaf_l[leaf_k] = self.__flow_style()
        leaf_l[leaf_k].extend(val)

        return data

    @staticmethod
    def __flow_style() -> CommentedSeq:
        ret = CommentedSeq()
        ret.fa.set_flow_style()
        return ret

    @staticmethod
    def __clean_base_path(base_path: str):
        if base_path is None:
            return ""

        base_path = base_path.strip()
        if not base_path.endswith("/"):
            base_path = f"{base_path}/"

        return base_path
