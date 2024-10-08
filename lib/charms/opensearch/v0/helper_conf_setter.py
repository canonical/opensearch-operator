# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for editing yaml config files at any depth level and maintaining comments."""
import logging
import re
import sys
import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping
from enum import Enum
from io import StringIO
from os.path import exists
from typing import Dict, List

from overrides import override
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


class ConfigSetter(ABC):
    """Base class for manipulating YAML Config, of multiple types and any depth level.

    conf_setter = YamlConfigSetter() or another config setter

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
        self.base_path = self.__clean_base_path(base_path)

    @abstractmethod
    def load(self, config_file: str) -> Dict[str, any]:
        """Load the content of a YAML file."""
        pass

    @abstractmethod
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
        """Add or update the value of a key (or content of array at index / key) if it exists.

        Args:
            config_file (str): Path to the source config file
            key_path (str): The path of the YAML key to target
            val (any): The value to store for the passed key
            sep (str): The separator / delimiter character to use in the key_path
            output_type (OutputType): The type of output we're expecting from this operation,
                i.e, set OutputType.all to have the output on both the console and target file
            inline_array (bool): whether the operation should format arrays in:
                - multiline fashion (false)
                - between brackets (true)
            output_file: Target file for the result config, by default same as config_file

        Returns:
            Dict[str, any]: The final version of the YAML config.
        """
        pass

    @abstractmethod
    def delete(
        self,
        config_file: str,
        key_path: str,
        sep="/",
        output_type: OutputType = OutputType.file,
        output_file: str = None,
    ) -> Dict[str, any]:
        """Delete the value of a key (or content of array at index / key) if it exists.

        Args:
            config_file (str): Path to the source config file
            key_path (str): The path of the YAML key to target
            sep (str): The separator / delimiter character to use in the key_path
            output_type (OutputType): The type of output we're expecting from this operation,
                i.e, set OutputType.all to have the output on both the console and target file
            output_file: Target file for the result config, by default same as config_file

        Returns:
            Dict[str, any]: The final version of the YAML config.
        """
        pass

    @abstractmethod
    def replace(
        self,
        config_file: str,
        old_val: str,
        new_val: any,
        regex: bool = False,
        add_line_if_missing: bool = False,
        output_type: OutputType = OutputType.file,
        output_file: str = None,
    ) -> None:
        """Replace any substring in a text file.

        Args:
            config_file (str): Path to the source config file
            old_val (str): The value we wish to replace
            new_val (any): The new value to replace old_val
            regex (bool): Whether to treat old_val as a regex.
            add_line_if_missing (bool): whether to append the new_val if old_val is not found.
            output_type (OutputType): The type of output we're expecting from this operation,
                i.e, set OutputType.all to have the output on both the console and target file
            output_file: Target file for the result config, by default same as config_file
        """
        pass

    @abstractmethod
    def append(
        self,
        config_file: str,
        text_to_append: str,
    ) -> None:
        """Append any string to a text file.

        Args:
            config_file (str): Path to the source config file
            text_to_append (str): The str to append to the config file
        """
        pass

    @staticmethod
    def __clean_base_path(base_path: str):
        if base_path is None:
            return ""

        base_path = base_path.strip()
        if not base_path.endswith("/"):
            base_path = f"{base_path}/"

        return base_path


class YamlConfigSetter(ConfigSetter):
    """Class for updating YAML config on the file system."""

    def __init__(self, base_path: str = None):
        """base_path: if set, where to look for files relatively on "load/put/delete" methods."""
        super().__init__(base_path)
        self.yaml = YAML()

    @override
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

    @override
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

    @override
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

    @override
    def replace(
        self,
        config_file: str,
        old_val: str,
        new_val: any,
        regex: bool = False,
        add_line_if_missing: bool = False,
        output_type: OutputType = OutputType.file,
        output_file: str = None,
    ) -> None:
        """Replace any substring in a text file.

        Args:
            config_file (str): Path to the source config file
            old_val (str): The value we wish to replace
            new_val (any): The new value to replace old_val
            regex (bool): Whether to treat old_val as a regex.
            add_line_if_missing (bool): whether to append the new_val if old_val is not found.
            output_type (OutputType): The type of output we're expecting from this operation,
                i.e, set OutputType.all to have the output on both the console and target file
            output_file: Target file for the result config, by default same as config_file
        """
        path = f"{self.base_path}{config_file}"
        if not exists(path):
            raise FileNotFoundError(f"{path} not found.")

        with open(path, "r+") as f:
            data = f.read()

            if regex and old_val and re.compile(old_val, re.MULTILINE).findall(data):
                data = re.sub(r"{}".format(old_val), f"{new_val}", data)
            elif old_val and old_val in data:
                data = data.replace(old_val, new_val)
            elif add_line_if_missing:
                data += f"{data.rstrip()}\n{new_val}\n"

            if output_type in [OutputType.console, OutputType.all]:
                logger.info(data)

            if output_type in [OutputType.file, OutputType.all]:
                if output_file is None or output_file == config_file:
                    f.seek(0)
                    f.write(data)
                else:
                    with open(output_file, "w") as g:
                        g.write(data)

    @override
    def append(
        self,
        config_file: str,
        text_to_append: str,
    ) -> None:
        """Append any string to a text file.

        Args:
            config_file (str): Path to the source config file
            text_to_append (str): The str to append to the config file
        """
        path = f"{self.base_path}{config_file}"

        if not exists(path):
            raise FileNotFoundError(f"{path} not found.")

        with open(path, "a") as f:
            f.write("\n" + text_to_append)

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
            leaf_container = self.__leaf_container(source, node_keys)
            leaf_key = node_keys.pop(0)

            # remove simple type elements and entire collections by key
            if leaf_key in leaf_container and leaf_key[0] not in {"{", "["}:
                del leaf_container[leaf_key]
                return

            # remove element from set
            if leaf_key.startswith("{"):
                leaf_container.remove(leaf_key[1:-1])
                return

            # remove element from list
            target_index = self.__target_array_index(leaf_container, leaf_key)
            del leaf_container[target_index]
        except AttributeError:
            # element not found
            logger.debug("Target element not found.")
            pass

    def __leaf_container(self, current, node_names: List[str]):
        if len(node_names) == 1:
            return current

        current_key = node_names.pop(0)
        if current_key.startswith("[") and current_key.endswith("]"):
            target_index = self.__target_array_index(current, current_key)
            return self.__leaf_container(current[target_index], node_names)

        return self.__leaf_container(current[current_key], node_names)

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

        leaf_l = self.__leaf_container(data, node_keys)
        leaf_l[leaf_k] = self.__flow_style()
        leaf_l[leaf_k].extend(val)

        return data

    @staticmethod
    def __flow_style() -> CommentedSeq:
        ret = CommentedSeq()
        ret.fa.set_flow_style()
        return ret
