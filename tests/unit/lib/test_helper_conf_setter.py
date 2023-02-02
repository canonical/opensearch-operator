# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_conf_setter library."""
import os
import unittest

from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter


class TestHelperConfSetter(unittest.TestCase):
    def setUp(self) -> None:
        self.conf = YamlConfigSetter()
        self.data = self.conf.load("tests/unit/resources/test_conf.yaml")

    def test_load(self):
        """Test loading a yaml file and serializing it into a dict."""
        self.assertEqual(len(self.data.keys()), 4)
        self.assertEqual(self.data["multiline_array"], ["item1", "item2"])
        self.assertTrue("complex_array" in self.data["obj"])

    def test_put_insert(self):
        """Test the insert on a file."""
        input_file = "tests/unit/resources/test_conf.yaml"
        output_file = "tests/unit/resources/produced.yaml"

        self.conf.put(input_file, "obj/nested_obj/new_key", "new_val", output_file=output_file)
        self.assertEqual(self.conf.load(output_file)["obj"]["nested_obj"]["new_key"], "new_val")

        self.conf.put(
            input_file, "obj/nested_obj/new_key", "new_val_updated", output_file=output_file
        )
        self.assertEqual(
            self.conf.load(output_file)["obj"]["nested_obj"]["new_key"], "new_val_updated"
        )

        self.conf.put(input_file, "a/b/c/d", {"e": "n", "f": [1, 2]}, output_file=output_file)
        self.assertDictEqual(
            self.conf.load(output_file)["a"]["b"]["c"]["d"], {"e": "n", "f": [1, 2]}
        )

        self.conf.put(input_file, "obj/simple_array/[]", "new", output_file=output_file)
        self.assertEqual(self.conf.load(output_file)["obj"]["simple_array"][-1], "new")

    def test_put_update(self):
        """Test the update on a file."""
        input_file = "tests/unit/resources/test_conf.yaml"
        output_file = "tests/unit/resources/produced.yaml"

        self.conf.put(input_file, "simple_key", "updated", output_file=output_file)
        self.assertEqual(self.conf.load(output_file)["simple_key"], "updated")

        self.conf.put(input_file, "obj/simple_array/[1]", "update_1", output_file=output_file)
        self.assertEqual(self.conf.load(output_file)["obj"]["simple_array"][1], "update_1")

        self.conf.put(
            input_file,
            "obj/complex_array/[name:elt1]",
            {"name": "elt1", "key": "val"},
            output_file=output_file,
        )
        complex_array = self.conf.load(output_file)["obj"]["complex_array"]
        self.assertDictEqual(
            [x for x in complex_array if x["name"] == "elt1"][0], {"name": "elt1", "key": "val"}
        )

    def test_delete(self):
        """Test deleting node from YAML doc."""
        input_file = "tests/unit/resources/test_conf.yaml"
        output_file = "tests/unit/resources/produced.yaml"

        self.conf.delete(input_file, "simple_key", output_file=output_file)
        self.assertFalse("simple_key" in self.conf.load(output_file))

        self.conf.delete(input_file, "non_existing_key.non_existing", output_file=output_file)

        self.conf.delete(input_file, "obj/simple_array/[1]", output_file=output_file)
        self.assertFalse("elt2" in self.conf.load(output_file)["obj"]["simple_array"])

        self.conf.delete(input_file, "obj/complex_array/[name:elt3]", output_file=output_file)
        complex_array = self.conf.load(output_file)["obj"]["complex_array"]
        for elt in complex_array:
            self.assertNotEqual(elt["name"], "name1")

    def tearDown(self) -> None:
        """Cleanup."""
        output = "tests/unit/resources/produced.yaml"
        if os.path.exists(output):
            os.remove("tests/unit/resources/produced.yaml")
