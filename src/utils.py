# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions."""
import os
import tarfile


def extract_tarball(tarball_path: str, extract_dir):
    """Extract tarball and strip first directory. Equivalent to --strip-components 1."""

    def fetch_members(tf):
        members = tar.getmembers()
        root_folder = members[0].name

        for member in tf.getmembers():
            if member.path.startswith(root_folder):
                member.path = f"{extract_dir}{member.path[len(root_folder):]}"
                yield member

    with tarfile.open(tarball_path) as tar:
        tar.extractall(extract_dir, members=fetch_members(tar))

    os.remove(tarball_path)
