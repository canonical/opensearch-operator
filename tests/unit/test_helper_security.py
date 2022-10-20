# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import math
import re
import unittest
from datetime import datetime

import ops
from charms.opensearch.v0.helper_security import (
    cert_expiration_remaining_hours,
    generate_hashed_password,
    generate_password,
    normalized_tls_subject,
    rfc2253_tls_subject,
)

ops.testing.SIMULATE_CAN_CONNECT = True


class TestHelperSecurity(unittest.TestCase):
    """Test class for the security related utility functions."""

    def test_generate_password(self):
        """Test password generation."""
        password_1 = generate_password()
        password_2 = generate_password()

        self.assertNotEqual(password_1, password_2)

        self.assertEqual(len(password_1), 32)
        self.assertEqual(len(password_2), 32)

        self.assertTrue(re.match("^[A-Za-z0-9]{32}$", password_1))
        self.assertTrue(re.match("^[A-Za-z0-9]{32}$", password_2))

    def test_generate_hashed_password(self):
        """Test password generation."""
        hash_1, password_1 = generate_hashed_password()
        hash_2, password_2 = generate_hashed_password()

        self.assertNotEqual(hash_1, hash_2)
        self.assertNotEqual(password_1, password_2)

        self.assertEqual(len(password_1), 32)
        self.assertEqual(len(password_2), 32)

        self.assertEqual(len(hash_1), 60)
        self.assertEqual(len(hash_2), 60)

        self.assertTrue(re.match("^[A-Za-z0-9]{32}$", password_1))
        self.assertTrue(re.match("^[A-Za-z0-9]{32}$", password_2))

        self.assertTrue(re.match("^\\$2[ayb]\\$.{56}$", hash_1))
        self.assertTrue(re.match("^\\$2[ayb]\\$.{56}$", hash_2))

    def test_cert_expiration_remaining_hours(self):
        """Test the evaluation of the correct expiration date in hours."""
        cert_exp_date = datetime.strptime("2023-10-11 13:48:31", "%Y-%m-%d %H:%M:%S")
        now = datetime.utcnow()

        expected_remaining = math.floor((cert_exp_date - now).total_seconds() / 3600)

        with open("tests/unit/resources/test.cert") as cert:
            result = cert_expiration_remaining_hours(cert.read())
            self.assertEqual(expected_remaining, result)

    def test_normalized_tls_subject(self):
        """Test the normalized subject of a certificate."""
        subject_1 = "/C=DE/ST=Berlin/L=Berlin/O=Canonical/OU=DataPlatform/CN=localhost"
        subject_2 = "CN=10.10.10.11"

        self.assertEqual(
            normalized_tls_subject(subject_1),
            "C=DE,ST=Berlin,L=Berlin,O=Canonical,OU=DataPlatform,CN=localhost",
        )
        self.assertEqual(normalized_tls_subject(subject_2), "CN=10.10.10.11")

    def test_rfc2253_tls_subject(self):
        """Test conversion of subject to the rfc2253 format."""
        subject_1 = "/C=DE/ST=Berlin/L=Berlin/O=Canonical/OU=DataPlatform/CN=localhost"
        subject_2 = "10.10.10.111"

        self.assertEqual(
            rfc2253_tls_subject(subject_1),
            "CN=localhost,OU=DataPlatform,O=Canonical,L=Berlin,ST=Berlin,C=DE",
        )
        self.assertEqual(rfc2253_tls_subject(subject_2), f"CN={subject_2}")
