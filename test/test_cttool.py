#!/usr/bin/env python3

import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../'))

import cttool
import json

current_dir = os.path.dirname(__file__)
data_dir = os.path.join(current_dir, "data")


class TestCTtool(unittest.TestCase):

    def setUp(self):
        self.cttool = cttool.CTtool("https://ct.googleapis.com/testtube", 3)

    def tearDown(self):
        pass

    def test_0_check_precertificate(self):
        with open(os.path.join(data_dir, "test_0_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            leaf_input = obj["leaf_input"]
            self.assertTrue(self.cttool.check_precertificate(leaf_input))

    def test_1_check_precertificate(self):
        with open(os.path.join(data_dir, "test_1_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            leaf_input = obj["leaf_input"]
            self.assertFalse(self.cttool.check_precertificate(leaf_input))

    def test_2_parse_cert(self):
        with open(os.path.join(data_dir, "test_0_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            extra_data = obj["extra_data"]
            self.assertTrue(self.cttool.parse_cert(extra_data))

    def test_3_parse_cert(self):
        with open(os.path.join(data_dir, "test_1_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            extra_data = obj["extra_data"]
            self.assertTrue(self.cttool.parse_cert(extra_data))

    def test_4_parse_entry_to_certificate(self):
        with open(os.path.join(data_dir, "test_0_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            precert_flag, pem, cert = self.cttool.parse_entry_to_certificate(obj)
            self.assertIsNotNone(precert_flag)
            self.assertIsNotNone(cert)

    def test_5_parse_entry_to_certificate(self):
        with open(os.path.join(data_dir, "test_1_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            precert_flag, pem, cert = self.cttool.parse_entry_to_certificate(obj)
            self.assertIsNotNone(precert_flag)
            self.assertIsNotNone(cert)

    def test_6_get_certificates(self):
        certificates = self.cttool.get_certificates(119191700, 119191708)
        for (flag, pem, cert) in certificates:
            self.assertIsInstance(flag, bool)
            self.assertTrue(cert)
