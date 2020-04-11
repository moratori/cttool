#!/usr/bin/env python3

import unittest
import sys
import os
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend

sys.path.append(os.path.join(os.path.dirname(__file__), '../'))

import cttool
import json

current_dir = os.path.dirname(__file__)
data_dir = os.path.join(current_dir, "data")


class TestCTclient(unittest.TestCase):

    def setUp(self):
        self.ctclient = cttool.CTclient("https://ct.googleapis.com/testtube", 3)

    def tearDown(self):
        pass

    def test_0_parse_entry_to_certificate(self):
        with open(os.path.join(data_dir, "test_0_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            self.assertTrue(self.ctclient.parse_entry_to_certificate(obj))

    def test_1_parse_entry_to_certificate(self):
        with open(os.path.join(data_dir, "test_1_data"),
                  "r",
                  encoding="ascii") as handle:
            obj = json.load(handle)
            self.assertTrue(self.ctclient.parse_entry_to_certificate(obj))

    def test_2_get_certificates(self):
        certificates = self.ctclient.get_certificates(119191700, 119191708)
        for (flag, pem, cert) in certificates:
            self.assertIsInstance(flag, bool)
            self.assertTrue(pem)
            self.assertTrue(cert)

    def test_3_get_roots(self):
        roots = self.ctclient.get_roots()
        self.assertIsInstance(roots, list)

    def test_4_get_roots(self):
        roots = self.ctclient.get_sth()
        self.assertIsInstance(roots, dict)

    def test_5__construct_chain_json(self):
        path = os.path.join(data_dir, "test_5_data")
        data = self.ctclient._construct_chain_json(path)
        self.assertIsInstance(data, dict)
        for pem in data["chain"]:
            cert = x509.load_der_x509_certificate(base64.b64decode(pem),
                                                  default_backend())
            self.assertIsNotNone(cert)

    def test_6__construct_chain_json(self):
        path = os.path.join(data_dir, "file_not_found")
        self.assertIsNone(self.ctclient._construct_chain_json(path))
