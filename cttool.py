#!/usr/bin/env python3

import io
import base64
import json
import argparse
import requests
import sys
import urllib.parse
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def prepare_commandline_arguments():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("command", choices=CTApp.COMMAND)
    argparser.add_argument("logserver",
                           type=str,
                           help="URL for log server")
    argparser.add_argument("--timeout", type=int, default=5)
    argparser.add_argument("--json", type=bool, default=False)
    argparser.add_argument("--interval",
                           type=int,
                           default=15,
                           help="interval for retrieving data")
    argparser.add_argument("--startsize",
                           type=int,
                           default=None,
                           help="index of first entry to retrieve, in decimal")
    argparser.add_argument("--endsize",
                           type=int,
                           default=None,
                           help="index of last entry to retrieve, in decimal")
    return argparser.parse_args()


def get_url(url, timeout, params=dict()):
    try:
        res = requests.get(url, params=params, timeout=timeout)
        content_type = res.headers["content-type"]
        if (res.status_code != 200 or
                not content_type.startswith("application/json")):
            return None
        return res.json()
    except Exception as ex:
        print(str(ex), file=sys.stderr)
        return None


class CTApp:

    COMMAND = ["monitor", "roots", "sth"]

    def __init__(self, args):
        self.cttool = CTtool(args.logserver, args.timeout)
        self.command = args.command
        self.interval = args.interval
        self.json = args.json
        self.startsize = args.startsize
        self.endsize = args.endsize

    def summarize_certificates(self, startsize, endsize):
        for (flag, pem, cert) in self.cttool.get_certificates(startsize,
                                                              endsize):
            print("%s\t%d\t%s\t%s\t%s\t%s" % (
                ("Precert" if flag else "Leafcrt"),
                cert.serial_number,
                cert.not_valid_before,
                cert.not_valid_after,
                cert.issuer.rfc4514_string(),
                cert.subject.rfc4514_string()))

    def summarize_certificates_in_json(self, startsize, endsize):
        result = []
        for (flag, pem, cert) in self.cttool.get_certificates(startsize,
                                                              endsize):
            result.append(
                dict(cert_type=("pre" if flag else "leaf"),
                     serial=cert.serial_number,
                     not_valid_before=str(cert.not_valid_before),
                     not_valid_after=str(cert.not_valid_after),
                     issuer=cert.issuer.rfc4514_string(),
                     subject=cert.subject.rfc4514_string(),
                     pem=pem))
        print(json.dumps(result))

    def start(self):
        pass


class CTtool:

    GET_STH = "ct/v1/get-sth"
    GET_ROOTS = "ct/v1/get-roots"
    GET_ENTRIES = "ct/v1/get-entries"

    def __init__(self, logserver, timeout):
        self.logserver = logserver.rstrip("/") + "/"
        self.timeout = timeout

    def get_current_tree_size(self):
        url = urllib.parse.urljoin(self.logserver,
                                   CTtool.GET_STH)
        ret = get_url(url, self.timeout)
        if ret is not None:
            return ret.get("tree_size")
        print("unable to get tree size", file=sys.stderr)
        return None

    def get_certificates(self, startsize, endsize):
        url = urllib.parse.urljoin(self.logserver,
                                   CTtool.GET_ENTRIES)
        params = dict(start=startsize, end=endsize)
        ret = get_url(url, self.timeout, params=params)

        result = []
        if ret is not None and ("entries" in ret):
            for entry in ret["entries"]:
                try:
                    precert_flag, pem, cert = \
                        self.parse_entry_to_certificate(entry)
                    if (precert_flag is not None) and \
                            (pem is not None) and \
                            (cert is not None):
                        result.append((precert_flag, pem, cert))
                except Exception:
                    continue
        else:
            print("data from log is None or \"entries\" key is not in data",
                  file=sys.stderr)
        return result

    def check_precertificate(self, leaf_input):
        PRECERT_ENTRY = 1
        try:
            with io.BytesIO(base64.b64decode(leaf_input)) as handle:
                int.from_bytes(handle.read(1), "big")  # version
                int.from_bytes(handle.read(1), "big")  # leaf_type
                int.from_bytes(handle.read(8), "big")  # timestamp
                log_entry_type = int.from_bytes(handle.read(2), "big")
                return log_entry_type == PRECERT_ENTRY
        except Exception:
            print("unable to determine log entry type",
                  file=sys.stderr)
            return None

    def parse_cert(self, extra_data):
        CERT_LENGTH_SIZE = 3
        DER_SEQUENCE_TAG = 48
        try:
            extra_data_bytes = base64.b64decode(extra_data)
            while True:
                size = int.from_bytes(extra_data_bytes[0:CERT_LENGTH_SIZE],
                                      "big")
                extra_data_bytes = extra_data_bytes[CERT_LENGTH_SIZE:
                                                    CERT_LENGTH_SIZE+size]
                if extra_data_bytes[0] == DER_SEQUENCE_TAG:
                    data = extra_data_bytes
                    break

            data = base64.b64encode(data).decode("utf8")
            amble = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----"
            pem = (amble % data)
            cert = x509.load_pem_x509_certificate(pem.encode("utf8"),
                                                  default_backend())

            return pem, cert
        except Exception as ex:
            print(str(ex), file=sys.stderr)
            return None, None

    def parse_entry_to_certificate(self, entry):

        leaf_input = entry["leaf_input"]
        extra_data = entry["extra_data"]

        precert_flag = self.check_precertificate(leaf_input)
        pem, cert = self.parse_cert(extra_data)

        return precert_flag, pem, cert


def main():
    args = prepare_commandline_arguments()
    CTApp(args).start()


if __name__ == "__main__":
    main()
