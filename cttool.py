#!/usr/bin/env python3

import io
import base64
import time
import json
import sys
import urllib.parse
import fire
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend


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


class Application:

    def _summarize_certificate(self, logserver, timeout, start, end, jsonflg):
        ctclient = CTclient(logserver, timeout)
        result = []
        for (flag, pem, cert) in ctclient.get_certificates(start, end):
            line = dict(cert_type=("precert" if flag else "leafcrt"),
                        serial=cert.serial_number,
                        not_valid_before=str(cert.not_valid_before),
                        not_valid_after=str(cert.not_valid_after),
                        issuer=cert.issuer.rfc4514_string(),
                        subject=cert.subject.rfc4514_string(),
                        pem=pem)
            result.append(line)
            if not jsonflg:
                tmp = line.copy()
                del tmp["pem"]
                print("\t".join([str(column) for column in tmp.values()]))
        if jsonflg:
            print(json.dumps(result, indent=4, sort_keys=True))

    def monitor(self, logserver, timeout=5, interval=10, jsonflg=False,
                start=None, end=None):
        ctclient = CTclient(logserver, timeout)
        if start is not None and end is not None:
            self._summarize_certificate(logserver, timeout, start, end,
                                        jsonflg)
        else:
            try:
                while True:
                    before = ctclient.get_sth()
                    time.sleep(interval)
                    after = ctclient.get_sth()
                    if not (before is not None and "tree_size" in before and
                            after is not None and "tree_size" in after):
                        print("unable to get tree_size", file=sys.stderr)
                        break
                    else:
                        start = before["tree_size"]
                        end = after["tree_size"]
                        if end > start:
                            self._summarize_certificate(logserver, timeout,
                                                        start, end, jsonflg)
            except KeyboardInterrupt:
                pass

    def sth(self, logserver, timeout=5):
        ctclient = CTclient(logserver, timeout)
        ret = ctclient.get_sth()
        if ret is not None:
            print(json.dumps(ret, indent=4, sort_keys=True))

    def logs(self, timeout=5):
        logs_list = "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json"
        ret = get_url(logs_list, timeout)
        if ret is not None and "operators" in ret:
            for operator in ret["operators"]:
                if "logs" in operator:
                    for log in operator["logs"]:
                        print("%s\n\t%s" % (log["description"],
                                            log["url"]))

    def roots(self, logserver, timeout=5):
        pass


class CTclient:

    GET_STH = "ct/v1/get-sth"
    GET_ROOTS = "ct/v1/get-roots"
    GET_ENTRIES = "ct/v1/get-entries"

    def __init__(self, logserver, timeout):
        self.logserver = logserver.rstrip("/") + "/"
        self.timeout = timeout

    def get_sth(self):
        url = urllib.parse.urljoin(self.logserver,
                                   CTclient.GET_STH)
        ret = get_url(url, self.timeout)
        if ret is None:
            print("unable to get tree size", file=sys.stderr)
        return ret

    def get_certificates(self, startsize, endsize):
        url = urllib.parse.urljoin(self.logserver,
                                   CTclient.GET_ENTRIES)
        params = dict(start=startsize, end=endsize)
        ret = get_url(url, self.timeout, params=params)

        result = []
        if ret is not None and ("entries" in ret):
            for entry in ret["entries"]:
                try:
                    precert_flag, pem, cert = \
                        self.parse_entry_to_certificate(entry)
                    if (precert_flag is not None and
                            pem is not None and
                            cert is not None):
                        result.append((precert_flag, pem, cert))
                except Exception:
                    continue
        else:
            print("data from log is None or \"entries\" key is not in data",
                  file=sys.stderr)
        return result

    def parse_first_found_cert_in_tls_encoded_data(self, bytes_data):
        CERT_LENGTH_SIZE = 3
        DER_SEQUENCE_TAG = 48
        try:
            while True:
                size = int.from_bytes(bytes_data[0:CERT_LENGTH_SIZE],
                                      "big")
                bytes_data = bytes_data[CERT_LENGTH_SIZE:CERT_LENGTH_SIZE+size]
                if bytes_data[0] == DER_SEQUENCE_TAG:
                    data = bytes_data
                    break

            data = base64.b64encode(data).decode("utf8")
            dlm = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----"
            pem = (dlm % data)
            cert = x509.load_pem_x509_certificate(pem.encode("utf8"),
                                                  default_backend())
            return data, cert
        except Exception as ex:
            print(str(ex), file=sys.stderr)
            print(pem, file=sys.stderr)
            return None, None

    def parse_entry_to_certificate(self, entry):
        X509_ENTRY = 0
        PRECERT_ENTRY = 1

        precert_flag = data = cert = None

        leaf_input = base64.b64decode(entry["leaf_input"])
        extra_data = base64.b64decode(entry["extra_data"])

        try:
            with io.BytesIO(leaf_input) as handle:
                version = int.from_bytes(handle.read(1), "big")
                mercle_leaf_type = int.from_bytes(handle.read(1), "big")
                timestamp = int.from_bytes(handle.read(8), "big")
                log_entry_type = int.from_bytes(handle.read(2), "big")
                rest_of_data = handle.read()

                if log_entry_type == PRECERT_ENTRY:
                    precert_flag = True
                    data, cert = \
                        self.parse_first_found_cert_in_tls_encoded_data(
                            extra_data)
                elif log_entry_type == X509_ENTRY:
                    precert_flag = False
                    data, cert = \
                        self.parse_first_found_cert_in_tls_encoded_data(
                            rest_of_data)
                else:
                    print("unknown log entry type", file=sys.stderr)

        except Exception as ex:
            print(str(ex), file=sys.stderr)
            print("unable to get certificate", file=sys.stderr)

        return precert_flag, data, cert


if __name__ == "__main__":
    fire.Fire(Application)
