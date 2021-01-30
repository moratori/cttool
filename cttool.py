#!/usr/bin/env python3

import io
import base64
import time
import sys
import urllib.parse
import re
import fire
import requests
import binascii
import json as jsn
from logging import StreamHandler, basicConfig, getLogger
from logging import WARNING
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


basicConfig(format="%(asctime)s [%(levelname)s] %(name)s %(funcName)s %(message)s",
            level=WARNING,
            handlers=[StreamHandler(stream=sys.stderr)])

LOGGER = getLogger(__name__)


def get_json_from_url(url, timeout, params=dict()):
    try:
        res = requests.get(url, params=params, timeout=timeout)
        content_type = res.headers["content-type"]
        if (res.status_code != 200 or
                (not content_type.startswith("application/json") and
                 not content_type.startswith("text/plain"))):
            LOGGER.error("status code: %s" % str(res.status_code))
            LOGGER.error("content type: %s" % str(content_type))
            return None
        return res.json()
    except Exception as ex:
        LOGGER.error("exception occurred: %s" % str(ex))
        LOGGER.error("unable to get json data from %s" % url)
        return None


def post_json_to_url(url, timeout, data=dict()):
    try:
        res = requests.post(url, data=data, timeout=timeout,
                            headers={'content-type': 'application/json'})
        content_type = res.headers["content-type"]
        if (res.status_code != 200 or
                (not content_type.startswith("application/json") and
                 not content_type.startswith("text/plain"))):
            LOGGER.error("status code: %s" % str(res.status_code))
            LOGGER.error("content type: %s" % str(content_type))
            return None
        return res.json()
    except Exception as ex:
        LOGGER.error("exception occurred: %s" % str(ex))
        LOGGER.error("unable to get json data from %s" % url)
        return None


class Application:

    def _summarize_certificate(self, logserver, timeout, start, end, json):
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
            if not json:
                tmp = line.copy()
                del tmp["pem"]
                print("\t".join([str(column) for column in tmp.values()]),
                      flush=True)
        if json:
            print(jsn.dumps(result, indent=4, sort_keys=True))

    def monitor(self, logserver, timeout=3, interval=5, json=False,
                start=None, end=None):
        """
        CTログサーバーから定期的に証明書の情報を取得する
        """
        ctclient = CTclient(logserver, timeout)
        if start is not None and end is not None:
            self._summarize_certificate(logserver, timeout, start, end,
                                        json)
        else:
            try:
                while True:
                    before = ctclient.get_sth()
                    time.sleep(interval)
                    after = ctclient.get_sth()
                    if not (before is not None and "tree_size" in before and
                            after is not None and "tree_size" in after):
                        LOGGER.error("unable to get tree_size from STH")
                        LOGGER.debug("before: %s" % str(before))
                        LOGGER.debug("after: %s" % str(after))
                        break

                    start = before["tree_size"]
                    end = after["tree_size"]
                    if end > start:
                        self._summarize_certificate(logserver, timeout,
                                                    start, end, json)
            except KeyboardInterrupt:
                pass

    def sth(self, logserver, timeout=5):
        """
        CTログサーバーの現在のSTHを取得する
        """
        ctclient = CTclient(logserver, timeout)
        ret = ctclient.get_sth()
        if ret is not None:
            print(jsn.dumps(ret, indent=4, sort_keys=True))

    def logs(self, timeout=5, chrome=False, json=False):
        """
        CTログサーバーの一覧を取得する
        """
        all_logs_list = \
            "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json"
        chrome_logs_list = \
            "https://www.gstatic.com/ct/log_list/v2/log_list.json"

        logs = chrome_logs_list if chrome else all_logs_list

        ret = get_json_from_url(logs, timeout)

        if ret is not None and json:
            print(jsn.dumps(ret, indent=4, sort_keys=True))
            return

        if ret is not None and "operators" in ret:
            for operator in ret["operators"]:
                if "logs" in operator:
                    for log in operator["logs"]:
                        print("%s\n\t%s" % (log["description"],
                                            log["url"]))

    def roots(self, logserver, timeout=5):
        """
        CTログサーバーが書き込みを許可しているルート認証局の一覧を取得する
        """
        ctclient = CTclient(logserver, timeout)
        for root in ctclient.get_roots():
            try:
                sha1_fg = \
                    binascii.b2a_hex(
                        root.fingerprint(hashes.SHA1())).decode("utf8").upper()
                print("SHA1 Fingerprint=%s:%s" %
                      (sha1_fg, root.issuer.rfc4514_string()))
            except Exception as ex:
                LOGGER.error("exception occurred: %s" % str(ex))
                LOGGER.error("unable to convert issuer name to string")
                continue

    def add(self, logserver, full_chainfile, timeout=5):
        """
        証明書をCTログサーバーに書き込む
        """
        ctclient = CTclient(logserver, timeout)
        ret = ctclient.add_chain(full_chainfile)
        if ret is not None:
            print(jsn.dumps(ret, indent=4, sort_keys=True))


def get_cert_object_from_der(der):
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as ex:
        LOGGER.debug("unable to parse data using cryptography: %s" % der)
        raise ex
    return cert


class CTclient:

    GET_STH = "ct/v1/get-sth"
    GET_ROOTS = "ct/v1/get-roots"
    GET_ENTRIES = "ct/v1/get-entries"
    ADD_CHAIN = "ct/v1/add-chain"

    def __init__(self, logserver, timeout):
        self.logserver = logserver.rstrip("/") + "/"
        self.timeout = timeout

    def _construct_chain_json(self, chainfile):
        preamble = "-----BEGIN CERTIFICATE-----"
        postamble = "-----END CERTIFICATE-----"
        pattern = \
            "[\r\n]*%s[\r\n]+[a-zA-Z0-9\+/=\r\n ]+[\r\n]+%s[\r\n]*" % (
                preamble,
                postamble)
        try:
            chain_json = []
            with open(chainfile, "r", encoding="ascii") as handle:
                chain = re.findall(pattern, handle.read())
                for pem in chain:
                    chain_json.append(pem.strip().
                                      replace(preamble, "").
                                      replace(postamble, ""))

            return jsn.dumps(dict(chain=chain_json))
        except Exception as ex:
            LOGGER.error("error occurred while constructing chain: %s"
                         % str(ex))
            return None

    def add_chain(self, chainfile):
        chain_json = self._construct_chain_json(chainfile)
        if chain_json is not None:
            url = urllib.parse.urljoin(self.logserver,
                                       CTclient.ADD_CHAIN)
            ret = post_json_to_url(url, self.timeout, data=chain_json)
            return ret

    def get_sth(self):
        url = urllib.parse.urljoin(self.logserver,
                                   CTclient.GET_STH)
        ret = get_json_from_url(url, self.timeout)

        return ret

    def get_roots(self):
        url = urllib.parse.urljoin(self.logserver,
                                   CTclient.GET_ROOTS)
        ret = get_json_from_url(url, self.timeout)
        result = []
        if ret is None or "certificates" not in ret:
            LOGGER.error("unable to get root certificates")
            return result
        else:
            for root in ret["certificates"]:
                try:
                    cert = get_cert_object_from_der(base64.b64decode(root))
                    result.append(cert)
                except Exception as ex:
                    LOGGER.error("exception occurred : %s" % str(ex))
                    LOGGER.error("unable to parse root certificate")
                    continue
            return result

    def get_certificates(self, startsize, endsize):
        url = urllib.parse.urljoin(self.logserver,
                                   CTclient.GET_ENTRIES)
        params = dict(start=startsize, end=endsize)
        ret = get_json_from_url(url, self.timeout, params=params)

        result = []
        if ret is not None and ("entries" in ret):
            for entry in ret["entries"]:
                precert_flag, pem, cert = \
                    self.parse_entry_to_certificate(entry)
                if not (precert_flag is None or pem is None or cert is None):
                    result.append((precert_flag, pem, cert))
        else:
            LOGGER.error("unable to get entries in properly")
            LOGGER.debug("return from log server: %s" % str(ret))
        return result

    def _parse_first_found_cert_in_tls_encoded_data(self, bytes_data):
        CERT_LENGTH_SIZE = 3
        DER_SEQUENCE_TAG = 48

        while True:
            size = int.from_bytes(bytes_data[0:CERT_LENGTH_SIZE],
                                  "big")
            bytes_data = bytes_data[CERT_LENGTH_SIZE:CERT_LENGTH_SIZE+size]
            if bytes_data[0] == DER_SEQUENCE_TAG:
                data = bytes_data
                break

        cert = get_cert_object_from_der(data)

        return data, cert

    def parse_entry_to_certificate(self, entry):
        X509_ENTRY = 0
        PRECERT_ENTRY = 1

        precert_flag = pem = cert = None

        try:

            leaf_input = base64.b64decode(entry["leaf_input"])
            extra_data = base64.b64decode(entry["extra_data"])

            with io.BytesIO(leaf_input) as handle:
                version = int.from_bytes(handle.read(1), "big")
                mercle_leaf_type = int.from_bytes(handle.read(1), "big")
                timestamp = int.from_bytes(handle.read(8), "big")
                log_entry_type = int.from_bytes(handle.read(2), "big")
                rest_of_data = handle.read()

                if log_entry_type == PRECERT_ENTRY:
                    precert_flag = True
                    target_data = extra_data
                elif log_entry_type == X509_ENTRY:
                    precert_flag = False
                    target_data = rest_of_data
                else:
                    precert_flag = False
                    target_data = b''
                    LOGGER.error("unknown log_entry_type: %s" %
                                 str(log_entry_type))

                rawdata, cert = \
                    self._parse_first_found_cert_in_tls_encoded_data(
                        target_data)

                pem = base64.b64encode(rawdata).decode("ascii")

        except Exception as ex:
            LOGGER.error("except occurred while parsing cert: %s" % str(ex))
            LOGGER.error("unable to get certificate from entry")
            LOGGER.debug("%s" % str(entry))

        return precert_flag, pem, cert


if __name__ == "__main__":
    fire.Fire(Application)
