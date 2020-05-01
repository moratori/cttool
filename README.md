# cttool

A command line tool for certificate transparency log.

# Installation

please check whether pipenv and python3.7 installed in advance.
[Pipenv - installation](https://github.com/pypa/pipenv#installation)

```
$ git clone https://github.com/moratori/cttool.git
$ cd cttool
$ pipenv install
```

# Usage

## Monitor a log server

```
$ pipenv shell
$ ./cttool.py monitor https://ct.googleapis.com/testtube
precert 21837295931541575158308100102794332606782844    2020-04-06 15:26:12     2020-07-05 15:26:12     CN=Fake LE Intermediate X1      CN=oncafepro.com
precert 21814683825173294305128559027474023930943028    2020-04-06 15:26:15     2020-07-05 15:26:15     CN=Fake LE Intermediate X1      CN=filecoin-monitor.byteark.cn
precert 21817878784482479703066680225981123633190528    2020-04-06 15:26:14     2020-07-05 15:26:14     CN=Fake LE Intermediate X1      CN=mcbenefits.info

$ ./cttool.py monitor https://ct.googleapis.com/testtube --start 119361290 --end 119361292 --json
[
    {
        "cert_type": "precert",
        "issuer": "CN=Fake LE Intermediate X1",
        "not_valid_after": "2020-07-05 15:29:06",
        "not_valid_before": "2020-04-06 15:29:06",
        "pem": "MIIFEzCCA/ugA...(snip)...",
        "serial": 21863364922683214852029586752934403698349576,
        "subject": "CN=newguiabr.com.br"
    },
    {
        "cert_type": "precert",
        "issuer": "CN=Fake LE Intermediate X1",
        "not_valid_after": "2020-07-05 15:29:03",
        "not_valid_before": "2020-04-06 15:29:03",
        "pem": "MIIEaDCCA1CgA...(snip)...",
        "subject": "CN=test-2.staging.us-e.cloudfoxy.com"
    }
]

```

## Retrieve Latest Signed Tree Head

```
$ pipenv shell
$ ./cttool.py sth https://ct.googleapis.com/testtube
{
    "sha256_root_hash": "9T5jyWtXYaMAzKCozV60CM6iTGeDriH6wMdprTeT+PI=",
    "timestamp": 1586190472335,
    "tree_head_signature": "BAMASDBGAiEAvQG8n0xs4l2eD3XGWzzUCJNHK7DXm/MHxNKaXgiRbk8CIQDMO9C3b3MPzs/BL8AaNQJVUfv8D2gUBI7wCBQGz66euw==",
    "tree_size": 119361142
}
```

## Retrieve Accepted Root Certificates

```
$ pipenv shell
$ ./cttool.py roots https://ct.googleapis.com/testtube/
CN=TEST UAE Global Root CA G4 E2,O=TEST UAE Government,C=AE
CN=Dubai Root CA TEST,OU=DESC,O=Dubai Government,L=Dubai,ST=Dubai,C=AE
CN=A-Trust-Test-nQual-04,OU=A-Trust-Test-nQual-04,O=A-Trust Ges. für Sicherheitssysteme im elektr. Datenverkehr GmbH,C=AT
CN=Test BRZ CA Root 2017,OU=BRZ CA,O=Bundesrechenzentrum GmbH,C=AT
...
(snip)
```

## Show Common Log Server
```
$ pipenv shell
$ ./cttool.py logs --chrome
Google 'Argon2020' log
https://ct.googleapis.com/logs/argon2020/
Google 'Argon2021' log
https://ct.googleapis.com/logs/argon2021/
Google 'Argon2022' log
https://ct.googleapis.com/logs/argon2022/
Google 'Argon2023' log
https://ct.googleapis.com/logs/argon2023/
Google 'Xenon2020' log
https://ct.googleapis.com/logs/xenon2020/
Google 'Xenon2021' log
https://ct.googleapis.com/logs/xenon2021/
Google 'Xenon2022' log
https://ct.googleapis.com/logs/xenon2022/
Google 'Xenon2023' log
https://ct.googleapis.com/logs/xenon2023/
Google 'Aviator' log
https://ct.googleapis.com/aviator/
Google 'Icarus' log
https://ct.googleapis.com/icarus/
Google 'Pilot' log
https://ct.googleapis.com/pilot/
Google 'Rocketeer' log
https://ct.googleapis.com/rocketeer/
Google 'Skydiver' log
https://ct.googleapis.com/skydiver/
Cloudflare 'Nimbus2020' Log
https://ct.cloudflare.com/logs/nimbus2020/
...
```

## Add chain to Logserver
```
$ pipenv shell
$ ./cttool.py add https://ct.cloudflare.com/logs/nimbus2020 full_chain_file
{
    "extensions": "",
    "id": "Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=",
    "sct_version": 0,
    "signature": "BAMASDBGAiEAvOmguJr/4cSmYdN3AbTRcdP5uOitAdS0AApF7uB1DrECIQCxSGGhr/3qJlb7lS5hPdHVjgc208nVU5JpnrlVCRIrSg==",
    "timestamp": 1586616243666
}
```

## How to run test
```
$ pipenv shell
$ python -m unittest discover ./test/
```

