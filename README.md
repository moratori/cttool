# cttool

A command line tool for certificate transparency log.

# Usage

## Monitor a log server

```
$ ./cttool.py monitor https://ct.googleapis.com/testtube
precert 21837295931541575158308100102794332606782844    2020-04-06 15:26:12     2020-07-05 15:26:12     CN=Fake LE Intermediate X1      CN=oncafepro.com
precert 21814683825173294305128559027474023930943028    2020-04-06 15:26:15     2020-07-05 15:26:15     CN=Fake LE Intermediate X1      CN=filecoin-monitor.byteark.cn
precert 21817878784482479703066680225981123633190528    2020-04-06 15:26:14     2020-07-05 15:26:14     CN=Fake LE Intermediate X1      CN=mcbenefits.info

$ ./cttool.py monitor https://ct.googleapis.com/testtube --start 119361290 --end 119361292 --jsonflg
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
$ ./cttool.py roots https://ct.googleapis.com/testtube

(TBD)
```

# Installtion

TBD
