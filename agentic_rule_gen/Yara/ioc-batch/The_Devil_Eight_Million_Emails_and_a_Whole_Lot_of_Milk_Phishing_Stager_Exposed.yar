// The Devil, Eight Million Emails, and a Whole Lot of Milk | Phishing Stager Exposed
// Source: huntress | https://www.huntress.com/blog/terminal-server-phishing-stager-exposed

import "hash"

rule IOC_The_Devil_Eight_Million_Emails_and_a_Whole_Lot_of_Milk_Phishing_Stager_Exposed_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Devil, Eight Million Emails, and a Whole Lot of Milk | Phishing Stager Exposed. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/terminal-server-phishing-stager-exposed"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "dc8a31a104df44b76a05c3e6d4fbe85be243cc6db0ff25e298e25cc469715046" or
        hash.sha256(0, filesize) == "95fc58dc321b07ecc99d95359bcdee08a5beb519ead8e70e40f33928533a1b14" or
        hash.sha256(0, filesize) == "5d2ad1795b0dfc4a58424b2fa2f002246f653b119d362954ae270b6998e9d575" or
        hash.sha256(0, filesize) == "c5ec55270af084d3c07d2918098d598bc2c5ca42f4189d69cdfcae2c958e5ec7" or
        hash.sha256(0, filesize) == "6c428acbd91be85fedf9cbb334457ddea08ff624d4de88041749578e968d62a8"
}

