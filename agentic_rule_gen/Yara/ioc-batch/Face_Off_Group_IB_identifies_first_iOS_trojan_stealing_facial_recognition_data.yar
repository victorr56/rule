// Face Off: Group-IB identifies first iOS trojan stealing facial recognition data
// Source: group-ib | https://www.group-ib.com/blog/goldfactory-ios-trojan/

import "hash"

rule IOC_Face_Off_Group_IB_identifies_first_iOS_trojan_stealing_facial_recognition_data_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Face Off: Group-IB identifies first iOS trojan stealing facial recognition data. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/goldfactory-ios-trojan/"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "8ce5b07506c8f90ceea307b56437ab158dd69785c6eeb239ffc83bb3f87ea4e7" or
        hash.sha256(0, filesize) == "4571f8c8560a8a66a90763d7236f55273750cf8dd8f4fdf443b5a07d7a93a3df" or
        hash.sha256(0, filesize) == "b72d9a6bd2c350f47c06dfa443ff7baa59eed090ead34bd553c0298ad6631875" or
        hash.sha256(0, filesize) == "d8834a21bc70fbe202cb7c865d97301540d4c27741380e877551e35be1b7276b"
}

