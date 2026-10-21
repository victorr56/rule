// Extra credit: VietCredCare information stealer takes aim at Vietnamese businesses
// Source: group-ib | https://www.group-ib.com/blog/vietcredcare-stealer/

import "hash"

rule IOC_Extra_credit_VietCredCare_information_stealer_takes_aim_at_Vietnamese_businesses_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Extra credit: VietCredCare information stealer takes aim at Vietnamese businesses. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/vietcredcare-stealer/"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "bd9eb106e265c5d0ae7a9e9d2d5925d558128599b1ba4a4cbc29b6fc7b3f48f0" or
        hash.sha256(0, filesize) == "71c4d0fc03bc4e083f64b2f80b2242618fb725efd64f362446f98c6d2051834f" or
        hash.sha256(0, filesize) == "b5621b540d1ca1dd802397822145ae4f80e96e59b81fdc8d0a7b18919ceadd12" or
        hash.sha256(0, filesize) == "17598536cf0bac6cb0d589410682e2cd9f813ea52bc931fe85292b149dbeb659"
}

