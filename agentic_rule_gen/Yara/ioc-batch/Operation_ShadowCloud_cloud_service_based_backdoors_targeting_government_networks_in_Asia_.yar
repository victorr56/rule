// Operation ShadowCloud: cloud service–based backdoors targeting government networks in Asia and Africa. Part 2
// Source: securelist | https://securelist.com/operation-shadowcloud-graphdoor/122005/

import "hash"

rule IOC_Operation_ShadowCloud_cloud_service_based_backdoors_targeting_government_networks_in_Asia__Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Operation ShadowCloud: cloud service–based backdoors targeting government networks in Asia and Africa. Part 2. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/operation-shadowcloud-graphdoor/122005/"
        date        = "2026-11-20"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "d89b2fe0759df2d534e7a728700a6f8c" or
        hash.md5(0, filesize) == "b4956b230d296cb4b015b42b11d80e32" or
        hash.md5(0, filesize) == "86a46af43e18288e1df439b2a9a6f7ca" or
        hash.md5(0, filesize) == "733f8002aa9531b25384c0014d15cc1f" or
        hash.md5(0, filesize) == "91bee19d31d32346cd4d1febb4308606" or
        hash.md5(0, filesize) == "45b3aa39bc33528650d9181cd946b2df" or
        hash.md5(0, filesize) == "9a5e0ab7466594dcf46943c413db7b81"
}

