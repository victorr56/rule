// Citrus Ransomware: VLESS for traffic, Sn00py for encryption, and LLMs lending a hand
// Source: securelist | https://securelist.com/citrus-ransomware/121879/

import "hash"

rule IOC_Citrus_Ransomware_VLESS_for_traffic_Sn00py_for_encryption_and_LLMs_lending_a_hand_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Citrus Ransomware: VLESS for traffic, Sn00py for encryption, and LLMs lending a hand. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/citrus-ransomware/121879/"
        date        = "2026-11-11"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "d631627131b90d576d77f4bf530e1abe" or
        hash.md5(0, filesize) == "7107fb029e7c63523e3aca5fc8e56b38" or
        hash.md5(0, filesize) == "e251df2d0b7c3682965efb4d2009a2f4" or
        hash.md5(0, filesize) == "17b29b6c9de80402a45e321bbe1168fa" or
        hash.md5(0, filesize) == "9eee984b187423c46c10a63d080da15d" or
        hash.md5(0, filesize) == "cf903e4a1629aa0582fd0363b5786676"
}

