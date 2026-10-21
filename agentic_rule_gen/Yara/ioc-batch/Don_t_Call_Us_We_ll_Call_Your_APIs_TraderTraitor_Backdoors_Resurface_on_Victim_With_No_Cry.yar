// Don’t Call Us, We’ll Call Your APIs | TraderTraitor Backdoors Resurface on Victim With No Crypto Ties
// Source: sentinelone-labs | https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/

import "hash"

rule IOC_Don_t_Call_Us_We_ll_Call_Your_APIs_TraderTraitor_Backdoors_Resurface_on_Victim_With_No_Cry_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Don’t Call Us, We’ll Call Your APIs | TraderTraitor Backdoors Resurface on Victim With No Crypto Ties. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "sentinelone-labs"
        reference   = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "4b2d3e8ccce8920a6d01e7d02b84236545a20e5f754b3eec253f8b416b731daa" or
        hash.md5(0, filesize) == "1cd6d13ff15adbf7a42025d10ec99b4a" or
        hash.sha1(0, filesize) == "5728b11d30586bbfc1d8bd12df1c722a06e767a2" or
        hash.sha1(0, filesize) == "02df07a173ab03b82a4fb6a08973fff8b1467f28" or
        hash.sha1(0, filesize) == "c491d477dbe0ae04e9aed9dbe237144c03f73ec4" or
        hash.sha1(0, filesize) == "4ad92bf92ee614b05c340ce17bef7b6ef5a25e82" or
        hash.sha1(0, filesize) == "930e5be6d34511bedbfb0d762bd08fffe64e9630" or
        hash.sha1(0, filesize) == "19af09ebe8b7ad03419677dda515507dd099bc39"
}

