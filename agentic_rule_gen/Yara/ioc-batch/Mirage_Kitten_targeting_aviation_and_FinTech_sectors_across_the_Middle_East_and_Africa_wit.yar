// Mirage Kitten targeting aviation and FinTech sectors across the Middle East and Africa with a new malware set
// Source: securelist | https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/

import "hash"

rule IOC_Mirage_Kitten_targeting_aviation_and_FinTech_sectors_across_the_Middle_East_and_Africa_wit_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Mirage Kitten targeting aviation and FinTech sectors across the Middle East and Africa with a new malware set. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "1ea83e4e4592b01e4acab63eb867bee5" or
        hash.md5(0, filesize) == "810f8e3b88eb05f710c09552941d6f56" or
        hash.md5(0, filesize) == "cbaaf0900a13f28e380f49adecec932c" or
        hash.md5(0, filesize) == "366515822d5ac1cc500711ef57a2e32e" or
        hash.md5(0, filesize) == "cf449f1992c2819e62ac44a0b06ac2e7" or
        hash.md5(0, filesize) == "e95a4366686e3f786ea3c056fab5b0da" or
        hash.md5(0, filesize) == "de5af16a3757ef700b01dc34d67079ae"
}

