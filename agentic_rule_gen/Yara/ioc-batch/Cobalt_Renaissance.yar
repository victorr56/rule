// Cobalt Renaissance
// Source: group-ib | https://www.group-ib.com/blog/renaissance/

import "hash"

rule IOC_Cobalt_Renaissance_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Cobalt Renaissance. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/renaissance/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "fa354151a3fc6d0dce69e8eeaa8cd197" or
        hash.md5(0, filesize) == "7b55c7ae346efb428aaf63d25ca0fcc7"
}

