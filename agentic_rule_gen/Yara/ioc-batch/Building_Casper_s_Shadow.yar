// Building Casper’s Shadow
// Source: nao-sec | http://nao-sec.org/2024/06/building-caspers-shadow.html

import "hash"

rule IOC_Building_Casper_s_Shadow_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Building Casper’s Shadow. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "nao-sec"
        reference   = "http://nao-sec.org/2024/06/building-caspers-shadow.html"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "b6d7c456423c871c7ffe418069a75c39055e4e3d023021c8b0885a02c7ce93c6" or
        hash.md5(0, filesize) == "eb99580e0d90ee61b3e2e3bd8715c633" or
        hash.sha1(0, filesize) == "706482eda6d747ca2688cdfd97399f800da9e73c"
}

