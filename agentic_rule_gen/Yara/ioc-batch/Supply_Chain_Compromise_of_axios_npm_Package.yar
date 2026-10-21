// Supply Chain Compromise of axios npm Package
// Source: huntress | https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package

import "hash"

rule IOC_Supply_Chain_Compromise_of_axios_npm_Package_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Supply Chain Compromise of axios npm Package. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd" or
        hash.sha256(0, filesize) == "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101" or
        hash.sha256(0, filesize) == "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf" or
        hash.md5(0, filesize) == "df0e06df00e993e7917436d0f73df626" or
        hash.md5(0, filesize) == "96575799bd87ae64cddbc55634a6d32d" or
        hash.sha1(0, filesize) == "2553649f2322049666871cea80a5d0d6adc700ca" or
        hash.sha1(0, filesize) == "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71" or
        hash.sha1(0, filesize) == "07d889e2dadce6f3910dcbc253317d28ca61c766"
}

