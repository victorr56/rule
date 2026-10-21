// RemotePE: The Lazarus RAT that lives in memory
// Source: fox-it | https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/

import "hash"

rule IOC_RemotePE_The_Lazarus_RAT_that_lives_in_memory_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: RemotePE: The Lazarus RAT that lives in memory. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "fox-it"
        reference   = "https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "710f15302859c7af1c1e25219d704841b3fdbc48f16a5a574d5ab6cf4f4842e8"
}

