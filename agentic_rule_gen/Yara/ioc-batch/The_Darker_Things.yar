// The Darker Things
// Source: group-ib | https://www.group-ib.com/blog/blackmatter2/

import "hash"

rule IOC_The_Darker_Things_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Darker Things. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/blackmatter2/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "072158f5588440e6c94cb419ae06a27cf584afe3b0cb09c28eff0b4662c15486" or
        hash.sha256(0, filesize) == "22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6" or
        hash.sha256(0, filesize) == "2c323453e959257c7aa86dc180bb3aaaa5c5ec06fa4e72b632d9e4b817052009" or
        hash.sha256(0, filesize) == "3a03530c732ebe53cdd7c17bee0988896d36c2b632dbd6118613697c2af82117"
}

