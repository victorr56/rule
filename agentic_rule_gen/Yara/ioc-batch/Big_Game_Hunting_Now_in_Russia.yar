// Big Game Hunting: Now in Russia
// Source: group-ib | https://www.group-ib.com/blog/oldgremlin/

import "hash"

rule IOC_Big_Game_Hunting_Now_in_Russia_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Big Game Hunting: Now in Russia. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/oldgremlin/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "e47a296bac49284371ac396a053a8488" or
        hash.md5(0, filesize) == "2c6a9a38ace198ab62e50ab69920bf42" or
        hash.md5(0, filesize) == "306978669ead832f1355468574df1680" or
        hash.md5(0, filesize) == "94293275fcc53ad5aca5392f3a5ff87b" or
        hash.md5(0, filesize) == "1e54c8bc19dab21e4bd9cfb01a4f5aa5" or
        hash.md5(0, filesize) == "fc30e902d1098b7efd85bd2651b2293f" or
        hash.md5(0, filesize) == "e0fe009b0b1ae72ba7a5d2127285d086" or
        hash.md5(0, filesize) == "f30e4d741018ef81da580ed971048707" or
        hash.md5(0, filesize) == "ac27db95366f4e7a7cf77f2988e119c2"
}

