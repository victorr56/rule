// Curse of the Krasue: New Linux Remote Access Trojan targets Thailand
// Source: group-ib | https://www.group-ib.com/blog/krasue-rat/

import "hash"

rule IOC_Curse_of_the_Krasue_New_Linux_Remote_Access_Trojan_targets_Thailand_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Curse of the Krasue: New Linux Remote Access Trojan targets Thailand. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/krasue-rat/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "c8f761d3ef7cd16ebe41042a0daf901c2fdffce96c8e9e1fa0d422c6e31332ea" or
        hash.sha256(0, filesize) == "8a58dce7b57411441ac1fbff3062f5eb43a432304b2ba34ead60e9dd4dc94831"
}

