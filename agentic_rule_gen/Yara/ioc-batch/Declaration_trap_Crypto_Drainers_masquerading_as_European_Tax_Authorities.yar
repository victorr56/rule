// Declaration trap: Crypto Drainers masquerading as European Tax Authorities
// Source: group-ib | https://www.group-ib.com/blog/declaration-trap/

import "hash"

rule IOC_Declaration_trap_Crypto_Drainers_masquerading_as_European_Tax_Authorities_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Declaration trap: Crypto Drainers masquerading as European Tax Authorities. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/declaration-trap/"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "5e73f708c447d1843ced8f884dc7f58a496f23a237955266bbf87b8977a04cce" or
        hash.sha256(0, filesize) == "f8226ca8f41f616dc7773ba37d7b73197eb7674954597dbeda5ee8ed91f4e275"
}

