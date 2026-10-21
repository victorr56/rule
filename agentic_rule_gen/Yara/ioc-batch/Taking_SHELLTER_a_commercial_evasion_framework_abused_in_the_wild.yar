// Taking SHELLTER: a commercial evasion framework abused in-the-wild
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/taking-shellter

import "hash"

rule IOC_Taking_SHELLTER_a_commercial_evasion_framework_abused_in_the_wild_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Taking SHELLTER: a commercial evasion framework abused in-the-wild. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/taking-shellter"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30" or
        hash.sha256(0, filesize) == "7d0c9855167e7c19a67f800892e974c4387e1004b40efb25a2a1d25a99b03a10" or
        hash.sha256(0, filesize) == "748149df038a771986691e3f54afea609ceb9fbfcbec92145beb586bec039e6a" or
        hash.sha256(0, filesize) == "263ab8c9ec821ae573979ef2d5ad98cda5009a39e17398cd31b0fad98d862892"
}

