// MIMICRAT: ClickFix Campaign Delivers Custom RAT via Compromised Legitimate Websites
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/mimicrat-custom-rat-mimics-c2-frameworks

import "hash"

rule IOC_MIMICRAT_ClickFix_Campaign_Delivers_Custom_RAT_via_Compromised_Legitimate_Websites_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: MIMICRAT: ClickFix Campaign Delivers Custom RAT via Compromised Legitimate Websites. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/mimicrat-custom-rat-mimics-c2-frameworks"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "a508d0bb583dc6e5f97b6094f8f910b5b6f2b9d5528c04e4dee62c343fce6f4b" or
        hash.sha256(0, filesize) == "bcc7a0e53ebc62c77b7b6e3585166bfd7164f65a8115e7c8bda568279ab4f6f1" or
        hash.sha256(0, filesize) == "5e0a30d8d91d5fd46da73f3e6555936233d870ac789ca7dd64c9d3cc74719f51" or
        hash.sha256(0, filesize) == "055336daf2ac9d5bbc329fd52bb539085d00e2302fa75a0c7e9d52f540b28beb"
}

