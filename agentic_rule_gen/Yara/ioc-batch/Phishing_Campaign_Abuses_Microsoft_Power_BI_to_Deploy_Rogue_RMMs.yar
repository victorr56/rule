// Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue RMMs
// Source: huntress | https://www.huntress.com/blog/screenconnect-power-bi

import "hash"

rule IOC_Phishing_Campaign_Abuses_Microsoft_Power_BI_to_Deploy_Rogue_RMMs_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue RMMs. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/screenconnect-power-bi"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "5956f9afb3ba610c38b2cfda88dd15be98783963769a12020c93ce05e749b3c3"
}

