// VAPOR PANDA Uses AI-Driven ARTEX to Scale a Global Espionage Campaign
// Source: crowdstrike | https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/

import "hash"

rule IOC_VAPOR_PANDA_Uses_AI_Driven_ARTEX_to_Scale_a_Global_Espionage_Campaign_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: VAPOR PANDA Uses AI-Driven ARTEX to Scale a Global Espionage Campaign. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "crowdstrike"
        reference   = "https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/"
        date        = "2026-10-30"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "49fe70419fd19b81ca8d730a6ef7c1ec71b681d60b390761070d42686c7d2068" or
        hash.sha256(0, filesize) == "3fb5a9fb3e2cb1d6208966bd4e55d10282d19c7250d827efa560463d60a12ee4" or
        hash.sha256(0, filesize) == "364251838edfcf5ef1107fa692da3c5bd9a540482449f645992830134bf807ab"
}

