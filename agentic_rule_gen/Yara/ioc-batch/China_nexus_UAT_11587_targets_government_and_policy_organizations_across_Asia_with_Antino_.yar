// China-nexus UAT-11587 targets government and policy organizations across Asia with Antino backdoor
// Source: talos | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/

import "hash"

rule IOC_China_nexus_UAT_11587_targets_government_and_policy_organizations_across_Asia_with_Antino__Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: China-nexus UAT-11587 targets government and policy organizations across Asia with Antino backdoor. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "talos"
        reference   = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34" or
        hash.sha256(0, filesize) == "e6ff096a0562c0042b09d250bd60272ffcd8d72bd95c563842acf765a8dc8bcf" or
        hash.sha256(0, filesize) == "e7e3b0bcd6798634adf8b49d305f3a7b7682e4b76db549682a183c5a186df4bb" or
        hash.sha256(0, filesize) == "fdbd047031c13a17c9f491c9355f44d587584ebe2b8927be8482e6c236c8e1c1"
}

