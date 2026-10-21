// Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like Activity
// Source: huntress | https://www.huntress.com/blog/rogue-screenconnect-installations

import "hash"

rule IOC_Rogue_ScreenConnect_Installations_Across_Unrelated_Hosts_Suggest_Worm_Like_Activity_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like Activity. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "08bc4e82883eb42fc5219b206555b7a02a879860c76b4a12b2f82a64f6cc9020" or
        hash.sha256(0, filesize) == "de3b6836a88ae4b117e3b6de0e9cce3cd56a2b27b462d69e50c2fcac4089a457" or
        hash.sha256(0, filesize) == "19a3534da9f60c726be426ec5cc2b72c2d1254fefa0782bd2f08ef08117f3260" or
        hash.sha256(0, filesize) == "110fffc85370bb7cc60fa023447165c7e99175473d76bc5ffb2abecaa3a41d66" or
        hash.sha256(0, filesize) == "de89d560fc8302c778d88e3938327b240fa0db9a64fc1d5643067eedcbd2aede" or
        hash.sha256(0, filesize) == "ffd6d23f579571cc61936145791975da78b6ae914d780a9447a8f53c3688a0de"
}

