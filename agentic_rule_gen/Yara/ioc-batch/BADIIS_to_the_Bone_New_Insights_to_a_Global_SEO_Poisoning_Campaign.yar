// BADIIS to the Bone: New Insights to a Global SEO Poisoning Campaign
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/badiis-to-the-bone-new-insights-to-global-seo-poisoning-campaign

import "hash"

rule IOC_BADIIS_to_the_Bone_New_Insights_to_a_Global_SEO_Poisoning_Campaign_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: BADIIS to the Bone: New Insights to a Global SEO Poisoning Campaign. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/badiis-to-the-bone-new-insights-to-global-seo-poisoning-campaign"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "055bdcaa0b69a1e205c931547ef863531e9fdfdaac93aaea29fb701c7b468294" or
        hash.sha256(0, filesize) == "2340f152e8cb4cc7d5d15f384517d756a098283aef239f8cbfe3d91f8722800a" or
        hash.sha256(0, filesize) == "c2ff48cfa38598ad514466673b506e377839d25d5dfb1c3d88908c231112d1b2" or
        hash.sha256(0, filesize) == "7f2987e49211ff265378349ea648498042cd0817e131da41156d4eafee4310ca" or
        hash.sha256(0, filesize) == "1b723a5f9725b607926e925d1797f7ec9664bb308c9602002345485e18085b72" or
        hash.sha256(0, filesize) == "1f9e694cac70d089f549d7adf91513f0f7e1d4ef212979aad67a5aea10c6d016" or
        hash.sha256(0, filesize) == "c5abe6936fe111bbded1757a90c934a9e18d849edd70e56a451c1547688ff96f" or
        hash.md5(0, filesize) == "1e4b23eee1b96b0cc705da1e7fb9e2f3"
}

