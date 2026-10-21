// Uncovering a Multi-Stage Ransomware Attack Through Behavioral Detection
// Source: darktrace | https://www.darktrace.com/blog/hiding-in-plain-sight-uncovering-a-multi-stage-ransomware-attack-through-behavioral-detection

import "hash"

rule IOC_Uncovering_a_Multi_Stage_Ransomware_Attack_Through_Behavioral_Detection_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Uncovering a Multi-Stage Ransomware Attack Through Behavioral Detection. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "darktrace"
        reference   = "https://www.darktrace.com/blog/hiding-in-plain-sight-uncovering-a-multi-stage-ransomware-attack-through-behavioral-detection"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "d6828e30ab66774a91a96ae93be4ae4c"
}

