// When AI Infrastructure Becomes Part of the Attack Surface
// Source: darktrace | https://www.darktrace.com/blog/when-ai-infrastructure-becomes-part-of-the-attack-surface

import "hash"

rule IOC_When_AI_Infrastructure_Becomes_Part_of_the_Attack_Surface_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: When AI Infrastructure Becomes Part of the Attack Surface. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "darktrace"
        reference   = "https://www.darktrace.com/blog/when-ai-infrastructure-becomes-part-of-the-attack-surface"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "85de36ff66fae9f4b059cbedf6d36e017ebc26c828f99f911a96e78636f21200"
}

