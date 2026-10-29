// NIK C2: The new AI-enabled command-and-control framework
// Source: talos | https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/

import "hash"

rule IOC_NIK_C2_The_new_AI_enabled_command_and_control_framework_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: NIK C2: The new AI-enabled command-and-control framework. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "talos"
        reference   = "https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/"
        date        = "2026-10-29"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d791dd0ff3228ed29a8d7333d4567be829159c5632ea347780992006f91c5295" or
        hash.sha256(0, filesize) == "4887afc0a574e9419a9695ef083460f58e4ef9a1c40793523ce112251273bdf9"
}

