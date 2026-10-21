// The Closed Quorum: Inside the first reported autonomous AI C2 implant
// Source: talos | https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/

import "hash"

rule IOC_The_Closed_Quorum_Inside_the_first_reported_autonomous_AI_C2_implant_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Closed Quorum: Inside the first reported autonomous AI C2 implant. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "talos"
        reference   = "https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "250d4fa37488af9b025333fa17705573d721467b203765bc360890b4f5a90cd7" or
        hash.sha256(0, filesize) == "c4dc171f2513fcaf9d5ecc815a94aee4063b213ab380f80bd3ac422dee5205a7" or
        hash.sha256(0, filesize) == "c13cea04f598e2b0c248d603a6e31bd13aabb64d8149c1b6a77b64e0b983a86f" or
        hash.sha256(0, filesize) == "f5f1f8c3e7b883793800ab6ccf21b3e60bd0730f300b4595fe74a33adc17a63c"
}

