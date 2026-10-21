// Gaming the system: how a Chinese-speaking actor turned Brazilian government sites into an SEO weapon
// Source: checkpoint-research | https://research.checkpoint.com/2026/gaming-the-system-how-a-chinese-speaking-actor-turned-brazilian-government-sites-into-an-seo-weapon/

import "hash"

rule IOC_Gaming_the_system_how_a_Chinese_speaking_actor_turned_Brazilian_government_sites_into_an_S_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Gaming the system: how a Chinese-speaking actor turned Brazilian government sites into an SEO weapon. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "checkpoint-research"
        reference   = "https://research.checkpoint.com/2026/gaming-the-system-how-a-chinese-speaking-actor-turned-brazilian-government-sites-into-an-seo-weapon/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "232ef6be134c2b7c14648aa193daf7e23e987477b8a40150dd77883947fdf017" or
        hash.sha256(0, filesize) == "088d0742a667f1acfc83edb94671a10b951f6745badec6d5c754ef594dddf815" or
        hash.sha256(0, filesize) == "88544d36beb6dc621c9376806836d0ad109ece64b589605d5674e0c86313d1c0" or
        hash.sha256(0, filesize) == "9d3085eac9a59a94f0473db5ec0173def8777d2f794da281fb1749389ae33cdb" or
        hash.sha256(0, filesize) == "263c14e84398339b25cd3e59da7e108340306fdbb8112bbe7dc0f07a71eb8a31"
}

