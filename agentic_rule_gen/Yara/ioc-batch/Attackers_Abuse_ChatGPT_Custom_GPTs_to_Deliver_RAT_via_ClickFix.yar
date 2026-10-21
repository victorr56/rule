// Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix
// Source: huntress | https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat

import "hash"

rule IOC_Attackers_Abuse_ChatGPT_Custom_GPTs_to_Deliver_RAT_via_ClickFix_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "14e3376befd4b7b52de0757b6264da294ac6b0f9e4ff51cb9bc5b19b243fe335" or
        hash.sha256(0, filesize) == "c4603646701069ebdeabc96f74e1f947355ace8575560986d8393fcc6b88d0b7" or
        hash.sha256(0, filesize) == "6761aad48a3f987238994d92bca97e4b8550e0150607bd67b47b1b6366a371fc" or
        hash.sha256(0, filesize) == "e58831766e8d4313db9f8b85f90c3a840aa0d84cfeac285beefa40e39ad0d1fb" or
        hash.sha256(0, filesize) == "b77575413c0f97eaf31e4a44c884c1ecdc0049ec89916ceb0bf3aaaedc0442fe" or
        hash.sha256(0, filesize) == "eff5d63ddf1813962f0d8ad1250cea5486c8bb5dd27c3f432b43957a33e43764" or
        hash.sha256(0, filesize) == "9c615db040b88c18ce6b96f30d08797045b7d506f940bea452dc7a6992fdbb8d" or
        hash.sha256(0, filesize) == "54c94f85ba6e950903d5ff42c0971c5a9d0741596be26e06afe7d60ec38edf31" or
        hash.sha256(0, filesize) == "e614b7d5a7a363fb1b355a87e2e8d9e8a05bbbca08f2cee3d606bdb5015ac53b" or
        hash.sha256(0, filesize) == "20c7befc174a61117770535e809046c75e93c71284bf1a9c6cd532f55b315f53" or
        hash.sha256(0, filesize) == "ab65bbfc505dbe1cebe6021fb36e2011f6aa1d64f5d87cee1cbee3fc2a0c7907" or
        hash.sha256(0, filesize) == "278e2f3e2f26c18666b89ef774b4af9ce954e36b2bf54a2392608619245d8c48" or
        hash.sha256(0, filesize) == "91a22cf3154944897cbcaffc7d20d4596e972d280ee134197d41d8d8eefb0fe2" or
        hash.sha256(0, filesize) == "22869e3326fe1de011cd500e666769027126c5c440b76837baf55139f30094e4" or
        hash.sha256(0, filesize) == "0457414c4504b70115798eee9c8384a8bf9e793461ffb2e0661a6dcc6ed4809f" or
        hash.sha256(0, filesize) == "3cd1484cc5bf10e22d79784beba58a75d7b126c46efb5e1a85d6aab884447621" or
        hash.sha256(0, filesize) == "b59a21a8d4c0c11a9ecbbdbe2a2938499c99c5ebb210c9c6db9683c7ad19f4c4" or
        hash.sha256(0, filesize) == "a27cafb84876a3374ef4aba1062345def6cd0b029eaf8e0dc44fa24fc943f3c6" or
        hash.sha256(0, filesize) == "d3fda1e6cf886fd530bf62e2d16c39ad23ed12a2c933fc211f1f4876ceaa033e" or
        hash.sha256(0, filesize) == "d5acf44658f0dce90bd160f15d8e07a96938c81661d87dc7e9cb0107863bfb90"
}

