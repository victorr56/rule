// Commit to Compromise: A New Threat Actor Targeting the Cryptocurrency Industry's Software Development Infrastructure
// Source: wiz | https://www.wiz.io/blog/threat-actors-target-crypto-orgs

import "hash"

rule IOC_Commit_to_Compromise_A_New_Threat_Actor_Targeting_the_Cryptocurrency_Industry_s_Software_D_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Commit to Compromise: A New Threat Actor Targeting the Cryptocurrency Industry's Software Development Infrastructure. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/threat-actors-target-crypto-orgs"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a" or
        hash.sha256(0, filesize) == "0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270" or
        hash.sha256(0, filesize) == "0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d" or
        hash.sha256(0, filesize) == "a35d2b67fa478a7174e308b43ce30bf69b3bc6f44fa76197fdf95fc2fbc1cf5b" or
        hash.sha256(0, filesize) == "65cba741fe30fa4799fb9002ea8de6d96042a59159dd7c3419c766af24c835e6" or
        hash.sha256(0, filesize) == "0b1a36a31b952341a534fe24890f1ed2921ee259773cff46e4f6273b8c4d5d21" or
        hash.sha256(0, filesize) == "e8ee6f5145c9d503c5130bfc6585567f6e19d409158c3c0ca0b259f1875b15f4" or
        hash.sha256(0, filesize) == "3e3901519c2305fbe9d5483b7234c25c6d2b562512916481d96f26b849c39fdb" or
        hash.sha256(0, filesize) == "402625ec79e3573a80b6de9b33fc1e503e3c7803603cd958ddd515fb0549007c" or
        hash.sha256(0, filesize) == "b6cab0b3aa8e56e2427f486c74588d598ae58bb0cbc0eda6939fe171cb0aed17" or
        hash.sha256(0, filesize) == "d4e863f9818bfb2f1dd932df6441dff204e6142c3bdb55b298cb08dc7b6a0c62" or
        hash.sha256(0, filesize) == "c6ef82d2864dfd26f117a1ef5602679153423f2742970a7949cec72722f0a01e" or
        hash.sha256(0, filesize) == "2a10ffe0367bb1b26ba2c3bc600892c21074725c0b8c9dc9161e6ceb33915460"
}

