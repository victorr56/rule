// Dark Web Profile: CyberXero
// Source: socradar | https://socradar.io/blog/dark-web-profile-cyberxero/

import "hash"

rule IOC_Dark_Web_Profile_CyberXero_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Dark Web Profile: CyberXero. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "socradar"
        reference   = "https://socradar.io/blog/dark-web-profile-cyberxero/"
        date        = "2026-11-11"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "92a789444708fa1cb4cc5a89e0aa6cc7a279b62a7b8a4d2857255a18197d0090" or
        hash.sha256(0, filesize) == "a5ae0aab352871bc0b038b3aa43b03eb223425628c884af7b9fc592cd34eb86c" or
        hash.sha256(0, filesize) == "71e21094c1ac1cf0275c91ed377965e248bca1c12711f6dd20e2682681fc1192" or
        hash.sha256(0, filesize) == "59c535f47ab4d35f6d9fc8b8aec4a72438ea0b89e5a4dcea74b05d2d32cfa483" or
        hash.md5(0, filesize) == "3870a559b5b6ea6076f5f90029c180b7"
}

