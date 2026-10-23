// APT41 World Tour 2021 on a tight schedule
// Source: group-ib | https://www.group-ib.com/blog/apt41-world-tour-2021/

import "hash"

rule IOC_APT41_World_Tour_2021_on_a_tight_schedule_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: APT41 World Tour 2021 on a tight schedule. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/apt41-world-tour-2021/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "8c93083440cd9ce5fe4cf58c3348bd85bdf07f6c" or
        hash.sha1(0, filesize) == "0cc907db409a259611f56abc7dead19c6ed51fd0" or
        hash.sha1(0, filesize) == "afef10f23f1403761173557178c21308461778ba" or
        hash.sha1(0, filesize) == "4690a60aa5e6e323ad04993bf0076e9c78e7413c"
}

