// Chamilo LMS... It's raining 0days, hallelujah, it's raining 0days
// Source: quarkslab | http://blog.quarkslab.com/chamilo-lms-its-raining-0days-hallelujah-its-raining-0days.html

import "hash"

rule IOC_Chamilo_LMS_It_s_raining_0days_hallelujah_it_s_raining_0days_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Chamilo LMS... It's raining 0days, hallelujah, it's raining 0days. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "quarkslab"
        reference   = "http://blog.quarkslab.com/chamilo-lms-its-raining-0days-hallelujah-its-raining-0days.html"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "dc7360e7ec809c26ed7aee5c45618cae" or
        hash.md5(0, filesize) == "83ec05a275b7bd3bfcc026a66720a099" or
        hash.md5(0, filesize) == "91222307076cd80c0a44a0076e5a5879"
}

