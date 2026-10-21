// Unpacking ClickFix: Darktrace Detection Insights
// Source: darktrace | https://www.darktrace.com/blog/unpacking-clickfix-darktraces-detection-of-a-prolific-social-engineering-tactic

import "hash"

rule IOC_Unpacking_ClickFix_Darktrace_Detection_Insights_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Unpacking ClickFix: Darktrace Detection Insights. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "darktrace"
        reference   = "https://www.darktrace.com/blog/unpacking-clickfix-darktraces-detection-of-a-prolific-social-engineering-tactic"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "34ff2f72c191434ce5f20ebc1a7e823794ac69bba9df70721829d66e7196b044" or
        hash.sha1(0, filesize) == "10a5eab3eef36e75bd3139fe3a3c760f54be33e3"
}

