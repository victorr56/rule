// AppleScript Abuse: Unpacking a macOS Phishing Campaign
// Source: darktrace | https://www.darktrace.com/blog/applescript-abuse-unpacking-a-macos-phishing-campaign

import "hash"

rule IOC_AppleScript_Abuse_Unpacking_a_macOS_Phishing_Campaign_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: AppleScript Abuse: Unpacking a macOS Phishing Campaign. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "darktrace"
        reference   = "https://www.darktrace.com/blog/applescript-abuse-unpacking-a-macos-phishing-campaign"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "d3539d71a12fe640f3af8d6fb4c680fd" or
        hash.md5(0, filesize) == "319d905b83bf9856b84340493c828a0c"
}

