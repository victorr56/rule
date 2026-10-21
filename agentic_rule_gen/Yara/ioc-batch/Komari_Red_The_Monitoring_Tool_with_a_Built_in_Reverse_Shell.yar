// Komari Red: The Monitoring Tool with a Built-in Reverse Shell
// Source: huntress | https://www.huntress.com/blog/komari-c2-agent-abuse

import "hash"

rule IOC_Komari_Red_The_Monitoring_Tool_with_a_Built_in_Reverse_Shell_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Komari Red: The Monitoring Tool with a Built-in Reverse Shell. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/komari-c2-agent-abuse"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "039e659ade3aa8ee7758c11fdb8fbfffd2491920046d638413cea2042f6d584c"
}

