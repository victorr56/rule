// Internet Scanning in VirusTotal: hunting infrastructure by what it exposes
// Source: virustotal | https://blog.virustotal.com/2026/10/internet-scanning-in-vt.html

import "hash"

rule IOC_Internet_Scanning_in_VirusTotal_hunting_infrastructure_by_what_it_exposes_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Internet Scanning in VirusTotal: hunting infrastructure by what it exposes. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "virustotal"
        reference   = "https://blog.virustotal.com/2026/10/internet-scanning-in-vt.html"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "29f69693228c27033209532b5a6a97d1" or
        hash.md5(0, filesize) == "3a85f1d2131fa2723ac6ade171eafacd"
}

