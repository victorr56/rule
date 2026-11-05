// The SOC Files 5: Ghost in the pipeline, or a fileless SharePoint breach by Storm-2603
// Source: securelist | https://securelist.com/storm-2603-fileless-toolshell-attack/121467/

import "hash"

rule IOC_The_SOC_Files_5_Ghost_in_the_pipeline_or_a_fileless_SharePoint_breach_by_Storm_2603_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The SOC Files 5: Ghost in the pipeline, or a fileless SharePoint breach by Storm-2603. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/storm-2603-fileless-toolshell-attack/121467/"
        date        = "2026-11-05"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "fd91321bf7ff7245dda9b7b5d791ace8" or
        hash.md5(0, filesize) == "3a55d8f8f29716c694671834d8c6cb29"
}

