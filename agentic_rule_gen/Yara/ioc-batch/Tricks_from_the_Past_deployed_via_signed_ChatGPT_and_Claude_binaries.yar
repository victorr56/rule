// Tricks from the Past deployed via signed ChatGPT and Claude binaries
// Source: checkpoint-research | https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/

import "hash"

rule IOC_Tricks_from_the_Past_deployed_via_signed_ChatGPT_and_Claude_binaries_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Tricks from the Past deployed via signed ChatGPT and Claude binaries. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "checkpoint-research"
        reference   = "https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/"
        date        = "2026-10-28"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "1d0d1368b4d53f3a6322cf40e84e63db" or
        hash.sha1(0, filesize) == "ba8bd67d8898cf378d4f73821deb5657f4bb98df" or
        hash.sha1(0, filesize) == "bead5748d813a9828ddb7603a32e52aa15349768" or
        hash.sha1(0, filesize) == "eeedc5c9007d7f01808285e0ae0c0b451bdba003" or
        hash.sha1(0, filesize) == "e7c0e981f81447892995d01ed986c0b462a6f0c5" or
        hash.sha1(0, filesize) == "7467b6980440ec27c4e0a8d940672c9f24e14216" or
        hash.sha1(0, filesize) == "ea16728f6928dc77deaddee74a6e736dd5f24fc5"
}

