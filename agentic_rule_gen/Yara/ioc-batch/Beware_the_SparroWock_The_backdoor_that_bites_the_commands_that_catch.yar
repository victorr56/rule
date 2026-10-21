// Beware the SparroWock: The backdoor that bites, the commands that catch
// Source: welivesecurity | https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/

import "hash"

rule IOC_Beware_the_SparroWock_The_backdoor_that_bites_the_commands_that_catch_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Beware the SparroWock: The backdoor that bites, the commands that catch. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "welivesecurity"
        reference   = "https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "44f0a22b143b79fa760bf31e14c8fff714c8a2a1"
}

