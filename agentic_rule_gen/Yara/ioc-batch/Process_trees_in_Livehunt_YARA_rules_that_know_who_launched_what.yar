// Process trees in Livehunt: YARA rules that know who launched what
// Source: virustotal | https://blog.virustotal.com/2026/10/process-trees-in-livehunt-yara-rules.html

import "hash"

rule IOC_Process_trees_in_Livehunt_YARA_rules_that_know_who_launched_what_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Process trees in Livehunt: YARA rules that know who launched what. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "virustotal"
        reference   = "https://blog.virustotal.com/2026/10/process-trees-in-livehunt-yara-rules.html"
        date        = "2026-10-28"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d30a0a6c09f664446943d82982f0630e85c447cbe84be8a74b6db6d66effbe80" or
        hash.sha256(0, filesize) == "4930cc4e7e3e258bf2815793f0e5698bdd45adfae8e052bb1dc4c05c6689ade6" or
        hash.sha256(0, filesize) == "77da8a02d71078564409863c358a544e981b9643c8f50c1daabc5d5d176e3c75" or
        hash.sha256(0, filesize) == "51bb5aeef2e48dd14fae764f80dc67f516df9914ea9c350329e229f6cea919a2" or
        hash.sha256(0, filesize) == "a549a6c8c01da1d03e8da663eec70997a5bd5207e665d8e23f6fa75804dafc06"
}

