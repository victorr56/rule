// Angry Birds: Toy Ghouls’ new toys
// Source: securelist | https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/

import "hash"

rule IOC_Angry_Birds_Toy_Ghouls_new_toys_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Angry Birds: Toy Ghouls’ new toys. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "bfadbeee63a4f0bf19ec9deb8fa58f58" or
        hash.md5(0, filesize) == "7916c33688385525078bee504c90f359"
}

