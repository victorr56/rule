// A USB worm’s second life: Retadup spreading CoffeeLoader
// Source: securelist | https://securelist.com/retadup-delivers-coffeeloader/121908/

import "hash"

rule IOC_A_USB_worm_s_second_life_Retadup_spreading_CoffeeLoader_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: A USB worm’s second life: Retadup spreading CoffeeLoader. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/retadup-delivers-coffeeloader/121908/"
        date        = "2026-11-20"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "d7785198d9341310978e4cedc7bdb735" or
        hash.md5(0, filesize) == "2272dde17925d6179bea6fcf4d543d20" or
        hash.md5(0, filesize) == "dce55eec553f6af16ba6481eaacb8638" or
        hash.md5(0, filesize) == "449c9e8bc6eb308aa3c46c88959e1a4f" or
        hash.md5(0, filesize) == "58886d45a0c5e802a5d0a7545c36112d" or
        hash.md5(0, filesize) == "cca710c5455c1fe2732771afbac16a09"
}

