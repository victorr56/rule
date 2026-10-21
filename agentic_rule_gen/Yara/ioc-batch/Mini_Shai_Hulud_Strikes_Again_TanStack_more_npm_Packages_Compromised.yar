// Mini Shai-Hulud Strikes Again: TanStack + more npm Packages Compromised
// Source: wiz | https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised

import "hash"

rule IOC_Mini_Shai_Hulud_Strikes_Again_TanStack_more_npm_Packages_Compromised_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Mini Shai-Hulud Strikes Again: TanStack + more npm Packages Compromised. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c" or
        hash.sha256(0, filesize) == "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96" or
        hash.sha256(0, filesize) == "2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df" or
        hash.sha256(0, filesize) == "1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898" or
        hash.sha1(0, filesize) == "79ac49eedf774dd4b0cfa308722bc463cfe5885c" or
        hash.sha1(0, filesize) == "e7d582b98ca80690883175470e96f703ef6dc497" or
        hash.sha1(0, filesize) == "12f35b1081b17d21815b35feb57ab03d02482116" or
        hash.sha1(0, filesize) == "820fa07a7328b6cf2b417078e103721d4d8f2e79"
}

