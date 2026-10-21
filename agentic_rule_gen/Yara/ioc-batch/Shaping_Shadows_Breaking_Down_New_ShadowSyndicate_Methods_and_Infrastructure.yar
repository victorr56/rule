// Shaping Shadows: Breaking Down New ShadowSyndicate Methods and Infrastructure
// Source: group-ib | https://www.group-ib.com/blog/new-shadowsyndicate-infrastructure/

import "hash"

rule IOC_Shaping_Shadows_Breaking_Down_New_ShadowSyndicate_Methods_and_Infrastructure_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Shaping Shadows: Breaking Down New ShadowSyndicate Methods and Infrastructure. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/new-shadowsyndicate-infrastructure/"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "543c114c1a399697a1bf2a194e2e62db4f64d9c8" or
        hash.sha1(0, filesize) == "df77f2ca72c82673334b4127fd881de4dc09abe2"
}

