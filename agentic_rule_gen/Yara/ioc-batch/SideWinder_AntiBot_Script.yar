// SideWinder.AntiBot.Script
// Source: group-ib | https://www.group-ib.com/blog/sidewinder-antibot/

import "hash"

rule IOC_SideWinder_AntiBot_Script_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: SideWinder.AntiBot.Script. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/sidewinder-antibot/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "a74f9baa1791476c489942dd9e24c8c6fd0822cd" or
        hash.sha1(0, filesize) == "4421f214c91a08ac0318871c6f918cfffe36d039" or
        hash.sha1(0, filesize) == "64a889e35b10a902170abe092c6c6b8f16c66dd1" or
        hash.sha1(0, filesize) == "5e5e038453fde5ddf57820783dd9ce8f5f042df2" or
        hash.sha1(0, filesize) == "6a99ce5387c5b67602b2ef633bfbdc184e4d845c"
}

