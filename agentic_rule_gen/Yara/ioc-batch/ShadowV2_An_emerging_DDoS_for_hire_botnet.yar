// ShadowV2: An emerging DDoS for hire botnet
// Source: darktrace | https://www.darktrace.com/blog/shadowv2-an-emerging-ddos-for-hire-botnet

import "hash"

rule IOC_ShadowV2_An_emerging_DDoS_for_hire_botnet_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: ShadowV2: An emerging DDoS for hire botnet. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "darktrace"
        reference   = "https://www.darktrace.com/blog/shadowv2-an-emerging-ddos-for-hire-botnet"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "1b552d19a3083572bc433714dfbc2b75eb6930a644696dedd600f9bd755042f6" or
        hash.sha256(0, filesize) == "1f70c78c018175a3e4fa2b3822f1a3bd48a3b923d1fbdeaa5446960ca8133e9c" or
        hash.sha256(0, filesize) == "2462467c89b4a62619d0b2957b21876dc4871db41b5d5fe230aa7ad107504c99"
}

