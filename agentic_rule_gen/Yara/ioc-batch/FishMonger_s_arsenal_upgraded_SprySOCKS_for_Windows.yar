// FishMonger’s arsenal upgraded: SprySOCKS for Windows
// Source: welivesecurity | https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/

import "hash"

rule IOC_FishMonger_s_arsenal_upgraded_SprySOCKS_for_Windows_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: FishMonger’s arsenal upgraded: SprySOCKS for Windows. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "welivesecurity"
        reference   = "https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "ffc3aa7909d4e72c360d65a1f45260dffe5c99b7"
}

