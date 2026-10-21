// MATCHBOIL: New tricks, same old evil intentions
// Source: welivesecurity | https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/

import "hash"

rule IOC_MATCHBOIL_New_tricks_same_old_evil_intentions_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: MATCHBOIL: New tricks, same old evil intentions. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "welivesecurity"
        reference   = "https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "f886b615cb9e23ead2718ff2a61155acfb04ce9e" or
        hash.sha1(0, filesize) == "1e2c4aac30edff86cd9a30bd08b199bcd3d0ccce" or
        hash.sha1(0, filesize) == "c85d28f7d272ce2bbbfb9dae71d21bf25b8d00fc" or
        hash.sha1(0, filesize) == "050926727cdd74f0b3a8a098e60b76d10fb06b14"
}

