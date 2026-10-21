// ClickLock Stealer: Paste Once, Lose Everything
// Source: group-ib | https://www.group-ib.com/blog/clicklock-stealer-macos-malware/

import "hash"

rule IOC_ClickLock_Stealer_Paste_Once_Lose_Everything_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: ClickLock Stealer: Paste Once, Lose Everything. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/clicklock-stealer-macos-malware/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "d9617710d4ed8e9b87f6fee0b7014c4101effba0" or
        hash.sha1(0, filesize) == "b67aa4f598c0ea625a7409ea7884e10a7bc9c3ff" or
        hash.sha1(0, filesize) == "8dda05168ea8610a2449419a47517bc32823d6ec" or
        hash.sha1(0, filesize) == "0a1fb016bd10bac5455175c79aa4511e5ff1a330" or
        hash.sha1(0, filesize) == "2fc970e25570532f9cbe33b7ebfe1f0383a7341a"
}

