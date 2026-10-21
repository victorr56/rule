// BTMOB: A stealthy RAT burrowing deep into Android devices
// Source: welivesecurity | https://www.welivesecurity.com/en/malware/btmob-stealthy-rat-burrowing-deep-android-devices/

import "hash"

rule IOC_BTMOB_A_stealthy_RAT_burrowing_deep_into_Android_devices_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: BTMOB: A stealthy RAT burrowing deep into Android devices. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "welivesecurity"
        reference   = "https://www.welivesecurity.com/en/malware/btmob-stealthy-rat-burrowing-deep-android-devices/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "58ac130a8ebb09e37592ac69841483edc5695d1545b1f04f23d5b760ac17cd94" or
        hash.sha256(0, filesize) == "0a542751724a432a8448324613e0ce10393e41739a1800cbb7d5a2c648fcdc35" or
        hash.sha256(0, filesize) == "a764d73795abe47ae640ba09999a18c47b5340e5ecc7b897afebf34f3f37638f" or
        hash.sha256(0, filesize) == "26a2268281e8043125ef72b92f8980b42912048753d56894bc378fb54c7c188a" or
        hash.sha256(0, filesize) == "6ae94ce710016d86ed7457236deef2c4c51478587f3609b6e827a348828b3931"
}

