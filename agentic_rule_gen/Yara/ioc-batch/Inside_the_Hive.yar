// Inside the Hive
// Source: group-ib | https://www.group-ib.com/blog/hive/

import "hash"

rule IOC_Inside_the_Hive_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Inside the Hive. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/hive/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "1e21c8e27a97de1796ca47a9613477cf7aec335a783469c5ca3a09d4f07db0ff" or
        hash.sha256(0, filesize) == "2f7d37c22e6199d1496f307c676223dda999c136ece4f2748975169b4a48afe5" or
        hash.sha256(0, filesize) == "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609" or
        hash.sha256(0, filesize) == "5954558d43884da2c7902ddf89c0cf7cd5bf162d6feefe5ce7d15b16767a27e5"
}

