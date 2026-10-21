// Determined Attacker Uploads Malicious Webshells to Parks and Rec Management Platform Servers
// Source: huntress | https://www.huntress.com/blog/parks-recreation-platform-webshell-attack

import "hash"

rule IOC_Determined_Attacker_Uploads_Malicious_Webshells_to_Parks_and_Rec_Management_Platform_Serve_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Determined Attacker Uploads Malicious Webshells to Parks and Rec Management Platform Servers. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/parks-recreation-platform-webshell-attack"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "0d8f7bf30aa1ac95d59fed24c433dd2b3d57767f38c088721699c841c6e861d3" or
        hash.sha256(0, filesize) == "5f69ff7a2e024f94cc5f816fa16c90054b09d9ac430b1f8b0631dfdd4472905e" or
        hash.sha256(0, filesize) == "e9dee286069afb6b411febb96b91a963cd16baffbf8b6aa951e0ef1a7e0e3879" or
        hash.sha256(0, filesize) == "0d93c3a8ded46887f79ac4ca7f238c458de2231243176f6c05062e34f238d19a" or
        hash.sha256(0, filesize) == "b06b581d91f4108900d188c3ee1af18502a8cb65d4e101663b791bd670867485" or
        hash.sha256(0, filesize) == "7bb594a77f726bf21a49f717024f2915f82f47eb623d2ad305259301de1f1ab4"
}

