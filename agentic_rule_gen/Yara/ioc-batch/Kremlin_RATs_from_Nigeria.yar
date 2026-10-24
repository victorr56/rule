// Kremlin RATs from Nigeria
// Source: group-ib | https://www.group-ib.com/blog/rats-nigeria/

import "hash"

rule IOC_Kremlin_RATs_from_Nigeria_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Kremlin RATs from Nigeria. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/rats-nigeria/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "95a6a416f682a9d254e76ec38ade01ce241b3366" or
        hash.sha1(0, filesize) == "a3816c37d0fbe26a87d1cc7beff91ce5816039e7" or
        hash.sha1(0, filesize) == "b42a3b8c6d53a28a2dc84042d95ce9ca6e09cbcf" or
        hash.sha1(0, filesize) == "d8826efc7c0865c873330a25d805c95c9e64ad05" or
        hash.sha1(0, filesize) == "7f1fdf605e00323c055341919173a7448e3641fb" or
        hash.sha1(0, filesize) == "19324fc16f99a92e737660c4737a41df044ecc54" or
        hash.sha1(0, filesize) == "403c0f9a210f917e88d20d97392d9b1b14cbe310" or
        hash.sha1(0, filesize) == "fd274f57e59c8ae3e69e0a4eb59a06ee8fd74f91" or
        hash.sha1(0, filesize) == "c992e0a46185bf0b089b3c4261e4faff15a5bc15" or
        hash.sha1(0, filesize) == "443c079b24d65d7fd74392b90c0eac4aab67060c" or
        hash.sha1(0, filesize) == "b6ff3e87ab7d6bd8c7abd3ee30af24b4e3709601" or
        hash.sha1(0, filesize) == "02799b41c97b6205f1999a72cef8b8991d4b8092" or
        hash.sha1(0, filesize) == "25abf0f75c56516134436c1f836d9db1e770ff30" or
        hash.sha1(0, filesize) == "523c5e0a1c9bc6d28f08500e96319571b57e4ba7" or
        hash.sha1(0, filesize) == "1230acfd1f6f5b13a218ff8658a835997d1f0774"
}

