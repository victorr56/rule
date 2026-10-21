// Phishing Abuses RMM Tools for Persistent Access
// Source: microsoft-security | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/

import "hash"

rule IOC_Phishing_Abuses_RMM_Tools_for_Persistent_Access_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Phishing Abuses RMM Tools for Persistent Access. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "microsoft-security"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc" or
        hash.sha256(0, filesize) == "f094b8263471c7b76dbed03d420736449920368fa0eca2ed6b1aea2645138d97" or
        hash.sha256(0, filesize) == "857c2f283de799faa74b56e862c0a9f96e67aa1b4fa4a9e46395098365b99de3" or
        hash.sha256(0, filesize) == "6a89de024ca62536de6f5fc10e49896bb1ac330ca39dce30203afdcc45ae237e" or
        hash.sha256(0, filesize) == "4188c6588f3dcda881c3f2d12df580051179a999f040b799af506edeb3211a26" or
        hash.sha256(0, filesize) == "ceb3f7fe9a618ff29a21b126383c23900fad58d6ae2b5552d7e306e4b6acf4b0" or
        hash.sha256(0, filesize) == "a93c946c237b981189d2668d938a9d4d1d9681757e48dae8d9d65ed25b5da657" or
        hash.sha256(0, filesize) == "529543b4fe6a4c21d28be56dbf92fcac91d8df808d8518b4275c973fa547ad63" or
        hash.sha256(0, filesize) == "ccea4e1acc51ac43ba9da76ada00e7e308cc33d9c5c264dff82d1be83e957b88" or
        hash.sha256(0, filesize) == "a03c84ae9e569c04fdd271277f508bba5a299d53c3c0efe0819338d178fe1c5b" or
        hash.sha1(0, filesize) == "f34330d4c6e0aa978dc3af40360c14b31ad51127"
}

