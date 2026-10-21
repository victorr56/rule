// The extension you never installed: KREMLIN forges Chrome's own integrity checks to steal banking sessions
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware

import "hash"

rule IOC_The_extension_you_never_installed_KREMLIN_forges_Chrome_s_own_integrity_checks_to_steal_ba_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The extension you never installed: KREMLIN forges Chrome's own integrity checks to steal banking sessions. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "106eac79396a3ff77b8f375c391260ce422be2ae4d55d3aa75b2635cbdc0fa42" or
        hash.sha256(0, filesize) == "5ece7fd3766b0b7f8aadefa562313cea6c3c94f9398658dd389910e5be44f552" or
        hash.sha256(0, filesize) == "223be3f8648bf6998c4a58b972522e5fda8d9d0a57b4e163811930de66c3f7ca" or
        hash.sha256(0, filesize) == "cb15cbf3f01a92e609e4c2bc26155e667e96c5d04770e83abba66ee07bcecea0" or
        hash.sha256(0, filesize) == "170dffb37e05f525f735bc9ad84b3908a488f7ce43fcb07739a10e4331e15a2c" or
        hash.md5(0, filesize) == "5c92d3b8734b4f498752f735a1ca0987" or
        hash.md5(0, filesize) == "87b76a60ba7c474dbf8f689df2808e1a" or
        hash.md5(0, filesize) == "5f109e7bb3df4dea81946f2f853da288" or
        hash.sha1(0, filesize) == "cd7360a83e5cdbbbbbceb0e78748baba6740d07b"
}

