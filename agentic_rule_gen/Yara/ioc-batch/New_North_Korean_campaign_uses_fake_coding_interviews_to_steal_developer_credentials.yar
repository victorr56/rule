// New North Korean campaign uses fake coding interviews to steal developer credentials
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography

import "hash"

rule IOC_New_North_Korean_campaign_uses_fake_coding_interviews_to_steal_developer_credentials_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: New North Korean campaign uses fake coding interviews to steal developer credentials. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "8e571d58794b9b44ae53c2c67bedef72c500e8adbb80aab7a5c263adcba55b1e" or
        hash.sha256(0, filesize) == "3e6360f83a95540aa2176d279ca4694513afb1e5116a7ffe591c6b5bcf3b9c3c" or
        hash.sha256(0, filesize) == "4e7639045b4a64de60bfb6312951a5c3dffbd3fb04b84837663242ed27f09864" or
        hash.sha256(0, filesize) == "54bf36910d81ab516037cb3d69d7c85190f90aa0da9e58617799c1fc738dc5a9" or
        hash.sha256(0, filesize) == "96357529d17c4690826d5d4c74deac51743a5388733b3f04004d898f0635ef20" or
        hash.sha256(0, filesize) == "9df01d242ef46adfedf8c35cb7cc67b1d27d7dc4a1ce74ab32e984090d579886" or
        hash.sha256(0, filesize) == "c5aed4c063d4970a03250778da8041da9e0c83d8f22d2f1994da0ad72567ebd9" or
        hash.sha256(0, filesize) == "cc97517f80f567977300450de11e9a0be53f52657525a20b1091c99fe9e45730" or
        hash.sha256(0, filesize) == "fb94b2caee2c40635448a98ba0118421e19a400e74ccff73315f8fa42351f53f"
}

