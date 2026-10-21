// Darktrace Tracks CVE‑2025‑31324 Activity
// Source: darktrace | https://www.darktrace.com/blog/tracking-cve-2025-31324-darktraces-detection-of-sap-netweaver-exploitation-before-and-after-disclosure

import "hash"

rule IOC_Darktrace_Tracks_CVE_2025_31324_Activity_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Darktrace Tracks CVE‑2025‑31324 Activity. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "darktrace"
        reference   = "https://www.darktrace.com/blog/tracking-cve-2025-31324-darktraces-detection-of-sap-netweaver-exploitation-before-and-after-disclosure"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "3268f269371a81dbdce8c4eedffd8817c1ec2eadec9ba4ab043cb779c2f8a5d2" or
        hash.sha256(0, filesize) == "1d26fff4232bc64f9ab3c2b09281d932dd6afb84a24f32d772d3f7bc23d99c60" or
        hash.sha256(0, filesize) == "1544d9392eedf7ae4205dd45ad54ec67e5ce831d2c61875806ce4c86412a4344" or
        hash.sha256(0, filesize) == "b8e56de3792dbd0f4239b54cfaad7ece3bd42affa4fbbdd7668492de548b5df8" or
        hash.md5(0, filesize) == "29274ca90e6dcf5ae4762739fcbadf01" or
        hash.md5(0, filesize) == "f662135bdd8bf792a941ea222e8a1330" or
        hash.md5(0, filesize) == "6900e844f887321f22dd606a6f2925ef" or
        hash.md5(0, filesize) == "83a797e5b47ce6e89440c47f6e33fa08" or
        hash.md5(0, filesize) == "72afde58a1bed7697c0aa7fa8b4e3b03" or
        hash.md5(0, filesize) == "8c8681e805e0ae7a7d1a609efc000c84" or
        hash.sha1(0, filesize) == "e007edd4688c5f94a714fee036590a11684d6a3a" or
        hash.sha1(0, filesize) == "fa645f33c0e3a98436a0161b19342f78683dbd9d" or
        hash.sha1(0, filesize) == "da23dab4851df3ef7f6e5952a2fc9a6a57ab6983" or
        hash.sha1(0, filesize) == "a29e8f030db8990c432020441c91e4b74d4a4e16" or
        hash.sha1(0, filesize) == "fe931adc0531fd1cb600af0c01f307da3314c5c9" or
        hash.sha1(0, filesize) == "17d65a9d8d40375b5b939b60f21eb06eb17054fc"
}

