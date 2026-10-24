// Massive malicious campaign by FakeSecurity JS-sniffer
// Source: group-ib | https://www.group-ib.com/blog/fakesecurity/

import "hash"

rule IOC_Massive_malicious_campaign_by_FakeSecurity_JS_sniffer_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Massive malicious campaign by FakeSecurity JS-sniffer. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/fakesecurity/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "6ec8b7ce6c9858755964f94acdf618773275589024e2b66583e3634127b7e32c" or
        hash.sha256(0, filesize) == "15abc3f55703b89ff381880a10138591c6214dee7cc978b7040dd8b1e6f96297" or
        hash.sha256(0, filesize) == "af04334369878408898a223e63ec50e1434c512bc21d919769c97964492fee19" or
        hash.sha256(0, filesize) == "4587da5dca2374fd824a15e434dae6630b24d6be6916418cee48589aa6145ef6" or
        hash.sha256(0, filesize) == "0660059f3e2fb2ab0349242b4dde6bf9e37305dacc2da870935f4bede78aed34" or
        hash.md5(0, filesize) == "1b8a824074b414419ac10f5ded847ef1" or
        hash.md5(0, filesize) == "53554192ca888cccbb5747e71825facd" or
        hash.md5(0, filesize) == "3ec1ac0be981ce6d3f83f4a776e37622" or
        hash.md5(0, filesize) == "58476e1923de46cd4b8bee4cdeed0911" or
        hash.md5(0, filesize) == "286096c7e3452aad4acdc9baf897fd0c" or
        hash.md5(0, filesize) == "fd0e11372a4931b262f0dd21cdc69c01" or
        hash.md5(0, filesize) == "772db176ff61e9addbffbb7e08d8b613" or
        hash.sha1(0, filesize) == "346d580ecb4ace858d71213808f4c75341a945c1" or
        hash.sha1(0, filesize) == "aafa9885b8b686092b003ebbd9aaf8e604eea3a6" or
        hash.sha1(0, filesize) == "26d71553098b5c92b55e49db85c719f5bb366513" or
        hash.sha1(0, filesize) == "54d34b6a6c4dc78e62ad03713041891b6e7eb90f" or
        hash.sha1(0, filesize) == "6ee62834ab3aa4294eebe4a9aebb77922429cb45"
}

