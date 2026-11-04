// Fake-download campaign uses trojanized installers to deliver monetization payloads
// Source: microsoft-security | https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/

import "hash"

rule IOC_Fake_download_campaign_uses_trojanized_installers_to_deliver_monetization_payloads_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Fake-download campaign uses trojanized installers to deliver monetization payloads. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "microsoft-security"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/"
        date        = "2026-11-04"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "006510ce1da2b7410376f0788c19e55616eb4bcc30072d25b7d0871dc32aa11c" or
        hash.sha256(0, filesize) == "21306fc5716f95e252388f920314b42f1c8bcc7df67cb4d39da30217b96f4044" or
        hash.sha256(0, filesize) == "72750d32b440e9f2b6d05ff3d218a561a75d3d75fb976b461fa59897674a7f70" or
        hash.sha256(0, filesize) == "ab2c2dd37fdcfe1e7620a57f98c80bd063258bea145adc0cc6a0f8b1e24c6a8f" or
        hash.sha256(0, filesize) == "452a210bba4c8d08f7cb7733a816d7220a7fa570a469aea0a997cfc8b594b6a0" or
        hash.sha256(0, filesize) == "523fb81fae0c7beba7b5171243cc0dee7a4d04ae0483be9172eef2394a5a2152" or
        hash.sha256(0, filesize) == "55cd3d36fdcc58016a64398357b2c9724a060da9f0d09266e537a61ec9552e4f"
}

