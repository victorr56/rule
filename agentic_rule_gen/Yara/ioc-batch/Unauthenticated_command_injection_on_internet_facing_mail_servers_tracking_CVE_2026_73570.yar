// Unauthenticated command injection on internet-facing mail servers: tracking CVE-2026-73570
// Source: microsoft-security | https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/

import "hash"

rule IOC_Unauthenticated_command_injection_on_internet_facing_mail_servers_tracking_CVE_2026_73570_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Unauthenticated command injection on internet-facing mail servers: tracking CVE-2026-73570. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "microsoft-security"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "dee5af1c0f76b45d28bafd6e60c07bb8e391d98addf81ef8f13d073acdb3c48a" or
        hash.sha256(0, filesize) == "aea991f694911e321b0ab97534f2ad0291c392c0a43dabff664c563618bd036d" or
        hash.sha256(0, filesize) == "6ab7de2509038edf580aef6229c1c3db17f4da8f2d7d940818faf617d1938244" or
        hash.sha256(0, filesize) == "bf28f38122bf20d5fac969cc414daa6a890cdea872d389ca93d2092b6b7773cf" or
        hash.sha256(0, filesize) == "b594a42b8f1c6f090327bb9a3361c2d3515537fb7ac8da6b9061b9a3f330e159" or
        hash.sha256(0, filesize) == "65a7576c389326b6cdf9c993d0be6e5d50fed9655d1cdf2a3a50f2c21c8ec435" or
        hash.sha256(0, filesize) == "22ef852f6ebc39ee71235b90648b4b200b385c47d25c79545986493f8c70db69" or
        hash.sha256(0, filesize) == "518fe65dd349180191d9b258ab24876aaed6613cd657d0b626d1fc24e03a22b6" or
        hash.sha1(0, filesize) == "25bda7feb3553995ad68a9a8ed8c731b73a71586"
}

