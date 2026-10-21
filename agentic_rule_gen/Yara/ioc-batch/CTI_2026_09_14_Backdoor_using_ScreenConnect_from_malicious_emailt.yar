// 2026-09-14: Backdoor using ScreenConnect from malicious emailt
// Source: malware-traffic-analysis | https://www.malware-traffic-analysis.net/2026/09/14/index.html

import "hash"

rule IOC_CTI_2026_09_14_Backdoor_using_ScreenConnect_from_malicious_emailt_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: 2026-09-14: Backdoor using ScreenConnect from malicious emailt. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "malware-traffic-analysis"
        reference   = "https://www.malware-traffic-analysis.net/2026/09/14/index.html"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "f1d103dd77d09697fa30fa14c4f39e394b0331a33ffd2ef5df2916dbe79e474b"
}

