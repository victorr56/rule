// 2026-09-08: XWorm infection
// Source: malware-traffic-analysis | https://www.malware-traffic-analysis.net/2026/09/08/index.html

import "hash"

rule IOC_CTI_2026_09_08_XWorm_infection_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: 2026-09-08: XWorm infection. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "malware-traffic-analysis"
        reference   = "https://www.malware-traffic-analysis.net/2026/09/08/index.html"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "9b4e654a8435d91c7f4e24e7fd844cbbb62328131b0065bc5a534c6e948c02c5" or
        hash.sha256(0, filesize) == "5ba1eee1204710adfe1963b730de79c7a8089b173e811052e7be464fc5da1a1d"
}

