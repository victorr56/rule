// Introducing the REF5961 intrusion set
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/introducing-the-ref5961-intrusion-set

import "hash"

rule IOC_Introducing_the_REF5961_intrusion_set_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Introducing the REF5961 intrusion set. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/introducing-the-ref5961-intrusion-set"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "ce4dfda471f2d3fa4e000f9e3839c3d9fbf2d93ea7f89101161ce97faceadf9a" or
        hash.sha256(0, filesize) == "29c90ac124b898b2ff2a4897921d5f5cc251396e8176fc8d6fa475df89d9274d"
}

