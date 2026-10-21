// From Invitation to Infection: How SILENTCONNECT Delivers ScreenConnect
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/silentconnect-delivers-screenconnect

import "hash"

rule IOC_From_Invitation_to_Infection_How_SILENTCONNECT_Delivers_ScreenConnect_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: From Invitation to Infection: How SILENTCONNECT Delivers ScreenConnect. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/silentconnect-delivers-screenconnect"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "281226ca0203537fa422b17102047dac314bc0c466ec71b2e6350d75f968f2a3" or
        hash.sha256(0, filesize) == "adc1cf894cd35a7d7176ac5dab005bea55516bc9998d0c96223b6c0004723c37" or
        hash.sha256(0, filesize) == "81956d08c8efd2f0e29fd3962bcf9559c73b1591081f14a6297e226958c30d03" or
        hash.sha256(0, filesize) == "c3d4361939d3f6cf2fe798fef68d4713141c48dce7dd29d3838a5d0c66aa29c7" or
        hash.sha256(0, filesize) == "349e78de0fe66d1616890e835ede0d18580abe8830c549973d7df8a2a7ffdcec"
}

