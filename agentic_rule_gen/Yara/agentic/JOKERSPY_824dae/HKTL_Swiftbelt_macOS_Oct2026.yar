/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $x, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
rule HKTL_Swiftbelt_macOS_Oct2026
{
    meta:
        description = "Detects the Swiftbelt open-source enumeration tool for macOS, used by REF9134."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/inital-research-of-jokerspy"
        date = "2026-10-26"
        hash1 = "8ca86f78f0c73a46f31be366538423ea0ec58089f3880e041543d08ce11fa626"
        hash2 = "452c832a17436f61ad5f32ee1c97db05575160105ed1dcd0d3c6db9fb5a9aea1"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "SwiftBelt/Sources/SwiftBelt" ascii  // source: strings_listing
        $x2 = "SSH/AWS/gcloud Credentials Search:" ascii  // source: strings_listing

    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and
        filesize < 10MB and
        1 of ($x*)
}
