/*
 Self-check
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
rule APT_BlueNorOff_RUSTBUCKET_macOS_Oct26
{
    meta:
        description = "Detects a variant of the RUSTBUCKET malware targeting macOS, used by BlueNorOff. This rule targets the Mach-O payload and triggers on a unique User-Agent string or a combination of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/DPRK-strikes-using-a-new-variant-of-rustbucket"
        date = "2026-10-18"
        hash1 = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
        hash2 = "7887638bcafd57e2896c7c16698e927ce92fd7d409aae698d33cdca3ce8d25b8"
        hash3 = "de81e5246978775a45f3dbda43e2716aaa1b1c4399fe7d44f918fccecc4dd500"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s2, s3, s4"

    strings:
        // Unique User-Agent string with a missing space before the Mozilla component
        $x1 = "User-AgentMozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)" ascii  // source: report strings_listing

        // Supporting strings related to file paths, persistence, and C2
        $s1 = "/var/log/install.log" ascii  // source: report strings_listing
        $s2 = "com.apple.systemupdate" ascii  // source: report prose
        $s3 = "System Update" ascii  // source: report prose
        $s4 = "cur1-agent" ascii  // source: report prose

    condition:
        (
            uint32(0) == 0xfeedface or // Mach-O 32-bit
            uint32(0) == 0xfeedfacf or // Mach-O 64-bit
            uint32(0) == 0xcafebabe or // FAT Mach-O
            uint32(0) == 0xcffaedfe    // FAT Mach-O 64-bit
        )
        and filesize < 20MB
        and (
            $x1 or
            3 of ($s*)
        )
}
