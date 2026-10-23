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
rule APT_TaskMasters_Albaniiutas_Oct26
{
    meta:
        description = "Detects the Albaniiutas malware (RAT and dropper) used by the TaskMasters APT group. The rule can be triggered by a unique high-entropy key, a specific error string, or a combination of other unique strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/task/"
        date = "2026-10-23"
        hash1 = "2629cae63cecc23bd30731e3a7e44fdabee75a1aaec14b3d7f56ac1674ad9c11"
        hash2 = "fd43fa2e70bcc3b602363667560494229287bf4716638477889ae3f816efc705"
        hash3 = "83b619f65d49afbb76c849c3f5315dbcb4d2c7f4ddf89ac93c26977e85105f32"
        hash4 = "2a3c8dabdee7393094d72ce26ccbce34bff924a1be801f745d184a33119eeda4"
        hash5 = "690bf6b83cecbf0ac5c5f4939a9283f194b1a8815a62531a000f3020fee2ec42"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, s1"

    strings:
        // Strong anchors: high-entropy key and long unique string
        $x1 = "L!Q@W#E$R%T^Y&U*A|}t~k" ascii  // source: explicit_literal
        $x2 = "GetRemoteFileData error!" ascii wide  // source: strings_listing

        // Supporting strings
        $s1 = "ClientX.dll" ascii wide  // source: explicit_literal
        $s2 = "FileVJCr error" ascii wide  // source: strings_listing
        $s3 = "zlib err0r" ascii wide  // source: strings_listing
        $s4 = "D4444 0k!" ascii wide  // source: strings_listing
        $s5 = "U5555 E00r!" ascii wide  // source: strings_listing

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
