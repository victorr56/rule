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
[x] No generic padding is required
[x] No empty meta fields
*/
rule APT_REF2731_PARALLAX_Loader_Oct2026
{
    meta:
        description = "Detects PARALLAX loader DLLs used by REF2731. The rule can be triggered by unique code sequences, a combination of specific strings like 'Clipboard Start' and '[Clipboard End]', or a combination of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/exploring-the-ref2731-intrusion-set"
        date = "2026-10-22"
        hash1 = "16227f50bbe42a13a2abf0bf0e146f356863de59525c54909ea8ccc2db448f77"
        hash2 = "443879ee2cb3d572bb928d0831be0771c7120968e442bafe713a6e0f803e8cd9"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$s2, $s4"

    strings:
        // Strong Anchors
        $x1 = { B9 01 00 00 00 6B D1 00 C6 44 15 D4 83 B8 01 00 00 00 C1 E0 00 C6 44 05 D4 B6 B9 01 00 00 00 D1 E1 C6 44 0D D4 33 BA 01 00 00 00 6B C2 03 C6 44 05 D4 28 B9 01 00 00 00 C1 E1 02 C6 44 0D D4 36 BA 01 00 00 00 6B C2 05 C6 44 05 D4 6B B9 01 00 00 00 6B D1 06 C6 44 15 D4 90 B8 01 00 00 00 6B C8 07 C6 44 0D D4 97 }  // source: strings_listing
        $x2 = { 8B 4D ?? 8B 04 B8 85 C9 74 ?? 8B F1 90 8A 08 8D 40 ?? 88 0C 1A 42 83 EE ?? 75 ?? 8B 4D ?? 8B 45 ?? 47 3B 7D ?? 72 ?? }  // source: strings_listing
        $x3 = { C7 45 F8 68 74 74 70 8B ?? ?? 8B 02 89 ?? ?? 6A 08 8D ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 8B ?? ?? 52 8D ?? ?? 50 8B ?? ?? 8B 51 0C FF D2 }  // source: strings_listing
        $x4 = ".DeleteFile(Wscript.ScriptFullName)" ascii wide  // source: strings_listing

        // Medium-strength strings
        $a1 = "Clipboard Start" ascii wide  // source: strings_listing
        $a2 = "[Clipboard End]" ascii wide  // source: strings_listing

        // Supporting strings
        $s1 = "msi.dll" ascii wide  // source: figure_or_disassembly
        $s2 = "msvcr100.dll" ascii wide  // source: prose
        $s3 = "UN.vbs" ascii wide  // source: strings_listing
        $s4 = "CMSTPLUA" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            1 of ($x*) or
            ($a1 and $a2) or
            3 of ($s*)
        )
}
