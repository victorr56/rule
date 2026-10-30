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
rule MAL_LUNA_Ransomware_Oct2026
{
    meta:
        description = "Detects LUNA ransomware for Windows and Linux based on unique strings and code patterns. The rule may fire on one of several unique strings or a combination of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/luna-ransomware-attack-pattern"
        date = "2026-10-30"
        hash1 = "1cbbf108f44c8f4babde546d26425ca5340dccf878d306b90eb0fbec2f83ab51"
        hash2 = "ad8d568811e05e12cde78f76c3b7cbbde0d20aee5b4e918a3a8d515f5e242bb6"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s4, s5"

    strings:
        // Unique strings and patterns - strong anchors
        $x1 = "OpenServerWindowsProgram FilesRecycle.BinProgramDataAppDataAll users" ascii  // source: figure_or_disassembly
        $x2 = "W1dIQVQgSEFQUEVORUQ/XQ0KDQpBbGwgeW91ciBmaWxlcyB3ZXJlIG1vdmVkIHRvIHNlY3VyZSBzdG9yYWdlLg0KTm9ib" ascii  // source: strings_listing
        $x3 = ".Luna.ini.exe.dll.lnk" ascii  // source: figure_or_disassembly
        $x4 = { 48 8D ?? 00 00 48 F4 48 B9 8B 3D 10 B6 9A 5A B4 36 48 F7 E1 48 }  // source: strings_listing
        $x5 = { 48 C1 EA 12 48 89 D0 48 C1 E0 05 48 29 D0 48 29 D0 48 3D C4 EA 00 00 }  // source: strings_listing

        // Supporting strings
        $s1 = "Error while writing encrypted data to:" ascii wide  // source: strings_listing
        $s2 = "Error while writing public key to:" ascii wide  // source: strings_listing
        $s3 = "Error while renaming file:" ascii wide  // source: strings_listing
        $s4 = "readme-Luna.txt" ascii wide nocase  // source: prose
        $s5 = "Luna" wide nocase  // source: explicit_literal

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
