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
rule MAL_TCLBANKER_Loader_Oct2026
{
    meta:
        description = "Detects the native loader component (screen_retriever_plugin.dll) of the TCLBANKER trojan."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/tclbanker-brazilian-banking-trojan"
        date = "2026-10-16"
        hash1 = "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626"
        hash2 = "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059"
        hash3 = "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3, s4, s5, s6"

    strings:
        $x1 = { D3 70 D4 66 D8 BD C4 13 }  // source: figure_or_disassembly, magic constant 0x13C4BDD866D470D3
        $x2 = { EB A3 CD 24 9B 32 A6 26 }  // source: figure_or_disassembly, magic constant 0x26A6329B24CDA3EB
        $x3 = { 9D C2 C1 2D AC E5 FC DB }  // source: figure_or_disassembly, magic constant 0xDBFCE5AC2DC1C29D
        $x4 = { 91 86 F4 E2 D5 C1 B3 A7 }  // source: figure_or_disassembly, magic constant 0xA7B3C1D5E2F48691
        $x5 = { C6 B5 D7 03 91 8A 2F 4E }  // source: figure_or_disassembly, magic constant 0x4E2F8A9103D7B5C6
        $x6 = { 09 75 C3 A1 F2 D8 E6 B4 }  // source: figure_or_disassembly, magic constant 0xB4E6D8F2A1C37509
        $x7 = { 94 B7 02 8C 5E 3D 1A 6F }  // source: figure_or_disassembly, magic constant 0x6F1A3D5E8C02B794

        $s1 = "screen_retriever_plugin.dll" ascii wide  // source: prose
        $s2 = "Ida_trusted_idbs" ascii wide  // source: prose
        $s3 = "cuckoomon.dll" ascii wide  // source: prose
        $s4 = "IDATopLevelWindow" ascii wide  // source: prose
        $s5 = "VBoxVBoxVBox" ascii wide  // source: prose
        $s6 = "YOURAPPNAMEHERE" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
