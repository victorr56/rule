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
rule MAL_WARMCOOKIE_Backdoor_Oct2026 {
    meta:
        description = "This rule detects the WARMCOOKIE backdoor. It triggers on one of several unique strings or code patterns, including hardcoded mutexes, an RC4 key, specific C2 communication strings and code signatures. The rule can be triggered by a single one of these unique indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/dipping-into-danger"
        date = "2026-10-18"
        hash1 = "ccde1ded028948f5cd3277d2d4af6b22fa33f53abde84ea2aa01f1872fad1d13"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x7, x8, x9"

    strings:
        // Unique strings from strings listing or disassembly figures
        $x1 = "ERROR: Cannot write file" ascii wide  // source: strings_listing
        $x2 = "OK (See 'Files' tab)" ascii wide  // source: strings_listing
        $x3 = "Mozilla / 4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1;.NET CLR 1.0.3705)" ascii wide  // source: figure_or_disassembly
        $x4 = "/data/5fb6dd81093a0d6812c17b12f139ce35" ascii  // source: figure_or_disassembly

        // Unique hex patterns from report's own YARA signatures
        $x5 = { 45 8D 5D ?? 45 33 C0 41 83 E3 ?? 49 8D 4E ?? 44 03 DB 41 8D 53 ?? }  // source: strings_listing
        $x6 = { 8B 69 04 48 8D 79 08 8B 31 89 6C 24 ?? 48 8D 4E ?? E8 }  // source: strings_listing

        // Unique strings from prose, but high quality (GUID, key)
        $x7 = "f92e6f3c-9cc3-4be0-966c-1be421e69140" ascii wide  // source: prose
        $x8 = "91f785f4-2fa4-4c85-954d-b96768ca76f2" ascii wide  // source: prose
        $x9 = "24de21a8dc08434c" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d
        and filesize < 2MB
        and 1 of ($x*)
}
