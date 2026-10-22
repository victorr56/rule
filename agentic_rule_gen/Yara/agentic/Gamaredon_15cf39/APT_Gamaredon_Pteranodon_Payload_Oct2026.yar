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
rule APT_Gamaredon_Pteranodon_Payload_Oct2026
{
    meta:
        description = "Detects Pteranodon malware payloads and droppers associated with the Gamaredon Group, identified by embedded VBA/VBS code fragments and specific strings. The rule can be triggered by one unique code fragment or a combination of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/playing-defense-against-gamaredon-group"
        date = "2026-10-22"
        hash1 = "c1524a4573bc6acbe59e559c2596975c657ae6bbc0b64f943fffca663b98a95f"
        hash2 = "145a61a14ec6d32b105a6279cd943317b41f1d27f21ac64df61bcdd464868edd"
        hash3 = "c4089686965df5e52105b6eac06703aa11c4891695278446370f623d531b505e"
        hash4 = "02e6e2bfaaf6e77cfaccadaf26167135c53cf2c934d17c5a83e5bbcadd85b47d"
        hash5 = "2f310c5b16620d9f6e5d93db52607f21040b4829aa6110e22ac55fab659e9fa1"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s2, s3"
    strings:
        // Unique VBA/VBS code fragments
        $x1 = "asrrCodes(i) = Asc( Mid( myPassPhrase, i + 1, 1 ) )" ascii wide  // source: figure_or_disassembly
        $x2 = "Drives(Environ(\"SystemDrive\")).SerialNumber" ascii wide  // source: figure_or_disassembly
        $x3 = "//posolreboot.php" ascii wide  // source: figure_or_disassembly

        // Supporting strings: file names and common script objects
        $s1 = "wordMacros.txt" ascii wide  // source: figure_or_disassembly
        $s2 = "ExcelMyMacros.vba" ascii wide  // source: explicit_literal
        $s3 = "wordMacros.vba" ascii wide  // source: explicit_literal
        $s4 = "CreateObject(\"MSXML2.XMLHTTP\")" ascii wide  // source: figure_or_disassembly
    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
