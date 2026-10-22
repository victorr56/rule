import "pe"

rule MAL_Deimos_Installer_Oct2026
{
    meta:
        description = "Detects Deimos malware installers by matching on a combination of metadata properties associated with the 'SlimReader' lure, such as File Description, Copyright, Product Version, or a hardcoded LNK filename."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant"
        date = "2026-10-22"
        hash1 = "f268491d2f7e9ab562a239ec56c4b38d669a7bd88181efb0bd89e450c68dd421"
        hash2 = "af1e952b5b02ca06497e2050bd1ce8d17b9793fdb791473bdae5d994056cb21f"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s4"

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

    strings:
        $s1 = "SlimReader Setup" wide ascii // source: figure_or_disassembly
        $s2 = "(c) InvestTech" wide ascii // source: figure_or_disassembly
        $s3 = "1.4.1.2" wide ascii // source: figure_or_disassembly
        $s4 = "a44f066dfa44db9fba953a982d48b.LNk" wide ascii // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        3 of them
}
