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
rule APT_WaterHydra_DarkMe_Payload_Oct2026
{
    meta:
        description = "Detects the final DarkMe RAT payload. The rule keys on a combination of unique project names and C2 commands. A match requires at least three of these strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/darkme-rat-abandons-exploits"
        date = "2026-10-16"
        hash1 = "54ed18aa883b53794810be0428b3a0167758183c5b3ba5660af747dc81dd5b76"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
    strings:
        // Supporting strings: project names and C2 commands
        $s1 = "PartiallyesOnes" ascii wide // source: explicit_literal
        $s2 = "Officially" ascii wide // source: figure_or_disassembly
        $s3 = "SHLEXE" ascii wide // source: explicit_literal
        $s4 = "ZIPALO" ascii wide // source: explicit_literal
        $s5 = "COPALO" ascii wide // source: explicit_literal
        $s6 = "PASALO" ascii wide // source: explicit_literal
        $s7 = "DELMAP" ascii wide // source: explicit_literal
        $s8 = "STRFLS" ascii wide // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        3 of ($s*)
}
