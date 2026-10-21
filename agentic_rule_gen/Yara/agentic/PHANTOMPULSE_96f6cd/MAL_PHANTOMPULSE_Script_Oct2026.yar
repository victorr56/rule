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
rule MAL_PHANTOMPULSE_Script_Oct2026
{
    meta:
        description = "Detects an initial access PowerShell script used in the PHANTOMPULSE campaign. This rule looks for unique status messages sent to the C2 and requires all three to be present for a match."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/phantom-in-the-vault"
        date = "2026-10-17"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $s1 = "GFILE FOUND ON PC" ascii // source: figure_or_disassembly, C2 status message
        $s2 = "GLAUNCH SUCCESS" ascii // source: figure_or_disassembly, C2 status message
        $s3 = "GSESSION CLOSED" ascii // source: figure_or_disassembly, C2 status message

    condition:
        // This is a script rule, so no PE/ELF header check is possible.
        // A stricter condition is applied, requiring multiple specific strings.
        filesize < 20KB and
        3 of ($s*)
}
