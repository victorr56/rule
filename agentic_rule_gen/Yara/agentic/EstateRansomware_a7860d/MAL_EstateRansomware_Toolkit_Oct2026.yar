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
rule MAL_EstateRansomware_Toolkit_Oct2026
{
    meta:
        description = "Detects a suspected toolkit associated with EstateRansomware activity. The rule looks for a combination of strings related to exploitation and discovery TTPs, such as creating a rogue SQL account on Veeam servers. A match requires 3 out of 4 supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/estate-ransomware/"
        date = "2026-10-26"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 55
        unverified_strings = "s2"

    strings:
        // Supporting strings related to actor's TTPs
        $s1 = "VeeamBkp" ascii wide  // source: explicit_literal
        $s2 = "xp_cmdshell" ascii wide  // source: prose
        $s3 = "ad_users.txt" ascii wide  // source: figure_or_disassembly
        $s4 = "Acc1" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        3 of ($s*)
}
