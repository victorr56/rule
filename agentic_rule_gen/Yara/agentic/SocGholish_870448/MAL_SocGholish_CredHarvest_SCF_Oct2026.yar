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
rule MAL_SocGholish_CredHarvest_SCF_Oct2026
{
    meta:
        description = "Detects malicious SCF (Shell Command File) used for credential harvesting. This technique is reported in conjunction with SocGholish activity."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/socgholish-from-loader-and-c2-activity-to-ransomhub-deployment"
        date = "2026-10-17"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s3"

    strings:
        // These strings define the structure of a malicious SCF file forcing NTLM authentication.
        $s1 = "[Shell]" ascii nocase  // source: figure_or_disassembly
        $s2 = "Command=2" ascii nocase  // source: figure_or_disassembly
        $s3 = "IconFile=\\\\" ascii nocase  // source: prose

    condition:
        // Match small text files, not executables
        uint16(0) != 0x5a4d and uint32(0) != 0x464c457f and filesize < 2KB and

        // Requires all three definitional components of the malicious SCF file.
        // This technique uses a combination of individually weak indicators.
        3 of them
}
