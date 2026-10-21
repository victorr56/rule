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
rule APT_WorldLeaks_Loader_Oct2025
{
    meta:
        description = "Detects a loader used by the World Leaks group, which drops a malicious dbghelp.dll. The rule requires two of three specific path and filename strings to match."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/when-reality-diverges-from-the-playbook-darktrace-identifies-encryption-in-a-world-leaks-ransomware-attack"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 55

    strings:
        $s1 = "$TargetDir\\dbghelp.dll" ascii wide  // source: report Fig.3 other
        $s2 = "C:\\Windows\\Temp\\dbghelp.tmp" ascii wide  // source: report Fig.3 other
        $s3 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application" ascii wide  // source: report Fig.3 other

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        2 of them
}
