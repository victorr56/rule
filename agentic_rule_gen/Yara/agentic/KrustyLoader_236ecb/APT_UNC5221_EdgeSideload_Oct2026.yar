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
rule APT_UNC5221_EdgeSideload_Oct2026
{
    meta:
        description = "Detects a likely DLL sideloading deployer targeting Microsoft Edge with dbghelp.dll. Based on strings from the report which appear unrelated to the main KrustyLoader payload."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/ivanti-under-siege-investigating-the-ivanti-endpoint-manager-mobile-vulnerabilities-cve-2025-4427-cve-2025-4428"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 55
    strings:
        $s1 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application" ascii wide // source: report Fig.3 Silent DLL deployer.
        $s2 = "$TargetDir\\dbghelp.dll" ascii wide // source: report Fig.3 Silent DLL deployer.
        $s3 = "C:\\Windows\\Temp\\dbghelp.tmp" ascii wide // source: report Fig.3 Silent DLL deployer.
    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        2 of ($s*)
}
