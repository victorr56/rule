/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
rule MAL_CikaBika_Loader_Oct2026
{
    meta:
        description = "Detects the CikaBika loader component based on file paths and registry keys used for sideloading its RAT into Microsoft Edge."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/unmasking-vo1d-inside-darktraces-botnet-detection"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $s1 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application" ascii wide  // source: Figure 3: Silent DLL deployer.
        $s2 = "C:\\Windows\\Temp\\dbghelp.tmp" ascii wide  // source: Figure 3: Silent DLL deployer.
        $s3 = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide  // source: artifact, explicit_literal
        $s4 = "$TargetDir\\dbghelp.dll" ascii wide  // source: Figure 3: Silent DLL deployer.

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        2 of them
}
