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
rule MAL_SANSAR_Rootkit_Nov2026
{
    meta:
        description = "Detects the SANSAR ftrace-based kernel rootkit based on unique strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        date = "2026-11-20"
        hash1 = "6ba1aa275e0e2826e8b48b36473539ca56cbdc41f429e539a45f8532b084d7a4"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, x3"

    strings:
        $x1 = "acpi_thermal_mgr.ko" ascii  // source: prose
        $x2 = "acpi_thermal_mgr.c" ascii  // source: prose
        $x3 = "T\xc3\xbcm gizli isimleri kontrol et" ascii  // source: prose

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        1 of ($x*)
}
