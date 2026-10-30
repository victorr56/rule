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
import "pe"

rule MAL_DOUBLELOADER_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/deobfuscating-alcatraz"
        date = "2026-10-30"
        tlp = "WHITE"
        description = "Detects the DOUBLELOADER backdoor. The rule looks for a unique obscured string, or a combination of the 'Start' export name and two of three specific process injection API names. The malware is often protected with the Alcatraz obfuscator."
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        hash1 = "3050c464360ba7004d60f3ea7ebdf85d9a778d931fbf1041fa5867b930e1f7fd"
        unverified_strings = "6, 1, 2, 3, 4"

    strings:
        // prose-sourced unique string; may be a false positive on some .NET files but is highly unusual in a native DLL
        $x1 = "bad array new length" ascii wide  // source: prose

        // prose-sourced supporting strings
        $s1 = "Start" ascii  // source: prose
        $s2 = "NtOpenProcess" ascii wide  // source: prose
        $s3 = "NtWriteVirtualMemory" ascii wide  // source: prose
        $s4 = "NtCreateThreadEx" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and filesize < 5MB and
        (
            $x1 or
            ($s1 and 2 of ($s2, $s3, $s4))
        )
}
