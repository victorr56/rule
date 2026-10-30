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

rule HKTL_Alcatraz_Obfuscator_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/deobfuscating-alcatraz"
        date = "2026-10-30"
        tlp = "WHITE"
        description = "Detects files obfuscated with the Alcatraz obfuscator. This detection is based on a combination of a characteristic section name and constants used in its LEA-based string obfuscation."
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 40
        unverified_strings = "0, 7, 8"

    strings:
        $s1 = ".0Dev" ascii  // source: prose
        $s2 = { 4F CF DC F4 01 }  // source: prose, for "1F4DFCF4F", little-endian

        $c1 = { C7 83 D9 74 }  // source: prose, for "74D983C7", little-endian

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            $c1 and 2 of ($s*)
        )
}
