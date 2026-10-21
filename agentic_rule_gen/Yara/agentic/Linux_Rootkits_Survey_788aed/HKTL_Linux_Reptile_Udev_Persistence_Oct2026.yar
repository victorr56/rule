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
rule HKTL_Linux_Reptile_Udev_Persistence_May2024
{
    meta:
        description = "Detects a udev persistence rule file used by the Reptile Linux rootkit. The condition requires both the device matching and the execution parts of the rule to be present."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/linux-rootkits-2-caught-in-the-act"
        date = "2024-05-09"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // These strings are components of a udev rule that Reptile uses for persistence.
        // It triggers when /dev/random (major 1, minor 8) is added.
        $s1 = "ACTION==\\\"add\\\", ENV{MAJOR}==\\\"1\\\", ENV{MINOR}==\\\"8\\\"" ascii  // source: report figure_or_disassembly
        $s2 = "RUN+=\\\"/lib/udev/reptile\\\"" ascii  // source: report figure_or_disassembly

    condition:
        // This is a text rule file, so no header check. Limit size and require both components.
        filesize < 2KB and
        2 of ($s*)
}
