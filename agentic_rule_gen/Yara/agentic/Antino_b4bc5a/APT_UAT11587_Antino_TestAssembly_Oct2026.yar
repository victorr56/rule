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
import "dotnet"

rule APT_UAT11587_Antino_TestAssembly_Oct2023 {
    meta:
        author = "ioc-yara-daily (agentic)"
        description = "Detects the TestAssembly.dll .NET downloader component of the Antino infection chain. The rule matches on a unique Assembly GUID, a COM Class GUID, or a combination of the assembly name and specific deserialization gadget strings. A match on any of the GUIDs is sufficient to trigger the rule."
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        date = "2023-10-16"
        hash1 = "d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2"

    strings:
        // Unique COM Class GUID - Strong Anchor
        $x1 = "{1F3D8AA5-9EBF-4EE4-85C2-EA40379AEDE8}" ascii wide // source: figure_or_disassembly

        // Supporting gadget strings
        $s1 = "ActivitySurrogateSelector" ascii wide // source: explicit_literal
        $s2 = "System.Windows.Forms.AxHost+State" ascii wide // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        dotnet.is_dotnet and
        (
            // Unique Assembly GUID from PE metadata
            dotnet.typelib == "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" or
            $x1 or
            (dotnet.assembly.name == "TestAssembly" and 2 of ($s*))
        )
}
