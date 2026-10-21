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

rule MAL_ARECHCLIENT2_DotNet_Loader_Oct2026
{
    meta:
        description = "Detects the .NET loader component for ARECHCLIENT2 based on specific error codes."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/a-wretch-client"
        date = "2026-10-17"
        hash1 = "f92b491d63bb77ed3b4c7741c8c15bdb7c44409f1f850c08dce170f5c8712d55"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 55
    strings:
        $s1 = "F1" wide  // source: figure_or_disassembly
        $s2 = "F2" wide  // source: figure_or_disassembly
        $s3 = "D1" wide  // source: figure_or_disassembly
        $s4 = "W2" wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        dotnet.is_dotnet and
        3 of ($s*)
}
