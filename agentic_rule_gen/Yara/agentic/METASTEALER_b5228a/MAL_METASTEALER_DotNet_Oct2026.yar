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
import "pe"
import "dotnet"

rule MAL_METASTEALER_DotNet_Oct2026
{
    meta:
        description = "Detects METASTEALER, a .NET infostealer. This rule matches on the presence of at least one unique obfuscated method name."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/globally-distributed-stealers"
        date = "2026-10-22"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // AGILE.NET obfuscator artifacts, considered unique/strong anchors (>=16 chars)
        $s1 = "Delegate11.smethod_0" ascii  // source: figure_or_disassembly
        $s2 = "Delegate11.delegate11_0" ascii  // source: figure_or_disassembly
        $s3 = "Class4.smethod_13" ascii  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d
        and filesize < 20MB
        and dotnet.is_dotnet
        and (
            1 of ($s*)
        )
}
