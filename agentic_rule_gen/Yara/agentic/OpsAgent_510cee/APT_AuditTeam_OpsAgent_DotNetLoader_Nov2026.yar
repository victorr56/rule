import "pe"
import "dotnet"

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
rule APT_AuditTeam_OpsAgent_DotNetLoader_Oct2024
{
    meta:
        description = "This rule detects the .NET loader component of OpsAgent, used by AuditTeam. It requires three specific strings related to command-line argument parsing in a .NET PE file."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/auditteam-opsagent-forced-audit/122031/"
        date = "2024-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$s1, $s2, $s3"

    strings:
        $s1 = "DApc" ascii wide  // source: explicit_literal
        $s2 = "DResume" ascii wide  // source: explicit_literal
        $s3 = "DProtect" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        dotnet.is_dotnet and
        3 of ($s*)
}
