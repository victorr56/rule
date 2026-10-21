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
rule HKTL_NordStream_CICD_Abuse_Oct2026
{
    meta:
        description = "Detects artifacts related to the Nord Stream CI/CD abuse toolset. The rule requires the presence of three specific supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/detecting-cicd-pipeline-abuse-with-llm-augmented-analysis"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "addSpnToEnvironment, DownloadSecureFile, ssh.js"

    strings:
        $s1 = "addSpnToEnvironment" ascii wide  // source: artifact 'addSpnToEnvironment' (explicit_literal)
        $s2 = "DownloadSecureFile" ascii wide  // source: artifact 'DownloadSecureFile' (explicit_literal)
        $s3 = "ssh.js" ascii wide  // source: artifact 'ssh.js' (explicit_literal)

    condition:
        uint16(0) == 0x5a4d and
        filesize < 1MB and
        3 of ($s*)
}
