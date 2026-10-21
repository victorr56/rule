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
rule APT_Lazarus_VSCode_Task_Poisoning_Oct2026
{
    meta:
        description = "Detects VS Code task poisoning configurations used by DPRK-linked actors. The rule requires the auto-execution trigger `runOn: folderOpen` combined with at least one other suspicious setting, or a combination of three suspicious settings for hiding tasks or files."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/detecting-cicd-pipeline-abuse-with-llm-augmented-analysis"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "runOn: folderOpen, reveal: never, echo: false, files.exclude"

    strings:
        // Main trigger: auto-execution of a task on folder open.
        $s1 = "\"runOn\": \"folderOpen\"" ascii wide  // source: artifact 'runOn: folderOpen' (explicit_literal)

        // Supporting strings for hiding the task and its output, or the directory itself.
        $s2 = "\"reveal\": \"never\"" ascii wide  // source: artifact 'reveal: never' (explicit_literal)
        $s3 = "\"echo\": false" ascii wide  // source: artifact 'echo: false' (explicit_literal)
        $s4 = "\"files.exclude\"" ascii wide  // source: artifact 'files.exclude' (explicit_literal)

    condition:
        // This is a text-based JSON configuration file, so no header check is possible.
        // The condition requires at least two strings, satisfying strict mode for text files.
        filesize < 50KB and
        (
            ( $s1 and 1 of ($s2,$s3,$s4) ) or
            3 of ($s2,$s3,$s4)
        )
}
