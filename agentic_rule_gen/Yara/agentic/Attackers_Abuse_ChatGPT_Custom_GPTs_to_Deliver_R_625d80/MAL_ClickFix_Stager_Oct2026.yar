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
rule MAL_ClickFix_Stager_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat"
        date = "2026-10-16"
        description = "Detects the obfuscated PowerShell stager used in the ClickFix campaign. It identifies the specific arithmetic deobfuscation pattern."
        hash1 = "14e3376befd4b7b52de0757b6264da294ac6b0f9e4ff51cb9bc5b19b243fe335"
        hash2 = "c4603646701069ebdeabc96f74e1f947355ace8575560986d8393fcc6b88d0b7"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $s1 = "$env:__ST=$MyInvocation.MyCommand.Path;" ascii // source: report Fig.6
        $s2 = "[scriptblock]::Create(" ascii // source: report Fig.6
        $s3 = "+=[char]([int64]" ascii // source: report Fig.6
        $s4 = "1520498" ascii // source: report Fig.6

    condition:
        filesize < 1MB and
        3 of them
}
