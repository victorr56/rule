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
rule WEBSHELL_UNC5221_PHP_PHP2Shell_Nov2026
{
    meta:
        description = "Detects a PHP webshell used by UNC5221 in the PHP2Shell campaign. The rule requires three specific strings to be present."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        date = "2026-11-20"
        hash1 = "edb3e92eb7bda7413a09edcc4b1ba3cbed4bcdf42808a8abce63b6e4c3fda2b3"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3"
    strings:
        $s1 = "upload_progress_pwn" ascii  // source: prose
        $s2 = "zz2026" ascii  // source: explicit_literal
        $s3 = "challenge_render.tpl" ascii  // source: prose
    condition:
        filesize < 1MB and
        3 of them
}
