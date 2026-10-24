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
rule MAL_LiteLlmSupplyChain_PyStealer_Oct2026
{
    meta:
        description = "Detects the credential stealing payload from the LiteLlm v1.107.0 supply chain compromise. This Python script exfiltrates credentials and other sensitive data. The rule requires a combination of strings, such as two unique table/value names, or one unique name and two supporting strings, or four supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        date = "2026-10-24"
        hash1 = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        hash2 = "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s_unique1, s_unique2, s_unique3, s_support1, s_support3, s_support4"

    strings:
        // Unique strings, but used in combination as it's a script file
        $s_unique1 = "LiteLLM_CredentialsTable" ascii  // source: explicit_literal
        $s_unique2 = "LiteLLM_ProxyModelTable" ascii  // source: explicit_literal
        $s_unique3 = "credential_values" ascii  // source: explicit_literal

        // Supporting strings
        $s_support1 = "TVM-2026-0003" ascii  // source: explicit_literal
        $s_support2 = "PRIVCOLLECT" ascii  // source: figure_or_disassembly
        $s_support3 = "litellm_params" ascii  // source: explicit_literal
        $s_support4 = "/healthcheck" ascii  // source: explicit_literal

    condition:
        filesize < 200KB and
        (
            2 of ($s_unique*) or
            4 of ($s_support*) or
            (1 of ($s_unique*) and 2 of ($s_support*))
        )
}
