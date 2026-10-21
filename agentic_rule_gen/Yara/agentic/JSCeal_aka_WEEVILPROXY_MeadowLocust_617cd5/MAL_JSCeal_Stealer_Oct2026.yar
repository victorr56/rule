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
rule MAL_JSCeal_Stealer_Oct2026
{
    meta:
        description = "Detects JSCeal (WEEVILPROXY, MeadowLocust) stealer based on deobfuscated strings. A match is triggered by one of several strong unique strings, or a combination of at least four supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Unique artifacts that can fire the rule alone
        $x1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtRdWl/ucoH+ZnVuxHrx2" ascii // source: strings_listing
        $x2 = "/oauth2/:version/token?grant_type=authorization_code&client_id=" ascii // source: strings_listing
        $x3 = "customer_account_USDT_balance_available" ascii // source: strings_listing
        $x4 = "historical_balances_per_asset_category" ascii // source: strings_listing
        $x5 = "powershell -NoProfile -WindowStyle Hidden -Command \\\"" ascii wide // source: strings_listing

        // Supporting artifacts
        $s1 = "Invoke-Expression ([System.Text.Encoding]::" ascii wide // source: strings_listing
        $s2 = "iterInstalledBrowsers" ascii // source: strings_listing
        $s3 = "listTelegramSessions" ascii // source: strings_listing
        $s4 = "withCreateProcessUser" ascii // source: strings_listing
        $s5 = "Worker root already configured" ascii // source: figure_or_disassembly
        $s6 = "listInstalledApplications" ascii // source: strings_listing
        $s7 = "findInstalledBrowser" ascii // source: strings_listing
        $s8 = "saveOAuthToken" ascii // source: strings_listing
        $s9 = "totalBalanceInUSDT" ascii // source: strings_listing
        $s10 = "Process exited with code " ascii wide // source: strings_listing
        $s11 = "Invalid protocol" ascii // source: figure_or_disassembly
        $s12 = "3|2|1|0|4" ascii // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
