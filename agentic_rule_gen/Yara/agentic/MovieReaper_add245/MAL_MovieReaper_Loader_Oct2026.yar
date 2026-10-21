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
rule MAL_MovieReaper_Loader_Oct2026 {
    meta:
        description = "Detects MovieReaper malware. A match is triggered by one unique string (module loading command, C2 paths) or by a combination of three supporting strings (undocumented API, decoy filenames, Solana RPC artifacts)."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "EtwpCreateEtwThread, /cloud/v192.4/ui/sync-status-icons.png, /cloud/v192.4/onboarding/welcome-bg.jpg, /cloud/v192.4/ui/file-preview-placeholder.png, /cloud/v192.4/shared/link-banner.jpg, the odyssey (2026) [1080p] [webrip] [5.1].exe, /getAccountInfo, api.mainnet.solana.com"

    strings:
        // Unique strings, can fire alone
        $x1 = "get_coff_module_cmd" ascii  // source: figure_or_disassembly
        $x2 = "/cloud/v192.4/ui/sync-status-icons.png" ascii  // source: explicit_literal
        $x3 = "/cloud/v192.4/onboarding/welcome-bg.jpg" ascii  // source: explicit_literal
        $x4 = "/cloud/v192.4/ui/file-preview-placeholder.png" ascii  // source: explicit_literal
        $x5 = "/cloud/v192.4/shared/link-banner.jpg" ascii  // source: explicit_literal

        // Supporting strings, need combinations
        $s1 = "EtwpCreateEtwThread" ascii wide  // source: explicit_literal
        $s2 = "the odyssey (2026) [1080p] [webrip] [5.1].exe" ascii wide  // source: explicit_literal
        $s3 = "/getAccountInfo" ascii  // source: explicit_literal
        $s4 = "api.mainnet.solana.com" ascii  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
