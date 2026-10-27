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
rule MAL_MacOS_ClickFix_Stealer_Oct2026 {
    meta:
        description = "Detects the ClickFix Crypto Drainer stealer payload for macOS based on a unique embedded string."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/mac-crypto-draining-malware"
        date = "2026-10-27"
        hash1 = "f0062f7e70e61493684a2f60748a475168e155bc2502163c844c42e87692abd0"
        hash2 = "619a99ba4ee9d7f33db8045c7e03c4265424977993fe8a53b0f45157c5abd3e5"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        malware_family = "ClickFix Crypto Drainer"
        threat_actor = "Aeza Group"
    strings:
        // Strong anchor, >16 bytes, likely a developer comment.
        $x1 = "DRAIN_PCT% to us" ascii  // source: figure_or_disassembly, yara_hint: eligible for $x if actor-specific

    condition:
        // Mach-O header
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and
        filesize < 20MB and
        $x1
}
