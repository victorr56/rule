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
rule APT_TraderTraitor_ROOFDECK_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        date = "2026-10-16"
        description = "Detects TraderTraitor's ROOFDECK (macOS.Gaslight) backdoor. The rule targets unique strings, command and control artifacts, and configuration markers. Detection is possible with one strong anchor, or a combination of medium anchors and supporting strings."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        malware_family = "ROOFDECK"
        threat_actor = "TraderTraitor"
        platform = "macos"
        file_type = "macho"
        unverified_strings = "s12, s13, s14"

    strings:
        // Strong anchors (>=16 bytes, high entropy, or specific hex)
        $x1 = "Screenshot command is not implemented yet." ascii  // source: explicit_literal
        $x2 = { 31 63 64 36 64 31 33 66 66 31 35 61 64 62 66 37 61 34 32 30 32 35 64 31 30 65 63 39 39 62 34 61 } // source: explicit_literal, cert serial "1cd6d13ff15adbf7a42025d10ec99b4a"
        $x3 = "zan/EObUVxXNfPHdkDyCVR0AC9apleciK9ZQw+neWo6q+wvAhnLpPe7FZLomuwntUgI3afLDblgw9t19Kh7w/8CVwFncxh4PdqtdYno4teQ6fDLKXSWaZBG7zZ9R22jxPpiY70XKilXJuds34q7pfzVfbLvLTmTWyTtcyrOnRSCOwEHP/gHX0gX+8s" ascii // source: explicit_literal, part of embedded RSA public key
        $x4 = "nostr_public_keys" ascii  // source: explicit_literal

        // Medium anchors
        $a1 = "--type=renderer" ascii  // source: explicit_literal
        $a2 = "/app_version" ascii  // source: explicit_literal

        // Supporting strings
        $s1 = "pastebin_key" ascii  // source: explicit_literal
        $s2 = "recovery_url" ascii  // source: explicit_literal
        $s3 = "rsa_private_key" ascii // source: explicit_literal
        $s4 = "wss://relay.damus.io" ascii // source: explicit_literal
        $s5 = "wss://nos.lol" ascii // source: explicit_literal
        $s6 = "wss://nostr.mom" ascii // source: explicit_literal
        $s7 = "wss://relay.snort.social" ascii // source: explicit_literal
        $s8 = "wss://offchain.pub" ascii // source: explicit_literal
        $s9 = "wss://relay.nostr.band" ascii // source: explicit_literal
        $s10 = "wss://nostr.oxtr.dev" ascii // source: explicit_literal
        $s11 = "wss://nostr.wine" ascii // source: explicit_literal
        
        // Prose-sourced supporting strings
        $s12 = "rssh" ascii  // source: prose
        $s13 = "clipboard" ascii // source: prose
        $s14 = ".terraform.lock.hcl" ascii // source: prose
        
    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe) and filesize < 10MB and
        (
            1 of ($x*) or
            (1 of ($a*) and 2 of ($s*)) or
            4 of ($s*)
        )
}
