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
rule MAL_DOORME_Winnti_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-26"
        description = "Detects DOORME, a native IIS module backdoor used by Winnti Group (REF2924). The rule matches on a custom Base64 alphabet, hardcoded keys and tokens, and a hex pattern for its custom Base64 implementation. The rule will fire if any of these strong, unique indicators are present."
        reference = "https://www.elastic.co/security-labs/threat-command/update-to-the-REF2924-intrusion-set-and-related-campaigns"
        malware_family = "DOORME"
        threat_actor = "Winnti Group"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x3, x4, x5"

    strings:
        // All strings are strong anchors and can fire the rule alone.
        $x1 = "VZkW6UKaPY8JR0bnMmzI4ugtCxsX2ejiE5q/9OH3vhfw1D+lQopdABTLrcNFGSy7" ascii  // source: explicit_literal
        $x2 = { 8A 45 ?? 8A 4D ?? C0 E0 ?? 89 CA C0 EA ?? 80 E2 ?? 08 C2 88 55 ?? C0 E1 ?? 8A 45 ?? C0 E8 ?? 24 ?? 08 C8 88 45 ?? 41 83 C4 ?? 31 F6 44 39 E6 7D ?? 66 90 }  // source: strings_listing
        $x3 = "79cfdd0e92b120faadd7eb253eb800d0" ascii  // source: explicit_literal
        $x4 = "5a430ab45c7e142c70018b99fe0d2da3" ascii  // source: explicit_literal
        $x5 = "57ce15b304a97772" ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of ($x*)
}
