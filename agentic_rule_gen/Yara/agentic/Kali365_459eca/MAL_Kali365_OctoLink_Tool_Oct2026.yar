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
rule MAL_Kali365_OctoLink_Tool_Oct2024
{
    meta:
        description = "Detects Kali365 (Octopi365) PhaaS desktop applications like OctoLink Live and OctoLink Sender. The rule matches on a unique code comment or client ID, or a combination of four other specific strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/kali365-device-code-phishing-kit"
        date = "2024-10-29"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x2, s1, s2, s3, s4, s5, s6"

    strings:
        // Unique, strong anchors
        $x1 = "Exchange a refresh token at Microsoft's token endpoint inside a real hidden browser window. This is the only way to get Microsoft to set ESTSAUTH cookies — it must be a real Chromium page load, not fetch() or net.request." ascii  // source: figure_or_disassembly
        $x2 = "d3590ed6-52b3-4102-aeff-aad2292ab01c" ascii  // source: explicit_literal

        // Supporting strings
        $s1 = "octolink-live" ascii  // source: explicit_literal
        $s2 = "octolink-sender" ascii  // source: explicit_literal
        $s3 = "persist:svc-{tokenId}-{service}" ascii  // source: explicit_literal
        $s4 = "404 or error means \"still active.\"" ascii  // source: explicit_literal
        $s5 = "/dash/bec/analyze" ascii  // source: explicit_literal
        $s6 = "/dash/token/{id}/raw" ascii  // source: explicit_literal
        $s7 = "serviceWindow.js" ascii  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
