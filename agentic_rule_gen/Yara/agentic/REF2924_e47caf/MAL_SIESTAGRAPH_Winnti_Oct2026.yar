import "dotnet"

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
rule MAL_SIESTAGRAPH_Winnti_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-26"
        description = "Detects SIESTAGRAPH, a .NET implant used by Winnti Group (REF2924). The rule matches on a unique typelib GUID, or a combination of strings related to its C2 mechanism of creating draft emails via the Microsoft Graph API. It requires the file to be a .NET assembly."
        reference = "https://www.elastic.co/security-labs/threat-command/update-to-the-REF2924-intrusion-set-and-related-campaigns"
        malware_family = "SIESTAGRAPH"
        threat_actor = "Winnti Group"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "graph.microsoft.com"

    strings:
        $x1 = "createEmailDraft" wide ascii  // source: strings_listing
        $s1 = "graph.microsoft.com" wide ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        dotnet.is_dotnet and
        (
            dotnet.typelib == "d3590ed6-52b3-4102-aeff-aad2292ab01c" or  // source: figure_or_disassembly
            ($x1 and $s1)
        )
}
