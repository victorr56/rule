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
rule MAL_EtherRAT_TONResolver_Oct2024
{
    meta:
        description = "Detects EtherRAT and TONResolver executables that use blockchain smart contracts for C2 resolution. Detection is based on hardcoded smart contract addresses."
        author = "ioc-yara-daily (agentic)"
        reference = "https://cofense.com/blog/from-guest-complaints-to-malware-blockchain-abuse-targets-hotels"
        date = "2024-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x2"

    strings:
        $x1 = "0x277852e1C349b03c79E348018a8391bD21C412E8" nocase ascii wide // source: report explicit_literal, EtherRAT smart contract
        $x2 = "0:c66119f0e5635c4380441d7a79baf0c02a0ab7ea6cd78de06507fc5dc2c1a5d9" nocase ascii wide // source: report explicit_literal, TONResolver smart contract

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of ($x*)
}
