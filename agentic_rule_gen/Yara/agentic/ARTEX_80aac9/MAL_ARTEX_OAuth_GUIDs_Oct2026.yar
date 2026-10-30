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
rule MAL_ARTEX_OAuth_GUIDs_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-30"
        description = "Detects tools related to the ARTEX framework by identifying hardcoded OAuth App IDs used by threat actor Storm-0940. This rule triggers on a PE file containing at least one of three specific GUIDs."
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/"
        malware_family = "ARTEX"
        threat_actor = "Storm-0940"
        score = 60
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        tlp = "WHITE"

    strings:
        $x1 = "506e08f9-6e9a-4da4-942b-a099a03644ae" ascii wide  // source: figure_or_disassembly
        $x2 = "24205314-2b89-4e07-a2a4-579e898a5640" ascii wide  // source: figure_or_disassembly
        $x3 = "0de14c77-b9b0-4137-9360-34878a929827" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        1 of ($x*)
}
