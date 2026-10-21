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
rule MAL_CHAINDROP_Package_Json_Oct2026
{
    meta:
        description = "Detects package.json files modified by the CHAINDROP worm to execute a malicious dropper. This rule requires the 'scripts' block to contain a 'preinstall' hook that executes 'node setup.mjs'."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // "node setup.mjs" is 14 bytes, not strong enough to be a lone $x anchor.
        $s1 = "node setup.mjs" ascii  // source: Preinstall hook in package.json, figure_or_disassembly

        // 'scripts' and 'preinstall' are standard keys, used here as supporting indicators.
        $s2 = "scripts" ascii  // source: Preinstall hook in package.json, figure_or_disassembly
        $s3 = "preinstall" ascii  // source: Preinstall hook in package.json, figure_or_disassembly

    condition:
        filesize < 20KB and
        3 of ($s*)
}
