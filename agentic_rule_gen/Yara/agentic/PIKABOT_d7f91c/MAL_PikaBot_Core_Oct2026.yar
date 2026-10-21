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
import "dotnet"

rule MAL_PikaBot_Core_Oct2026
{
    meta:
        description = "Detects the core component of PIKABOT malware based on a unique typelib GUID or a unique hex pattern. The rule can be triggered by either of these strong unique identifiers."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/pikabot-i-choose-you"
        date = "2026-10-18"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s2"

    strings:
        // Unique, strong anchor
        $x1 = { 72 26 [6] 6F 24 [6] CB 0A [6] 6C 03 [6] 92 07 }  // source: strings_listing

        // Supporting strings

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        (
            // typelib GUID was "{6F70D3AF-34EF-433C-A803-E83654F6FD7C}", source: explicit_literal
            dotnet.typelib == "6F70D3AF-34EF-433C-A803-E83654F6FD7C" or
            $x1
        )
}
