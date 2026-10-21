/*
    This rule detects CHOSEN BRICK malware, used by Iranian state cyber actors.
    The detection is based on a unique mutex string reported as commonly
    used by the malware. Another reported mutex is present but is too weak 
    to be used for detection alone.
*/

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

rule APT_CHOSEN_BRICK_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-16"
        description = "This rule detects CHOSEN BRICK malware by searching for a specific mutex string."
        reference = "https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists"
        malware_family = "CHOSEN BRICK"
        threat_actor = "Iranian state cyber actors"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, s1"

    strings:
        $x1 = "noi672pp434awkc12f" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        1 of ($x*)
}
