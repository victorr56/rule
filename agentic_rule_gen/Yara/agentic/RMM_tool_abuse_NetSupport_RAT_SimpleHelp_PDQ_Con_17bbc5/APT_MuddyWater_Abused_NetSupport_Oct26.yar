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
rule APT_MuddyWater_Abused_NetSupport_Oct26
{
    meta:
        description = "Detects potentially malicious or cracked versions of NetSupport Manager RMM tool based on specific strings associated with MuddyWater activity. The condition requires the presence of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://redcanary.com/blog/security-operations/rmm-detection/"
        date = "2024-05-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "s1, s2, s3"
        malware_family = "NetSupport"
        threat_actor = "MuddyWater"

    strings:
        $s1 = "HANEYMANEY" ascii wide  // source: prose
        $s2 = "NSM1234" ascii wide  // source: prose
        $s3 = "NetSupport Manager/1.3" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        3 of them
}
