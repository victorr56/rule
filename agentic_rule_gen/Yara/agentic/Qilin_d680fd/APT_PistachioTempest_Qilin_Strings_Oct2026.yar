/*
 Self-check
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
rule APT_PistachioTempest_Qilin_Strings_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/a-busy-agenda-darktraces-detection-of-qilin-ransomware-as-a-service-operator"
        date = "2026-10-17"
        description = "Detects components associated with Pistachio Tempest's use of Qilin ransomware, based on a unique certificate subject and a file download URI path. The rule can be triggered by either of the unique strings."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x2"

    strings:
        $x1 = "CN=ne.com,OU=key operations,O=1000,L=,ST=,C=KM" ascii  // source: explicit_literal
        $x2 = "/download/sihost64.dll" ascii  // source: explicit_literal

    condition:
        ( uint16(0) == 0x5a4d or uint32(0) == 0x464c457f ) and filesize < 20MB and
        1 of ($x*)
}
