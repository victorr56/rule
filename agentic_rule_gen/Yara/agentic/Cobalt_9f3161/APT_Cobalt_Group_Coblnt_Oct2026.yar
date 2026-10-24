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
rule APT_Cobalt_Group_Coblnt_Oct2026
{
    meta:
        description = "Detects binaries related to the Cobalt Group by looking for a combination of at least four strings associated with their tools and infrastructure, such as 'InfoStealer 0.2', 'Coblnt', or C2 domains."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/renaissance/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s2, s3, s4, s5, s6"

    strings:
        $s1 = "InfoStealer 0.2" ascii wide // source: prose
        $s2 = "Coblnt" ascii wide          // source: prose
        $s3 = "CobInt" ascii wide          // source: prose
        $s4 = "kaspersky-security.com" ascii wide // source: prose
        $s5 = "/Complaint.doc" ascii wide  // source: prose
        $s6 = "Complaint.scr" ascii wide   // source: prose

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and 4 of ($s*)
}
