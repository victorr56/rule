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
rule MAL_CUBA_Ransomware_Oct2026
{
    meta:
        description = "Detects CUBA ransomware based on unique ransom note strings and other indicators. The rule can be triggered by a single unique ransom note string or a combination of three supporting indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/cuba-ransomware-malware-analysis"
        date = "2026-10-25"
        hash1 = "0f385cc69a93abeaf84994e7887cb173e889d309a515b55b2205805bdfe468a3"
        hash2 = "3654af86dc682e95c811e4fd87ea405b627bca81c656f3a520a4b24bf2de879f"
        hash3 = "32beefe2c5e28e87357813c0ef91f47b631a3dff4a6235256aa123fc77564346"
        hash4 = "bcf0f202db47ca671ed6146040795e3c8315b7fb4f886161c675d4ddf5fdd0c4"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$s3"

    strings:
        // Strong anchors (>= 16 chars)
        $x1 = "!! READ ME !!.txt" ascii wide  // source: strings_listing
        $x2 = "Good day. All your files are encrypted. For decryption contact us." ascii wide  // source: strings_listing
        $x3 = "We also inform that your databases, ftp server and file server were downloaded by us to our servers." ascii wide  // source: strings_listing

        // Supporting strings
        $s1 = ".cuba" ascii wide  // source: strings_listing
        $s2 = "http://cuba4ikm4jakjgmkezytyawtdgr2xymvy6nvzgw5cglswg3si76icnqd.onion/" ascii  // source: strings_listing
        $s3 = "FIDEL.CA" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB
        and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
