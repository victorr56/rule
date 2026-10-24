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
rule APT_Nigerian_KremlinRATs_Campaign_Oct2026
{
    meta:
        description = "Detects artifacts associated with a Nigerian threat actor's campaigns, which often leverage various RATs and 'kremlin' themed C2 infrastructure."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/rats-nigeria/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "s6, s7, s8"

    strings:
        $s1 = "https://paste.ee/r/rSrae" ascii wide  // source: figure_or_disassembly
        $s2 = "office-cloud-reserve.com" ascii wide  // source: figure_or_disassembly
        $s3 = "ftp.centredebeautenellycettier.fr" ascii wide  // source: figure_or_disassembly
        $s4 = "avantfirewall.exe" ascii wide  // source: figure_or_disassembly
        $s5 = "wd32PrvSE.wmf" ascii wide  // source: figure_or_disassembly
        $s6 = "kremlin-turbo.duckdns.org" ascii wide  // source: prose
        $s7 = "kremlin-crimea.duckdns.org" ascii wide  // source: prose
        $s8 = "screw-malwrhunterteams.com" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        3 of them
}
