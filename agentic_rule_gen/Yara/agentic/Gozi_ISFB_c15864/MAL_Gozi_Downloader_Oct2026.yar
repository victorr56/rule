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
rule MAL_Gozi_Downloader_Oct2026
{
    meta:
        description = "Detects a Gozi ISFB downloader component based on a unique server key and other configuration artifacts. The rule can be triggered by the unique server key alone, or by a combination of four other configuration artifacts."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/gozi-latest-ttps/"
        date = "2026-10-23"
        hash1 = "011F6F038B1398C03AE15D3CB81412D32AD0AD554DFBB5D38FAE78577FB2B777"
        hash2 = "3EF96CFB78CB553943CE591C985FDC793D2ACF342A536B90D0F9EF72BDB15ECD"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        // Strong anchor: 16-byte key with mixed character classes
        $x1 = "guVZ8lGzorgMS7cj" ascii  // source: figure_or_disassembly

        // Supporting strings from configuration
        $s1 = "update.zonealarm.com" ascii  // source: figure_or_disassembly
        $s2 = "/drew/" ascii  // source: figure_or_disassembly
        $s3 = "iiso.in" ascii  // source: figure_or_disassembly
        $s4 = ".jlk" ascii  // source: figure_or_disassembly
        $s5 = "7776" ascii  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            $x1 or
            4 of ($s*)
        )
}
