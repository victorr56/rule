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
rule SUSP_Cactus_QlikSense_PostEx_Output_Oct2026
{
    meta:
        description = "Detects files containing command output consistent with Cactus ransomware post-exploitation on Qlik Sense servers. The rule matches on specific command prompts found in the output, or a combination of file paths."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.fox-it.com/2024/04/25/sifting-through-the-spines-identifying-potential-cactus-ransomware-victims/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // These strings are from command output redirected to a file.
        $x1 = "PS C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts> dir" ascii wide // source: figure_literals
        $x2 = "Directory: C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts" ascii wide // source: figure_literals

        $s1 = "C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts\\qle.ttf" ascii wide // source: figure_literals
        $s2 = "C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts\\qle.woff" ascii wide // source: figure_literals
        $s3 = "C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts\\lui-icons.ttf" ascii wide // source: figure_literals
        $s4 = "C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts\\qlikview-sans-bold.ttf" ascii wide // source: figure_literals
        $s5 = "C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts\\qlikview-sans.ttf" ascii wide // source: figure_literals
        $s6 = "C:\\Program Files\\Qlik\\Sense\\Client\\qmc\\fonts\\SourceSansPro-Regular.ttf" ascii wide // source: figure_literals

    condition:
        // Not a valid TTF/WOFF/WOFF2 font file header
        (
            uint32be(0) != 0x00010000 and
            uint32be(0) != 0x74727565 and
            uint32be(0) != 0x774F4646 and
            uint32be(0) != 0x774F4632
        )
        and filesize < 1MB
        and (
            1 of ($x*) or
            3 of ($s*)
        )
}
