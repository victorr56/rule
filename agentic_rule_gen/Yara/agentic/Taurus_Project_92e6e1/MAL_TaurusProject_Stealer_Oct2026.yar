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
rule MAL_TaurusProject_Stealer_Oct2026
{
    meta:
        description = "Detects Taurus Project stealer, an evolution of PredatorTheThief, distributed through fake carding shops. Rule can be triggered by a unique message string or a combination of four supporting strings (filenames/domains)."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/cannibal-carders-fake-shops/"
        date = "2026-10-23"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s8, s9, s10, s11, s12, s13, s14"

    strings:
        // Strong anchor string from the fake shop download page, likely embedded in the malware
        $x1 = "Your account is activated! For safe use of the store. Download the protected app" ascii wide  // source: artifact unique_string, from figure_or_disassembly

        // Supporting strings: filenames and domains associated with the malware and its distribution
        $s1 = "panelcontorl.rar" ascii wide  // source: artifact file_name, from figure_or_disassembly
        $s2 = "PanelControl.exe" ascii wide  // source: artifact file_name, from figure_or_disassembly
        $s3 = "LitePanel.exe" ascii wide  // source: artifact file_name, from figure_or_disassembly
        $s4 = "monerdomen.ru" ascii wide  // source: artifact domain, from figure_or_disassembly
        $s5 = "briansclub.ru" ascii wide  // source: artifact domain, from figure_or_disassembly
        $s6 = "unicc.cx" ascii wide  // source: artifact domain, from figure_or_disassembly
        $s7 = "festore-dumps.ru" ascii wide  // source: artifact domain, from figure_or_disassembly
        $s8 = "panelshopload.su" ascii wide  // source: artifact domain, from prose
        $s9 = "unicc.cm" ascii wide  // source: artifact domain, from prose
        $s10 = "briansclub.store" ascii wide  // source: artifact domain, from prose
        $s11 = "briansclub.shop" ascii wide  // source: artifact domain, from prose
        $s12 = "briansclub.me" ascii wide  // source: artifact domain, from prose
        $s13 = "jokerstash.cc" ascii wide  // source: artifact domain, from prose
        $s14 = "unicc.me" ascii wide  // source: artifact domain, from prose

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            $x1 or
            4 of ($s*)
        )
}
