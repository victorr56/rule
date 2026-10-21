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
rule MAL_ModularRAT_Exodus_Loader_Oct2026
{
    meta:
        description = "Detects the loader component of a modular RAT, delivered via a trojanized Exodus wallet installer. The rule matches on a hardcoded AES key, IV, or a specific JavaScript snippet used to hide the application window."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat"
        date = "2026-10-17"
        hash1 = "c513a7346484ee69a2931c4a89956ee50aa63e4366ef989315e669d8f10d7485"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $x2"

    strings:
        $x1 = "SXD9WPcPiVBt76Y09wg/YLDTk/uOOrKWbSmMSrystI8=" ascii  // source: explicit_literal
        $x2 = "3ssyBCFqLnkYA2aJ70rxRw==" ascii  // source: explicit_literal
        $x3 = "BrowserWindow.prototype.show = function () {};" ascii  // source: figure_or_disassembly

    condition:
        ( uint16(0) == 0x5a4d or uint32be(0) == 0xD0CF11E0 ) and
        filesize < 30MB and
        1 of ($x*)
}
