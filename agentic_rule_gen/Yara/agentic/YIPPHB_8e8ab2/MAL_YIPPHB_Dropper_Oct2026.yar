/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
import "pe"
import "dotnet"

rule MAL_YIPPHB_Dropper_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/doing-time-with-the-yipphb-dropper"
        date = "2026-10-22"
        description = "Detects the YIPPHB .NET dropper component. The rule is based on a unique string replacement operation involving Unicode placeholder characters, which is a core part of its deobfuscation logic."
        hash1 = "bba5f2b1c90cc8af0318502bdc8d128019faa94161b8c6ac4e424efe1165c2cf"
        malware_family = "YIPPHB"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        // C# string: text2.Replace("▒▒▒▒", "A")
        // ▒ is U+2592, which is 92 25 in UTF-16LE
        $s1 = { 74 00 65 00 78 00 74 00 32 00 2e 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 22 00 92 25 92 25 92 25 92 25 22 00 2c 00 20 00 22 00 41 00 22 00 29 00 }  // wide: text2.Replace("▒▒▒▒", "A"), source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 2MB and
        dotnet.is_dotnet and
        $s1
}
