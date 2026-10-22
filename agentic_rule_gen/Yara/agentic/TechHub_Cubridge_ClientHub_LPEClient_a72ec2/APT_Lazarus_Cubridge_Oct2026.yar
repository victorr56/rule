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
rule APT_Lazarus_Cubridge_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects the Cubridge malware component used by the Lazarus Group. The rule matches on unique authentication tokens, passwords, C2 URL generation keywords, or a combination of several supporting strings like internal module names and export functions. This can be triggered by one of the unique, high-entropy strings, or four of the supporting strings."
        family = "Cubridge"
        reference = "https://securelist.com/lazarus-operation-flashhole/121541/"
        threat_actor = "Lazarus Group"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x2, s1, s2, s5, s6, s7"

    strings:
        $x1 = "KW4Ofw982CNJjxd51AVqkGAop" ascii // source: explicit_literal, Cubridge fixed authentication token.
        $x2 = "xdkiTajAAxc3i/w[<881fnC!G*cb1Dit2sh.gAk/" ascii // source: explicit_literal, Hard-coded password for legacy ZipCrypto used by Cubridge.
        $x3 = "economy, opinion, politics, national, international, medical, investment, sports, lifestyle, shopping, culture" ascii // source: figure_or_disassembly, Cubridge predefined word list for C2 URL generation (page1).

        $s1 = "ActionModule.dll" ascii wide // source: explicit_literal, Internal name for Cubridge module managing file/process operations.
        $s2 = "FunctionModule.dll" ascii wide // source: explicit_literal, Internal name for Cubridge module implementing Windows commands.
        $s3 = "article, list, story" ascii // source: figure_or_disassembly, Cubridge predefined word list for C2 URL generation (page2).
        $s4 = "cubedesign.co.kr/news/" ascii // source: figure_or_disassembly, Hardcoded Cubridge C2 URL template (AABBCC is replaced).
        $s5 = "AppinfoView" ascii // source: explicit_literal, Export function in ActionModule invoked by Cubridge.
        $s6 = "PresentationFontConfig" ascii // source: explicit_literal, Export function in FunctionModule invoked by Cubridge.
        $s7 = "encrypted_key" ascii wide // source: explicit_literal, Keyword to extract AES key from Chromium's Local State file.

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
