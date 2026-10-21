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
rule MAL_WWAHost_WinRT_Abuse_SetupScript_Oct2026
{
    meta:
        description = "Detects setup scripts associated with the WWAHost WinRT abuse technique for OAuth token theft. A match requires at least four of the strings associated with the malicious script."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/stealing-oauth-tokens-through-microsofts-front-door"
        date = "2024-05-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s7"

    strings:
        $s1 = "WWAHost OAuth Token Theft - Windows Setup" ascii wide  // source: figure_literals, Figure 2:
        $s2 = "MicrosoftAccountVerification_ap5pwk43ghhtp" ascii wide  // source: figure_or_disassembly
        $s3 = "[+] Manifest written:" ascii wide  // source: figure_literals, Figure 2:
        $s4 = "[*] Registering AppX package..." ascii wide  // source: figure_literals, Figure 2:
        $s5 = "[+] Package registered successfully." ascii wide  // source: figure_literals, Figure 2:
        $s6 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock" ascii wide  // source: explicit_literal
        $s7 = "AllowAllTrustedApps" ascii wide  // source: prose

    condition:
        filesize < 1MB and
        4 of ($s*)
}
