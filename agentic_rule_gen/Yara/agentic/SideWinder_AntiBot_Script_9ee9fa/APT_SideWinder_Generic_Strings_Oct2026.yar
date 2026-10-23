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
rule APT_SideWinder_Generic_Strings_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-23"
        description = "Detects artifacts associated with SideWinder campaigns, such as specific filenames and C2 domains."
        reference = "https://www.group-ib.com/blog/sidewinder-antibot/"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "x1, x2, s1, s2, s3, s4, s5, s6, s10"

    strings:
        $x1 = "Pay and Pension Increase Circular_Finance Division.zip" ascii wide // source: explicit_literal
        $x2 = "Pay and Pension Increase Circular_Finance Division.pdf.lnk" ascii wide // source: explicit_literal

        $s1 = "Duser.dll" ascii wide // source: prose
        $s2 = "finance.govpk-mail.net" ascii wide // source: explicit_literal
        $s3 = "api.vpn-secure.co" ascii wide // source: explicit_literal
        $s4 = "faujifoundation.bitlyy.me" ascii wide // source: explicit_literal
        $s5 = "kdf-mail.com" ascii wide // source: explicit_literal
        $s6 = "/secureVpn/register" ascii wide // source: explicit_literal
        $s7 = "vpn.pakgov.net" ascii wide // source: figure_or_disassembly
        $s8 = "csd.pakgov.net" ascii wide // source: figure_or_disassembly
        $s9 = "nadra.pakgov.net" ascii wide // source: figure_or_disassembly
        $s10 = "ross jack" ascii wide // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
