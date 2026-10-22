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
rule APT_APT41_BlackX_Driver_Oct2026
{
    meta:
        description = "Detects the BlackX UEFI bootkit kernel driver based on unique certificate artifacts. This rule can fire on the certificate subject or serial number."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        date = "2026-10-22"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$x1, $x2"

    strings:
        $x1 = { E6 B8 A9 E6 B1 9F E5 8C BA E6 98 8E E5 AE 87 E7 BD 91 E7 BB 9C E6 8A 80 E6 9C AF E6 9C 8D E5 8A A1 E5 B7 A5 E4 BD 9C E5 AE A4 } // source: explicit_literal, certificate subject "\u6e29\u6c5f\u533a\u660e\u5b87\u7f51\u7edc\u6280\u672f\u670d\u52a1\u5de5\u4f5c\u5ba4" (UTF-8)
        $x2 = "0bcdf5e0da32d68900b8b7638459d072" ascii // source: explicit_literal, certificate serial number

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of them
}
