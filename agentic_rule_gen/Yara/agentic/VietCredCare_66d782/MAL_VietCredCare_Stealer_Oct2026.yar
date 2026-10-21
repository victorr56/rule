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
import "pe"
import "dotnet"

rule MAL_VietCredCare_Stealer_Oct2026
{
    meta:
        description = "Detects VietCredCare .NET stealer. The rule may fire on unique Vietnamese language strings related to Facebook ad account checks, or on a combination of supporting artifacts like persistence filenames and C2 URLs."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/vietcredcare-stealer/"
        date = "2026-10-18"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        hash1 = "bd9eb106e265c5d0ae7a9e9d2d5925d558128599b1ba4a4cbc29b6fc7b3f48f0"
        hash2 = "71c4d0fc03bc4e083f64b2f80b2242618fb725efd64f362446f98c6d2051834f"
        hash3 = "b5621b540d1ca1dd802397822145ae4f80e96e59b81fdc8d0a7b18919ceadd12"
        hash4 = "17598536cf0bac6cb0d589410682e2cd9f813ea52bc931fe85292b149dbeb659"
        hash5 = "20ac10ea3a964c25f09b0008406388cf4195828eed6daaeda139c55ce84986f4"
        unverified_strings = "x1, x2, s2, s3"

    strings:
        // $x* strings are highly unique and can fire alone
        $x1 = { 44 01 E3 00 20 00 6B 00 69 00 1B 01 6D 00 20 00 74 00 72 00 61 00 20 00 74 00 E0 00 69 00 20 00 6B 00 68 00 6F 00 A3 01 6E 00 20 00 71 00 75 00 A3 01 6E 00 67 00 20 00 63 00 E1 00 6F 00 20 00 78 00 6F 00 6E 00 67 00 } // "Đã kiểm tra tài khoản quảng cáo xong" (UTF-16-LE) - source: explicit_literal
        $x2 = "số lượng quảng cáo = 0 + %FACEBOOK_DATA%" ascii wide // source: explicit_literal

        // $s* strings are supporting and require a combination
        $s1 = "crsysys.exe" ascii wide // source: figure_or_disassembly
        $s2 = "https://business.facebook.com/content_management/" ascii wide // source: explicit_literal
        $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36" ascii wide // source: explicit_literal
        $s4 = "https://ipinfo.io/ip" ascii wide // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 2MB
        and dotnet.is_dotnet
        and (
            1 of ($x*) or
            3 of ($s*)
        )
}
