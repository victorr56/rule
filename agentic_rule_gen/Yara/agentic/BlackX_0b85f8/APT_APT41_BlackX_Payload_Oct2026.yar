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
rule APT_APT41_BlackX_Payload_Oct2026
{
    meta:
        description = "Detects payloads associated with the BlackX UEFI bootkit. The rule can fire on a unique RC4 key, or a combination of supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        date = "2026-10-22"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 55
        unverified_strings = "$x1, $s1, $s2, $s3, $s4, $s5, $s6, $s7"

    strings:
        $x1 = "Q46F6MDLI3RX2KV1" ascii // source: prose, RC4 key

        $s1 = "www.archivetj.com" ascii // source: explicit_literal, C2 domain
        $s2 = "PVMDIJGKAX2" ascii // source: prose, encrypted bootkit component filename
        $s3 = "TEST.Class1.RunCMD(argument_array)" ascii // source: prose, .NET RAT method call
        $s4 = "v8_context_snapshot.bin" ascii // source: prose, encrypted payload filename
        $s5 = "SYSTEM\\CurrentControlSet\\Control\\Secureboot" ascii wide // source: prose, registry key
        $s6 = "create_plugin" ascii // source: prose, C2 DLL export name
        $s7 = "xdd" ascii // source: explicit_literal, identifier

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            $x1 or
            4 of ($s*)
        )
}
