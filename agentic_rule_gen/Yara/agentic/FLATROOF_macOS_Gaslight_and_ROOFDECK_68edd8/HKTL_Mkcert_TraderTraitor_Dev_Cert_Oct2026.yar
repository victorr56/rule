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
rule HKTL_Mkcert_TraderTraitor_Dev_Cert_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        date = "2026-10-16"
        description = "Detects PE files embedding a specific self-signed development certificate generated with the mkcert tool. This certificate was observed in TraderTraitor's ROOFDECK malware and its subject is specific to the actor's development environment."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50

    strings:
        $x1 = "O=mkcert development CA, OU=ub@ub-Standard-PC-Q35-ICH9-2009, CN=mkcert ub@ub-Standard-PC-Q35-ICH9-2009" ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        $x1
}
