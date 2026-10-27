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
rule MAL_AgentTesla_Oct2026
{
    meta:
        description = "Detects AgentTesla malware based on unique strings observed in recent campaigns. The rule triggers on a combination of at least three such strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/attack-chain-leads-to-xworm-and-agenttesla"
        date = "2026-10-27"
        hash1 = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$s6"

    strings:
        $s1 = "GetMozillaFromLogins" ascii wide  // source: strings_listing
        $s2 = "AccountConfiguration+username" ascii wide  // source: strings_listing
        $s3 = "MailAccountConfiguration" ascii wide  // source: strings_listing
        $s4 = "SmtpAccountConfiguration" ascii wide  // source: strings_listing
        $s5 = "GetMozillaFromSQLite" ascii wide  // source: strings_listing
        $s6 = "discord.com/api/webhooks/1089956337733087274/uYNA_D8Ns1z9NZ3B1mGp0XXyGq-785KLGIfEAZsrz3TJd5fvOjXA927F7bUTTzbNT6Zk" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        3 of them
}
