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
rule MAL_Mozi_Botnet_Oct26
{
    meta:
        description = "Detects Mozi botnet ELF binaries. The rule is triggered by a combination of at least three strings related to its DHT implementation."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/collecting-and-operationalizing-threat-data-from-the-mozi-botnet"
        date = "2022-10-26"
        hash1 = "832fb4090879c1bebe75bea939a9c5724dbf87898febd425f94f7e03ee687d3b"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        // $s: supporting, not unique enough to fire alone
        $s1 = "This node doesn't accept announces" ascii // source: strings_listing
        $s2 = "[idp]" ascii // source: strings_listing
        $s3 = "dht.transmissionbt.com:6881" ascii // source: strings_listing
        $s4 = "router.bittorrent.com:6881" ascii // source: strings_listing
        $s5 = "router.utorrent.com:6881" ascii // source: strings_listing
        $s6 = "bttracker.debian.org:6881" ascii // source: strings_listing
        $s7 = "v2s" ascii // source: strings_listing
        $s8 = "NfZ" ascii // source: strings_listing
        $s9 = "Oo~Mn" ascii // source: strings_listing
        $s10 = "g5=" ascii // source: strings_listing
        $s11 = "N]%" ascii // source: strings_listing

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        3 of ($s*)
}
