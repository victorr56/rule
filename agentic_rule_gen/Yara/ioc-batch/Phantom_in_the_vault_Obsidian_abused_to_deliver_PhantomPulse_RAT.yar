// Phantom in the vault: Obsidian abused to deliver PhantomPulse RAT
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/phantom-in-the-vault

import "hash"

rule IOC_Phantom_in_the_vault_Obsidian_abused_to_deliver_PhantomPulse_RAT_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Phantom in the vault: Obsidian abused to deliver PhantomPulse RAT. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/phantom-in-the-vault"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206" or
        hash.md5(0, filesize) == "a6fa4adfc20e8e6b77e2dd631dc8ff18" or
        hash.md5(0, filesize) == "dcf5a9b27cbeedb769ccc8635d204af9" or
        hash.md5(0, filesize) == "346272f0582541ae5dd08429bb4dc4ff"
}

