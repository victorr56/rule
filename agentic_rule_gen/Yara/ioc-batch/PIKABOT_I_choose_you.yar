// PIKABOT, I choose you!
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/pikabot-i-choose-you

import "hash"

rule IOC_PIKABOT_I_choose_you_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: PIKABOT, I choose you!. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/pikabot-i-choose-you"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "2f66fb872c9699e04e54e5eaef982784b393a5ea260129a1e2484dd273a5a88b" or
        hash.sha256(0, filesize) == "ca5fb5814ec62c8f04936740aabe2664b3c7d036203afbd8425cd67cf1f4b79d"
}

