// Malicious npm campaign targets developers integrating Twilio
// Source: reversinglabs | https://www.reversinglabs.com/blog/malicious-npm-campaign-twilio

import "hash"

rule IOC_Malicious_npm_campaign_targets_developers_integrating_Twilio_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Malicious npm campaign targets developers integrating Twilio. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "reversinglabs"
        reference   = "https://www.reversinglabs.com/blog/malicious-npm-campaign-twilio"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "ea40177789e7a1b972c27c61dffff195dd85c544" or
        hash.sha1(0, filesize) == "3fb29cf1ef3ce6b187e724c8e7dc4b6a5dfefa50" or
        hash.sha1(0, filesize) == "7108c1079ac0de030902b049770e8cb822e82055" or
        hash.sha1(0, filesize) == "985c294988e80f17414fb371b690080ee57387ea" or
        hash.sha1(0, filesize) == "35b21553837b74e1fc5ac43efd839cdc28109fdf" or
        hash.sha1(0, filesize) == "19c886b57a0c86e1efc82f4c4f2691f3ddc9f92c" or
        hash.sha1(0, filesize) == "fbc422912fa5af59ba278b30d8c1707e0fd1711b" or
        hash.sha1(0, filesize) == "fe4b42d7cf37ef2137fe5259626d51cb9922309e"
}

