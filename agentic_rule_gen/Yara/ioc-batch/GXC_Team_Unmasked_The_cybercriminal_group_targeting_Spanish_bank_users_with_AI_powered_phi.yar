// GXC Team Unmasked: The cybercriminal group targeting Spanish bank users with AI-powered phishing tools and Android malware
// Source: group-ib | https://www.group-ib.com/blog/gxc-team-unmasked/

import "hash"

rule IOC_GXC_Team_Unmasked_The_cybercriminal_group_targeting_Spanish_bank_users_with_AI_powered_phi_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: GXC Team Unmasked: The cybercriminal group targeting Spanish bank users with AI-powered phishing tools and Android malwa. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/gxc-team-unmasked/"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "402544c3c74924c7a9f355108f474fd3b0d643a38aba45c933d880b1c2a206de" or
        hash.sha256(0, filesize) == "e65c24d6e5f883ca02f79edc0bd4fdbd28dc130f11fdbca75b7fd26b2587bfa4" or
        hash.sha256(0, filesize) == "b1b0eb10002669be6b32792a196227f1d595e26b0039e719ef9357e2b8f5361b" or
        hash.sha256(0, filesize) == "944f0568ce0394b4db3fd618d6f1a0c53f94712f91fa162a4f28b1f93ad9f18f" or
        hash.sha256(0, filesize) == "2826a1c5ed1456ba00421ffdd4e331c691b39fc0334f4590eb860c38452d606b" or
        hash.sha256(0, filesize) == "e047f13914278ad4e5cc63d30cfdac56cf20f86d3a4cf26414001e9aed5f9875" or
        hash.sha256(0, filesize) == "05a5cf0d0eb2a224d0326f2ac95a2d60ca9935d015070ed17439c2dd7a79d50c" or
        hash.sha256(0, filesize) == "ae2976f99876605df0e043ac62081af43426286ec5759dc3eca080e26cb16b97" or
        hash.sha256(0, filesize) == "492682f877607ee99df2ddd2bd5953fd727bdf6e19d397de9dbbafd582bcad75"
}

