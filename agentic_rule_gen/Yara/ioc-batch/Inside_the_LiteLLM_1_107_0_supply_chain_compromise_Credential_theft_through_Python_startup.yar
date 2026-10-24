// Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks
// Source: microsoft-security | https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/

import "hash"

rule IOC_Inside_the_LiteLLM_1_107_0_supply_chain_compromise_Credential_theft_through_Python_startup_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "microsoft-security"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25" or
        hash.sha256(0, filesize) == "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea" or
        hash.sha256(0, filesize) == "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa" or
        hash.sha256(0, filesize) == "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465" or
        hash.sha256(0, filesize) == "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb" or
        hash.sha256(0, filesize) == "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d" or
        hash.sha256(0, filesize) == "7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d" or
        hash.sha256(0, filesize) == "0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a" or
        hash.sha256(0, filesize) == "668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6" or
        hash.sha256(0, filesize) == "462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7" or
        hash.sha256(0, filesize) == "c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054" or
        hash.sha256(0, filesize) == "1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00" or
        hash.sha256(0, filesize) == "12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484"
}

