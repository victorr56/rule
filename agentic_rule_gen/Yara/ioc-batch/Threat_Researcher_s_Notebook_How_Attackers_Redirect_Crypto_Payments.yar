// Threat Researcher’s Notebook: How Attackers Redirect Crypto Payments
// Source: reversinglabs | https://www.reversinglabs.com/blog/threat-researchers-notebook-how-attackers-redirect-crypto-payments

import "hash"

rule IOC_Threat_Researcher_s_Notebook_How_Attackers_Redirect_Crypto_Payments_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Threat Researcher’s Notebook: How Attackers Redirect Crypto Payments. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "reversinglabs"
        reference   = "https://www.reversinglabs.com/blog/threat-researchers-notebook-how-attackers-redirect-crypto-payments"
        date        = "2026-10-30"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "e46f514e456c5e27f60854e4156234e6ae8c4dd5892ddb4d2d557de02fc2cd15" or
        hash.sha256(0, filesize) == "bb796bb63f6985e75dbb6c1f8eb8640dee859f989f09a4a2fd9102d33918139b" or
        hash.sha256(0, filesize) == "3cc7dab11f0f333fad56e428efaa638ccbf7af16eb4dfc8dab2621732fb22d92" or
        hash.sha256(0, filesize) == "5250927806bc7087963d16298a341c301fa0f29f94cd6eb40518827ede3b04d4" or
        hash.sha256(0, filesize) == "c49dc64559ca84df2716113592b84ada7704e783a3e31b3ab42b531cc835e996" or
        hash.sha256(0, filesize) == "2226f06646126f16779442632a472803e14e0d5bc5a7a22f172b8f58d3113593" or
        hash.sha256(0, filesize) == "030edb0266cbb6f7b998461096304bcf345a44ceb67ac16ae88a7839a539f271" or
        hash.sha256(0, filesize) == "12f14940567788a509fbb700948eb6f9eec1f311aa456ba6f6dba661c9dcc0da" or
        hash.sha256(0, filesize) == "17b2fa8686141b4f5d2e7bef36e992caa4ca8763827976d3fa8a45dc9a6eb4de" or
        hash.sha256(0, filesize) == "1943d401836d4f87ce42ab82e40d695a9c507bdb116714bdf7315d4a58af048c" or
        hash.sha256(0, filesize) == "3d3b91df2fdac41a8a455397e1037daade8c399286b2e1ae067eb1941c1a3113"
}

