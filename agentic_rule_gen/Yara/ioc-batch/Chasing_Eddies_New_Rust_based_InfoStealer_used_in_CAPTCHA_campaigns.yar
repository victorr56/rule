// Chasing Eddies: New Rust-based InfoStealer used in CAPTCHA campaigns
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/eddiestealer

import "hash"

rule IOC_Chasing_Eddies_New_Rust_based_InfoStealer_used_in_CAPTCHA_campaigns_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Chasing Eddies: New Rust-based InfoStealer used in CAPTCHA campaigns. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/eddiestealer"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "47409e09afa05fcc9c9eff2c08baca3084d923c8d82159005dbae2029e1959d0" or
        hash.sha256(0, filesize) == "162a8521f6156070b9a97b488ee902ac0c395714aba970a688d54305cb3e163f" or
        hash.sha256(0, filesize) == "f8b4e2ca107c4a91e180a17a845e1d7daac388bd1bb4708c222cda0eff793e7a" or
        hash.sha256(0, filesize) == "53f803179304e4fa957146507c9f936b38da21c2a3af4f9ea002a7f35f5bc23d" or
        hash.sha256(0, filesize) == "20eeae4222ff11e306fded294bebea7d3e5c5c2d8c5724792abf56997f30aaf9" or
        hash.sha256(0, filesize) == "1bdc2455f32d740502e001fce51dbf2494c00f4dcadd772ea551ed231c35b9a2" or
        hash.sha256(0, filesize) == "d905ceb30816788de5ad6fa4fe108a202182dd579075c6c95b0fb26ed5520daa" or
        hash.sha256(0, filesize) == "b8b379ba5aff7e4ef2838517930bf20d83a1cfec5f7b284f9ee783518cb989a7" or
        hash.sha256(0, filesize) == "f6536045ab63849c57859bbff9e6615180055c268b89c613dfed2db1f1a370f2" or
        hash.sha256(0, filesize) == "d318a70d7f4158e3fe5f38f23a241787359c55d352cb4b26a4bd007fd44d5b80" or
        hash.sha256(0, filesize) == "73b9259fecc2a4d0eeb0afef4f542642c26af46aa8f0ce2552241ee5507ec37f" or
        hash.sha256(0, filesize) == "2bef71355b37c4d9cd976e0c6450bfed5f62d8ab2cf096a4f3b77f6c0cb77a3b" or
        hash.sha256(0, filesize) == "218ec38e8d749ae7a6d53e0d4d58e3acf459687c7a34f5697908aec6a2d7274d" or
        hash.sha256(0, filesize) == "5330cf6a8f4f297b9726f37f47cffac38070560cbac37a8e561e00c19e995f42" or
        hash.sha256(0, filesize) == "acae8a4d92d24b7e7cb20c0c13fd07c8ab6ed8c5f9969504a905287df1af179b" or
        hash.sha256(0, filesize) == "0f5717b98e2b44964c4a5dfec4126fc35f5504f7f8dec386c0e0b0229e3482e7" or
        hash.sha256(0, filesize) == "e8942805238f1ead8304cfdcf3d6076fa0cdf57533a5fae36380074a90d642e4" or
        hash.sha256(0, filesize) == "7930d6469461af84d3c47c8e40b3d6d33f169283df42d2f58206f43d42d4c9f4" or
        hash.md5(0, filesize) == "20745dc4d048f67e0b62aca33be80283" or
        hash.md5(0, filesize) == "6cc654225172ef70a189788746cbb445" or
        hash.md5(0, filesize) == "c8c3e658881593d798da07a1b80f250c" or
        hash.md5(0, filesize) == "4776ff459c881a5b876da396f7324c64"
}

