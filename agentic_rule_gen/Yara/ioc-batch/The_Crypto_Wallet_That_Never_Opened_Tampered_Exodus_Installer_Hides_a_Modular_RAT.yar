// The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular RAT
// Source: huntress | https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat

import "hash"

rule IOC_The_Crypto_Wallet_That_Never_Opened_Tampered_Exodus_Installer_Hides_a_Modular_RAT_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular RAT. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "c513a7346484ee69a2931c4a89956ee50aa63e4366ef989315e669d8f10d7485" or
        hash.sha256(0, filesize) == "8c3b41ea5a85778145a6e5772bfee2eb0f8b027d0af199fb71a76dfb8bb29e5a" or
        hash.sha256(0, filesize) == "fdd376562aac4be64fb635546a61e1912ff2c353360db73d2c553dcbb5a44f54" or
        hash.sha256(0, filesize) == "2f47cfbb13f7a8a2d30d287f4ddd974fabea6762ad9781d438eb53da41b4582d" or
        hash.sha256(0, filesize) == "84437d4239d2a3d90c4faad0a3c0630b2f61a40f7bbd12109bef74d7613b8756" or
        hash.sha256(0, filesize) == "5274e93e35586a341d14b50cdf8413d59c51fd94f32bdc70bfdfb77198367603" or
        hash.sha256(0, filesize) == "7e74f6e2eb7a17a8d25bb322a14c392c9d92c6ab29fc66b50221da134a1bdba8" or
        hash.sha256(0, filesize) == "5fe753945da0eaac2c2ef3845cba603dea6c3e8529fa581d7e0192f8af60391a"
}

