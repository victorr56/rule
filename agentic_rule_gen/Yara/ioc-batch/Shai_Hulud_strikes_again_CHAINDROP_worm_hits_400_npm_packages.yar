// Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain

import "hash"

rule IOC_Shai_Hulud_strikes_again_CHAINDROP_worm_hits_400_npm_packages_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc" or
        hash.sha256(0, filesize) == "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb" or
        hash.sha256(0, filesize) == "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668" or
        hash.sha1(0, filesize) == "e1f2395ee43e45a1556ec6438a88c31b83493103"
}

