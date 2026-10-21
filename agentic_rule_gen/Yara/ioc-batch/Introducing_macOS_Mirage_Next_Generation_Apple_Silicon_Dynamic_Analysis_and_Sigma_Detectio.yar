// Introducing macOS Mirage: Next-Generation Apple Silicon Dynamic Analysis and Sigma Detections
// Source: virustotal | https://blog.virustotal.com/2026/10/introducing-macos-mirage.html.html

import "hash"

rule IOC_Introducing_macOS_Mirage_Next_Generation_Apple_Silicon_Dynamic_Analysis_and_Sigma_Detectio_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Introducing macOS Mirage: Next-Generation Apple Silicon Dynamic Analysis and Sigma Detections. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "virustotal"
        reference   = "https://blog.virustotal.com/2026/10/introducing-macos-mirage.html.html"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "be77bca22f078d57058535ddcf26a39a752a8df030392cb45ba6a60e06651878" or
        hash.sha256(0, filesize) == "f7dcdc4167ec267aef007f9d5f98e9e0314185e5355effd3e304b6fa686ea84c" or
        hash.sha256(0, filesize) == "d7dd630f67e03d2945185838dca887211ea3693c91fc0bd0d2e257948bb3b678" or
        hash.sha256(0, filesize) == "01f9a24bd868a856909db5eb61be6f30939e402fd7dd2e40180ffe2406de5c35"
}

