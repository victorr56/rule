// Locked and Loaded: Phishing through Fake Bids and Protected Documents
// Source: cofense | https://cofense.com/blog/locked-and-loaded-phishing-through-fake-bids-and-protected-documents

import "hash"

rule IOC_Locked_and_Loaded_Phishing_through_Fake_Bids_and_Protected_Documents_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Locked and Loaded: Phishing through Fake Bids and Protected Documents. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "cofense"
        reference   = "https://cofense.com/blog/locked-and-loaded-phishing-through-fake-bids-and-protected-documents"
        date        = "2026-10-28"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "9ca705d6466d4d71c3fb0cae5097933afe1de1bc139d53bb63565a52dc9ebccb" or
        hash.md5(0, filesize) == "c9281ea6828b9de4443ac56361ac29da"
}

