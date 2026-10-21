// macOS.Gaslight | Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox
// Source: sentinelone-labs | https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/

import "hash"

rule IOC_macOS_Gaslight_Rust_Backdoor_Turns_Prompt_Injection_on_the_Analyst_Not_the_Sandbox_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: macOS.Gaslight | Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "sentinelone-labs"
        reference   = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525" or
        hash.sha256(0, filesize) == "77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca" or
        hash.sha256(0, filesize) == "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239" or
        hash.sha256(0, filesize) == "e4503e31d5a297d93ade64f50a5b5fe91e73dad251ac2615b4c975684f68e080" or
        hash.sha1(0, filesize) == "5555494492fc075f441637fb9d894913dde3a2ea"
}

