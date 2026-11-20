// We caught the agent-framework PyPI compromise six minutes after it published
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published

import "hash"

rule IOC_We_caught_the_agent_framework_PyPI_compromise_six_minutes_after_it_published_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: We caught the agent-framework PyPI compromise six minutes after it published. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published"
        date        = "2026-11-20"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110" or
        hash.sha256(0, filesize) == "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9" or
        hash.sha256(0, filesize) == "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663" or
        hash.sha256(0, filesize) == "c275ccbe520ef3c0f02dc6a35389e427f9f1b4e0b12e140cd7bf7179ce143f02" or
        hash.sha256(0, filesize) == "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e" or
        hash.sha256(0, filesize) == "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f" or
        hash.sha256(0, filesize) == "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93"
}

