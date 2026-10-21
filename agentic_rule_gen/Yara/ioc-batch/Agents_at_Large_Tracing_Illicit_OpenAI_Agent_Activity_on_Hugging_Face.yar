// Agents at Large | Tracing Illicit OpenAI Agent Activity on Hugging Face
// Source: sentinelone-labs | https://www.sentinelone.com/labs/agents-at-large-tracing-illicit-openai-agent-activity-on-hugging-face/

import "hash"

rule IOC_Agents_at_Large_Tracing_Illicit_OpenAI_Agent_Activity_on_Hugging_Face_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Agents at Large | Tracing Illicit OpenAI Agent Activity on Hugging Face. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "sentinelone-labs"
        reference   = "https://www.sentinelone.com/labs/agents-at-large-tracing-illicit-openai-agent-activity-on-hugging-face/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "a502264fa0b64eecae60498b0c48fca3"
}

