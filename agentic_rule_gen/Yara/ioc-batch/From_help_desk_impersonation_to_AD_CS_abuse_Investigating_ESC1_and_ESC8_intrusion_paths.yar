// From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths
// Source: microsoft-security | https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/

import "hash"

rule IOC_From_help_desk_impersonation_to_AD_CS_abuse_Investigating_ESC1_and_ESC8_intrusion_paths_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "microsoft-security"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/"
        date        = "2026-10-31"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "85b6c424117494d3056e88689dbc94c75e9afdb187a339714043aec0da109f17" or
        hash.sha256(0, filesize) == "f326201269f1ee2f803ae435317507263bb6e0dbfdeb70bd1bb5446e2e46f001" or
        hash.sha256(0, filesize) == "06c5c14f043aee3bcc5843b5f50909623d5c9a6239a7c1fba9cddad4111469e7"
}

