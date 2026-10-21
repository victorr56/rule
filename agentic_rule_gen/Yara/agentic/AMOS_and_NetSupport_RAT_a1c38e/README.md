# AMOS and NetSupport RAT

Source: https://www.huntress.com/blog/defcon-phishing-google-doc-malware

An unnamed actor targets security conference attendees using a malicious Google Doc with a custom Apps Script. The campaign delivers AMOS infostealer to macOS victims, while Windows users receive NetSupport RAT, a TLS-intercepting proxy, and a Ledger wallet implant via a multi-stage infection chain.

- **MAL_NetSupportRAT_Campaign_Oct2026** (yara, high): This rule detects a specific NetSupport RAT build via a unique PDB-like path found in its configuration.
- **MAL_LocalProxy_Campaign_Oct2026** (yara, high): This rule targets the TLS proxy's unique, hardcoded, and misleading certificate subject string.
- **AMOS_Stealer_Initial_Access_Via_Curl_Zsh_Pipe** (sigma, high): This rule detects the specific curl-to-shell command used for initial access on macOS systems.
- **AMOS_NetSupport_RAT_Ledger_Implant_Artifact** (sigma, high): This rule combines the masqueraded process MsBuild.exe with the specific malicious file it creates.
- **AMOS_NetSupport_RAT_Firewall_Rule_For_LocalProxy** (sigma, high): This rule detects the specific netsh command line used to create a firewall rule with a name unique to this campaign.
- **AMOS_NetSupport_RAT_C2_Domain_Query** (sigma, high): This rule detects DNS queries for domains exclusively associated with the AMOS/NetSupport RAT campaign.
