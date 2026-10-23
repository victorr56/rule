# SideWinder.AntiBot.Script

Source: https://www.group-ib.com/blog/sidewinder-antibot/

SideWinder uses a custom JavaScript tool, SideWinder.AntiBot.Script, to vet visitors to phishing pages. The script profiles the browser, checking geolocation (Pakistan), OS, language, and other fingerprints before serving a malicious ZIP with a LNK file. The LNK file downloads and executes an HTA payload, ultimately deploying a RAT via DLL side-loading.

- **APT_SideWinder_Generic_Strings_Oct2026** (yara, medium): This rule detects SideWinder PE files using highly specific lure filenames or a combination of supporting C2 domains and other strings.
- **SideWinderHTAPayloadExecution** (sigma, high): This rule keys on mshta.exe execution with a command line containing a known actor-controlled C2 domain, making it a high-confidence indicator.
- **SideWinderDuserDllSideloadingViaCredwiz** (sigma, high): This rule detects a specific DLL sideloading TTP by filtering for `Duser.dll` loaded by `credwiz.exe` from any path other than the legitimate system directory.
- **SideWinderMaliciousLNKFileCreation** (sigma, high): This rule detects a highly specific and complex malicious LNK filename pattern associated with SideWinder's phishing themes.
- **SideWinderC2URLPatterns** (sigma, high): This rule detects specific and structured URL patterns used by SideWinder for payload delivery and C2, making it a resilient behavioral detection.
- **SideWinderC2andPhishingDomainDNSQuery** (sigma, high): This rule detects DNS queries for a list of known SideWinder C2 and phishing domains, which is a strong indicator of compromise.
- **SideWinderC2andPhishingIPConnection** (sigma, medium): This rule detects network connections to known SideWinder C2 IP addresses, which are strong but potentially short-lived indicators.
