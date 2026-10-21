# Kali365

Source: https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/

Kali365 is a phishing-as-a-service platform that automates OAuth device code phishing and adversary-in-the-middle session capture against Microsoft 365, using Cloudflare-hosted (workers.dev/pages.dev) landing pages that return real user_code values and let the platform collect the resulting access and refresh tokens. Post-access activity includes password changes, device registration and BEC-style inbox rule creation using special-character-only rule names. Red Canary also observed copy-and-paste ('paste and run') execution chains delivering Atomic Stealer, HijackLoader, NetSupport Manager and Scarlet Goldfinch payloads.

- **NetSupport_Manager_msIeXec_Execution** (sigma, high): This rule combines a specific typosquatted executable name (`msIeXec.exe`) with unique command-line arguments (`-PAcK`, `/Cpcha`), making it a high-fidelity indicator for this specific NetSupport Manager delivery.
- **Scarlet_Goldfinch_Obfuscated_Cmd_Execution** (sigma, high): This rule detects a complex, obfuscated command-line sequence combining a `for` loop, caret-obfuscated `curl` and `mshta` commands, and a specific C2 domain, making it unique to this threat.
- **Scarlet_Goldfinch_Payload_Drop** (sigma, medium): This rule is precise by requiring the `Voter.pdf` file in a specific path to be created by the `curl.exe` process, matching the observed TTP for Scarlet Goldfinch payload delivery.
