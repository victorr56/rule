# Red Agent SSRF

Source: https://www.wiz.io/blog/red-agent-pov-ssrf

An AI-driven tool, Red Agent, discovered a critical SSRF vulnerability in a GCP Cloud Run service by chaining multiple observations. The exploit bypassed a strict GitHub URL validator by appending a double-slash `//` to force the backend to interpret the subsequent string as an absolute local file path. This allowed unauthenticated file reads, leading to the theft of GCP service account credentials and application source code.

- **SSRF_Attempt_Against_GCP_Metadata_Via_URL_Authority_Bypass** (sigma, high): This rule detects the highly specific URL authority bypass (`userinfo@host`) technique used to target the GCP metadata service, which is a strong indicator of an SSRF attack.
- **Potential_SSRF_Attempt_Via_GCP_Metadata_Subdomain_Spoofing** (sigma, high): This rule keys on DNS queries for non-existent subdomains of `metadata.google.internal`, a specific and high-fidelity indicator of an SSRF bypass attempt.
- **Red_Agent_SSRF_Attempt_Via_Double_Slash_Path_Bypass** (sigma, high): This rule detects the specific `github.com` URL validation bypass using a `//` sequence followed by sensitive file paths observed in the Red Agent SSRF attack.
- **Web_Server_Process_Accessing_GCP_Metadata_Service** (sigma, medium): This rule provides behavioral detection for a common SSRF outcome by identifying web server processes connecting to the GCP metadata service to steal credentials.
- **Potential_SSRF_Path_Traversal_In_GitHub_URL** (sigma, medium): This rule detects URL-encoded path traversal sequences (`..%2f`) in URLs targeting github.com, a specific indicator of an SSRF payload injection attempt.
