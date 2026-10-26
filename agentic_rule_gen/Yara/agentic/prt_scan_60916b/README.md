# prt-scan

Source: https://www.wiz.io/blog/six-accounts-one-actor-inside-the-prt-scan-supply-chain-campaign

prt-scan is an automated supply chain attack targeting GitHub Actions. The actor uses AI-generated, language-aware payloads injected via misconfigured `pull_request_target` workflows to steal secrets and probe cloud metadata. Exfiltration occurs through Base64-encoded data in workflow logs and pull request comments.

- **MAL_PrtScan_GitHub_Action_Oct2026** (yara, medium): The rule keys on highly specific strings found in `prt-scan` attack scripts, including a unique temporary file path prefix, a regex for finding secrets, and compromised package names. These strong indicators can fire the rule alone. A combination of four less specific but still relevant strings provides an alternative detection path, improving recall while maintaining precision.
- **LinuxPrtScanExfiltrationCommandLine** (sigma, high): This rule keys on a highly specific command line used to collect credentials, archive them with gzip, and encode them with base64.
- **ProxyPrtScanWorkflowCreationAPI** (sigma, high): This rule combines the GitHub API host, the HTTP PUT method, and the specific temporary workflow path prefix used by the malware.
- **FileEventPrtScanTempWorkflowFile** (sigma, medium): This rule keys on the highly specific temporary workflow file prefix `.github/workflows/.prt_tmp_`, a hardcoded artifact.
