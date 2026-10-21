# CI/CD pipeline abuse: the problem no one is watching

Source: https://www.elastic.co/security-labs/threat-command/detecting-cicd-pipeline-abuse-with-llm-augmented-analysis

Adversaries abuse CI/CD pipelines by using stolen developer credentials to modify workflow YAML and harvest the cloud tokens, package registry credentials and deploy keys available to the runner. This profile captures the concrete artefacts behind that tradecraft: Nord Stream double-base64 environment exfiltration, pull_request_target/checkout_ref abuse, GITHUB_ENV and LD_PRELOAD injection, artifact-based GITHUB_TOKEN leakage, and VS Code task poisoning, together with the MITRE ATT&CK mappings Elastic uses for detection.

- **APT_Lazarus_VSCode_Task_Poisoning_Oct2026** (yara, high): This rule detects VS Code task poisoning by targeting the specific `runOn: folderOpen` auto-execution trigger or a combination of settings used to hide the malicious task and its containing folder.
- **HKTL_NordStream_CICD_Abuse_Oct2026** (yara, medium): This rule detects the Nord Stream tool by looking for combinations of its specific strings, such as `addSpnToEnvironment` and `DownloadSecureFile`, found in malicious Azure DevOps configurations.
- **Suspicious_Nord_Stream_CI_CD_Exfiltration_Pattern** (sigma, high): This rule detects a highly specific command-line chain used by the Nord Stream exfiltration tool, including the awk filter for secrets and the double base64 pipe.
- **Suspicious_Nord_Stream_Azure_OIDC_Token_Exfiltration** (sigma, high): This rule detects the specific command line used by the Nord Stream tool to exfiltrate Azure tokens, combining the legitimate 'az' command with a suspicious double base64 encoding pipe.
- **Suspicious_Modification_of_Azure_DevOps_SSH_Task_File** (sigma, high): This rule detects modifications to a very specific file path related to Azure DevOps tasks, which is a strong indicator of CI/CD pipeline tampering.
- **Potential_Credential_Access_via_proc_mem** (sigma, high): This rule detects access to the sensitive /proc/mem file, a high-fidelity indicator of memory scraping attempts for credentials, with few legitimate use cases.
- **Remote_Script_Execution_via_Pipe_to_Interpreter** (sigma, medium): This rule detects the classic "curl | bash" pattern and its variants, a common TTP for code execution that is valuable for threat hunting despite potential FPs in developer environments.
- **Suspected_CI_CD_Exfiltration_Domain_Query** (sigma, high): This rule detects DNS queries for a specific, non-shared domain identified as an exfiltration target in the context of CI/CD attacks.
