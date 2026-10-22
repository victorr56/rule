# XZ Backdoor

Source: https://www.elastic.co/security-labs/threat-command/500ms-to-midnight

A backdoor was surreptitiously added to XZ Utils versions 5.6.0 and 5.6.1. The malware uses a manipulated build process to modify the liblzma library, enabling it to circumvent authentication in sshd and achieve remote code execution. The compromise was discovered due to a 500ms latency increase in SSH connections.

- **XZ_Backdoor_SSHD_Loading_Vulnerable_Liblzma** (sigma, high): This rule keys on the sshd process loading a specific vulnerable version of liblzma, a direct and high-confidence indicator of the XZ backdoor being active.
- **XZ_Backdoor_SSHD_Spawning_Shell** (sigma, high): This rule detects the highly anomalous behavior of the sshd process spawning a shell, a strong indicator of remote code execution via the exploited service.
