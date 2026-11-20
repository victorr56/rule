# agent-framework stealer

Source: https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published

Malicious versions (1.26.1, 1.26.2) of the 'agent-framework' PyPI package act as a credential stealer. The malware uses a .pth file to execute on Python interpreter startup, harvesting environment variables, configuration files, and cloud credentials from Azure and GitHub. Collected data is Base64 encoded, zlib compressed, and exfiltrated via a POST request to a hardcoded webhook.site URL.

- **AgentFramework_Exfiltration** (sigma, high): This rule detects the unique exfiltration URL path and specific User-Agent strings used by the malware.
- **AgentFramework_File_Creation** (sigma, high): This rule is precise because it detects the creation of files with names that are highly specific to this malware.
