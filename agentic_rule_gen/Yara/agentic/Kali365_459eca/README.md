# Kali365

Source: https://www.huntress.com/blog/kali365-device-code-phishing-kit

Kali365, also known as Octopi365, is a Phishing-as-a-Service (PhaaS) platform using the device code flow and Adversary-in-the-Middle (AiTM) to steal Microsoft 365 tokens. The ecosystem includes web-based panels and companion Electron desktop apps (OctoLink Live, OctoLink Sender) for session replay and mass-mailing. Advanced versions feature AI-assisted BEC drafting, credential scanning, and Exchange admin abuse capabilities to monetize stolen access.

- **MAL_Kali365_OctoLink_Tool_Oct2026** (yara, high): The rule keys on highly specific strings from Kali365/OctoLink desktop applications, including a unique code comment, a hardcoded client ID, and various distinctive user agents and API paths.
- **Kali365_OctoLink_Tool_Execution** (sigma, high): This rule detects the execution of specific, uniquely named tools from the Kali365 PhaaS ecosystem.
- **Kali365_Phishing_Panel_URI_Access** (sigma, high): This rule detects access to highly specific URI paths associated with the Kali365 C2 panel.
