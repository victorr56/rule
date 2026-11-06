# ARTEX

Source: https://research.checkpoint.com/2026/hacking-on-autopilot-inside-artex-cybercrime-campaigns/

ARTEX is an AI-powered penetration testing platform used by cybercriminals for autonomous, opportunistic attacks. It leverages LLMs like Deepseek to exploit web vulnerabilities for financial gain, such as stealing code-signing certificates, cryptocurrency, or gaming accounts. The platform is notable for its scale of deployment and the minimal operator interaction required for its attacks.

- **ArtexC2Ip** (sigma, high): This rule detects connections to C2 IPs directly linked to different ARTEX operator clusters.
