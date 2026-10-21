# ClickFix

Source: https://www.darktrace.com/blog/unpacking-clickfix-darktraces-detection-of-a-prolific-social-engineering-tactic

ClickFix is a social engineering technique using fake prompts to trick users into running malicious PowerShell commands. This establishes C2 communication for reconnaissance and data exfiltration via HTTP. The tactic is used by actors like APT28 and MuddyWater to deliver malware payloads like XWorm, Lumma, and AsyncRAT.

- **ClickFix_Initial_C2_Beacon** (sigma, high): This rule detects the specific combination of a PowerShell User-Agent and a unique URI path pattern seen in ClickFix C2 communication.
- **ClickFix_C2_IPs** (sigma, high): This rule detects network connections to a list of known C2 IP addresses associated with ClickFix campaigns.
- **ClickFix_C2_Domains** (sigma, high): This rule detects DNS queries for a list of known C2 domains, including a compromised legitimate site, used in ClickFix campaigns.
