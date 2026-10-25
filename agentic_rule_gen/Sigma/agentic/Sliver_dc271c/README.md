# Sliver

Source: https://www.wiz.io/blog/cve-2024-0012-pan-os-vulnerability-exploited-in-the-wild

Opportunistic actors are exploiting PAN-OS vulnerabilities CVE-2024-0012 and CVE-2024-9474 for unauthenticated remote code execution. Post-exploitation activity includes deploying simple PHP web shells, Sliver implants, and crypto miners. A specific Sliver implant has been observed communicating with a C2 at 77.221.158.154.

- **Sliver_Implant_Execution_from_PAN-OS_Font_Path** (sigma, high): This rule detects the execution of a masqueraded implant from a highly specific staging path on PAN-OS devices.
- **PHP_Webshell_Creation_in_PAN-OS_Unauth_Directory** (sigma, high): This rule detects webshell creation in a very specific directory path associated with post-exploitation of PAN-OS devices.
- **Sliver_C2_Connection_CVE_2024_0012** (sigma, high): This rule detects network traffic to a unique IP address identified as a Sliver C2 server in this campaign.
- **Sliver_C2_DNS_Query_CVE_2024_0012** (sigma, high): This rule detects DNS lookups for a unique domain identified as part of the Sliver C2 infrastructure in this campaign.
