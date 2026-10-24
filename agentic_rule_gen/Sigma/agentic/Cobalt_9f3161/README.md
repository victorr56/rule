# Cobalt

Source: https://www.group-ib.com/blog/renaissance/

The Cobalt group conducts financially-motivated attacks against banks, using spear-phishing with malicious documents to deliver custom backdoors like Coblnt. After gaining access, they perform extensive reconnaissance for weeks before exfiltrating funds through card processing, ATMs, or SWIFT systems. Their TTPs include using custom tools like PetrWrap (a Petya modification) and JS-backdoors, and impersonating security companies and financial institutions.

- **APT_Cobalt_Group_Coblnt_Oct2026** (yara, medium): This rule keys on a combination of tool names, malware family names, and infrastructure strings associated with Cobalt Group. All strings are from prose, so a high threshold of 4 strings is required to improve precision.
- **Cobalt_Group_C2_Domains** (sigma, high): This rule detects DNS queries for a list of domains specifically registered and used by Cobalt Group for C2 and phishing.
- **Cobalt_Group_C2_IPs** (sigma, high): This rule detects network connections to a list of IP addresses identified as Cobalt Group infrastructure.
