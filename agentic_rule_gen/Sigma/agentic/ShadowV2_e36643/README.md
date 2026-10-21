# ShadowV2

Source: https://www.darktrace.com/blog/shadowv2-an-emerging-ddos-for-hire-botnet

ShadowV2 is a DDoS-for-hire botnet whose Go-based ELF implant is deployed into exposed Docker daemons (observed against AWS EC2 honeypots) via a Python spreader running from GitHub CodeSpaces. The unstripped implant registers with a FastAPI/Pydantic C2 at shadow.aurozacloud[.]xyz, heartbeats every second, polls for commands every five seconds, and launches HTTP floods including HTTP/2 rapid reset and a ChromeDP-based Cloudflare UAM bypass. Detection should focus on the implant's Go symbol and string artifacts, the /app/deployment drop path, the Docker SDK user agent, and the C2 API endpoints.

- **MAL_ShadowV2_Go_Implant_Oct2026** (yara, high): This rule detects the ShadowV2 Go implant using highly specific function names, strings, and code patterns from the unstripped binary.
- **ShadowV2_ChromeDP_Execution** (sigma, high): This rule detects the unique parent-child process relationship of the ShadowV2 implant and its bundled Cloudflare bypass tool.
- **ShadowV2_C2_DNS_Query** (sigma, high): This rule detects DNS queries for a known, high-confidence ShadowV2 C2 domain.
- **ShadowV2_C2_API_Communication** (sigma, high): This rule detects calls to the highly specific C2 API URI paths used by the ShadowV2 implant.
- **ShadowV2_Spreader_Initial_Access** (sigma, medium): This rule detects the specific User-Agent string used by the ShadowV2 spreader to find and infect exposed Docker daemons.
