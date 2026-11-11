# wp2shell

Source: https://socradar.io/blog/dark-web-profile-cyberxero/

CyberXero is a Russian-speaking Initial Access Broker conducting both opportunistic mass-exploitation and targeted attacks against critical infrastructure, particularly in Ukraine. The actor uses custom tooling like the wp2shell WordPress exploiter, alongside pirated Cobalt Strike, and notably augments operations with a large number of AI agents. Detections can be based on rogue WordPress user and plugin patterns, a custom persistence service name, and specific C2 infrastructure.

- **CyberXero_C2_Network_Activity** (sigma, high): This rule keys on a list of specific C2 and infrastructure IP addresses identified in the report.
- **CyberXero_Persistence_Service** (sigma, high): This rule keys on the command line creation of a Windows service with a specific name used for persistence.
- **CyberXero_Tooling_Windows_abuse_monitor** (sigma, high): This rule keys on a specific malicious python script name executed via a python interpreter on Windows.
