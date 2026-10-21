# CNCmachineRMS

Source: https://www.malware-traffic-analysis.net/2026/10/01/index.html

Traffic analysis exercise from a Windows host in the NATUREFORCE Active Directory domain (natureforce.com) that received a Windows EXE over unusual TCP port 9000 from 107.175.82.242 and generated CNCmachineRMS RAT C2 traffic to 195.64.128.106:443. The report provides only the pcap context and alert indicators; the infected client's identity and the EXE's SHA-256 are left as analyst questions without stated answers.

- **Network_Connection_to_CNCmachineRMS_C2_and_Staging_IPs** (sigma, high): Keys on the only concrete, observable indicators in the profile - the two actor-controlled IPs (payload staging host on 107.175.82.242 and RAT C2 on 195.64.128.106) - expressed as a single network_connection rule since per-IP rules would be redundant; no host-side command line, file name, mutex or persistence artifact was provided, so no behavioural rule could be written without inventing specifics.
