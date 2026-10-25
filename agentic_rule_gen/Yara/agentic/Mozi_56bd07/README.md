# Mozi

Source: https://www.elastic.co/security-labs/threat-command/collecting-and-operationalizing-threat-data-from-the-mozi-botnet

Mozi is a P2P botnet that has been active since at least 2019, targeting vulnerable Internet of Things (IoT) devices. It spreads by exploiting weak/default credentials and unpatched vulnerabilities, and infected devices are used to propagate the malware further. Mozi samples are often packed with a modified version of UPX to hinder analysis.

- **MAL_Mozi_Botnet_Oct26** (yara, medium): The rule keys on a unique DHT error message and a collection of supporting strings, including DHT bootstrap nodes and short, high-entropy strings found in Mozi samples.
- **MoziIptablesFirewallRule** (sigma, high): This rule detects highly specific iptables commands used by Mozi to open UDP ports, keying on the process, chains, protocol, and action.
- **MoziP2PDHTBootstrapNodeQuery** (sigma, medium): This rule detects network connections to known P2P bootstrap nodes hardcoded in the Mozi botnet, which are anomalous on most enterprise devices.
- **MoziPayloadServerArtifacts** (sigma, medium): This rule detects the specific combination of HTTP server (nginx) and content type (application/zip) used by infected Mozi nodes to serve payloads.
