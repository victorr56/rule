# JarService

Source: https://securelist.com/android-head-unit-malware/121106/

A multi-stage Android malware chain (JarService dropper, loader, clicker/reverse-proxy loader) delivered to DoFun automotive head units through the legitimate TWCore updater (com.tw.core) and its MQTT-driven APK installer. The final stage installs the "zhima" reverse-proxy module to build a proxy botnet and perform ad fraud, with configuration and commands pulled from C2 JSON APIs. Kaspersky attributes the campaign with high confidence to the MoYu Group, an actor linked to the BADBOX botnet.

- **MoYu_Group_JarService_Kookjar_Beacon** (sigma, high): This rule detects a highly specific C2 beacon by combining the destination domain with unique URL path and parameter values.
- **MoYu_Group_JarService_Payload_Download** (sigma, high): This rule keys on a unique and static URL path segment '/vr34der34/' used for second-stage payload delivery.
- **MoYu_Group_JarService_C2_DNS_Query** (sigma, medium): This rule detects DNS lookups for a list of C2 domains specifically registered and used by the MoYu Group.
- **MoYu_Group_JarService_C2_Connection** (sigma, medium): This rule detects network connections to a list of C2 and payload-hosting IP addresses hardcoded in the malware.
