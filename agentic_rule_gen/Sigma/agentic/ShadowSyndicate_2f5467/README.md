# ShadowSyndicate

Source: https://www.group-ib.com/blog/shadowsyndicate-raas/

ShadowSyndicate is a suspected Ransomware-as-a-Service (RaaS) affiliate active since July 2022, distinguished by a unique SSH fingerprint (1ca4cbac895fc3bd12417b77fc6ed31d) found on at least 85 servers. The actor uses a versatile toolkit including Cobalt Strike, Sliver, and IcedID to deploy multiple ransomware families such as Quantum, Nokoyawa, and ALPHV, and shows infrastructure overlap with past Cl0p-affiliated clusters.

- **ShadowSyndicate_C2_Domain_Queries** (sigma, high): This rule is based on a list of specific C2 domains from the report, making it a high-confidence indicator of compromise.
- **ShadowSyndicate_C2_IP_Connections** (sigma, high): This rule is based on a list of specific C2 IP addresses from the report, making it a high-confidence indicator of compromise.
