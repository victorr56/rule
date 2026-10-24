# FakeSecurity

Source: https://www.group-ib.com/blog/fakesecurity/

FakeSecurity is a JS-sniffer used to steal payment card data from Magento e-commerce websites. To gain access, threat actors distribute the Vidar password stealer using the Mephistophilus phishing kit and malicious email attachments, aiming to compromise administrator credentials to install the sniffer.

- **APT_FakeSecurity_Campaign_Infra_Oct2026** (yara, medium): This rule keys on highly specific C2 URL paths from infrastructure associated with the FakeSecurity campaign.
- **Suspicious_DNS_Queries_Linked_to_FakeSecurity_Vidar_Campaigns** (sigma, high): This rule detects DNS queries for a list of high-confidence malicious domains, providing broad network-level visibility into C2 and payload delivery.
- **Potential_Vidar_Stealer_Execution_Masquerading_as_Adobe_Plugin** (sigma, high): This rule detects the execution of a Vidar stealer payload by its specific and unusual masquerading filename pattern.
- **Lokibot_AZORUlt_C2_Panel_Access** (sigma, high): This rule detects C2 communication based on highly specific and unique URL path fragments associated with Lokibot and AZORult panels.
- **Network_Connection_to_FakeSecurity_Vidar_C2_IP** (sigma, high): This rule detects network connections to a known malicious C2 IP address, providing a high-confidence indicator of compromise.
- **Potential_Vidar_Stealer_File_Creation** (sigma, medium): This rule detects the creation of files with filenames known to be used by the Vidar stealer, indicating a potential dropper or payload stage.
