# Prometheus TDS

Source: https://www.group-ib.com/blog/prometheus-tds/

Prometheus TDS is a Traffic Direction System (TDS) sold as a service on underground forums, attributed to an actor named 'Main'. It utilizes a PHP backdoor, Prometheus.Backdoor, on compromised websites to filter victims and deliver malware payloads such as Hancitor, QBot, IcedID, and Buer Loader. The system can also redirect users to phishing sites or other malicious content based on configurable rules.

- **PrometheusVBSLoaderPersistence** (sigma, high): This rule detects the specific command line used by a VBS loader to create a scheduled task for persistence, keying on the unique task name and script path.
- **PrometheusVBSLoaderBitsadminDownload** (sigma, high): This rule detects a specific `bitsadmin` command line, combining the distinctive BITS job name `EncodingFirm` and the temporary output filename `DefineKeeps.tmp`.
- **PrometheusAssociatedMalwareUriPaths** (sigma, high): This rule keys on highly specific URI paths and patterns used by various malware families delivered through the Prometheus TDS infrastructure.
- **PrometheusAssociatedC2AndPhishingDomains** (sigma, medium): This rule detects DNS queries for a list of domains explicitly linked to Prometheus TDS operations, including C2, phishing, and payload delivery.
- **PrometheusTDSAdminPanelConnection** (sigma, medium): This rule detects network connections to IP addresses specifically identified as hosting Prometheus TDS admin panels.
