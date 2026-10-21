# NodeRabbit, PollCat

Source: https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/

Mirage Kitten delivers two new cross-platform implants, the Node.js NodeRabbit RAT and the obfuscated JavaScript PollCat RAT, through trojanized coding-challenge archives hosted on Amazon S3 and pitched by fake recruiters on job platforms. NodeRabbit wraps JSON C2 traffic in AES-256-GCM and reaches Azure-hosted endpoints, persisting via Edge/Intel DSA masquerades, Run keys, scheduled tasks, cron and LaunchAgents; PollCat beacons Base64 binary records to /beacon and /gate/* endpoints and adds fake VS Code extension and Git-hook persistence. Victims are aviation/aerospace and fintech organizations in Egypt, Ethiopia and Afghanistan.

- **mirage_kitten_noderabbit_persistence_run_key** (sigma, high): This rule detects a highly specific NodeRabbit v1 Run key by combining the key name and its unique value.
- **mirage_kitten_noderabbit_persistence_execution** (sigma, high): This rule detects NodeRabbit v2 execution by matching the masqueraded process name with its specific script argument.
- **mirage_kitten_pollcat_persistence_file_drop** (sigma, high): This rule detects a highly specific file path used by the PollCat backdoor for Windows persistence.
- **mirage_kitten_noderabbit_curl_proxy_auth** (sigma, medium): This rule detects a suspicious `curl.exe` command line used by NodeRabbit to handle proxy authentication.
- **mirage_kitten_noderabbit_c2_traffic** (sigma, high): This rule detects specific and unique URI paths used by NodeRabbit for C2 communication across multiple versions.
- **mirage_kitten_c2_domains** (sigma, high): This rule lists known high-confidence C2 and distribution domains associated with Mirage Kitten malware families.
