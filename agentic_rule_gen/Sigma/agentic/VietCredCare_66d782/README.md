# VietCredCare

Source: https://www.group-ib.com/blog/vietcredcare-stealer/

VietCredCare is a .NET information stealer active since at least August 2022, primarily targeting users in Vietnam. Distributed via phishing under a stealer-as-a-service model, it steals browser credentials and cookies with a unique feature to identify and exfiltrate Facebook business accounts with positive Meta ad credit balances. Stolen data is exfiltrated to the operator via Telegram bots.

- **MAL_VietCredCare_Stealer_Oct2026** (yara, high): The rule keys on unique Vietnamese strings and a combination of other stealer artifacts for high-confidence detection.
- **VietCredCare_Execution_from_Startup** (sigma, high): This rule detects the execution of a file with a specific name from a specific persistence location, making it a high-confidence indicator of VietCredCare.
- **Suspicious_Access_to_CocCoc_Browser_Credentials** (sigma, high): This rule detects access to sensitive CocCoc browser files from any process except the browser itself, a strong indicator of credential theft activity.
- **VietCredCare_Facebook_Business_Account_Check** (sigma, medium): This rule is precise by combining three specific network indicators: a hostname, a URL path, and a hardcoded User-Agent string, which together are characteristic of this malware.
