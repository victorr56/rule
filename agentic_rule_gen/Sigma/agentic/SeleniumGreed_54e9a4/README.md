# SeleniumGreed

Source: https://www.wiz.io/blog/seleniumgreed-cryptomining-exploit-attack-flow-remediation-steps

SeleniumGreed is a cryptomining campaign that exploits publicly exposed and misconfigured Selenium Grid services. Attackers execute a Python reverse shell to download and run a modified XMRig miner, which is packed with a custom UPX header. The threat actor uses various anti-forensic techniques like timestomping, disabling shell history, and using compromised infrastructure for C2 and as a mining pool proxy.

- **SeleniumGreed_Python_Reverse_Shell** (sigma, high): The rule keys on a highly specific python command line, including a unique Base64 payload and Selenium-specific arguments.
- **SeleniumGreed_Miner_Runner_Download** (sigma, high): This rule detects curl downloading specific files and saving them to unusual paths (`/bin/xm`, `/bin/wxm`), which is characteristic of this threat.
- **SeleniumGreed_Timestomping** (sigma, high): The rule matches a `touch` command with a hardcoded historical date and specific file paths, a clear anti-forensic technique used by the actor.
- **SeleniumGreed_Miner_Runner_File_Creation** (sigma, high): This rule detects `curl` creating files with specific names directly in the `/bin` directory, a highly anomalous and actor-specific behavior.
- **SeleniumGreed_C2_And_Mining_Pool_IPs** (sigma, high): This rule detects network traffic to a list of IPs specifically identified as infrastructure for the SeleniumGreed campaign.
