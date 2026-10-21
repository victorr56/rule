# ResumeLooters

Source: https://www.group-ib.com/blog/resumelooters/

ResumeLooters is a threat group active since early 2023, targeting job search and retail websites, primarily in the APAC region. They use SQL injection to steal user databases and XSS to inject malicious scripts aiming to steal credentials. The group utilizes a variety of publicly available penetration testing tools and sells stolen data on Telegram.

- **ResumeLooters_PowerShell_Download_Cradle** (sigma, high): This rule detects a highly specific PowerShell command line pattern, including multiple IEX and DownloadString calls and a unique URL path segment, used by ResumeLooters.
- **ResumeLooters_C2_Domains** (sigma, high): This rule detects DNS queries for a list of domains exclusively controlled by the ResumeLooters actor for C2 and malware distribution.
- **ResumeLooters_C2_IP_Addresses** (sigma, high): This rule detects network connections to a list of IP addresses exclusively controlled by the ResumeLooters actor for C2 and payload hosting.
- **Tool_Sqlmap_OS_Shell_Execution** (sigma, high): This rule detects the use of sqlmap's '--os-shell' feature, a strong indicator of post-exploitation activity following an SQL injection, as used by ResumeLooters.
