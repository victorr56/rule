# TOLLBOOTH

Source: https://www.elastic.co/security-labs/threat-command/tollbooth

REF3927 compromises misconfigured IIS servers by exploiting publicly exposed ASP.NET machine keys. The actor deploys TOLLBOOTH, a malicious IIS module with SEO cloaking and webshell capabilities, alongside a Godzilla-based webshell and a custom rootkit called HIDDENDRIVER. The main objective appears to be monetizing access via traffic redirection and SEO fraud.

- **APT_REF3927_TOLLBOOTH_IISModule_Oct2026** (yara, medium): This rule detects the actor-specific TOLLBOOTH IIS module by keying on hardcoded keys, C2 URLs, and user agents.
- **HKTL_Hidden_Rootkit_Oct2026** (yara, high): This rule detects the HIDDENDRIVER rootkit by its unique `Kbj_` prefixed configuration strings and IOCTL commands.
- **REF3927_TOLLBOOTH_IIS_Module_Load** (sigma, high): This rule precisely targets the TOLLBOOTH malware by correlating known malicious DLLs with the legitimate IIS worker process that loads them.
- **REF3927_HIDDENDRIVER_Userland_Tool_Execution** (sigma, high): This rule detects the execution of uniquely named executables that serve as userland components for the HIDDENDRIVER rootkit.
- **REF3927_TOLLBOOTH_Temp_Directory_Activity** (sigma, high): This rule detects activity in a highly specific, hardcoded temporary directory path used by the TOLLBOOTH malware.
- **REF3927_TOLLBOOTH_C2_Domain_Query** (sigma, high): This rule identifies DNS queries to domains specifically linked to the TOLLBOOTH malware's C2 and operational infrastructure.
- **REF3927_TOLLBOOTH_Webshell_URI_Access** (sigma, high): This rule detects specific and unique URI paths and query parameters known to be used by the TOLLBOOTH webshell and its SEO fraud components.
