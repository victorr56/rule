# LiteLlmSupplyChain

Source: https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/

A compromised LiteLLM 1.107.0 package used Python startup hooks (cook.pth, sitecustomize.py) to execute a credential stealer without requiring a direct import. The payload, identifying as PRIVCOLLECT, exfiltrated credentials and sensitive data via HTTP POST after encrypting it with AES/RSA. A secondary loader on Unix systems could fetch and execute additional code from a C2 server.

- **MAL_LiteLlmSupplyChain_PyStealer_Oct2026** (yara, high): This rule keys on highly specific strings from the Python stealer payload, including the internal identifier 'PRIVCOLLECT' and unique database query artifacts.
- **LiteLlmSupplyChain_Python_Startup_Hook_Files** (sigma, high): This rule detects the creation of specific malicious hook files in Python library paths.
- **LiteLlmSupplyChain_C2_Domain** (sigma, high): This rule detects queries for a C2 domain specifically identified with this threat.
- **LiteLlmSupplyChain_Windows_Reconnaissance** (sigma, medium): This rule detects anomalous system discovery commands spawned by the Python interpreter.
