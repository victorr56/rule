# BUGHATCH

Source: https://www.elastic.co/security-labs/threat-command/bughatch-malware-analysis

BUGHATCH is a custom implant used in CUBA ransomware campaigns. It is deployed via a PowerShell dropper and communicates with its C2 over HTTP using a custom protocol with 2-byte XOR encryption. The malware supports various payload execution methods, including reflective loading and shellcode injection, and collects system information for fingerprinting.

- **APT_CUBA_BUGHATCH_Implant_Oct2026** (yara, high): The rule keys on a unique code pattern and highly specific internal function names from the BUGHATCH implant.
- **BughatchPayloadDownload** (sigma, high): This rule keys on the specific and unique URI paths used by BUGHATCH to download its 32-bit and 64-bit agent payloads.
