# BLISTER

Source: https://www.elastic.co/security-labs/threat-command/elastic-security-uncovers-blister-malware-campaign

BLISTER is a novel loader that uses valid code-signing certificates to evade detection. It is typically dropped as a DLL, executed by rundll32.exe, and establishes persistence via the user's Startup folder. The loader decodes and injects second-stage payloads like Cobalt Strike or BitRat into memory, often into a WerFault.exe process.

- **MAL_BLISTER_Loader_Oct2026** (yara, medium): The rule detects BLISTER loaders via the characteristic DLL export 'LaunchColorCpl' or the 'Blist LLC' certificate subject, both based on prose evidence from the report.
- **BlisterLoaderExecutionViaRundll32** (sigma, high): This rule keys on the specific command line pattern of the Blister loader: `rundll32.exe` execution, a misspelled path `\Temp\Framwork\`, and the unique export function `LaunchColorCpl`.
- **BlisterLoaderDLLDroppedInTemp** (sigma, high): This rule detects the creation of Blister DLLs by combining the unique misspelled path `\Temp\Framwork\` with a list of known malicious DLL filenames.
- **BlisterMalwareC2NetworkConnection** (sigma, high): This rule detects network connections to a list of IP addresses specifically identified as Blister C2 infrastructure.
