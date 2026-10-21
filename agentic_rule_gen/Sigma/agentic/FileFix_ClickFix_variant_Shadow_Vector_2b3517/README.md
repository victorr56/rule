# FileFix (ClickFix variant), Shadow Vector

Source: https://blog.virustotal.com/2025/11/vtpractitioners-acronis.html

Acronis TRU used VirusTotal Livehunt/retrohunt YARA hunting to track three campaigns: SideWinder's South Asian maldoc chain abusing CVE-2017-0199/CVE-2017-11882 with geofenced empty-RTF decoys, the Colombian Shadow Vector campaign using judicial-themed SVG lures with embedded HTTPS payload links, and the FileFix ClickFix variant that copies a PowerShell command to the clipboard and extracts an executable from a downloaded JPG. Detection anchors include the SideWinder decoy RTF hash and hex patterns, the Spanish judicial lure strings plus the 'Generado Automaticamente' generator marker in SVGs, and the clipboard-copy JavaScript/PowerShell deobfuscation chain used by FileFix.

- **FileFix_PowerShell_Loader_CommandLine** (sigma, high): The rule matches a specific PowerShell command line with unique variable assignments and execution flow, characteristic of FileFix.
- **SideWinder_FileFix_C2_Lure_Domains** (sigma, high): This rule lists multiple domains exclusively used by the threat actors for lure delivery and C2, making it a high-confidence indicator.
- **FileFix_Masquerade_PDF_Creation** (sigma, high): The rule correlates file creation at a highly specific and unusual path with the PowerShell interpreter, a strong indicator of the FileFix payload.
- **SideWinder_Spearphishing_EML_File_Creation** (sigma, high): This rule detects the creation of a file with a highly specific name, characteristic of a SideWinder lure, by a browser or email client.
- **SideWinder_RTF_Lure_URL_Pattern** (sigma, medium): This rule detects a specific URI path regex pattern for RTF file downloads that is a behavioral indicator of SideWinder lure delivery.
- **SideWinder_Associated_IP_Access** (sigma, high): This rule uses a known SideWinder IP address as a high-confidence indicator of compromise.
