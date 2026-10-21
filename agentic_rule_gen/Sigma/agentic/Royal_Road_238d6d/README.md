# Royal Road

Source: http://nao-sec.org/2021/01/royal-road-redive.html

Royal Road is an RTF weaponizer that exploits the Microsoft Office Equation Editor vulnerabilities (CVE-2017-11882, CVE-2018-0798, CVE-2018-0802) and is shared among multiple China-nexus targeted-attack groups. RTF files it generates carry a shellcode-decoded embedded object (classically named "8.t") whose leading bytes identify the encoding variant used for the payload. Observed payloads include AttackBot, Chinoxy, FlowCloud and the unknown XLBug RAT, along with the dropped loader intel.wll and Startup-folder shortcuts.

- **MAL_RoyalRoad_Payload_XLBug_Oct2026** (yara, high): The rule detects the XLBug RAT using unique Base64-like strings and filenames found in the binary, or by combining a specific export name with other artifacts.
- **MAL_RoyalRoad_Payloads_Generic_Oct2026** (yara, medium): This rule detects droppers and other components of Royal Road campaigns by matching either of two high-confidence filenames or a combination of three less unique but still characteristic filenames.
- **Royal_Road_Intel_WLL_Load** (sigma, high): This rule detects the loading of the specific `intel.wll` by Microsoft Word, a high-fidelity indicator of a Royal Road exploitation chain.
- **Royal_Road_RTF_Object_Drop** (sigma, high): This rule detects the creation of the file '8.t' by an Office application, a hallmark of the Royal Road weaponizer's exploitation process.
- **Royal_Road_Persistence_SecurityProfile_LNK** (sigma, high): This rule detects the creation of a specific LNK file in a specific persistence location, a high-confidence indicator of the Royal Road chain.
- **Royal_Road_Chinoxy_Payload_Execution** (sigma, high): This rule detects the execution of a specific DLL, `faxprint.dll`, by rundll32.exe, which is indicative of the Chinoxy payload from a Royal Road infection.
- **Royal_Road_Chinoxy_Script_Execution** (sigma, high): This rule detects the execution of a specific VBS file, `bss.vbs`, a known indicator of the Chinoxy malware family often associated with Royal Road.
