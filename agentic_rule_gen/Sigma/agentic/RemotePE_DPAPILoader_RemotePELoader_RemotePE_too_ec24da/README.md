# RemotePE (DPAPILoader / RemotePELoader / RemotePE toolset)

Source: https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/

DPAPILoader is an environmentally keyed first-stage DLL that decrypts a DPAPI-protected, 0x8D-XORed RemotePELoader payload from the DeviceMetadataStore directory, then reflectively loads it with libpeconv. RemotePELoader applies HellsGate/TartarusGate unhooking and ETW patching before polling an HTTP C2 for the final RemotePE RAT, which executes entirely in memory and exposes RTTI-based command classes. Detection anchors include masquerading service DLLs (Iassvc.dll), DPAPI-encrypted blobs in DeviceMetadataStore, the ETW patch bytes 48 33 c0 c3, the wake-up event 554D5C1F-AABE-49E4-AB57-994D22ECED28 and the cookie/JSON keys MicrosoftApplicationsTelemetryDeviceId, at_check, ai_session, MSFPC, MUID and armAuthorization.

- **APT_Lazarus_RemotePE_Toolset_Oct2026** (yara, medium): The rule combines high-confidence strings from all components of the RemotePE toolset, including unique RTTI class names, C2-related strings, and distinctive error messages from its loader, creating a comprehensive and precise signature.
- **Lazarus_RemotePE_Masquerading_Service_Installation** (sigma, high): This rule detects the specific registry key modification for the masquerading 'Ias' service, a high-fidelity persistence artifact.
- **Lazarus_RemotePE_Masquerading_DLL_File_Creation** (sigma, high): This rule detects the creation of the specifically named malicious DLL `Iassvc.dll` in `System32`, a high-confidence indicator.
- **Lazarus_RemotePE_Sideloading_via_ESET_Binary** (sigma, high): This rule detects a specific DLL sideloading pattern (edp.exe loading a non-system sspicli.dll), which is a precise indicator of this campaign.
- **Lazarus_RemotePE_C2_Communication** (sigma, high): This rule detects specific combinations of URI path, User-Agent, and custom cookie values that are highly characteristic of RemotePE C2 behavior.
- **Lazarus_RemotePE_C2_Domain_Query** (sigma, high): This rule detects DNS queries for a list of domains specifically identified as RemotePE C2 infrastructure.
- **Lazarus_RemotePE_Payload_Staging** (sigma, medium): This rule detects file writes to a specific, unusual directory used for payload staging, filtering for known good system processes.
