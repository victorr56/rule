# AccountGuard

Source: https://www.huntress.com/blog/bank-spam-rmm

This malware is delivered via a phishing email impersonating Bank of America. A VBScript within a ZIP file initiates a multi-stage PowerShell execution chain that decodes and runs further scripts, ultimately downloading a legitimate ScreenConnect installer. The malware uses a UAC bypass to silently install ScreenConnect with elevated privileges, then uses SDDL and registry modifications to hide the service and prevent its removal.

- **AccountGuard_UAC_Bypass_ICMLuaUtil** (sigma, high): This rule detects the specific and uncommon COM object `ICMLuaUtil` used by the malware for UAC bypass.
- **AccountGuard_ScreenConnect_Masquerading** (sigma, high): This rule detects ScreenConnect running from a specific, non-default path created by the malware for masquerading.
- **AccountGuard_VBS_Dropper_Execution** (sigma, high): This rule detects the execution of the specifically named initial access VBScript dropper.
- **AccountGuard_MSI_Execution** (sigma, medium): This rule detects the execution of an MSI with a suspicious name and path combination used by the malware.
- **AccountGuard_Phishing_And_C2_Domains** (sigma, high): This rule detects DNS queries for specific typosquatting and malware-hosting domains used by the threat actor.
