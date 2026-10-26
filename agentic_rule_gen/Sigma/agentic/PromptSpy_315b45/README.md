# PromptSpy

Source: https://www.welivesecurity.com/en/eset-research/promptspy-ushers-in-era-android-threats-using-genai/

PromptSpy is an Android malware family that leverages Google's Gemini generative AI to achieve persistence by dynamically navigating the UI to lock itself in the recent apps list. Its primary purpose is to deploy a VNC module for remote device control, and it also features capabilities for data theft, screen recording, and anti-removal via invisible overlays.

- **PromptSpy_APK_Download** (sigma, high): This rule is highly specific, combining a known malware distribution domain with a unique APK naming pattern.
- **PromptSpy_C2_Connection** (sigma, high): This rule detects connections to dedicated IP addresses used by PromptSpy malware for C2 and distribution.
- **PromptSpy_DNS_Query** (sigma, high): This rule detects DNS lookups for domains specifically registered for PromptSpy distribution and phishing.
- **PromptSpy_Phishing_Access** (sigma, medium): This rule detects web access to a domain known to be used for phishing in the PromptSpy campaign.
