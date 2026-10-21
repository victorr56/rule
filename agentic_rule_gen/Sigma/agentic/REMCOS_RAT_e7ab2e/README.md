# REMCOS RAT

Source: https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-four

REMCOS RAT is a widespread trojan that achieves persistence via Run keys and injects into other processes like svchost.exe and iexplore.exe for its watchdog and main functionality. It performs data collection through keylogging, screenshots with a distinct file naming pattern (time_YYYYMMDD_HHMMSS.jpg), and audio recording. The malware also features UAC bypass capabilities and browser data deletion.

- **RemcosRatScreenshotFile** (sigma, high): This rule keys on the highly specific screenshot filename pattern `time_YYYYMMDD_HHMMSS.jpg` used by REMCOS RAT.
- **RemcosRatRegistryKey** (sigma, high): This rule keys on the creation of the specific `HKCU\Software\Remcos` registry key, which is unique to this malware.
- **RemcosRatC2IPs** (sigma, high): This rule keys on a list of C2 IP addresses specifically associated with recent REMCOS RAT campaigns.
