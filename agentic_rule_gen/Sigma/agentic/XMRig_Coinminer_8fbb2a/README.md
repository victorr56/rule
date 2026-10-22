# XMRig Coinminer

Source: https://www.group-ib.com/blog/mxdr-cryptominer/

A cryptojacking campaign uses a drive-by download from a compromised website to deliver a ZIP archive. The archive contains a dropper that installs the XMRig Monero miner, establishes persistence via a scheduled task, and disables security tools. The initial infection is triggered by a multi-stage JavaScript loader that displays a fake Chrome error page.

- **XMRigPersistenceViaGoogleUpdateTaskMachineQC** (sigma, high): This rule detects the specific command line used by the malware to create a persistent scheduled task.
- **ExecutionOfMasqueradingChromeUpdater** (sigma, medium): This rule detects the execution of the miner from a suspicious path by a generic parent process.
- **XMRigDropperZIPDownload** (sigma, high): This rule detects the download of a file with a highly specific name pattern by a web browser.
- **XMRigC2DomainChromeErrorCo** (sigma, high): This rule detects DNS queries to a known-malicious C2 domain specific to this campaign.
- **XMRigPayloadDownloadFromIPFS** (sigma, high): This rule detects network traffic to unique IPFS content hashes used by the malware for staging.
