# TriBack Loader

Source: https://www.group-ib.com/blog/jadeprox-china-nexus-triback-loader/

JadeProx is a China-nexus cluster delivering phishing archives that chain LNK/VBS/MSI stagers into signed-binary DLL sideloading (TriBack Loader) to decrypt and run AdaptixC2 beacons or the Beagle backdoor from .dat/.log companion files. Four TriBack Loader variants share two-stage byte-reversal plus rolling-XOR decryption and rotate Win32 callback APIs (InitOnceExecuteOnce, TimerQueue, EtwpCreateEtwThread) to evade EDR, with hands-on post-exploitation tunnelling tooling (iox, suo5, Neo-reGeorg, nuclei, fscan) staged from an exposed Alibaba Cloud server. C2 and phishing domains are NameSilo-registered with Alibaba/Cloudflare hosting, and the same loader builder output recurs across all campaigns.

- **JadeProxTriBackLoaderSideloadPayloadCreation** (sigma, high): This rule detects the specific combination of a signed executable creating an unusually named payload file, a core TTP of TriBack variants 1 and 2.
- **JadeProxTriBackLoaderPersistenceInStartupFolder** (sigma, high): This rule detects the creation of a specifically named payload file ('NOVUpdate.exe.dat') in the Windows Startup folder, a high-fidelity persistence indicator.
- **JadeProxTriBackStagerExecutionViaFtp** (sigma, high): This rule combines the LOLBAS `ftp.exe -s:` with the actor-specific path marker `_CL_`, making it a highly precise behavioral detection.
- **JadeProxTriBackC2DomainQuery** (sigma, high): This rule detects queries for a list of specific, actor-controlled command-and-control domains identified in the threat profile.
- **JadeProxLinuxSOCKS5ProxyStaging** (sigma, high): This rule detects a highly specific `curl` command line used to download a malicious tool from an actor-controlled URL on a Linux system.
