# MacSync

Source: https://www.huntress.com/blog/macsync-stealer-rat-reverse-engineering

MacSync is a multi-stage macOS stealer and RAT delivered via malvertising campaigns using fake AI-themed install guides. The malware steals a wide range of data including browser credentials, keychain secrets, and cryptocurrency wallets, and can trojanize existing wallet applications to phish for recovery phrases. It establishes persistence with a native Mach-O RAT that communicates over a raw-IP TLS channel.

- **MAL_MacSync_RAT_Oct2026** (yara, high): This rule detects the core MacSync RAT via its unique, hardcoded 61-byte C2 encryption token, which is a strong indicator.
- **MAL_MacSync_Stealer_Oct2026** (yara, medium): This rule detects the MacSync stealer script using a highly unique Russian developer comment and other identifying strings.
- **MacSyncRATPayloadDrop** (sigma, high): This rule detects the specific file path and name pattern for the dropped MacSync RAT binary.
- **MacSyncDataArchiving** (sigma, high): This rule detects a specific `ditto` command line used by MacSync to archive stolen files.
- **MacSyncPasswordValidation** (sigma, high): This rule detects the specific `dscl` command and arguments used to validate user passwords.
- **MacSyncC2Domains** (sigma, high): This rule detects DNS lookups for domains exclusively used by MacSync C2 infrastructure.
- **MacSyncC2Connections** (sigma, high): This rule detects network traffic to IP addresses exclusively used by MacSync C2 infrastructure.
