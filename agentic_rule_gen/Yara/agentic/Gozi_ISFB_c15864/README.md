# Gozi ISFB

Source: https://www.group-ib.com/blog/gozi-latest-ttps/

A Gozi ISFB variant uses a multi-stage, in-memory infection chain starting with a self-extracting executable. A .NET downloader fetches a .NET packer from a Discord URL, which in turn executes the Gozi downloader DLL. The final payload communicates with C2 servers specified in its embedded configuration.

- **MAL_Gozi_Downloader_Oct2026** (yara, high): The rule keys on a unique 16-byte server key and a combination of C2/configuration strings from a Gozi ISFB downloader.
- **Gozi_ISFB_C2_Domain_Query** (sigma, high): This rule detects DNS queries for a C2 domain specifically used by Gozi ISFB, as identified in its configuration.
