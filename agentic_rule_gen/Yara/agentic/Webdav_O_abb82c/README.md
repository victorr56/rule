# Webdav-O

Source: https://www.group-ib.com/blog/task/

Webdav-O is a RAT used by Chinese APTs, primarily linked to TaskMasters and sharing code with tools from TA428. It is considered an evolution of the BlueTraveller/RemShell family. The malware uses Yandex.Disk for C2 via the WebDAV protocol, with commands and data encrypted using hardcoded or session-based RC4 keys. Webdav-O exists in both x86 and x64 versions and typically establishes persistence as a service.

- **APT_TaskMasters_WebdavO_Oct26** (yara, medium): This rule detects Webdav-O using two unique 16-byte RC4 keys or combinations of supporting strings.
- **APT_TaskMasters_Albaniiutas_Oct26** (yara, medium): This rule detects Albaniiutas RAT/dropper with its unique high-entropy RC4 key and distinctive error strings.
- **TaskMasters_WebdavO_Yandex_C2** (sigma, high): This rule detects highly specific C2 URIs used by Webdav-O on the legitimate Yandex service.
