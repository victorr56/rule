# ABYSSWORKER

Source: https://www.elastic.co/security-labs/threat-command/abyssworker

ABYSSWORKER is a revoked certificate-signed Windows driver used to disable EDR products. It accepts a range of IOCTL commands to terminate processes, remove kernel callbacks, and manipulate driver objects after being enabled with a hardcoded password. This driver is deployed by a loader packed with HEARTCRYPT as part of campaigns delivering MEDUSA ransomware.

- **ABYSSWORKER_Device_Object_Creation** (sigma, high): This rule keys on the highly specific and unique device object name created by the ABYSSWORKER driver.
- **ABYSSWORKER_Symbolic_Link_Creation** (sigma, high): This rule keys on the highly specific and unique symbolic link name created by the ABYSSWORKER driver, which is often persisted in the registry.
- **ABYSSWORKER_Driver_Load** (sigma, medium): This rule keys on the specific filename of the ABYSSWORKER driver, 'smuol.sys', being loaded into memory.
