# ldapnomnom

Source: https://www.huntress.com/blog/ldap-active-directory-detection-part-six

ldapnomnom is a tool for unauthenticated Active Directory username enumeration using a technique called LDAP Ping. By default, it uses TCP, making connection attempts visible via Event 5156, while the LDAP Ping mechanism itself bypasses Event 1644. All queries are logged with usernames but no source IP in netlogon.log if debug logging is enabled.

- **Netlogon_Full_Debug_Logging_Enabled_Via_Registry** (sigma, high): Keys on registry modification setting the Netlogon DBFlag to its maximum debug value, a precursor to LDAP enumeration.
- **Netlogon_Full_Debug_Logging_Enabled_Via_Nltest** (sigma, high): Keys on nltest.exe execution setting the Netlogon DBFlag to its maximum debug value, a precursor to LDAP enumeration.
- **Ldeep_LDAP_User_Enumeration** (sigma, high): Keys on the ldeep tool execution with command line arguments specific to LDAP user enumeration.
